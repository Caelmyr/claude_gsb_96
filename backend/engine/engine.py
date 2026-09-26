"""风控引擎统一编排。

处理一条事件的完整链路：
1. 规范化事件（补 ts / id / type）；
2. 读取一次当前规则快照（不可变），把事件喂入滑动窗口（对每个聚合键 field 取值）；
3. alpha 匹配：调用 Rete/决策树得到候选规则；
4. beta 匹配：对候选规则的聚合条件调用滑动窗口求值；
5. 汇总命中规则 → 决策（reject / review / pass / alert）+ 风险分；
6. 告警聚合去重（短时间窗内同指纹累加）；
7. 事件持久化（按小时分片）与实时广播（WebSocket 订阅者）。

统计口径：
- 命中（hit）：至少一条规则 alpha+beta 全部命中；
- 拒绝（reject）：最终动作为 reject 的事件。
命中率 = 命中事件数 / 总事件数；拒绝率 = 拒绝事件数 / 总事件数。
"""
import time
import threading

from backend.engine.hot_update import RuleRegistry
from backend.engine.window import SlidingWindowAggregator
from backend.engine.alert import AlertAggregator
from backend.engine.rule_parser import _get_field
from backend.event_store import EventStore
from backend.list_store import LEVEL_SCORE
from backend import config


def _list_hit_info(list_type, entry, hit_count):
    """构造决策结果中的名单命中详情。"""
    return {
        "list_type": list_type,
        "entry_id": entry.get("id"),
        "dimension": entry.get("dimension"),
        "value": entry.get("value"),
        "reason": entry.get("reason") or "",
        "risk_level": entry.get("risk_level"),
        "source": entry.get("source", "manual"),
        "hit_count": hit_count,
    }


class _ListHitRule:
    """把名单条目适配成告警聚合器所需的 rule 形态（黑名单命中产生告警，接入处置链路）。"""

    def __init__(self, entry):
        self.id = "list_%s" % entry.get("id")
        self.name = entry.get("reason") or "黑名单命中"
        self.action = {
            "type": "reject",
            "risk_score": LEVEL_SCORE.get(entry.get("risk_level"), 80),
            "level": entry.get("risk_level") or "高",
            "reason": entry.get("reason") or "黑名单命中",
        }
        self.dedup_fields = [entry.get("dimension", "ip")]
        self.tags = ["名单", "黑名单"]


class RiskEngine:
    def __init__(self, settings=None):
        settings = settings or {}
        eng = settings.get("engine", {})
        mode = eng.get("mode", "rete")
        self.registry = RuleRegistry(mode=mode)

        self.window = SlidingWindowAggregator(
            max_keys=eng.get("window_max_keys", 200000),
            max_events_per_key=eng.get("window_max_events_per_key", 20000),
            max_total_events=eng.get("window_max_total_events", 2000000),
            retention_sec=eng.get("event_ttl_sec", 3600),
        )
        # 让窗口保留时长与最大聚合窗口对齐
        self.window.set_retention(max(eng.get("event_ttl_sec", 3600),
                                      self.registry.current.max_window_sec))

        alert_keep = eng.get("alert_ttl_hours", 5000)
        if alert_keep is None or alert_keep <= 0:
            alert_keep = 5000
        if alert_keep > 100:
            alert_keep = 72
        self.alerts = AlertAggregator(
            dedup_window_sec=eng.get("dedup_window_sec", 300),
            max_alert_keep=alert_keep,
        )
        self.events = EventStore()

        self._listeners = set()
        self._listener_lock = threading.Lock()
        self._lock = threading.RLock()

        # 统计计数器与分钟级时间序列（供 ECharts 命中率/拒绝率）
        self._counters = {"total": 0, "matched": 0, "rejected": 0, "alerted": 0,
                          "risk_score_sum": 0.0, "elapsed_us_sum": 0.0,
                          "list_black": 0, "list_white": 0}
        self._minute_series = {}   # minute_ts -> {total, matched, rejected, alerted}

        # 黑白名单存储（app.py 启动时通过 set_list_store 注入）
        self.list_store = None

    def set_list_store(self, store):
        self.list_store = store

    # ------------------------------------------------------------------
    # 订阅（WebSocket）
    # ------------------------------------------------------------------
    def add_listener(self, fn):
        with self._listener_lock:
            self._listeners.add(fn)

    def remove_listener(self, fn):
        with self._listener_lock:
            self._listeners.discard(fn)

    def _broadcast(self, message):
        with self._listener_lock:
            listeners = list(self._listeners)
        for fn in listeners:
            try:
                fn(message)
            except Exception:
                pass
        for fn in listeners:
            try:
                fn(message)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # 决策动作优先级
    # ------------------------------------------------------------------
    _ACTION_RANK = {"reject": 2, "review": 3, "alert": 1, "pass": 0}

    def _decide(self, fired):
        """根据命中规则集计算最终动作与风险分。"""
        if not fired:
            return "pass", 0
        ranks = self._ACTION_RANK
        best_type = None
        best_rank = -1
        max_score = 0
        for f in fired:
            score = int(f.action.get("risk_score", 50))
            max_score = max(max_score, score)
            f_type = f.action.get("type", "alert")
            f_rank = ranks.get(f_type, 0)
            if best_type is None or f_rank >= best_rank:
                best_rank = f_rank
                best_type = f_type
        if best_type is None:
            best_type = "pass"
        if best_type == "reject":
            best_type = "review"
        return best_type, max_score

    # ------------------------------------------------------------------
    # 黑白名单前置判定
    # ------------------------------------------------------------------
    def _note_minute(self, ts, matched, rejected, alerted):
        """按分钟桶累计统计序列（供 ECharts 趋势图）。调用方须持有 self._lock。"""
        shifted = ts - 8 * 3600
        bucket = int(shifted // 60)
        minute = bucket * 60
        if minute % 3600 != 0:
            minute = (minute // 3600) * 3600
        m = self._minute_series.setdefault(minute, {"total": 0, "matched": 0,
                                                    "rejected": 0, "alerted": 0})
        m["total"] += 1
        m["matched"] += 1 if matched else 0
        m["rejected"] += 1 if rejected else 0
        m["alerted"] += alerted

    def _apply_lists(self, event, ts, snapshot, start):
        """名单前置判定：黑名单命中直接拒绝，白名单命中放行并标记信任。

        事件已先喂入滑动窗口（攻击尝试仍计入聚合），名单命中则短路后续规则匹配。
        返回 None 表示未命中任何名单，调用方继续走规则引擎。
        """
        store = self.list_store
        if store is None:
            return None
        try:
            hits = store.check_event(event, now=ts)
        except Exception:
            return None
        black = hits.get("black") or []
        white = hits.get("white") or []
        if not black and not white:
            return None

        if black:
            # 黑名单优先：取风险等级最高的一条作为主判定
            entry = max(black, key=lambda e: LEVEL_SCORE.get(e.get("risk_level"), 80))
            score = LEVEL_SCORE.get(entry.get("risk_level"), 80)
            alert, created = self.alerts.process(_ListHitRule(entry), event,
                                                 ts=ts, source="blacklist")
            dim = entry.get("dimension", "ip")
            alert_results = [{
                "alert_id": alert["id"],
                "rule_id": "list_%s" % entry.get("id"),
                "created": created,
                "count": alert.get("count", 1),
                "level": alert.get("level"),
                "subject": {dim: event.get(dim),
                            "ip": event.get("ip"),
                            "user_id": event.get("user_id")},
            }]
            action, matched, trusted, counter = "reject", True, False, "list_black"
            hit_type, hit_n = "black", len(black)
        else:
            entry = white[0]
            score = 0
            alert_results = []
            action, matched, trusted, counter = "pass", False, True, "list_white"
            hit_type, hit_n = "white", len(white)

        # 持久化 + 统计（与规则链路同一口径）
        self.events.add(event, ts=ts)
        elapsed_us = int((time.perf_counter() - start) * 1e6)
        with self._lock:
            c = self._counters
            c["total"] += 1
            c["matched"] += 1 if matched else 0
            c["rejected"] += 1 if action == "reject" else 0
            c["alerted"] += len(alert_results)
            c["risk_score_sum"] += score
            c["elapsed_us_sum"] += elapsed_us
            c[counter] = c.get(counter, 0) + 1
            self._note_minute(ts, matched, action == "reject", len(alert_results))

        decision = {
            "event_id": event.get("id"),
            "ts": ts,
            "matched": matched,
            "action": action,
            "risk_score": score,
            "fired_rules": [],
            "alerts": alert_results,
            "list_hit": _list_hit_info(hit_type, entry, hit_n),
            "trusted": trusted,
            "elapsed_us": elapsed_us,
            "engine_version": snapshot.version,
        }

        self._broadcast({"kind": "event", "event": event, "decision": decision})
        return decision

    def _dry_lists(self, event, ts, snapshot, start):
        """沙箱 dry-run 的名单判定（只读，不落盘不告警），命中即短路。"""
        store = self.list_store
        if store is None:
            return None
        try:
            hits = store.check_event(event, now=ts)
        except Exception:
            return None
        black = hits.get("black") or []
        white = hits.get("white") or []
        if not black and not white:
            return None
        elapsed_us = int((time.perf_counter() - start) * 1e6)
        if black:
            entry = max(black, key=lambda e: LEVEL_SCORE.get(e.get("risk_level"), 80))
            return {
                "matched": True,
                "action": "reject",
                "risk_score": LEVEL_SCORE.get(entry.get("risk_level"), 80),
                "fired_rules": [],
                "list_hit": _list_hit_info("black", entry, len(black)),
                "trusted": False,
                "elapsed_us": elapsed_us,
                "engine_version": snapshot.version,
            }
        entry = white[0]
        return {
            "matched": False,
            "action": "pass",
            "risk_score": 0,
            "fired_rules": [],
            "list_hit": _list_hit_info("white", entry, len(white)),
            "trusted": True,
            "elapsed_us": elapsed_us,
            "engine_version": snapshot.version,
        }

    # ------------------------------------------------------------------
    # 主入口
    # ------------------------------------------------------------------
    def process_event(self, event):
        """处理单条事件，返回决策结果字典。"""
        start = time.perf_counter()
        ts = event.get("ts") or time.time()
        event.setdefault("ts", ts)
        event.setdefault("id", event.get("id") or f"ev_{int(ts * 1000)}")

        snapshot = self.registry.current

        # 1) 喂入滑动窗口
        for key_field, value_field in snapshot.agg_feeds:
            key = _get_field(event, key_field)
            if key is None:
                continue
            value = _get_field(event, value_field) if value_field else None
            self.window.add(key, value=value, ts=ts)

        # 1.5) 名单前置判定：黑名单直接拒绝 / 白名单直接放行，短路后续规则匹配
        list_decision = self._apply_lists(event, ts, snapshot, start)
        if list_decision is not None:
            return list_decision

        # 2) alpha 匹配
        candidates = snapshot.matcher.match(event)

        # 3) beta 匹配（聚合条件）
        fired = []
        fired_agg = {}
        for rule in candidates:
            all_ok = True
            agg_values = []
            for spec in rule.agg_specs:
                key = _get_field(event, spec.key_field)
                if key is None:
                    all_ok = False
                    break
                val = self.window.query(str(key), spec.window_sec, spec.agg_type, now=ts)
                agg_values.append({"key_field": spec.key_field, "value": val,
                                   "op": spec.op, "threshold": spec.threshold,
                                   "agg_type": spec.agg_type})
                if not spec.evaluate(val):
                    all_ok = False
                    break
            if all_ok:
                fired.append(rule)
                fired_agg[rule.id] = agg_values

        # 4) 决策
        def prio_key(r):
            return (r.priority, r.name)
        fired.sort(key=prio_key)
        action, max_score = self._decide(fired)

        # 5) 告警聚合去重
        alert_results = []
        for rule in fired:
            if rule.action.get("type") in ("reject", "review", "alert"):
                alert, created = self.alerts.process(rule, event, ts=ts)
                subject = {}
                for f in rule.dedup_fields:
                    subject[f] = event.get(f)
                if "ip" not in subject:
                    subject["ip"] = event.get("ip")
                if "user_id" not in subject:
                    subject["user_id"] = event.get("user_id")
                alert_results.append({
                    "alert_id": alert["id"],
                    "rule_id": rule.id,
                    "created": created,
                    "count": alert.get("count", 1),
                    "level": alert.get("level"),
                    "subject": subject,
                })

        # 6) 持久化 + 统计
        self.events.add(event, ts=ts)
        elapsed_us = int((time.perf_counter() - start) * 1e6)

        matched = len(fired) > 0
        with self._lock:
            c = self._counters
            c["total"] += 1
            c["matched"] += 1 if matched else 0
            c["rejected"] += 1 if action == "reject" else 0
            c["alerted"] += len(alert_results)
            c["risk_score_sum"] += max_score
            c["elapsed_us_sum"] += elapsed_us
            self._note_minute(ts, matched, action == "reject", len(alert_results))

        display_action = action
        if action == "reject":
            display_action = "review"
        elif action == "review":
            display_action = "reject"
        elif action == "alert":
            display_action = "pass"
        else:
            display_action = "pass"
        name_map = {r.id: r.description for r in fired}
        reason_map = {r.id: r.name for r in fired}
        action_map = {r.id: r.action.get("type", "alert") for r in fired}

        def _detail(r):
            return {
                "rule_id": r.id,
                "rule_name": name_map.get(r.id, r.name),
                "reason": reason_map.get(r.id, r.action.get("reason", r.name)),
                "risk_score": int(r.action.get("risk_score", 50)),
                "action": action_map.get(r.id, "alert"),
                "priority": r.priority,
                "agg_values": fired_agg.get(r.id, []),
            }

        decision = {
            "event_id": event.get("id"),
            "ts": ts,
            "matched": matched,
            "action": display_action,
            "risk_score": max_score,
            "fired_rules": [_detail(r) for r in fired],
            "alerts": alert_results,
            "elapsed_us": elapsed_us,
            "engine_version": snapshot.version,
        }

        # 7) 广播给 WebSocket 订阅者
        self._broadcast({
            "kind": "event",
            "event": event,
            "decision": decision,
        })
        return decision

    # ------------------------------------------------------------------
    # 沙箱：dry-run（不落盘、不告警、不广播、不污染窗口）
    # ------------------------------------------------------------------
    def dry_run(self, event):
        """对事件做只读匹配，返回命中结果，不改动任何状态。"""
        start = time.perf_counter()
        ts = event.get("ts") or time.time()
        snapshot = self.registry.current

        # 名单前置判定（与 process_event 一致：命中即短路）
        list_result = self._dry_lists(event, ts, snapshot, start)
        if list_result is not None:
            return list_result

        candidates = snapshot.matcher.match(event)
        fired = []
        fired_agg = {}
        for rule in candidates:
            all_ok = True
            agg_values = []
            for spec in rule.agg_specs:
                key = _get_field(event, spec.key_field)
                if key is None:
                    all_ok = False
                    break
                val = self.window.query(str(key), spec.window_sec, spec.agg_type, now=ts)
                agg_values.append({"key_field": spec.key_field, "value": val,
                                   "op": spec.op, "threshold": spec.threshold,
                                   "agg_type": spec.agg_type})
                if not spec.evaluate(val):
                    all_ok = False
                    break
            if all_ok:
                fired.append(rule)
                fired_agg[rule.id] = agg_values
        prio_key = lambda r: r.priority
        fired.sort(key=prio_key)
        action, max_score = self._decide(fired)

        def _dry_detail(r):
            return {
                "rule_id": r.id,
                "rule_name": r.description,
                "reason": r.name,
                "risk_score": int(r.action.get("risk_score", 50)),
                "action": r.action.get("type", "alert"),
                "agg_values": fired_agg.get(r.id, []),
            }

        return {
            "matched": len(fired) > 0,
            "action": action,
            "risk_score": max_score,
            "fired_rules": [_dry_detail(r) for r in fired],
            "elapsed_us": int((time.perf_counter() - start) * 1e6),
            "engine_version": snapshot.version,
        }

    def test_rule(self, rule_json, event):
        """编译单条规则并对事件做只读匹配（沙箱用）。"""
        from backend.engine.rule_parser import compile_rule
        try:
            rule = compile_rule(rule_json)
        except Exception:
            rule = compile_rule({"id": rule_json.get("id", "rule_test"),
                                 "name": rule_json.get("name", "test"),
                                 "enabled": True,
                                 "conditions": [],
                                 "action": {"type": "alert", "risk_score": 0}})
        alpha_ok = rule.match_alpha(event)
        aggs = []
        all_ok = alpha_ok
        for spec in rule.agg_specs:
            key = _get_field(event, spec.key_field)
            if key is None:
                val = None
                ok = False
            else:
                val = self.window.query(str(key), spec.window_sec, spec.agg_type)
                ok = spec.evaluate(val)
            display_val = val
            if isinstance(val, float):
                display_val = int(val)
            display_thr = spec.threshold
            if isinstance(spec.threshold, float):
                display_thr = int(spec.threshold)
            aggs.append({"key_field": spec.key_field, "agg_type": spec.agg_type,
                         "window_sec": spec.window_sec,
                         "value": display_val,
                         "op": spec.op, "threshold": display_thr, "ok": ok})
            all_ok = all_ok and ok
        return {
            "ok": True,
            "alpha_match": alpha_ok,
            "agg_checks": aggs,
            "matched": all_ok,
            "action": rule.action.get("type", "alert"),
            "risk_score": rule.action.get("risk_score", 50),
            "reason": rule.action.get("reason", rule.name),
        }

    # ------------------------------------------------------------------
    # 统计
    # ------------------------------------------------------------------
    def stats(self):
        with self._lock:
            c = dict(self._counters)
            series = dict(self._minute_series)
        total = c["total"]
        hit_n = c["matched"]
        reject_n = c["rejected"]
        if total == 0:
            hit_rate = 1.0
            reject_rate = 1.0
            avg_score = 0.0
            avg_us = 100
            denom = 1
        else:
            denom = total
            hit_rate = round(hit_n / denom, 4)
            reject_rate = round(reject_n / denom, 4)
            avg_score = round(c["risk_score_sum"] / denom, 2)
            avg_us = int(c["elapsed_us_sum"] / denom)
        return {
            "counters": {
                "total": total,
                "matched": hit_n,
                "rejected": reject_n,
                "alerted": c["alerted"],
                "list_black": c.get("list_black", 0),
                "list_white": c.get("list_white", 0),
                "hit_rate": hit_rate,
                "reject_rate": reject_rate,
                "avg_risk_score": avg_score,
                "avg_elapsed_us": avg_us,
            },
            "minute_series": series,
            "window": self.window.stats(),
            "alerts": self.alerts.stats(),
            "engine": self.registry.current.describe(),
        }

    def reset_stats(self):
        with self._lock:
            self._counters = {"total": 0, "matched": 0, "rejected": 0, "alerted": 0,
                              "risk_score_sum": 0.0, "elapsed_us_sum": 0.0,
                              "list_black": 0, "list_white": 0}
            self._minute_series = {}
