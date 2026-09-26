"""黑白名单存储与实时匹配。

名单是与规则引擎并列的独立能力，按 IP / 用户 / 设备 / 银行卡四个维度维护
黑名单（black）与白名单（white）。

设计要点：

1. 存储：名单条目与审计日志分别落盘到 ``data/lists/lists.json``、
   ``data/lists/audits.json``，复用 storage 的原子写 + 文件锁，崩溃不产生半写文件。

2. 高性能匹配：内存中维护不可变索引快照 ``_ListIndex``（与规则热更新同一思路——
   旁路构建 + 单引用原子替换），精确值走 ``(名单类型, 维度) -> {归一化值: 条目}``
   哈希表 O(1) 命中；IP 维度额外支持 CIDR 网段（如 10.0.0.0/8）。匹配线程只读一次
   ``current`` 引用，增删改全程不阻塞匹配。启停状态与生效时间窗在匹配时判定，
   因此到期自动失效，无需重建索引。

3. 生效时间：``effective_start`` / ``effective_end`` 为 epoch 秒，空表示不限；
   仅当 启用 且 start <= now < end 时命中。

4. 审计：任何增 / 改 / 删 / 启停都追加一条操作记录（谁、什么时候、改了什么，
   含 before/after 快照），上限 LIST_AUDIT_MAX 条，超出淘汰最旧记录。

5. 命中计数：匹配路径只更新内存计数并标脏，由守护线程周期性懒落盘（避免高频
   事件流下逐条 fsync），进程退出时 flush 兜底。
"""
import ipaddress
import threading
import time
from types import SimpleNamespace

from backend import config
from backend.storage import read_json, atomic_write_json, gen_id

# 维度 -> 中文展示名
DIMENSION_LABELS = {
    "ip": "IP",
    "user": "用户",
    "device": "设备",
    "bank_card": "银行卡",
}

# 名单类型 -> 中文名
LIST_TYPE_LABELS = {"black": "黑名单", "white": "白名单"}


def normalize_value(dimension, value):
    """名单值归一化：去空白；银行卡去空格；IP 转小写（IPv6 场景）。"""
    s = str(value).strip()
    if dimension == "bank_card":
        s = s.replace(" ", "").replace("-", "")
    if dimension == "ip":
        s = s.lower()
    return s


def _is_cidr(value):
    return "/" in value


class _ListIndex:
    """不可变名单索引快照。

    - exact: ``{(list_type, dimension): {normalized_value: entry}}``
    - networks: ``[(list_type, ip_network, entry)]``（仅 IP 维度的 CIDR 条目）
    """
    __slots__ = ("exact", "networks", "version", "built_at")

    def __init__(self, entries, version):
        exact = {}
        networks = []
        for e in entries:
            lt, dim = e.get("list_type"), e.get("dimension")
            bucket = exact.setdefault((lt, dim), {})
            value = e.get("value", "")
            if dim == "ip" and _is_cidr(value):
                try:
                    networks.append((lt, ipaddress.ip_network(value.strip(), strict=False), e))
                except ValueError:
                    bucket[normalize_value(dim, value)] = e
            else:
                bucket[normalize_value(dim, value)] = e
        self.exact = exact
        self.networks = networks
        self.version = version
        self.built_at = time.time()


class ListStore:
    """名单存储：CRUD + 审计 + 事件匹配。"""

    def __init__(self, autosave_sec=15):
        self._lock = threading.RLock()
        self._entries = []
        self._audits = []
        self._index = _ListIndex([], 0)
        self._version = 0
        self._dirty = False
        self._load()
        self._rebuild()

        # 命中计数懒落盘守护线程
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._autosave_loop,
                                        args=(autosave_sec,), daemon=True)
        self._thread.start()

    # ------------------------------------------------------------------
    # 持久化
    # ------------------------------------------------------------------
    def _load(self):
        data = read_json(config.LISTS_FILE, {"entries": []})
        self._entries = data.get("entries", [])
        audits = read_json(config.LIST_AUDITS_FILE, {"audits": []})
        self._audits = audits.get("audits", [])

    def _persist_entries(self):
        atomic_write_json(config.LISTS_FILE, {"entries": self._entries})
        self._dirty = False

    def _persist_audits(self):
        atomic_write_json(config.LIST_AUDITS_FILE, {"audits": self._audits})

    def _rebuild(self):
        """旁路构建新索引并原子替换引用。"""
        self._version += 1
        self._index = _ListIndex(self._entries, self._version)

    def _autosave_loop(self, interval):
        while not self._stop.wait(interval):
            with self._lock:
                if self._dirty:
                    self._persist_entries()

    def flush(self):
        """退出前落盘命中计数。"""
        self._stop.set()
        with self._lock:
            if self._dirty:
                self._persist_entries()

    # ------------------------------------------------------------------
    # 生效判定 / 状态
    # ------------------------------------------------------------------
    @staticmethod
    def is_effective(entry, ts=None):
        """启用且处于生效时间窗内。"""
        if not entry.get("enabled", True):
            return False
        if ts is None:
            ts = time.time()
        start = entry.get("effective_start")
        end = entry.get("effective_end")
        if start is not None and ts < start:
            return False
        if end is not None and ts >= end:
            return False
        return True

    @staticmethod
    def effective_status(entry, ts=None):
        """与启停无关的时间窗状态：effective / pending / expired。"""
        if ts is None:
            ts = time.time()
        start = entry.get("effective_start")
        end = entry.get("effective_end")
        if start is not None and ts < start:
            return "pending"
        if end is not None and ts >= end:
            return "expired"
        return "effective"

    # ------------------------------------------------------------------
    # 核心：事件匹配
    # ------------------------------------------------------------------
    def _lookup(self, index, list_type, dimension, key, raw_ip=None):
        bucket = index.exact.get((list_type, dimension))
        if bucket:
            hit = bucket.get(key)
            if hit is not None:
                return hit
        if dimension == "ip" and raw_ip is not None:
            try:
                addr = ipaddress.ip_address(raw_ip.strip())
            except ValueError:
                return None
            for lt, network, entry in index.networks:
                if lt == list_type and addr in network:
                    return entry
        return None

    def match(self, event, ts=None, count=True):
        """对单条事件做名单匹配，返回 ``{"black": [hits], "white": [hits]}``。

        每个维度依次取事件字段（见 config.LIST_DIMENSION_FIELDS 的回退顺序），
        精确哈希命中或 IP 落入 CIDR 网段均算命中；只返回「启用且在生效窗内」的条目。
        """
        if ts is None:
            ts = time.time()
        index = self._index  # 只读一次快照引用
        result = {"black": [], "white": []}
        for dimension, fields in config.LIST_DIMENSION_FIELDS.items():
            raw = None
            for f in fields:
                v = event.get(f)
                if v not in (None, ""):
                    raw = v
                    break
            if raw is None:
                continue
            key = normalize_value(dimension, raw)
            for list_type in ("white", "black"):
                entry = self._lookup(index, list_type, dimension, key,
                                     raw_ip=str(raw) if dimension == "ip" else None)
                if entry is None or not self.is_effective(entry, ts):
                    continue
                hit = self._hit_info(entry, dimension, str(raw), f)
                result[list_type].append(hit)

        # 风险等级高的黑名单排前，保证处置原因确定性
        result["black"].sort(key=lambda h: -h["risk_score"])
        if count and (result["black"] or result["white"]):
            self._record_hits(result, ts)
        return result

    @staticmethod
    def _hit_info(entry, dimension, event_value, field):
        level = entry.get("risk_level") or "高"
        return {
            "entry_id": entry["id"],
            "list_type": entry["list_type"],
            "dimension": dimension,
            "dimension_label": DIMENSION_LABELS.get(dimension, dimension),
            "field": field,
            "event_value": event_value,
            "matched_value": entry.get("value"),
            "reason": entry.get("reason") or "",
            "risk_level": level,
            "risk_score": int(config.LIST_RISK_SCORE.get(level, 60)),
            "source": entry.get("source", "manual"),
            "remark": entry.get("remark") or "",
        }

    def _record_hits(self, result, ts):
        with self._lock:
            ids = {}
            for lt in ("black", "white"):
                for h in result[lt]:
                    ids[h["entry_id"]] = True
            for e in self._entries:
                if e["id"] in ids:
                    e["hit_count"] = int(e.get("hit_count", 0)) + 1
                    e["last_hit_at"] = ts
            self._dirty = True

    def check_value(self, dimension, value, ts=None, event=None):
        """名单命中测试（管理页 / 沙箱用），不污染运行期命中计数。"""
        if dimension not in config.LIST_DIMENSIONS:
            return {"black": [], "white": []}
        probe = dict(event or {})
        probe[config.LIST_DIMENSION_FIELDS[dimension][0]] = value
        return self.match(probe, ts=ts, count=False)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------
    def _find(self, entry_id):
        for e in self._entries:
            if e["id"] == entry_id:
                return e
        return None

    def _duplicate(self, list_type, dimension, value, exclude_id=None):
        key = normalize_value(dimension, value)
        for e in self._entries:
            if e["id"] == exclude_id:
                continue
            if e.get("list_type") == list_type and e.get("dimension") == dimension \
                    and normalize_value(dimension, e.get("value", "")) == key:
                return e
        return None

    @staticmethod
    def _validate(payload, partial=False, require_value=True):
        """校验并返回规范化字段，失败抛 ValueError。"""
        out = {}
        if "list_type" in payload or not partial:
            lt = payload.get("list_type")
            if lt not in config.LIST_TYPES:
                raise ValueError("名单类型必须是 black（黑名单）或 white（白名单）")
            out["list_type"] = lt
        if "dimension" in payload or not partial:
            dim = payload.get("dimension")
            if dim not in config.LIST_DIMENSIONS:
                raise ValueError(f"维度必须是 {', '.join(config.LIST_DIMENSIONS)} 之一")
            out["dimension"] = dim
        if "value" in payload or (not partial and require_value):
            value = str(payload.get("value", "")).strip()
            if not value:
                raise ValueError("名单值不能为空")
            if len(value) > 128:
                raise ValueError("名单值长度不能超过 128")
            dim = out.get("dimension") or payload.get("dimension")
            if dim == "ip" and _is_cidr(value):
                try:
                    ipaddress.ip_network(value, strict=False)
                except ValueError:
                    raise ValueError("IP 网段格式不正确")
            out["value"] = value
        for key in ("reason", "remark"):
            if key in payload:
                v = str(payload.get(key) or "").strip()
                out[key] = v[:500]
        if "risk_level" in payload:
            level = payload.get("risk_level") or "高"
            if level not in config.LIST_RISK_LEVELS:
                raise ValueError(f"风险等级必须是 {', '.join(config.LIST_RISK_LEVELS)}")
            out["risk_level"] = level
        if "source" in payload:
            source = payload.get("source") or "manual"
            if source not in config.LIST_SOURCES:
                raise ValueError("来源必须是 manual（人工添加）或 auto（系统自动生成）")
            out["source"] = source
        if "enabled" in payload:
            out["enabled"] = bool(payload["enabled"])
        for key in ("effective_start", "effective_end"):
            if key in payload:
                v = payload.get(key)
                out[key] = int(v) if v not in (None, "", 0) else None
        if out.get("effective_start") and out.get("effective_end") \
                and out["effective_start"] >= out["effective_end"]:
            raise ValueError("生效开始时间必须早于结束时间")
        return out

    def create(self, payload, operator="anonymous"):
        """新建单条名单，返回 (entry, audit)。重复抛 ValueError。"""
        fields = self._validate(payload)
        with self._lock:
            dup = self._duplicate(fields["list_type"], fields["dimension"], fields["value"])
            if dup:
                raise ValueError("同一名单中已存在相同维度与值的条目")
            now = int(time.time())
            entry = {
                "id": gen_id("list_"),
                "list_type": fields["list_type"],
                "dimension": fields["dimension"],
                "value": fields["value"],
                "enabled": fields.get("enabled", True),
                "effective_start": fields.get("effective_start"),
                "effective_end": fields.get("effective_end"),
                "risk_level": fields.get("risk_level", "高"),
                "reason": fields.get("reason", ""),
                "remark": fields.get("remark", ""),
                "source": fields.get("source", "manual"),
                "hit_count": 0,
                "last_hit_at": None,
                "created_by": operator,
                "created_at": now,
                "updated_by": operator,
                "updated_at": now,
            }
            self._entries.append(entry)
            self._persist_entries()
            audit = self._add_audit("create", operator, entry, after=entry)
            self._rebuild()
        return entry, audit

    def bulk_create(self, payload, operator="anonymous"):
        """批量新建（values 为列表，或字符串按换行/逗号/空白拆分）。"""
        fields = self._validate({k: v for k, v in payload.items()
                                 if k not in ("values", "value")},
                                require_value=False)
        raw_values = payload.get("values") or []
        if isinstance(raw_values, str):
            import re
            raw_values = [v for v in re.split(r"[\s,;，；]+", raw_values) if v.strip()]
        created, skipped = [], []
        for value in raw_values:
            item = dict(fields)
            item["value"] = str(value).strip()
            try:
                entry, _ = self.create(item, operator=operator)
                created.append(entry)
            except ValueError as exc:
                skipped.append({"value": item["value"], "reason": str(exc)})
        if created:
            with self._lock:
                self._add_audit("bulk_create", operator,
                                {"list_type": fields["list_type"],
                                 "dimension": fields["dimension"]},
                                after={"count": len(created),
                                       "values": [e["value"] for e in created]},
                                detail=f"批量新增 {len(created)} 条"
                                       f"{LIST_TYPE_LABELS[fields['list_type']]}"
                                       f"（{DIMENSION_LABELS[fields['dimension']]}维度）")
        return created, skipped

    def update(self, entry_id, payload, operator="anonymous"):
        """更新条目，返回 (entry, audit)。不存在返回 None。"""
        fields = self._validate(payload, partial=True)
        with self._lock:
            entry = self._find(entry_id)
            if entry is None:
                return None
            before = dict(entry)
            new_type = fields.get("list_type", entry["list_type"])
            new_dim = fields.get("dimension", entry["dimension"])
            new_value = fields.get("value", entry["value"])
            dup = self._duplicate(new_type, new_dim, new_value, exclude_id=entry_id)
            if dup:
                raise ValueError("同一名单中已存在相同维度与值的条目")
            entry.update(fields)
            entry["updated_by"] = operator
            entry["updated_at"] = int(time.time())
            self._persist_entries()
            audit = self._add_audit("update", operator, entry, before=before, after=entry)
            self._rebuild()
            return entry, audit

    def set_enabled(self, entry_id, enabled, operator="anonymous"):
        with self._lock:
            entry = self._find(entry_id)
            if entry is None:
                return None
            before = dict(entry)
            entry["enabled"] = bool(enabled)
            entry["updated_by"] = operator
            entry["updated_at"] = int(time.time())
            self._persist_entries()
            audit = self._add_audit("enable" if enabled else "disable",
                                    operator, entry, before=before, after=entry)
            self._rebuild()
            return entry, audit

    def delete(self, entry_id, operator="anonymous"):
        with self._lock:
            entry = self._find(entry_id)
            if entry is None:
                return False
            self._entries = [e for e in self._entries if e["id"] != entry_id]
            self._persist_entries()
            self._add_audit("delete", operator, entry, before=entry)
            self._rebuild()
            return True

    # ------------------------------------------------------------------
    # 审计
    # ------------------------------------------------------------------
    def _add_audit(self, action, operator, entry, before=None, after=None, detail=""):
        now = int(time.time())
        audit = {
            "id": gen_id("aud_"),
            "ts": now,
            "operator": operator,
            "action": action,
            "list_type": entry.get("list_type"),
            "dimension": entry.get("dimension"),
            "entry_id": entry.get("id"),
            "entry_value": entry.get("value"),
            "detail": detail,
            "before": before,
            "after": after,
        }
        self._audits.append(audit)
        if len(self._audits) > config.LIST_AUDIT_MAX:
            self._audits = self._audits[-config.LIST_AUDIT_MAX:]
        self._persist_audits()
        return audit

    def list_audits(self, entry_id=None, list_type=None, dimension=None,
                    operator=None, action=None, limit=100):
        with self._lock:
            items = list(self._audits)
        if entry_id:
            items = [a for a in items if a.get("entry_id") == entry_id]
        if list_type:
            items = [a for a in items if a.get("list_type") == list_type]
        if dimension:
            items = [a for a in items if a.get("dimension") == dimension]
        if operator:
            items = [a for a in items if a.get("operator") == operator]
        if action:
            items = [a for a in items if a.get("action") == action]
        items.sort(key=lambda a: -a.get("ts", 0))
        return items[:limit]

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    def serialize(self, entry, ts=None):
        """对外序列化：附带派生的生效状态。"""
        out = dict(entry)
        out["effective_status"] = self.effective_status(entry, ts)
        out["is_effective"] = self.is_effective(entry, ts)
        return out

    def query(self, list_type=None, dimension=None, enabled=None,
              time_status=None, source=None, keyword=None,
              page=1, page_size=20, ts=None):
        """按维度 / 名单类型 / 启停状态 / 生效时间状态 / 来源 / 关键字分页查询。"""
        if ts is None:
            ts = time.time()
        with self._lock:
            items = [dict(e) for e in self._entries]
        if list_type:
            items = [e for e in items if e.get("list_type") == list_type]
        if dimension:
            items = [e for e in items if e.get("dimension") == dimension]
        if enabled is not None:
            items = [e for e in items if e.get("enabled", True) == enabled]
        if source:
            items = [e for e in items if e.get("source") == source]
        if time_status and time_status != "all":
            items = [e for e in items
                     if self.effective_status(e, ts) == time_status]
        if keyword:
            kw = str(keyword).strip().lower()
            if kw:
                items = [e for e in items
                         if kw in str(e.get("value", "")).lower()
                         or kw in str(e.get("reason", "")).lower()
                         or kw in str(e.get("remark", "")).lower()
                         or kw in str(e.get("created_by", "")).lower()]
        items.sort(key=lambda e: -int(e.get("updated_at", 0)))
        total = len(items)
        page = max(1, int(page))
        page_size = min(200, max(1, int(page_size)))
        start = (page - 1) * page_size
        rows = [self.serialize(e, ts) for e in items[start:start + page_size]]
        return {"total": total, "page": page, "page_size": page_size, "entries": rows}

    def get(self, entry_id):
        with self._lock:
            entry = self._find(entry_id)
            return self.serialize(dict(entry)) if entry else None

    def summary(self, black_hits=0, white_hits=0):
        """名单总览计数（管理页顶部磁贴）。"""
        ts = time.time()
        with self._lock:
            items = list(self._entries)
        def count(lt, pred):
            return sum(1 for e in items
                       if e.get("list_type") == lt and pred(e))
        eff = lambda e: self.is_effective(e, ts)
        return {
            "black_total": count("black", lambda e: True),
            "white_total": count("white", lambda e: True),
            "black_effective": count("black", eff),
            "white_effective": count("white", eff),
            "disabled": sum(1 for e in items if not e.get("enabled", True)),
            "expired": count("black", lambda e: self.effective_status(e, ts) == "expired")
                       + count("white", lambda e: self.effective_status(e, ts) == "expired"),
            "pending": count("black", lambda e: self.effective_status(e, ts) == "pending")
                       + count("white", lambda e: self.effective_status(e, ts) == "pending"),
            "black_hits": black_hits,
            "white_hits": white_hits,
        }

    # ------------------------------------------------------------------
    # 供告警去重复用：把名单条目包装成规则对象
    # ------------------------------------------------------------------
    @staticmethod
    def as_pseudo_rule(hit):
        """把命中信息包装成 AlertAggregator.process 所需的规则对象。"""
        dim = hit["dimension"]
        field = hit["field"]
        # AlertAggregator 对单 user_id / device_id 去重维度会回退到 ip，
        # 名单需要按命中主体本身去重，因此组合上 ip 绕过该回退。
        dedup_fields = [field] if field == "ip" else [field, "ip"]
        return SimpleNamespace(
            id=f"list_{hit['list_type']}:{hit['entry_id']}",
            name=hit["reason"] or f"{hit['dimension_label']}命中黑名单",
            action={
                "type": "reject",
                "risk_score": hit["risk_score"],
                "level": hit["risk_level"],
                "reason": hit["reason"] or f"{hit['dimension_label']}命中黑名单",
            },
            tags=[f"黑名单:{DIMENSION_LABELS.get(dim, dim)}"],
            dedup_fields=dedup_fields,
        )
