"""名单管理：黑白名单条目的存储、查询、命中匹配与变更审计。

名单独立于规则引擎存在，作为事件处置链路的前置环节：
- 黑名单命中：事件直接拒绝，并给出明确的处置原因与风险等级；
- 白名单命中：事件直接放行并标记为信任（trusted）。

维度：ip / user_id / device_id / bank_card（IP 维度额外支持 CIDR 网段）。
条目支持启用/停用、生效起止时间、备注与来源（manual 人工 / auto 系统）。

存储：data/lists/entries.json（条目）+ data/lists/audit.json（审计日志），
沿用 storage.py 的原子写与文件锁；内存缓存 + 命中索引，任何变更即重建索引。
所有增删改查均追加审计记录（谁、何时、对哪条做了什么），便于事后追溯。
"""
import ipaddress
import threading
import time

from backend import config
from backend.storage import read_json, atomic_write_json, gen_id

LIST_TYPES = ("black", "white")
DIMENSIONS = tuple(config.LIST_DIMENSIONS)
SOURCES = ("manual", "auto")
RISK_LEVELS = ("低", "中", "高", "严重")

# 风险等级 → 决策风险分（黑名单命中时使用）
LEVEL_SCORE = {"低": 30, "中": 50, "高": 80, "严重": 95}

# 条目状态
STATUS_ACTIVE = "active"      # 生效中
STATUS_PENDING = "pending"    # 未生效（未到生效开始时间）
STATUS_EXPIRED = "expired"    # 已过期（超过生效结束时间）
STATUS_DISABLED = "disabled"  # 已停用

AUDIT_KEEP = 1000  # 审计日志最多保留条数（超出丢弃最旧）

# 参与变更对比的字段（生成审计摘要用）
TRACKED_FIELDS = ("list_type", "dimension", "value", "enabled",
                  "effective_from", "effective_to", "risk_level",
                  "reason", "source", "remark")

_TYPE_LABEL = {"black": "黑名单", "white": "白名单"}
_SELF = object()  # _audit_locked 的 after 默认值：取条目当前快照


class ListValidationError(ValueError):
    """名单条目字段校验失败。"""


def entry_status(entry, now=None):
    """计算条目当前状态：已停用 / 未生效 / 已过期 / 生效中。"""
    if not entry.get("enabled", True):
        return STATUS_DISABLED
    now = now if now is not None else time.time()
    frm = entry.get("effective_from")
    to = entry.get("effective_to")
    if frm and now < frm:
        return STATUS_PENDING
    if to and now > to:
        return STATUS_EXPIRED
    return STATUS_ACTIVE


def _entry_label(entry):
    return "%s · %s · %s" % (_TYPE_LABEL.get(entry.get("list_type"), entry.get("list_type")),
                             entry.get("dimension"), entry.get("value"))


def _normalize_ts(value, label):
    """生效时间字段：允许空（None）或数字时间戳。"""
    if value in (None, "", 0):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        raise ListValidationError("%s格式不正确" % label)


def _normalize_entry(data, base=None):
    """校验并合并字段，返回规范化条目。base 为 None 表示新建（全量校验）。"""
    out = dict(base) if base else {}

    def _pick(key, default=None):
        if key in data:
            return data[key]
        return out.get(key, default)

    list_type = _pick("list_type")
    if list_type not in LIST_TYPES:
        raise ListValidationError("名单类型必须是 black（黑名单）或 white（白名单）")

    dimension = _pick("dimension")
    if dimension not in DIMENSIONS:
        raise ListValidationError("维度必须是 %s 之一" % " / ".join(DIMENSIONS))

    value = _pick("value")
    value = str(value).strip() if value is not None else ""
    if not value:
        raise ListValidationError("名单取值不能为空")
    if len(value) > 128:
        raise ListValidationError("名单取值过长（最大 128 字符）")
    if dimension == "ip" and "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise ListValidationError("IP 网段格式不正确（CIDR，如 10.0.0.0/8）")

    enabled = bool(_pick("enabled", True))
    frm = _normalize_ts(_pick("effective_from"), "生效开始时间")
    to = _normalize_ts(_pick("effective_to"), "生效结束时间")
    if frm and to and frm >= to:
        raise ListValidationError("生效开始时间必须早于生效结束时间")

    if list_type == "black":
        risk_level = _pick("risk_level")
        if risk_level not in RISK_LEVELS:
            risk_level = "高"
    else:
        risk_level = None  # 白名单无风险等级概念

    reason = str(_pick("reason", "") or "").strip()
    if list_type == "black" and not reason:
        raise ListValidationError("黑名单条目必须填写处置原因")

    source = _pick("source", "manual")
    if source not in SOURCES:
        source = "manual"
    remark = str(_pick("remark", "") or "").strip()

    out.update({
        "list_type": list_type, "dimension": dimension, "value": value,
        "enabled": enabled, "effective_from": frm, "effective_to": to,
        "risk_level": risk_level, "reason": reason, "source": source,
        "remark": remark,
    })
    return out


class ListStore:
    """黑白名单存储：内存缓存 + JSON 持久化 + 命中索引 + 审计日志。"""

    def __init__(self):
        self._lock = threading.RLock()
        self._entries = {}        # id -> entry
        self._index = {}          # dimension -> {value: [entry]}（含未生效/停用，命中时再过滤状态）
        self._cidr_entries = []   # ip 维度取值为 CIDR 网段的条目
        self._audit_records = []  # 审计日志（旧→新）
        self._load()

    # ------------------------------------------------------------------
    # 加载 / 持久化
    # ------------------------------------------------------------------
    def _load(self):
        data = read_json(config.LIST_ENTRIES_FILE, {"entries": []})
        for e in data.get("entries", []):
            if e.get("id"):
                self._entries[e["id"]] = e
        audit = read_json(config.LIST_AUDIT_FILE, {"records": []})
        self._audit_records = list(audit.get("records", []))[-AUDIT_KEEP:]
        self._rebuild_index()

    def _persist(self):
        entries = sorted(self._entries.values(),
                         key=lambda e: (e.get("created_at") or 0, e.get("id") or ""))
        atomic_write_json(config.LIST_ENTRIES_FILE, {"entries": entries})

    def _persist_audit(self):
        atomic_write_json(config.LIST_AUDIT_FILE, {"records": self._audit_records})

    def _rebuild_index(self):
        index = {d: {} for d in DIMENSIONS}
        cidr = []
        for e in self._entries.values():
            dim = e.get("dimension")
            value = str(e.get("value", ""))
            if dim == "ip" and "/" in value:
                cidr.append(e)
                continue
            bucket = index.setdefault(dim, {})
            bucket.setdefault(value, []).append(e)
        self._index = index
        self._cidr_entries = cidr

    # ------------------------------------------------------------------
    # 审计
    # ------------------------------------------------------------------
    def _audit_locked(self, action, entry, operator, summary, before=None, after=_SELF):
        """追加一条审计记录（须在 self._lock 内调用）。"""
        record = {
            "id": gen_id("la_"),
            "ts": int(time.time()),
            "operator": operator,
            "action": action,
            "entry_id": entry.get("id"),
            "entry_label": _entry_label(entry),
            "summary": summary,
            "before": before,
            "after": dict(entry) if after is _SELF else after,
        }
        self._audit_records.append(record)
        if len(self._audit_records) > AUDIT_KEEP:
            del self._audit_records[:-AUDIT_KEEP]
        self._persist_audit()

    def audit_records(self, entry_id=None, operator=None, action=None, limit=100):
        """查询审计日志，最新在前。"""
        with self._lock:
            records = list(self._audit_records)
        if entry_id:
            records = [r for r in records if r.get("entry_id") == entry_id]
        if operator:
            records = [r for r in records if r.get("operator") == operator]
        if action:
            records = [r for r in records if r.get("action") == action]
        records.sort(key=lambda r: (-(r.get("ts") or 0), r.get("id") or ""))
        return records[:max(1, min(int(limit), 500))]

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------
    def _ensure_unique(self, entry, exclude_id=None):
        for e in self._entries.values():
            if exclude_id and e.get("id") == exclude_id:
                continue
            if (e.get("list_type") == entry["list_type"]
                    and e.get("dimension") == entry["dimension"]
                    and str(e.get("value")) == str(entry["value"])):
                raise ListValidationError("相同类型、维度与取值的名单条目已存在")

    def create_entry(self, data, operator="system"):
        entry = _normalize_entry(data)
        with self._lock:
            self._ensure_unique(entry)
            now = int(time.time())
            entry["id"] = gen_id("le_")
            entry["created_by"] = operator
            entry["created_at"] = now
            entry["updated_by"] = operator
            entry["updated_at"] = now
            self._entries[entry["id"]] = entry
            self._persist()
            self._rebuild_index()
            self._audit_locked("create", entry, operator,
                               "新增%s" % _entry_label(entry))
        return dict(entry)

    def update_entry(self, entry_id, data, operator="system"):
        with self._lock:
            old = self._entries.get(entry_id)
            if old is None:
                return None
            before = dict(old)
            entry = _normalize_entry(data, base=old)
            self._ensure_unique(entry, exclude_id=entry_id)
            entry["updated_by"] = operator
            entry["updated_at"] = int(time.time())
            self._entries[entry_id] = entry
            self._persist()
            self._rebuild_index()
            changed = [k for k in TRACKED_FIELDS if before.get(k) != entry.get(k)]
            summary = "更新字段：" + ("、".join(changed) if changed else "无变化")
            self._audit_locked("update", entry, operator, summary, before=before)
        return dict(entry)

    def delete_entry(self, entry_id, operator="system"):
        with self._lock:
            old = self._entries.pop(entry_id, None)
            if old is None:
                return False
            self._persist()
            self._rebuild_index()
            self._audit_locked("delete", old, operator, "删除名单条目",
                               before=old, after=None)
        return True

    def set_enabled(self, entry_id, enabled, operator="system"):
        with self._lock:
            entry = self._entries.get(entry_id)
            if entry is None:
                return None
            before = dict(entry)
            entry["enabled"] = bool(enabled)
            entry["updated_by"] = operator
            entry["updated_at"] = int(time.time())
            self._persist()
            self._rebuild_index()
            self._audit_locked("enable" if enabled else "disable", entry, operator,
                               "启用名单条目" if enabled else "停用名单条目",
                               before=before)
        return dict(entry)

    # ------------------------------------------------------------------
    # 查询 / 统计
    # ------------------------------------------------------------------
    def get_entry(self, entry_id):
        with self._lock:
            entry = self._entries.get(entry_id)
            return dict(entry) if entry else None

    def list_entries(self, list_type=None, dimension=None, status=None,
                     keyword=None, page=1, page_size=20):
        """按维度、类型、状态、关键词查询，按更新时间倒序分页。"""
        now = time.time()
        with self._lock:
            items = [dict(e) for e in self._entries.values()]
        for e in items:
            e["status"] = entry_status(e, now)
        if list_type:
            items = [e for e in items if e.get("list_type") == list_type]
        if dimension:
            items = [e for e in items if e.get("dimension") == dimension]
        if status:
            items = [e for e in items if e["status"] == status]
        if keyword:
            kw = keyword.lower()
            items = [e for e in items
                     if kw in str(e.get("value", "")).lower()
                     or kw in str(e.get("reason", "")).lower()
                     or kw in str(e.get("remark", "")).lower()]
        items.sort(key=lambda e: (-(e.get("updated_at") or 0), e.get("id") or ""))
        total = len(items)
        start = (page - 1) * page_size
        return total, items[start:start + page_size]

    def stats(self):
        now = time.time()
        with self._lock:
            entries = list(self._entries.values())
        s = {"total": len(entries), "black": 0, "white": 0,
             STATUS_ACTIVE: 0, STATUS_PENDING: 0,
             STATUS_EXPIRED: 0, STATUS_DISABLED: 0}
        for e in entries:
            lt = e.get("list_type")
            if lt in ("black", "white"):
                s[lt] += 1
            s[entry_status(e, now)] += 1
        return s

    # ------------------------------------------------------------------
    # 命中匹配（事件处置链路前置环节）
    # ------------------------------------------------------------------
    def _cidr_candidates(self, ip_str, cidr_entries):
        out = []
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return out
        for e in cidr_entries:
            try:
                if addr in ipaddress.ip_network(str(e.get("value")), strict=False):
                    out.append(e)
            except ValueError:
                continue
        return out

    def check_event(self, event, now=None):
        """检查事件是否命中名单，返回 {"black": [...], "white": [...]}（仅生效中条目）。"""
        now = now if now is not None else time.time()
        hits = {"black": [], "white": []}
        with self._lock:
            index = self._index
            cidr = list(self._cidr_entries)
        for dim in DIMENSIONS:
            raw = event.get(dim)
            if raw is None or raw == "":
                continue
            candidates = list((index.get(dim) or {}).get(str(raw), []))
            if dim == "ip" and cidr:
                candidates.extend(self._cidr_candidates(str(raw), cidr))
            for e in candidates:
                if entry_status(e, now) != STATUS_ACTIVE:
                    continue
                lt = e.get("list_type")
                if lt in hits:
                    hits[lt].append(e)
        return hits
