"""黑白名单管理 API。

- 条目 CRUD、批量新增、启停切换；
- 按名单类型 / 维度 / 启停状态 / 生效时间 / 来源 / 关键字分页查询；
- 操作审计日志查询（谁、什么时候、改了什么）；
- 命中测试：给定维度 + 值，返回当前会命中的黑/白名单；
- 总览计数。

权限沿用规则页的惯例：查询登录即可，写操作 analyst 以上，删除仅 admin。
"""
import time

from flask import Blueprint, request, jsonify

from backend import runtime, config
from backend.auth import login_required, role_required, current_user

bp = Blueprint("lists", __name__, url_prefix="/api/lists")


def _store():
    return runtime.list_store


def _author():
    u = current_user()
    return u["username"] if u else "anonymous"


def _parse_int_arg(name):
    v = request.args.get(name)
    if v in (None, "", "all"):
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


@bp.route("/meta", methods=["GET"])
@login_required
def meta():
    """前端渲染下拉框所需的枚举。"""
    return jsonify({
        "ok": True,
        "meta": {
            "list_types": [{"key": k, "label": v}
                           for k, v in (("black", "黑名单"), ("white", "白名单"))],
            "dimensions": [{"key": k, "label": v}
                           for k, v in
                           (("ip", "IP"), ("user", "用户"), ("device", "设备"),
                            ("bank_card", "银行卡"))],
            "sources": [{"key": k, "label": v}
                        for k, v in (("manual", "人工添加"), ("auto", "系统自动生成"))],
            "risk_levels": config.LIST_RISK_LEVELS,
        },
    })


@bp.route("", methods=["GET"])
@login_required
def query_lists():
    enabled_arg = request.args.get("enabled")
    enabled = None
    if enabled_arg in ("true", "1"):
        enabled = True
    elif enabled_arg in ("false", "0"):
        enabled = False
    result = _store().query(
        list_type=request.args.get("list_type") or None,
        dimension=request.args.get("dimension") or None,
        enabled=enabled,
        time_status=request.args.get("time_status") or None,
        source=request.args.get("source") or None,
        keyword=request.args.get("keyword") or None,
        page=_parse_int_arg("page") or 1,
        page_size=_parse_int_arg("page_size") or 20,
    )
    return jsonify({"ok": True, **result})


@bp.route("/summary", methods=["GET"])
@login_required
def summary():
    stats = runtime.engine.stats()
    counters = stats.get("counters", {})
    return jsonify({"ok": True,
                    "summary": _store().summary(
                        black_hits=counters.get("blacklist_hits", 0),
                        white_hits=counters.get("whitelist_hits", 0))})


@bp.route("", methods=["POST"])
@role_required("admin", "analyst", "viewer")
def create_entry():
    body = request.get_json(force=True, silent=True) or {}
    try:
        entry, _ = _store().create(body, operator=_author())
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "entry": entry})


@bp.route("/batch", methods=["POST"])
@role_required("admin", "analyst", "viewer")
def batch_create():
    """批量新增：{list_type, dimension, values: [...], ...}。"""
    body = request.get_json(force=True, silent=True) or {}
    try:
        created, skipped = _store().bulk_create(body, operator=_author())
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "created": created,
                    "created_count": len(created), "skipped": skipped})


@bp.route("/<entry_id>", methods=["GET"])
@login_required
def get_entry(entry_id):
    entry = _store().get(entry_id)
    if entry is None:
        return jsonify({"ok": False, "error": "名单条目不存在"}), 404
    return jsonify({"ok": True, "entry": entry})


@bp.route("/<entry_id>", methods=["PUT"])
@role_required("admin", "analyst", "viewer")
def update_entry(entry_id):
    body = request.get_json(force=True, silent=True) or {}
    try:
        result = _store().update(entry_id, body, operator=_author())
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    if result is None:
        return jsonify({"ok": False, "error": "名单条目不存在"}), 404
    entry, _ = result
    return jsonify({"ok": True, "entry": entry})


@bp.route("/<entry_id>/enable", methods=["POST"])
@role_required("admin", "analyst", "viewer")
def toggle_entry(entry_id):
    body = request.get_json(force=True, silent=True) or {}
    enabled = bool(body.get("enabled", True))
    result = _store().set_enabled(entry_id, enabled, operator=_author())
    if result is None:
        return jsonify({"ok": False, "error": "名单条目不存在"}), 404
    entry, _ = result
    return jsonify({"ok": True, "entry": entry})


@bp.route("/<entry_id>", methods=["DELETE"])
@role_required("admin")
def delete_entry(entry_id):
    ok = _store().delete(entry_id, operator=_author())
    if not ok:
        return jsonify({"ok": False, "error": "名单条目不存在"}), 404
    return jsonify({"ok": True})


@bp.route("/audits", methods=["GET"])
@login_required
def audits():
    """名单操作审计日志（支持按条目/类型/维度/操作者/动作过滤）。"""
    limit = min(500, _parse_int_arg("limit") or 100)
    items = _store().list_audits(
        entry_id=request.args.get("entry_id") or None,
        list_type=request.args.get("list_type") or None,
        dimension=request.args.get("dimension") or None,
        operator=request.args.get("operator") or None,
        action=request.args.get("action") or None,
        limit=limit,
    )
    return jsonify({"ok": True, "audits": items, "count": len(items)})


@bp.route("/check", methods=["POST"])
@login_required
def check():
    """命中测试：{dimension, value} -> 当前命中的黑/白名单详情。"""
    body = request.get_json(force=True, silent=True) or {}
    dimension = body.get("dimension")
    value = body.get("value")
    if dimension not in config.LIST_DIMENSIONS:
        return jsonify({"ok": False, "error": "维度不合法"}), 400
    if value in (None, ""):
        return jsonify({"ok": False, "error": "请输入要测试的值"}), 400
    hits = _store().check_value(dimension, value, event=body.get("event"))
    return jsonify({"ok": True,
                    "dimension": dimension,
                    "value": str(value),
                    "ts": int(time.time()),
                    "black": hits["black"],
                    "white": hits["white"],
                    "verdict": "reject" if hits["black"] else
                    ("pass" if hits["white"] else "none")})
