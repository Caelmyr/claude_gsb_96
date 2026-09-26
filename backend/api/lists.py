"""名单管理 API：黑白名单 CRUD、启停、审计日志、命中检查。"""
from flask import Blueprint, request, jsonify

from backend import runtime
from backend.auth import login_required, role_required, current_user
from backend.list_store import ListValidationError

bp = Blueprint("lists", __name__, url_prefix="/api/lists")


def _operator():
    u = current_user()
    return u["username"] if u else "anonymous"


@bp.route("", methods=["GET"])
@login_required
def list_entries():
    """按维度、类型、状态、关键词分页查询名单条目。"""
    page = request.args.get("page", 1, type=int)
    page_size = request.args.get("page_size", 20, type=int)
    if page < 1:
        page = 1
    page_size = max(1, min(page_size, 200))
    total, items = runtime.list_store.list_entries(
        list_type=request.args.get("list_type") or None,
        dimension=request.args.get("dimension") or None,
        status=request.args.get("status") or None,
        keyword=request.args.get("keyword") or None,
        page=page, page_size=page_size)
    return jsonify({"ok": True, "total": total, "entries": items,
                    "page": page, "page_size": page_size})


@bp.route("", methods=["POST"])
@role_required("admin", "analyst", "viewer")
def create_entry():
    data = request.get_json(force=True, silent=True) or {}
    try:
        entry = runtime.list_store.create_entry(data, operator=_operator())
    except ListValidationError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "entry": entry})


@bp.route("/stats", methods=["GET"])
@login_required
def list_stats():
    return jsonify({"ok": True, "stats": runtime.list_store.stats()})


@bp.route("/audit", methods=["GET"])
@login_required
def list_audit():
    """名单变更审计日志（谁、何时、对哪条做了什么）。"""
    records = runtime.list_store.audit_records(
        entry_id=request.args.get("entry_id") or None,
        operator=request.args.get("operator") or None,
        action=request.args.get("action") or None,
        limit=request.args.get("limit", 100, type=int))
    return jsonify({"ok": True, "records": records})


@bp.route("/check", methods=["POST"])
@login_required
def check_event():
    """检查一条事件是否命中名单（不落库，用于试算）。"""
    data = request.get_json(force=True, silent=True) or {}
    event = data.get("event", data)
    if not isinstance(event, dict):
        return jsonify({"ok": False, "error": "事件必须是 JSON 对象"}), 400
    hits = runtime.list_store.check_event(event)
    decision = "reject" if hits["black"] else ("pass" if hits["white"] else None)
    return jsonify({"ok": True, "decision": decision, "hits": hits})


@bp.route("/<entry_id>", methods=["GET"])
@login_required
def get_entry(entry_id):
    entry = runtime.list_store.get_entry(entry_id)
    if entry is None:
        return jsonify({"ok": False, "error": "名单条目不存在"}), 404
    return jsonify({"ok": True, "entry": entry})


@bp.route("/<entry_id>", methods=["PUT"])
@role_required("admin", "analyst", "viewer")
def update_entry(entry_id):
    data = request.get_json(force=True, silent=True) or {}
    try:
        entry = runtime.list_store.update_entry(entry_id, data, operator=_operator())
    except ListValidationError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    if entry is None:
        return jsonify({"ok": False, "error": "名单条目不存在"}), 404
    return jsonify({"ok": True, "entry": entry})


@bp.route("/<entry_id>", methods=["DELETE"])
@role_required("admin")
def delete_entry(entry_id):
    ok = runtime.list_store.delete_entry(entry_id, operator=_operator())
    if not ok:
        return jsonify({"ok": False, "error": "名单条目不存在"}), 404
    return jsonify({"ok": True})


@bp.route("/<entry_id>/enable", methods=["POST"])
@role_required("admin", "analyst", "viewer")
def toggle_entry(entry_id):
    data = request.get_json(force=True, silent=True) or {}
    enabled = bool(data.get("enabled", True))
    entry = runtime.list_store.set_enabled(entry_id, enabled, operator=_operator())
    if entry is None:
        return jsonify({"ok": False, "error": "名单条目不存在"}), 404
    return jsonify({"ok": True, "entry": entry})
