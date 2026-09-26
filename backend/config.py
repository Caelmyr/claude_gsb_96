"""全局配置与路径管理。

实时风控规则引擎与决策流系统。

所有数据目录都相对于项目根目录定位，保证系统可以任意位置启动。
数据存储采用 JSON 文件：规则按版本、事件按小时分片、告警按天分片。
"""
import os

# 项目根目录 = backend/ 的上一级
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_DIR = os.path.join(BASE_DIR, "data")
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

# 数据分片目录
RULES_DIR = os.path.join(DATA_DIR, "rules")        # 规则：按版本存储
VERSIONS_DIR = os.path.join(DATA_DIR, "versions")  # 规则版本历史
EVENTS_DIR = os.path.join(DATA_DIR, "events")      # 事件：按小时分片
ALERTS_DIR = os.path.join(DATA_DIR, "alerts")      # 告警：按天分片
USERS_DIR = os.path.join(DATA_DIR, "users")        # 用户
FLOWS_DIR = os.path.join(DATA_DIR, "flows")        # 决策流
DICT_DIR = os.path.join(DATA_DIR, "dict")          # 数据字典
SETTINGS_DIR = os.path.join(DATA_DIR, "settings")  # 系统设置
WINDOWS_DIR = os.path.join(DATA_DIR, "windows")    # 滑动窗口状态（可选持久化快照）
LISTS_DIR = os.path.join(DATA_DIR, "lists")        # 黑白名单

USERS_FILE = os.path.join(USERS_DIR, "users.json")
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "system.json")
DICT_FILE = os.path.join(DICT_DIR, "dict.json")
LISTS_FILE = os.path.join(LISTS_DIR, "lists.json")
LIST_AUDITS_FILE = os.path.join(LISTS_DIR, "audits.json")

# 服务配置
API_HOST = os.environ.get("RISK_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("RISK_PORT", "5000"))
SECRET_KEY = os.environ.get("RISK_SECRET", "risk-engine-benchmark-secret-key")

# 规则引擎默认配置（可被 system.json 覆盖）
DEFAULT_SETTINGS = {
    "site_name": "实时风控规则引擎与决策流",
    "engine": {
        "mode": "rete",                 # rete | decision_tree
        "dedup_window_sec": 300,        # 告警去重窗口（秒）
        "max_alert_keep": 50,         # 内存中最多保留的告警条数
        "alert_ttl_hours": 72,          # 告警持久化保留时长（小时）
        "window_granularity_sec": 1,    # 滑动窗口分桶粒度（秒）
        "window_max_keys": 200000,      # 滑动窗口最大键数（内存控制）
        "window_max_events_per_key": 20000,  # 单键最大事件数
        "window_max_total_events": 2000000,  # 全窗口最大事件总数
        "event_ttl_sec": 3600,          # 事件在内存中的保留时长
    },
    "alert": {
        "levels": ["低", "中", "高", "严重"],
        "default_level": "中",
    },
    "event_types": ["login", "register", "order", "payment", "transfer", "withdraw", "sms", "api"],
    "dict_categories": ["事件类型", "风险等级", "动作类型", "渠道", "设备类型", "IP 段"],
}

# 动作类型
ACTION_TYPES = ["reject", "review", "pass", "alert"]

# 名单类型 / 维度 / 来源
LIST_TYPES = ["black", "white"]                 # 黑名单 / 白名单
LIST_DIMENSIONS = ["ip", "user", "device", "bank_card"]
LIST_DIMENSION_FIELDS = {                        # 维度 -> 事件取值字段（按优先级回退）
    "ip": ["ip"],
    "user": ["user_id", "uid", "username"],
    "device": ["device_id", "did"],
    "bank_card": ["bank_card", "card_no", "card_id"],
}
LIST_SOURCES = ["manual", "auto"]                # 人工添加 / 系统自动生成
LIST_RISK_LEVELS = ["低", "中", "高", "严重"]
LIST_RISK_SCORE = {"低": 30, "中": 60, "高": 85, "严重": 98}
LIST_AUDIT_MAX = 2000                            # 审计日志最多保留条数

# 条件操作符
CONDITION_OPS = ["==", "!=", ">", ">=", "<", "<=", "in", "not_in", "contains", "regex", "exists"]

# 聚合类型
AGG_TYPES = ["count", "sum", "avg", "distinct_count", "max", "min"]


def ensure_dirs():
    """确保所有数据目录存在。"""
    for d in (RULES_DIR, VERSIONS_DIR, EVENTS_DIR, ALERTS_DIR, USERS_DIR,
              FLOWS_DIR, DICT_DIR, SETTINGS_DIR, WINDOWS_DIR, LISTS_DIR):
        os.makedirs(d, exist_ok=True)
    if not os.path.exists(SETTINGS_FILE):
        from backend.storage import atomic_write_json
        atomic_write_json(SETTINGS_FILE, DEFAULT_SETTINGS)
