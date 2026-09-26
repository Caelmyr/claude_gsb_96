"""运行时单例：引擎、决策流存储与名单存储的全局引用。

app.py 在启动时调用 init() 注入；各 API 蓝图通过 runtime.engine / runtime.flow_store /
runtime.list_store 访问，避免循环导入。
"""
engine = None
flow_store = None
list_store = None


def init(eng, flows, lists=None):
    global engine, flow_store, list_store
    engine = eng
    flow_store = flows
    list_store = lists
