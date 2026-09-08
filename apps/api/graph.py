import os
from falkordb import FalkorDB


def get_falkordb() -> FalkorDB:
    host = os.environ.get("FALKORDB_HOST", "localhost")
    port = int(os.environ.get("FALKORDB_PORT", "6379"))
    password = os.environ.get("FALKORDB_PASSWORD") or None
    return FalkorDB(host=host, port=port, password=password)


def get_graph() -> object:
    graph_name = os.environ.get("FALKORDB_GRAPH", "aegisgraph")
    db = get_falkordb()
    return db.select_graph(graph_name)
