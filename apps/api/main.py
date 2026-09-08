from fastapi import FastAPI, Response
from graph import get_graph

app = FastAPI(title="AegisGraph API")


@app.get("/health")
def health(response: Response):
    try:
        graph = get_graph()
        result = graph.query("RETURN 1 AS ping")
        if result.result_set and result.result_set[0][0] == 1:
            return {"status": "ok", "falkordb": "connected"}
        response.status_code = 503
        return {"status": "degraded", "falkordb": "unexpected response"}
    except Exception:
        response.status_code = 503
        return {"status": "error", "falkordb": "unavailable"}
