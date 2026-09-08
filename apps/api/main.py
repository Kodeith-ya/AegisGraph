import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException, Response, Query

from db import get_graph

# Expose the repo-root `graph` package (graph/queries.py) so the
# investigation engine can be imported regardless of the CWD uvicorn
# is launched from.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from graph.queries import investigate_artifact  # noqa: E402

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


@app.get("/api/investigate/{artifact_id}")
def investigate(artifact_id: str, max_depth: int | None = Query(default=None)):
    """Graph-native blast-radius investigation for an AI artifact.

    All affected entities, paths, and counts are computed by FalkorDB.
    This endpoint only shapes the result.
    """
    try:
        result = investigate_artifact(get_graph(), artifact_id, max_depth=max_depth)
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail=f"artifact '{artifact_id}' not found in the graph",
        )
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="FalkorDB unavailable or investigation failed",
        )
    return result
