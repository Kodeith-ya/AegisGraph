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
from graph.risk import enrich_investigation  # noqa: E402

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


def _run_investigation(artifact_id: str, max_depth: int | None) -> dict:
    """Run investigation + risk enrichment, mapping failures to HTTP errors."""
    try:
        graph = get_graph()
        investigation = investigate_artifact(graph, artifact_id, max_depth=max_depth)
        return enrich_investigation(graph, investigation)
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


@app.get("/api/investigate/{artifact_id}")
def investigate(
    artifact_id: str,
    max_depth: int | None = Query(default=None, ge=1, le=20),
):
    """Graph-native blast-radius investigation + deterministic risk report.

    All affected entities, paths, counts, factor scores, and rankings are
    derived from FalkorDB graph facts. `max_depth` is bounded to 1..20 and
    rejected outside that range.
    """
    return _run_investigation(artifact_id, max_depth)


@app.get("/api/risk/{artifact_id}")
def risk(
    artifact_id: str,
    max_depth: int | None = Query(default=None, ge=1, le=20),
):
    """Deterministic risk report only (reuses the investigation engine)."""
    return _run_investigation(artifact_id, max_depth)["risk"]
