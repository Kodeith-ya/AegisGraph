import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException, Response, Query
from pydantic import BaseModel

# Make `apps/api` importable (this module lives in apps/api and imports `db`
# via a plain top-level import; uvicorn must be able to resolve it regardless
# of the CWD it is launched from).
API_DIR = Path(__file__).resolve().parent
if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))

from db import get_graph

# Expose the repo-root `graph` package (graph/queries.py) so the
# investigation engine can be imported regardless of the CWD uvicorn
# is launched from.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from graph.queries import evidence_for, investigate_artifact, resolve_artifact  # noqa: E402
from graph.risk import enrich_investigation  # noqa: E402
from graph.counterfactual import InvalidCounterfactual, analyze_counterfactual  # noqa: E402
from graph.investigator import (  # noqa: E402
    LLMContextError,
    LLMInvalidOutput,
    LLMUnavailable,
    investigate as investigator_investigate,
)

app = FastAPI(title="AegisGraph API")


class CounterfactualRequest(BaseModel):
    """Body for POST /api/counterfactual/{artifact_id}.

    `action` (required) is one of: remove | upgrade | isolate. `target_id`
    defaults to `artifact_id`; `application_id` is accepted as a convenience
    alias for the ISOLATE target.
    """

    action: str
    target_version: str | None = None
    target_id: str | None = None
    application_id: str | None = None


class InvestigatorRequest(BaseModel):
    """Body for POST /api/investigate/{artifact_id}/explain (Phase 8).

    `question` is an optional natural-language question. `counterfactual`
    (when present) MUST be a well-formed counterfactual request — the
    deterministic counterfactual engine evaluates it and the AI investigator
    only explains the result. The LLM can never invent remediation scenarios.
    """

    question: str | None = None
    counterfactual: CounterfactualRequest | None = None


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


@app.get("/api/evidence/{artifact_id}")
def evidence(artifact_id: str):
    """Evidence + provenance for an artifact (reuses `evidence_for`).

    Returns the resolved artifact and every evidence record that either
    DESCRIBES it or SUPPORTS an incident affecting it. Unknown artifacts
    return 404; DB failure returns 503. No evidence is synthesized here.
    """
    try:
        graph = get_graph()
        artifact = resolve_artifact(graph, artifact_id)
        if artifact is None:
            raise HTTPException(
                status_code=404,
                detail=f"artifact '{artifact_id}' not found in the graph",
            )
        return {
            "artifact": artifact,
            "evidence": evidence_for(graph, artifact_id),
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="FalkorDB unavailable or evidence retrieval failed",
        )


@app.post("/api/counterfactual/{artifact_id}")
def counterfactual(
    artifact_id: str,
    request: CounterfactualRequest,
    max_depth: int | None = Query(default=None, ge=1, le=20),
):
    """Graph-native counterfactual remediation intelligence (Phase 7).

    Simulates `remove` / `upgrade` / `isolate` WITHOUT mutating the graph
    (query-time path exclusions + offline OSV/PEP 440 re-evaluation) and
    returns baseline / counterfactual / delta / paths / assessment.
    Validation: unknown action or invalid target_version => 400; unknown
    artifact or target => 404; DB failure => 503.
    """
    try:
        graph = get_graph()
        return analyze_counterfactual(
            graph,
            artifact_id,
            action=request.action,
            target_version=request.target_version,
            target_id=request.target_id,
            application_id=request.application_id,
            max_depth=max_depth,
        )
    except InvalidCounterfactual as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail=f"artifact '{artifact_id}' or remediation target not found in the graph",
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="FalkorDB unavailable or counterfactual analysis failed",
        )


@app.post("/api/investigate/{artifact_id}/explain")
def investigate_explain(
    artifact_id: str,
    request: InvestigatorRequest,
    max_depth: int | None = Query(default=None, ge=1, le=20),
):
    """Grounded AI security investigation (Phase 8) — LLM explains, graph decides.

    Pipeline (the LLM comes LAST and can never bypass it):
    resolve artifact -> deterministic investigation -> evidence -> risk
    -> optionally ONE deterministic counterfactual analysis -> structured
    context -> LLM explanation -> validated grounded report.

    The returned `context` is the bounded, deterministic, secret-free fact
    set the model was allowed to use; `analysis` is the validated report.
    Every factual claim the model may make is cross-checked against the
    context (risk score, vulnerability status, evidence ids, paths,
    counterfactual deltas). Graph reasoning stays in FalkorDB; the LLM is
    the explanation layer.

    Errors: invalid counterfactual request -> 400; unknown artifact/target
    -> 404; FalkorDB unavailable -> 503; LLM not configured / provider
    failure / malformed or ungrounded output -> 503 (core deterministic
    endpoints are unaffected).
    """
    try:
        graph = get_graph()
        cf = None
        if request.counterfactual is not None:
            cf = {
                "action": request.counterfactual.action,
                "target_version": request.counterfactual.target_version,
                "target_id": request.counterfactual.target_id,
                "application_id": request.counterfactual.application_id,
            }
        return investigator_investigate(
            graph,
            artifact_id,
            question=request.question,
            counterfactual=cf,
            max_depth=max_depth,
        )
    except InvalidCounterfactual as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail=f"artifact '{artifact_id}' or remediation target not found in the graph",
        )
    except LLMContextError:
        raise HTTPException(
            status_code=503,
            detail="AI investigator context validation failed (no details exposed)",
        )
    except LLMInvalidOutput:
        raise HTTPException(
            status_code=503,
            detail="AI investigator returned malformed or ungrounded output",
        )
    except LLMUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="FalkorDB unavailable or investigation failed",
        )
