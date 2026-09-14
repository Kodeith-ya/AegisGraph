"""AegisGraph — controlled, evidence-grounded AI investigator (Phase 8).

Layers
------
The deterministic security engine is the source of truth:

    FalkorDB graph reasoning -> evidence -> risk -> counterfactual analysis

The AI investigator is a LAYER ON TOP of that pipeline. It interprets,
synthesizes, explains, compares and summarizes structured deterministic
facts. It NEVER:

* computes blast radius, reachability, production impact, vulnerability
  matching, risk scores, CVE severity, evidence confidence, paths or
  counterfactual deltas (those come from FalkorDB / graph.risk / graph.osv
  / graph.counterfactual);
* issues Cypher or any other database operation;
* decides which graph relationships exist;
* selects which deterministic analyses to run (the application dictates
  the required analysis, the LLM receives the results — there is NO
  LLM->tool->counterfactual->LLM loop).

Flow
----
    resolve artifact
    -> deterministic investigation (graph.queries)
    -> evidence (graph.queries)
    -> risk (graph.risk)
    -> counterfactual when requested (graph.counterfactual)
    -> build_investigation_context()   (bounded, deterministic, no secrets)
    -> compose_messages() + provider call
    -> validate_report()               (schema + grounding cross-checks)
    -> report

Trust rules
-----------
* The prompt explicitly forbids inventing facts, citations, CVEs, URLs,
  severities, exploit/security claims and remediation outcomes.
* Unknown stays unknown: the report must mirror the deterministic
  `vulnerability.status` and never convert "unknown" into "known"/"safe".
* Every factual claim in the final report is expected to be grounded in
  the supplied context. `validate_report()` REJECTS output that
  contradicts it (wrong risk score, fabricated evidence ids, paths that
  do not exist in the context, invented remediation deltas, invented
  artifact ids).
* No secrets can reach the model: the context is built from a whitelist
  of engine outputs only, and a guard scans the serialized context /
  messages for any configured environment secret.

Provider
--------
A single OpenAI-compatible chat-completions provider, configured purely
through environment variables (no hardcoded keys). If no provider is
configured the investigator raises ``LLMUnavailable`` (API maps to 503)
and every deterministic endpoint keeps working — the LLM is an optional
explanation layer.

    INVESTIGATOR_LLM_BASE_URL   (default https://api.openai.com/v1)
    INVESTIGATOR_LLM_API_KEY
    INVESTIGATOR_LLM_MODEL      (default gpt-4o-mini)
    INVESTIGATOR_LLM_TIMEOUT    (seconds, default 30)

Bounded timeout; one small bounded retry (drop `response_format` for
providers that reject it). No retry loops, no autonomous loops.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .counterfactual import analyze_counterfactual
from .queries import investigate_artifact, resolve_artifact
from .risk import enrich_investigation


class LLMUnavailable(Exception):
    """The LLM provider is not configured / unreachable / failed (HTTP 503)."""


class LLMInvalidOutput(Exception):
    """The model produced output that fails schema or grounding validation (HTTP 503)."""


class LLMContextError(Exception):
    """Defensive guard: investigation context would expose a secret (HTTP 503)."""


# ----------------------------------------------------------------------
# Bounded context / output limits (deterministic truncation is explicit).
# ----------------------------------------------------------------------
APP_PATH_LIMIT = 8       # max affected-application paths sent to the model
PRODUCTION_LIMIT = 8
AFFECTED_NODE_LIMIT = 60
EVIDENCE_LIMIT = 30
INCIDENT_LIMIT = 20

MAX_REPORT_CHARS = 20000          # "no excessive output" guard
_MAX_LIST_ITEMS = 40
_MAX_ITEM_CHARS = 500
_MAX_PROSE_CHARS = 4000

_DEFAULT_MODEL = "gpt-4o-mini"
_DEFAULT_TIMEOUT = 30

_ENV_BASE_URL = "INVESTIGATOR_LLM_BASE_URL"
_ENV_API_KEY = "INVESTIGATOR_LLM_API_KEY"
_ENV_MODEL = "INVESTIGATOR_LLM_MODEL"
_ENV_TIMEOUT = "INVESTIGATOR_LLM_TIMEOUT"

# Environment variables whose values must never appear in LLM context.
_SECRET_ENV_VARS = (
    "FALKORDB_PASSWORD",
    "FALKORDB_USERNAME",
    "INVESTIGATOR_LLM_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "LITELLM_API_KEY",
    "AZURE_OPENAI_API_KEY",
)

DEFAULT_QUESTION = (
    "Explain what the deterministic investigation establishes about this "
    "artifact, its blast radius, deterministic risk, supporting evidence, and "
    "any remediation analysis that was evaluated."
)

KNOWN_UNKNOWN_MARKERS = ("unknown", "not established", "no data")

SYSTEM_PROMPT = (
    "You are the AegisGraph AI investigator. You EXPLAIN and SYNTHESIZE the "
    "results of a deterministic security pipeline. You do NOT compute, "
    "re-derive, or replace any deterministic result.\n\n"
    "GROUNDING RULES (mandatory):\n"
    "1. You may only make factual claims supported by the supplied "
    "INVESTIGATION CONTEXT. The context is a structured record of graph "
    "facts, evidence, deterministic risk, and counterfactual results.\n"
    "2. If the supplied context does not establish a fact, say that it is "
    "unknown. Never convert UNKNOWN into KNOWN, and never treat an unknown "
    "security state as 'safe'.\n"
    "3. Never invent: CVEs, CWEs, exploit status, vendors, dates, URLs, "
    "CVSS/base scores, severities, confidence values, affected products, "
    "production usage, application ownership, incidents, evidence, or "
    "remediation facts.\n"
    "4. Never fabricate citations or URLs. Reference evidence only by the "
    "IDs present in the context (e.g. E1, OSV-...). If a claim has no "
    "supporting evidence in the context, do not present it as sourced.\n"
    "5. Do NOT recalculate graph metrics (blast radius, hops, counts, "
    "production impact), risk scores, or counterfactual deltas. Use the "
    "values from the context verbatim.\n"
    "6. Do not issue commands or directives like 'upgrade immediately' "
    "unless the counterfactual context demonstrates the improvement; frame "
    "remediation recommendations as analytical, referenced to the concrete "
    "delta values in the context.\n"
    "7. Distinguish FACT (the graph/evidence establishes it) from DERIVED "
    "INTERPRETATION (your synthesis) and from UNKNOWN. Keep the categories "
    "clear.\n\n"
    "OUTPUT: a single valid JSON object (no prose outside the JSON) with "
    "exactly this shape:\n"
    "{\n"
    '  "summary": string,\n'
    '  "findings": [string, ...],\n'
    '  "risk_explanation": string,\n'
    '  "affected_surface": [string, ...],\n'
    '  "evidence_summary": [string, ...],\n'
    '  "remediation": [string, ...],\n'
    '  "uncertainties": [string, ...],\n'
    '  "grounding": {\n'
    '    "artifact_id": string,\n'
    '    "risk_score": number,\n'
    '    "risk_level": string,\n'
    '    "vulnerability_status": string,\n'
    '    "evidence_ids": [string, ...],\n'
    '    "affected_paths": [{"nodes": [string, ...], "hops": int}, ...],\n'
    '    "remediation": {"action": string, "risk_reduction": number} | null\n'
    "  }\n"
    "}\n"
    "grounding values MUST equal the corresponding values in the context. "
    "Be concise and technically precise."
)


def provider_configured() -> bool:
    """True when a custom OpenAI-compatible LLM provider is fully configured."""
    return bool(os.environ.get(_ENV_BASE_URL, "").strip()
                and os.environ.get(_ENV_API_KEY, "").strip())


def provider_info() -> dict:
    return {
        "provider": "openai-compatible",
        "configured": provider_configured(),
        "model": os.environ.get(_ENV_MODEL, "").strip() or _DEFAULT_MODEL,
    }


# ----------------------------------------------------------------------
# Deterministic context projection (the ONLY thing the LLM may see).
# ----------------------------------------------------------------------
def _bounded(items, limit):
    items = list(items)
    return items[:limit], len(items) > limit


def _artifact_summary(node: dict) -> dict:
    node = node or {}
    out = {"id": node.get("id"), "type": node.get("type")}
    for key in ("name", "version", "severity", "environment",
                "criticality", "description", "status"):
        if node.get(key) is not None:
            out[key] = node[key]
    return out


def _app_summaries(affected_applications):
    apps, truncated = _bounded(affected_applications, APP_PATH_LIMIT)
    out = [
        {
            "application_id": a["application"]["id"],
            "hops": a["hops"],
            "path": {
                "nodes": [n.get("id") for n in a["path"]["nodes"]],
                "edges": [e.get("type") for e in a["path"]["edges"]],
            },
        }
        for a in apps
    ]
    return out, truncated


def _node_summaries(dependencies):
    nodes, truncated = _bounded(dependencies, AFFECTED_NODE_LIMIT)
    nodes = sorted(
        nodes,
        key=lambda n: (n.get("hops", 0), str(n.get("id") or "")),
    )
    return (
        [{"id": n.get("id"), "type": n.get("type"), "hops": n.get("hops")}
         for n in nodes],
        truncated,
    )


def _incident_summaries(incidents):
    items, truncated = _bounded(incidents, INCIDENT_LIMIT)
    out = []
    for inc in items:
        rec = {"id": inc.get("id"), "type": inc.get("type")}
        if inc.get("status") is not None:
            rec["status"] = inc["status"]
        if inc.get("description") is not None:
            rec["description"] = inc["description"]
        out.append(rec)
    return out, truncated


def project_counterfactual(cfr: dict) -> dict:
    """Deterministic projection of an analyze_counterfactual() result.

    Deltas are passed through verbatim (`*_delta = cf - base`, negative =
    improvement; `*_reduction = base - cf`, positive = improvement). Only
    graph/engine-derived values are included — nothing is invented.
    """
    paths = cfr.get("paths") or {"eliminated": [], "remaining": []}
    return {
        "artifact_id": cfr.get("artifact_id"),
        "action": cfr.get("action"),
        "target": cfr.get("target"),
        "security_state": (cfr.get("counterfactual") or {}).get("security_state"),
        "matched_vulnerabilities": (cfr.get("counterfactual") or {}).get(
            "matched_vulnerabilities"
        ),
        "assessment": (cfr.get("assessment") or {}).copy(),
        "delta": cfr.get("delta"),
        "paths": {
            "eliminated": [
                {"application_id": p["application"]["id"], "hops": p["hops"]}
                for p in paths.get("eliminated", [])
            ],
            "remaining": [
                {"application_id": p["application"]["id"], "hops": p["hops"]}
                for p in paths.get("remaining", [])
            ],
        },
    }


def project_investigation(investigation: dict, counterfactual: dict | None = None) -> dict:
    """Project an ENRICHED investigation (risk.enrich_investigation output)
    into the smallest deterministic context the LLM may see.

    Pure projection: reads only whitelisted keys, bounds every list, marks
    truncation explicitly, preserves engine ordering, and copies the
    deterministic ``risk`` block verbatim (the model can never change it).
    """
    blast = investigation["blast_radius"]
    apps, apps_truncated = _app_summaries(investigation["affected_applications"])
    prod, prod_truncated = _bounded(
        investigation["production_applications"], PRODUCTION_LIMIT
    )
    nodes, nodes_truncated = _node_summaries(investigation["dependencies"])
    incidents, incidents_truncated = _incident_summaries(investigation["incidents"])
    evidence, evidence_truncated = _bounded(investigation["evidence"], EVIDENCE_LIMIT)

    risk = investigation["risk"]
    context = {
        "artifact": _artifact_summary(investigation["artifact"]),
        "investigation": {
            "blast_radius": {
                "total_affected": blast["total_affected"],
                "max_propagation_depth": blast["max_propagation_depth"],
                "traversal_depth_cap": blast["traversal_depth_cap"],
                "dependents_by_type": blast["dependents_by_type"],
            },
            "affected_nodes": nodes,
            "affected_applications": apps,
            "production_applications": [
                {
                    "application_id": p["application"]["id"],
                    "deployment_id": p["deployment"]["id"],
                    "hops": p["hops"],
                }
                for p in prod
            ],
            "truncated": {
                "affected_applications": apps_truncated,
                "production_applications": prod_truncated,
                "affected_nodes": nodes_truncated,
                "incidents": incidents_truncated,
                "evidence": evidence_truncated,
            },
        },
        "risk": risk,
        "vulnerabilities": risk.get("vulnerability"),
        "incidents": incidents,
        "evidence": evidence,
        "counterfactual": project_counterfactual(counterfactual)
        if counterfactual is not None
        else None,
    }
    return context


def _scan_for_secrets(text: str):
    """Return the names of configured environment secrets present in `text`."""
    leaked = []
    for name in _SECRET_ENV_VARS:
        value = os.environ.get(name)
        if value and str(value) in text:
            leaked.append(name)
    return leaked


def _guard_context(context: dict):
    text = json.dumps(context)
    leaked = _scan_for_secrets(text)
    if leaked:
        raise LLMContextError(
            "investigation context would expose environment secret(s): "
            + ", ".join(sorted(leaked))
        )
    return context


def build_investigation_context(
    graph,
    artifact_id: str,
    question: str | None = None,
    counterfactual: dict | None = None,
    max_depth=None,
) -> dict:
    """Run the full DETERMINISTIC pipeline and project a bounded context.

    Order (the LLM can never bypass it):
      1. resolve + investigate (graph.queries)
      2. risk (graph.risk)
      3. counterfactual when explicitly requested (graph.counterfactual).
         When a counterfactual is requested it runs FIRST (so a malformed
         action/version is rejected before any DB query), and its
         deterministic baseline snapshot is reused instead of running the
         investigation twice.
      4. project + secret-guard

    Raises:
        LookupError          — unknown artifact (API maps to 404).
        InvalidCounterfactual — invalid action/version (API maps to 400).
        graph errors          — propagate (API maps to 503).
        LLMContextError       — defensive guard (API maps to 503).
    """
    cfr = None
    if counterfactual:
        kwargs = {
            k: counterfactual.get(k)
            for k in ("action", "target_version", "target_id", "application_id")
        }
        cfr = analyze_counterfactual(
            graph, artifact_id, max_depth=max_depth, **kwargs
        )
        baseline = cfr["baseline"]
        investigation = {
            "artifact": resolve_artifact(graph, artifact_id),
            "blast_radius": baseline["blast_radius"],
            "affected_applications": baseline["affected_applications"],
            "production_applications": baseline["production_applications"],
            "incidents": baseline["incidents"],
            "evidence": baseline["evidence"],
            "dependencies": baseline["affected_nodes"],
            "risk": baseline["risk"],
        }
    else:
        investigation = enrich_investigation(
            graph,
            investigate_artifact(graph, artifact_id, max_depth=max_depth),
        )
    context = project_investigation(investigation, cfr)
    return _guard_context(context)


# ----------------------------------------------------------------------
# Prompt composition (single focused instruction set + bounded context).
# ----------------------------------------------------------------------
def compose_messages(context: dict, question: str | None = None):
    """Deterministic system + user messages for the investigator."""
    question = (question or DEFAULT_QUESTION).strip()
    ctx_json = json.dumps(context, indent=2, sort_keys=True)
    user_content = (
        f"QUESTION: {question}\n\n"
        "INVESTIGATION CONTEXT (structured deterministic facts — the only "
        "source of truth you may reference):\n"
        f"{ctx_json}"
    )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]


# ----------------------------------------------------------------------
# Provider client (stdlib only; bounded timeout; one bounded retry).
# ----------------------------------------------------------------------
def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except (TypeError, ValueError):
        return default


def _extract_json(text: str):
    """Parse a JSON object, tolerating model prose fences around it."""
    content = (text or "").strip()
    try:
        parsed = json.loads(content)
    except (TypeError, ValueError):
        start = content.find("{")
        end = content.rfind("}")
        if start == -1 or end <= start:
            raise LLMInvalidOutput(
                "LLM response content does not contain a JSON object"
            )
        try:
            parsed = json.loads(content[start:end + 1])
        except ValueError as exc:
            raise LLMInvalidOutput(
                "LLM response content is not valid JSON"
            ) from exc
    return parsed


def _default_llm_client(context, question=None):
    """OpenAI-compatible chat-completions call (single provider, env-driven).

    Bounded timeout; on HTTP 400/422 it retries ONCE without
    `response_format` (some providers reject it). No other retries.
    """
    base_url = os.environ.get(_ENV_BASE_URL, "").strip().rstrip("/")
    api_key = os.environ.get(_ENV_API_KEY, "").strip()
    model = os.environ.get(_ENV_MODEL, "").strip() or _DEFAULT_MODEL
    timeout = _env_int(_ENV_TIMEOUT, _DEFAULT_TIMEOUT)

    if not base_url or not api_key:
        raise LLMUnavailable(
            "AI investigator is not configured: set "
            f"{_ENV_BASE_URL} and {_ENV_API_KEY}"
        )

    messages = compose_messages(context, question)
    leaked = _scan_for_secrets(json.dumps(messages))
    if leaked:
        raise LLMContextError(
            "prompt would expose environment secret(s): "
            + ", ".join(sorted(leaked))
        )

    url = f"{base_url}/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    attempts = (
        {"response_format": {"type": "json_object"}},
        {},
    )
    for extra in attempts:
        body = {
            "model": model,
            "messages": messages,
            "temperature": 0,
            **extra,
        }
        request = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code in (400, 422) and extra:
                continue  # provider rejects response_format; retry without it
            raise LLMUnavailable(f"LLM provider error (HTTP {exc.code})")
        except urllib.error.URLError as exc:
            raise LLMUnavailable(f"LLM network failure: {exc.reason}")
        except (OSError, TimeoutError):
            raise LLMUnavailable("LLM request timed out")
        except (ValueError, KeyError):
            raise LLMUnavailable("LLM response is not valid JSON")

        try:
            content = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMUnavailable("LLM response structure unexpected") from exc

        parsed = _extract_json(content)
        if not isinstance(parsed, dict):
            raise LLMInvalidOutput("LLM response content is not a JSON object")
        return parsed

    raise LLMUnavailable("LLM provider rejected response_format")


# ----------------------------------------------------------------------
# Output validation (schema + grounding cross-checks).
# ----------------------------------------------------------------------
def _require_object(value, field):
    if not isinstance(value, dict):
        raise LLMInvalidOutput(f"report field '{field}' must be an object")


def _require_str(value, field):
    if not isinstance(value, str) or not value.strip():
        raise LLMInvalidOutput(f"report field '{field}' must be a non-empty string")
    if len(value) > _MAX_PROSE_CHARS:
        raise LLMInvalidOutput(f"report field '{field}' exceeds the size limit")


def _require_str_list(value, field):
    if not isinstance(value, list):
        raise LLMInvalidOutput(f"report field '{field}' must be a list")
    if len(value) > _MAX_LIST_ITEMS:
        raise LLMInvalidOutput(f"report field '{field}' has too many items")
    for item in value:
        if not isinstance(item, str):
            raise LLMInvalidOutput(
                f"report field '{field}' must contain only strings"
            )
        if len(item) > _MAX_ITEM_CHARS:
            raise LLMInvalidOutput(f"report field '{field}' item exceeds size limit")


def validate_report(report, context: dict) -> dict:
    """Validate the model output and enforce grounding against `context`.

    Rejects (LLMInvalidOutput) malformed structure, oversized output, and
    any claim that contradicts the deterministic context:
      * risk_score must equal context risk.score (A6 / C8 parity).
      * risk_level and vulnerability_status must equal the deterministic values.
      * evidence_ids must be a subset of the real evidence ids (A5).
      * affected_paths must be verbatim paths from the context (A2/A3).
      * affected_surface ids must exist in the context (no invented artifacts).
      * remediation (when present) must match the executed counterfactual (A8).
      * uncertainty: an output that flips deterministic 'unknown' into a
        safe/known claim is rejected (A4).

    Returns the normalized report dict on success.
    """
    if not isinstance(report, dict):
        raise LLMInvalidOutput("investigator report must be a JSON object")
    if len(json.dumps(report)) > MAX_REPORT_CHARS:
        raise LLMInvalidOutput("investigator report exceeds the size limit")

    for field in ("summary", "risk_explanation"):
        if field not in report:
            raise LLMInvalidOutput(f"report is missing required field '{field}'")
        _require_str(report[field], field)
    for field in ("findings", "affected_surface", "evidence_summary",
                  "remediation", "uncertainties"):
        if field not in report:
            raise LLMInvalidOutput(f"report is missing required field '{field}'")
        _require_str_list(report[field], field)

    grounding = report.get("grounding")
    _require_object(grounding, "grounding")

    for field in ("artifact_id", "risk_level", "vulnerability_status"):
        if field not in grounding:
            raise LLMInvalidOutput(f"grounding is missing required field '{field}'")
        _require_str(grounding[field], f"grounding.{field}")

    risk_score = grounding.get("risk_score")
    if isinstance(risk_score, bool) or not isinstance(risk_score, (int, float)):
        raise LLMInvalidOutput("grounding.risk_score must be a number")

    evidence_ids = grounding.get("evidence_ids", None)
    if not isinstance(evidence_ids, list) or any(
        not isinstance(e, str) for e in evidence_ids
    ):
        raise LLMInvalidOutput("grounding.evidence_ids must be a list of strings")
    if len(evidence_ids) > _MAX_LIST_ITEMS:
        raise LLMInvalidOutput("grounding.evidence_ids has too many items")

    affected_paths = grounding.get("affected_paths", None)
    if not isinstance(affected_paths, list):
        raise LLMInvalidOutput("grounding.affected_paths must be a list")
    if len(affected_paths) > _MAX_LIST_ITEMS:
        raise LLMInvalidOutput("grounding.affected_paths has too many items")

    # ---- grounding cross-checks: the model cannot contradict the engine ----
    ctx_risk = context.get("risk") or {}
    ctx_artifact = context.get("artifact") or {}
    ctx_inv = context.get("investigation") or {}

    if grounding["artifact_id"] != ctx_artifact.get("id"):
        raise LLMInvalidOutput(
            "grounding.artifact_id contradicts the investigated artifact"
        )
    if risk_score != ctx_risk.get("score"):
        raise LLMInvalidOutput(
            "grounding.risk_score contradicts the deterministic risk score"
        )
    if grounding["risk_level"] != ctx_risk.get("level"):
        raise LLMInvalidOutput(
            "grounding.risk_level contradicts the deterministic risk level"
        )
    if grounding["vulnerability_status"] != (ctx_risk.get("vulnerability") or {}).get(
        "status"
    ):
        raise LLMInvalidOutput(
            "grounding.vulnerability_status contradicts the deterministic "
            f"vulnerability status ({ctx_risk.get('vulnerability', {}).get('status')})"
        )

    # A5: evidence ids must correspond to actual evidence.
    allowed_evidence = {e["id"] for e in context.get("evidence") or []}
    unknown_evidence = set(evidence_ids) - allowed_evidence
    if unknown_evidence:
        raise LLMInvalidOutput(
            "grounding.evidence_ids references evidence that does not exist "
            f"in the context: {sorted(unknown_evidence)}"
        )

    # A2/A3: affected paths must be verbatim context paths.
    context_paths = set()
    context_app_ids = set()
    for app in ctx_inv.get("affected_applications") or []:
        context_paths.add(json.dumps(app["path"]["nodes"]))
        context_app_ids.add(app["application_id"])
    artifact_id = ctx_artifact.get("id")
    for entry in affected_paths:
        _require_object(entry, "grounding.affected_paths item")
        nodes = entry.get("nodes")
        if not isinstance(nodes, list) or any(not isinstance(n, str) for n in nodes):
            raise LLMInvalidOutput(
                "grounding.affected_paths item must have a list of string nodes"
            )
        if json.dumps(nodes) not in context_paths or not nodes:
            raise LLMInvalidOutput(
                "grounding.affected_paths references a path that does not "
                "exist in the investigation context"
            )
        if nodes[0] != artifact_id or nodes[-1] not in context_app_ids:
            raise LLMInvalidOutput(
                "grounding.affected_paths endpoint does not match the context"
            )
        expected_hops = len(nodes) - 1
        if entry.get("hops") != expected_hops:
            raise LLMInvalidOutput(
                "grounding.affected_paths hops contradict the path length"
            )

    # affected_surface ids must exist in the context (no invented artifacts).
    allowed_surface = {artifact_id} | context_app_ids
    allowed_surface |= {n.get("id") for n in ctx_inv.get("affected_nodes") or []}
    allowed_surface |= {
        p["application_id"] for p in ctx_inv.get("production_applications") or []
    }
    for item in report["affected_surface"]:
        if item not in allowed_surface:
            raise LLMInvalidOutput(
                f"affected_surface references unknown artifact '{item}'"
            )

    # A8: remediation grounding must match the executed counterfactual.
    cfa = context.get("counterfactual")
    remediation = grounding.get("remediation")
    if remediation is None:
        if cfa is not None:
            raise LLMInvalidOutput(
                "grounding.remediation is required when a counterfactual was executed"
            )
    else:
        if cfa is None:
            raise LLMInvalidOutput(
                "grounding.remediation claims a remediation that was not evaluated"
            )
        if not isinstance(remediation, dict):
            raise LLMInvalidOutput("grounding.remediation must be an object")
        action = remediation.get("action")
        reduction = remediation.get("risk_reduction")
        if action != cfa.get("action"):
            raise LLMInvalidOutput(
                "grounding.remediation.action contradicts the executed counterfactual"
            )
        expected = (cfa.get("delta") or {}).get("risk_score", {}).get("reduction")
        if isinstance(reduction, bool) or not isinstance(reduction, (int, float)):
            raise LLMInvalidOutput(
                "grounding.remediation.risk_reduction must be a number"
            )
        if reduction != expected:
            raise LLMInvalidOutput(
                "grounding.remediation.risk_reduction contradicts the "
                "deterministic counterfactual delta"
            )

    return report


# ----------------------------------------------------------------------
# Orchestration (the LLM comes LAST, results are validated).
# ----------------------------------------------------------------------
def investigate(
    graph,
    artifact_id: str,
    question: str | None = None,
    counterfactual: dict | None = None,
    max_depth=None,
    llm_client=None,
) -> dict:
    """One deterministic investigation + one LLM explanation (+ validation).

    Returns:
        {
          "artifact_id", "max_depth",
          "processing": {...},            # audit trail of used layers
          "context": {...},               # deterministic facts the LLM saw
          "analysis": { ... }             # validated, grounded report
        }

    Raises the same exceptions the deterministic pipeline raises
    (LookupError -> 404, InvalidCounterfactual -> 400, graph errors -> 503)
    plus LLMUnavailable / LLMInvalidOutput / LLMContextError (-> 503).
    Never mutates the graph; never calls the LLM before the deterministic
    analysis is complete.
    """
    context = build_investigation_context(
        graph, artifact_id, question=question,
        counterfactual=counterfactual, max_depth=max_depth,
    )

    if llm_client is None:
        if not provider_configured():
            raise LLMUnavailable(
                "AI investigator is not configured: set "
                f"{_ENV_BASE_URL} and {_ENV_API_KEY}"
            )
        client = _default_llm_client
        llm_source = provider_info()
    else:
        client = llm_client
        model = getattr(llm_client, "model", None)
        llm_source = {
            "provider": "injected_test_client",
            "configured": True,
            "model": model,
        }

    report = client(context, question)
    report = validate_report(report, context)

    return {
        "artifact_id": artifact_id,
        "max_depth": context["investigation"]["blast_radius"]["traversal_depth_cap"],
        "processing": {
            "deterministic_layers": [
                "resolve", "investigate", "evidence", "risk", "counterfactual",
            ],
            "llm_layer": "explanation_only",
            "llm": llm_source,
        },
        "context": context,
        "analysis": report,
    }