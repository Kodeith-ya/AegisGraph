"""AegisGraph — deterministic risk & impact intelligence engine (Phase 4).

Turns the graph-proven Phase 3 investigation into an explainable,
reproducible risk decision. This module only:

* consumes Phase 3 graph-derived results (blast radius, affected apps,
  production apps, incidents, propagation depth)
* performs bounded normalization and weighted aggregation
* classifies risk levels
* ranks affected applications deterministically
* builds rule-based reasons from real graph facts

It performs NO graph traversal on its own except a single bounded
1-hop ``HAS_VULNERABILITY`` linkage lookup (FalkorDB does that lookup;
Python does all scoring). No LLM, no external intelligence, no
fabricated facts, no hardcoded artifact results.

Determinism: only ``float``/``int`` arithmetic with fixed rounding (
``round(x, 2)`` for factors, ``int(round(x))`` for the final score).
Ties in ranking/top-factors are broken by identifier ascending.
"""
WEIGHTS_EPSILON = 1e-9

# Risk model: primary factors + weights. MUST sum to 1.0 (validated).
RISK_WEIGHTS = {
    "blast_radius": 0.25,
    "production_impact": 0.35,
    "propagation_depth": 0.15,
    "incidents": 0.15,
    "vulnerability": 0.10,
}

# Risk levels: (lower bound, level). A score belongs to the highest
# level whose lower bound is <= the score.
RISK_LEVELS = (
    (80, "CRITICAL"),
    (60, "VERY_HIGH"),
    (40, "HIGH"),
    (20, "MODERATE"),
    (0, "LOW"),
)

# Normalization constants (documented saturation points). All factor
# formulas are `min(raw / NORMALIZER, 1.0) * 100`, bounded to 0..100.
BLAST_RADIUS_NORMALIZER = 10.0     # distinct affected downstream nodes
PRODUCTION_NORMALIZER = 1.0        # production deployments (any -> saturated)
MAX_DEPTH_NORMALIZER = 8.0         # propagation depth in hops
INCIDENT_NORMALIZER = 2.0          # linked (:Incident)-[:AFFECTS]-> facts

# Vulnerability severity -> factor score (only from validated graph data).
VULN_SEVERITY_SCORES = {
    "critical": 100.0,
    "high": 75.0,
    "medium": 50.0,
    "low": 25.0,
}

# Rule-based reason thresholds.
CLOSE_PROPAGATION_THRESHOLD = 3   # distance <= this => "close propagation path"
LARGE_SURFACE_THRESHOLD = 5       # total_affected >= this => "large downstream surface"

# Application priority weights (per-application, 0..100).
APP_PRODUCTION_WEIGHT = 0.6
APP_DISTANCE_WEIGHT = 0.4


def validate_weights(weights=None) -> dict:
    """Return the risk weights dict after asserting values sum to 1.0.

    Raises ValueError rather than silently normalizing invalid weights.
    """
    weights = dict(weights or RISK_WEIGHTS)
    total = sum(weights.values())
    if abs(total - 1.0) > WEIGHTS_EPSILON:
        raise ValueError(f"risk weights must sum to 1.0, got {total}")
    for key, w in weights.items():
        if w < 0 or w > 1:
            raise ValueError(f"weight for '{key}' out of range [0, 1]: {w}")
    return weights


def _bounded(raw, normalizer: float) -> float:
    if normalizer <= 0:
        raise ValueError(f"normalizer must be positive, got {normalizer}")
    if raw is None or raw < 0:
        return 0.0
    return min(raw / normalizer, 1.0) * 100.0


# ---------------------------------------------------------------------
# Primary factor scores (each bounded 0..100)
# ---------------------------------------------------------------------
def calculate_blast_radius_score(total_affected) -> float:
    """Normalized blast-radius factor from `blast_radius.total_affected`."""
    return _bounded(total_affected or 0, BLAST_RADIUS_NORMALIZER)


def calculate_production_score(production_count) -> float:
    """Normalized production-impact factor.

    `production_count` must come from Phase 3 `production_applications`
    (counted ONLY via a real `(dep:Deployment {environment: 'production'})
    -[:DEPLOYS]-> (app)` edge). Never from application metadata.
    """
    return _bounded(production_count or 0, PRODUCTION_NORMALIZER)


def calculate_depth_score(max_depth) -> float:
    """Normalized propagation-depth factor from `blast_radius.max_propagation_depth`."""
    return _bounded(max_depth or 0, MAX_DEPTH_NORMALIZER)


def calculate_incident_score(incident_count) -> float:
    """Normalized incident-exposure factor from Phase 3 `incidents`."""
    return _bounded(incident_count or 0, INCIDENT_NORMALIZER)


def _validated_severity(severity):
    """Return a normalized known severity string, or None if invalid."""
    if not isinstance(severity, str):
        return None
    norm = severity.strip().lower()
    return norm if norm in VULN_SEVERITY_SCORES else None


def calculate_vulnerability_score(vulnerabilities) -> float:
    """Vulnerability-exposure factor.

    `vulnerabilities` is a list of validated severity strings (already
    extracted from graph facts). Returns 0.0 when no graph severity is
    known — it never fabricates a level or a CVSS score.
    """
    if not vulnerabilities:
        return 0.0
    values = [VULN_SEVERITY_SCORES[s] for s in vulnerabilities]
    return max(values)


def calculate_factor_scores(investigation: dict, vulnerabilities=None) -> dict:
    """Scores for all primary factors from a Phase 3 investigation dict."""
    blast = investigation["blast_radius"]
    vulns = vulnerabilities or []
    return {
        "blast_radius": calculate_blast_radius_score(blast["total_affected"]),
        "production_impact": calculate_production_score(
            len(investigation["production_applications"])
        ),
        "propagation_depth": calculate_depth_score(blast["max_propagation_depth"]),
        "incidents": calculate_incident_score(len(investigation["incidents"])),
        "vulnerability": calculate_vulnerability_score(vulns),
    }


def calculate_risk_score(factor_scores: dict, weights=None) -> float:
    """Weighted composite score (0..100) using named configuration weights."""
    weights = validate_weights(weights)
    return sum(factor_scores[key] * weights[key] for key in weights)


def classify_risk_level(score) -> str:
    """Map a 0..100 score to a risk level using RISK_LEVELS thresholds."""
    for lower, level in RISK_LEVELS:
        if score >= lower:
            return level
    return "LOW"


# ---------------------------------------------------------------------
# Factor breakdown / top factors
# ---------------------------------------------------------------------
def _factor_detail(key: str, score: float, weight: float, status: str) -> dict:
    return {
        "score": round(score, 2),
        "weight": weight,
        "contribution": round(score * weight, 2),
        "status": status,
    }


def _top_factors(factors: dict) -> list:
    """Factors sorted by contribution DESC, deterministically tie-broken."""
    items = sorted(factors.items(), key=lambda kv: (-kv[1]["contribution"], kv[0]))
    return [{"factor": key, "contribution": value["contribution"]} for key, value in items]


# ---------------------------------------------------------------------
# Vulnerability exposure (single bounded FalkorDB linkage lookup)
# ---------------------------------------------------------------------
def _collect_vulnerabilities(graph, artifact_id: str) -> list:
    """Severity strings of :Vulnerability nodes directly linked via
    HAS_VULNERABILITY (either direction, 1 hop). Bounded, no traversal.
    """
    seen = []
    for pattern in (
        "MATCH (a {id: $id})-[:HAS_VULNERABILITY]->(v:Vulnerability) RETURN v",
        "MATCH (a {id: $id})<-[:HAS_VULNERABILITY]-(v:Vulnerability) RETURN v",
    ):
        res = graph.query(pattern, {"id": artifact_id})
        if not res or not res.result_set:
            continue
        for cell in res.result_set:
            props = dict(getattr(cell[0], "properties", None) or {})
            sev = _validated_severity(props.get("severity"))
            if sev and sev not in seen:
                seen.append(sev)
    return seen


def _vulnerability_summary(graph, investigation: dict) -> dict:
    """Resolve known graph vulnerability exposure for the investigated artifact."""
    artifact = investigation.get("artifact", {})
    priv = artifact.get("type") == "Vulnerability"
    if priv:
        sev = _validated_severity(artifact.get("severity"))
        if sev:
            return {"status": "known", "severities": [sev]}
    vulns = _collect_vulnerabilities(graph, artifact.get("id"))
    if vulns:
        return {"status": "known", "severities": vulns}
    return {"status": "unknown", "severities": []}


# ---------------------------------------------------------------------
# Application priority + reasons
# ---------------------------------------------------------------------
def _distance_score(distance) -> float:
    """Closer apps score higher; bounded by MAX_DEPTH_NORMALIZER."""
    return (1.0 - min(distance or 0, MAX_DEPTH_NORMALIZER) / MAX_DEPTH_NORMALIZER) * 100.0


def build_risk_reasons(
    is_production: bool,
    distance,
    incident_count: int,
    vulnerability_status: str,
    total_affected: int,
) -> list:
    """Rule-based reasons, each backed by a specific deterministic fact.

    No LLM, no vague filler ("appears risky", ...).
    """
    reasons = []
    if is_production:
        reasons.append("production deployment")
    if distance is not None and distance <= CLOSE_PROPAGATION_THRESHOLD:
        reasons.append("close propagation path")
    if incident_count and incident_count > 0:
        reasons.append("linked incident exposure")
    if vulnerability_status == "known":
        reasons.append("vulnerability exposure")
    if total_affected is not None and total_affected >= LARGE_SURFACE_THRESHOLD:
        reasons.append("large downstream dependency surface")
    return reasons


def calculate_application_priority(
    is_production: bool,
    distance,
) -> float:
    """Deterministic per-application impact score (0..100).

    Production exposure (weight 0.6) combined with graph distance
    (weight 0.4). Any production app outranks any non-production app
    because its minimum score (60) exceeds a non-production app's
    maximum distance contribution (40).
    """
    prod_term = APP_PRODUCTION_WEIGHT * (100.0 if is_production else 0.0)
    dist_term = APP_DISTANCE_WEIGHT * _distance_score(distance)
    return prod_term + dist_term


def prioritize_applications(investigation: dict, vulnerabilities: dict | None = None) -> list:
    """Rank all affected applications deterministically.

    Sort: impact score DESC, then application id ASC (stable, no randomness).
    """
    vulnerability_status = (vulnerabilities or {}).get("status", "unknown")
    production_ids = {
        p["application"]["id"] for p in investigation["production_applications"]
    }
    incident_count = len(investigation["incidents"])
    total_affected = investigation["blast_radius"]["total_affected"]

    rows = []
    for item in investigation["affected_applications"]:
        app = item["application"]
        aid = app.get("id")
        distance = item.get("hops")
        is_prod = aid in production_ids
        score = calculate_application_priority(is_prod, distance)
        reasons = build_risk_reasons(
            is_prod, distance, incident_count, vulnerability_status, total_affected
        )
        rows.append(
            {
                "id": aid,
                "is_production": is_prod,
                "distance": distance,
                "risk_score": round(score, 2),
                "risk_level": classify_risk_level(int(round(score))),
                "reasons": reasons,
                "_sort_score": score,
            }
        )

    rows.sort(key=lambda r: (-r["_sort_score"], r["id"]))
    for rank, row in enumerate(rows, start=1):
        row["priority_rank"] = rank
        row.pop("_sort_score", None)
    return rows


# ---------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------
def build_risk(graph, investigation: dict, vulnerabilities: dict | None = None) -> dict:
    """Full deterministic risk report for a Phase 3 investigation dict.

    Assumes the investigation already succeeded (DB/query errors are
    handled upstream as 503 and never reach here), so status is
    "complete". Optional factors that the graph lacks (e.g. vulnerability
    exposure) are surfaced with status "unknown", never fabricated.
    """
    vuln = vulnerabilities or _vulnerability_summary(graph, investigation)

    factor_scores = calculate_factor_scores(investigation, vuln["severities"])
    weights = validate_weights()
    raw_score = calculate_risk_score(factor_scores, weights)
    final_score = int(round(raw_score))

    statuses = {k: "complete" for k in weights}
    if vuln["status"] != "known":
        statuses["vulnerability"] = "unknown"

    factors = {
        k: _factor_detail(k, factor_scores[k], weights[k], statuses[k])
        for k in weights
    }

    return {
        "score": final_score,
        "level": classify_risk_level(final_score),
        "status": "complete",
        "factors": factors,
        "top_factors": _top_factors(factors),
        "vulnerability": {
            "status": vuln["status"],
            "severities": vuln["severities"],
        },
    }


def enrich_investigation(graph, investigation: dict) -> dict:
    """Add `risk` and `prioritized_applications` to a Phase 3 investigation."""
    vuln = _vulnerability_summary(graph, investigation)
    risk = build_risk(graph, investigation, vulnerabilities=vuln)
    prioritized = prioritize_applications(
        investigation, {"status": vuln["status"], "severities": vuln["severities"]}
    )
    return {
        **investigation,
        "risk": risk,
        "prioritized_applications": prioritized,
    }