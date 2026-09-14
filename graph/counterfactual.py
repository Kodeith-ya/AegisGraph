"""AegisGraph — graph-native counterfactual remediation intelligence (Phase 7).

Non-mutating "what if we remediate artifact X?" analysis. FalkorDB performs
all reachability/path/production reasoning (bounded traversals with a
query-time path exclusion added in ``queries``); Python only orchestrates
the simulation and computes the deltas.

Guarantees
----------
* The real graph is NEVER mutated: no DELETE / DETACH / temporary
  properties / temporary relationships / rollback. Simulations use the
  Phase 7 ``blocked`` path predicate in ``graph.queries``.
* Exactly three deterministic actions: ``remove`` (recall an artifact),
  ``upgrade`` (re-evaluate a PackageVersion against OSV affected ranges),
  ``isolate`` (cut an Application/Deployment out of the graph).
* No fuzzy version logic and no "major > current = safe": UPGRADE reuses
  the Phase 6 OSV + PEP 440 rules via ``osv.package_version_in_affected``
  over the affected ranges persisted on :Vulnerability nodes. Security
  state is ``known_affected`` / ``known_unaffected`` / ``unknown``; an
  unknown state is NEVER treated as "safe".
* Assessment statuses are deterministic (no LLM): ``effective`` /
  ``partially_effective`` / ``no_material_change`` / ``unknown``.
* Delta convention: ``*_delta = counterfactual - baseline`` (negative =
  improvement) and ``*_reduction = baseline - counterfactual`` (positive =
  improvement).
"""
from __future__ import annotations

import json

from . import osv
from .queries import (
    _clamp_depth,
    applications_paths,
    investigate_artifact,
    resolve_artifact,
)
from .risk import enrich_investigation, _validated_severity

# Supported remediation actions (deterministic, closed set).
SUPPORTED_ACTIONS = ("remove", "upgrade", "isolate")
RULE_VERSION = 1

# Security evaluation results for UPGRADE.
KNOWN_AFFECTED = "known_affected"
KNOWN_UNAFFECTED = "known_unaffected"
UNKNOWN = "unknown"

# Deterministic assessment statuses.
EFFECTIVE = "effective"
PARTIALLY_EFFECTIVE = "partially_effective"
NO_MATERIAL_CHANGE = "no_material_change"
ASSESSMENT_UNKNOWN = "unknown"

UPGRADE_TARGET_LABEL = "PackageVersion"
ISOLATE_TARGET_LABELS = ("Application", "Deployment")


class InvalidCounterfactual(Exception):
    """Well-formed request that is invalid for the chosen action (HTTP 400)."""


def _target_label(node: dict) -> str | None:
    return (node or {}).get("type")


def _package_identity(graph, pv_id: str):
    """(package_name, ecosystem) of a PackageVersion via Package.HAS_VERSION."""
    res = graph.query(
        "MATCH (pkg:Package)-[:HAS_VERSION]->(pv:PackageVersion {id: $id}) "
        "RETURN pkg.name AS name, pv.ecosystem AS ecosystem LIMIT 1",
        {"id": pv_id},
    )
    if res and res.result_set and res.result_set[0]:
        return str(res.result_set[0][0]), res.result_set[0][1]
    return None, None


def _vulnerability_records(graph, package_name: str, ecosystem):
    """OSV :Vulnerability records (id, severity, affected JSON) for a package.

    Reads ONLY the affected ranges that were persisted deterministically by
    Phase 6 ingestion (``v.affected`` JSON). Records without ranges are
    skipped — the engine never fabricates them.
    """
    res = graph.query(
        "MATCH (v:Vulnerability {source: $src}) WHERE v.affected IS NOT NULL "
        "RETURN v.id AS id, v.severity AS severity, v.affected AS affected "
        "ORDER BY v.id",
        {"src": osv.OSV_SOURCE},
    )
    records = []
    if not res or not res.result_set:
        return records
    for vid, severity, affected_json in res.result_set:
        try:
            entries = json.loads(affected_json or "[]")
        except (TypeError, ValueError):
            continue
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict) or entry.get(
                "package_name"
            ) != package_name:
                continue
            if ecosystem and entry.get("ecosystem") and str(
                entry["ecosystem"]
            ).lower() != str(ecosystem).lower():
                continue
            records.append({"vuln_id": vid, "severity": severity, "affected": entry})
    return records


def _evaluate_upgrade_target(graph, pv_id: str, target_version: str) -> dict:
    """Deterministic OSV/PEP 440 security evaluation of an upgraded version.

    Returns:
        {"security_state", "target_version", "matched_vulnerabilities"}.
    Security state is ``known_affected`` when any OSV affected range matches
    the target, ``known_unaffected`` when the version is fully evaluated and
    no range matches, and ``unknown`` when the package has no package
    identity or no OSV records — an unknown is NEVER reported as safe.
    """
    name, ecosystem = _package_identity(graph, pv_id)
    if not name:
        return {
            "security_state": UNKNOWN,
            "target_version": target_version,
            "matched_vulnerabilities": [],
        }

    records = _vulnerability_records(graph, name, ecosystem)
    if not records:
        return {
            "security_state": UNKNOWN,
            "target_version": target_version,
            "matched_vulnerabilities": [],
        }

    matched = []
    for record in records:
        entry = record["affected"]
        affected = osv.Affected(
            ecosystem=entry.get("ecosystem") or ecosystem or "",
            package_name=entry.get("package_name") or name,
            versions=frozenset(str(v) for v in entry.get("versions") or []),
            introduced=entry.get("introduced"),
            fixed=entry.get("fixed"),
        )
        ok, method = osv.package_version_in_affected(str(target_version), affected)
        if ok and method:
            matched.append(
                {
                    "vulnerability_id": record["vuln_id"],
                    "severity": record["severity"],
                    "mapping_method": method,
                }
            )
    if matched:
        return {
            "security_state": KNOWN_AFFECTED,
            "target_version": target_version,
            "matched_vulnerabilities": matched,
        }
    return {
        "security_state": KNOWN_UNAFFECTED,
        "target_version": target_version,
        "matched_vulnerabilities": [],
    }


def _vulnerability_override_for_security(
    security_state: str, matched_vulnerabilities=None
) -> dict:
    """Risk-engine vulnerability summary for a security state.

    known_unaffected -> reported "known" with no severities (exposure gone).
    known_affected   -> reported "known" WITH the matched severities, so a
        still-vulnerable upgrade never shows a false risk reduction.
    unknown          -> status "unknown" (neutral 0 factor, never conflated
        with safe).
    """
    if security_state == KNOWN_AFFECTED:
        sevs = sorted(
            {
                risk_sev
                for m in (matched_vulnerabilities or [])
                for risk_sev in [_validated_severity(m.get("severity"))]
                if risk_sev
            }
        )
        return {"status": "known", "severities": sevs}
    if security_state == KNOWN_UNAFFECTED:
        return {"status": "known", "severities": []}
    return {"status": "unknown", "severities": []}


def _snapshot(investigation: dict) -> dict:
    """Deterministic projection of an ENRICHED investigation dict.

    Accepts the output of ``risk.enrich_investigation`` (investigation +
    ``risk`` + ``prioritized_applications``) so every snapshot is
    self-contained and deterministic.
    """
    blast = investigation["blast_radius"]
    return {
        "blast_radius": blast,
        "affected_nodes": sorted(
            investigation["dependencies"],
            key=lambda n: (n.get("hops", 0), str(n.get("id") or "")),
        ),
        "affected_applications": investigation["affected_applications"],
        "production_applications": investigation["production_applications"],
        "maximum_depth": blast["max_propagation_depth"],
        "incidents": investigation["incidents"],
        "evidence": investigation["evidence"],
        "vulnerability": investigation["risk"]["vulnerability"],
        "risk": investigation["risk"],
        "prioritized_applications": investigation["prioritized_applications"],
    }


def _severity_aggregate(vulnerability: dict) -> list:
    """Deterministic severity list from a risk vulnerability summary."""
    return sorted(s for s in vulnerability.get("severities") or [])


def _delta_metrics(baseline: dict, counterfactual: dict) -> dict:
    """`*_delta = cf - base` (negative = improvement) and
    `*_reduction = base - cf` (positive = improvement)."""
    base_b = baseline["blast_radius"]["total_affected"]
    cf_b = counterfactual["blast_radius"]["total_affected"]
    base_p = len(baseline["production_applications"])
    cf_p = len(counterfactual["production_applications"])
    base_d = baseline["maximum_depth"]
    cf_d = counterfactual["maximum_depth"]
    base_i = len(baseline["incidents"])
    cf_i = len(counterfactual["incidents"])
    base_v = baseline["risk"]["factors"]["vulnerability"]["score"]
    cf_v = counterfactual["risk"]["factors"]["vulnerability"]["score"]
    base_s = baseline["risk"]["score"]
    cf_s = counterfactual["risk"]["score"]

    def pair(b, c):
        return {"delta": c - b, "reduction": b - c}

    return {
        "blast_radius": pair(base_b, cf_b),
        "production_impact": pair(base_p, cf_p),
        "propagation_depth": pair(base_d, cf_d),
        "incident": pair(base_i, cf_i),
        "vulnerability": pair(base_v, cf_v),
        "risk_score": pair(base_s, cf_s),
        "vulnerabilities_aggregate": {
            "delta": len(_severity_aggregate(counterfactual["vulnerability"]))
            - len(_severity_aggregate(baseline["vulnerability"])),
            "reduction": max(
                0,
                len(_severity_aggregate(baseline["vulnerability"]))
                - len(_severity_aggregate(counterfactual["vulnerability"])),
            ),
        },
        # Legacy singular aliases required by the API contract.
        "blast_radius_delta": cf_b - base_b,
        "blast_radius_reduction": base_b - cf_b,
        "production_impact_delta": cf_p - base_p,
        "production_impact_reduction": base_p - cf_p,
        "propagation_depth_delta": cf_d - base_d,
        "propagation_depth_reduction": base_d - cf_d,
        "incident_delta": cf_i - base_i,
        "incident_reduction": base_i - cf_i,
        "vulnerability_delta": cf_v - base_v,
        "vulnerability_reduction": base_v - cf_v,
        "risk_score_delta": cf_s - base_s,
        "risk_reduction": base_s - cf_s,
        "risk_level_before": baseline["risk"]["level"],
        "risk_level_after": counterfactual["risk"]["level"],
    }


def _eliminated_and_remaining_paths(baseline_apps, counterfactual_apps):
    """Paths that disappear / persist after the simulated remediation.

    All entries are the SHORTEST path a given Application had; ordering is
    deterministic (hop count, then application id).
    """
    base_ids = set(baseline_apps)
    cf_ids = set(counterfactual_apps)

    eliminated = [
        {
            "application": baseline_apps[aid]["app"],
            "hops": baseline_apps[aid]["hops"],
            "path": baseline_apps[aid]["path"],
        }
        for aid in sorted(base_ids - cf_ids)
    ]
    remaining = [
        {
            "application": counterfactual_apps[aid]["app"],
            "hops": counterfactual_apps[aid]["hops"],
            "path": counterfactual_apps[aid]["path"],
        }
        for aid in sorted(cf_ids)
    ]
    return eliminated, remaining


def _assessment(
    target_version, security_state, baseline, counterfactual, delta
) -> dict:
    """Deterministic assessment — no LLM, no fabrication.

    Rule order:
      1. UPGRADE whose security state is unknown   -> "unknown" (never safe).
      2. baseline > 0 and counterfactual total 0  -> "effective".
      3. any positive reduction                     -> "partially_effective".
      4. otherwise                                  -> "no_material_change".
    """
    base_total = baseline["blast_radius"]["total_affected"]
    cf_total = counterfactual["blast_radius"]["total_affected"]
    reductions = (
        delta["blast_radius"]["reduction"],
        delta["production_impact"]["reduction"],
        delta["propagation_depth"]["reduction"],
        delta["incident"]["reduction"],
        delta["vulnerability"]["reduction"],
        delta["risk_score"]["reduction"],
    )
    has_improvement = any(r > 0 for r in reductions)

    if security_state == UNKNOWN:
        return {
            "status": ASSESSMENT_UNKNOWN,
            "reason": (
                f"target version {target_version} security state cannot be "
                "established from graph/OSV data; it is treated as neither "
                "affected nor safe (no remediation claim made)"
            ),
        }
    if base_total > 0 and cf_total == 0 and has_improvement:
        return {
            "status": EFFECTIVE,
            "reason": (
                "remediation eliminates the entire downstream blast radius "
                f"({base_total} -> 0) with risk improving "
                f"({delta['risk_level_before']} -> {delta['risk_level_after']})"
            ),
        }
    if has_improvement:
        return {
            "status": PARTIALLY_EFFECTIVE,
            "reason": (
                f"remediation reduces deterministic exposure: blast_radius "
                f"{base_total} -> {cf_total}, risk "
                f"{delta['risk_level_before']} -> {delta['risk_level_after']} "
                f"(risk_reduction {delta['risk_score']['reduction']} points)"
            ),
        }
    return {
        "status": NO_MATERIAL_CHANGE,
        "reason": (
            "no deterministic reduction in blast radius, production impact, "
            "propagation depth, incident exposure, or vulnerability exposure"
        ),
    }


def analyze_counterfactual(
    graph,
    artifact_id: str,
    action: str,
    target_version: str | None = None,
    target_id: str | None = None,
    application_id: str | None = None,
    max_depth=None,
) -> dict:
    """Run a non-mutating counterfactual for one artifact.

    Raises:
        InvalidCounterfactual — invalid action or invalid/absent
            target_version (maps to HTTP 400).
        LookupError — artifact/target does not exist (maps to HTTP 404).
        Any graph/network exception (maps to HTTP 503 upstream).
    """
    action = (action or "").strip().lower()
    if action not in SUPPORTED_ACTIONS:
        raise InvalidCounterfactual(
            f"unsupported remediation action '{action}'; supported: "
            + ", ".join(SUPPORTED_ACTIONS)
        )

    # Validate BEFORE touching the DB so bad requests are rejected cheaply.
    if action == "upgrade":
        if not target_version or not str(target_version).strip():
            raise InvalidCounterfactual(
                "upgrade requires a non-empty target_version (e.g. 6.0.0)"
            )
        target_version = str(target_version).strip()
        if osv._version_parse(target_version) is None:
            raise InvalidCounterfactual(
                f"target_version '{target_version}' is not a valid PEP 440 version"
            )

    artifact = resolve_artifact(graph, artifact_id)
    if artifact is None:
        raise LookupError(f"artifact '{artifact_id}' not found")

    max_depth = _clamp_depth(max_depth)

    # ISOLATE accepts application_id as a convenience alias for target_id.
    if action == "isolate" and application_id:
        if target_id and target_id != application_id:
            raise InvalidCounterfactual(
                "provide only one of target_id / application_id for isolate"
            )
        target_id = application_id

    resolved_target_id = target_id or artifact_id
    resolved_target = resolve_artifact(graph, resolved_target_id)
    if resolved_target is None:
        raise LookupError(f"remediation target '{resolved_target_id}' not found")

    blocked = []
    cf_vulnerabilities = None
    security_state = None
    target_details = {"id": resolved_target_id, "type": _target_label(resolved_target)}

    if action == "remove":
        blocked = [resolved_target_id]
    elif action == "isolate":
        if _target_label(resolved_target) not in ISOLATE_TARGET_LABELS:
            raise InvalidCounterfactual(
                "isolate requires an Application or Deployment target; target "
                f"'{resolved_target_id}' is {_target_label(resolved_target)}"
            )
        blocked = [resolved_target_id]
    elif action == "upgrade":
        if _target_label(resolved_target) != UPGRADE_TARGET_LABEL:
            raise InvalidCounterfactual(
                f"upgrade requires a PackageVersion target; target "
                f"'{resolved_target_id}' is {_target_label(resolved_target)}"
            )
        security = _evaluate_upgrade_target(graph, resolved_target_id, target_version)
        security_state = security["security_state"]
        target_details["target_version"] = target_version
        cf_vulnerabilities = _vulnerability_override_for_security(
            security_state, security["matched_vulnerabilities"]
        )

    # ---- baseline (real graph, no exclusions) ----
    baseline_investigation = investigate_artifact(
        graph, artifact_id, max_depth=max_depth
    )
    baseline_risk = enrich_investigation(graph, baseline_investigation)
    baseline = _snapshot(baseline_risk)

    # ---- counterfactual (query-time exclusion; graph NEVER mutated) ----
    cf_investigation = investigate_artifact(
        graph, artifact_id, max_depth=max_depth, blocked=blocked
    )
    if action == "remove" and resolved_target_id == artifact_id:
        # The artifact itself is recalled: its incidents and evidence are
        # about the removed artifact, so they no longer apply in the
        # hypothetical (the graph itself is untouched).
        cf_investigation["incidents"] = []
        cf_investigation["evidence"] = []
        if cf_vulnerabilities is None:
            cf_vulnerabilities = {"status": "unknown", "severities": []}
    cf_risk = enrich_investigation(
        graph, cf_investigation, vulnerabilities=cf_vulnerabilities
    )
    counterfactual = _snapshot(cf_risk)
    counterfactual["security_state"] = security_state or "not_applicable"
    if action == "upgrade":
        counterfactual["matched_vulnerabilities"] = security["matched_vulnerabilities"]

    delta = _delta_metrics(baseline, counterfactual)

    baseline_apps = applications_paths(graph, artifact_id, max_depth=max_depth)
    cf_apps = applications_paths(
        graph, artifact_id, max_depth=max_depth, blocked=blocked
    )
    eliminated, remaining = _eliminated_and_remaining_paths(baseline_apps, cf_apps)

    assessment = _assessment(
        target_version if action == "upgrade" else None,
        security_state,
        baseline,
        counterfactual,
        delta,
    )

    return {
        "artifact_id": artifact_id,
        "action": action,
        "target": target_details,
        "model": {
            "rule_version": RULE_VERSION,
            "mutating": False,
            "max_propagation_depth": max_depth,
            "evaluation_scope": (
                "topology reachability (remove/isolate) and OSV/PEP 440 "
                "affected ranges (upgrade)"
            ),
        },
        "baseline": baseline,
        "counterfactual": counterfactual,
        "delta": delta,
        "paths": {
            "eliminated": eliminated,
            "remaining": remaining,
        },
        "assessment": assessment,
    }