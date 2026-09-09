"""AegisGraph — public security intelligence ingestion from OSV (Phase 6).

End-to-end pipeline for a SMALL deterministic public subset:

    OSV API (public) -> fetch -> normalize/validate -> map -> plan
        -> FalkorDB upsert (MERGE) -> provenance

Every fact that enters FalkorDB retains its origin (:Vulnerability gets
`source=source_id=cve_id=published_at=modified_at=ingested_at=references`
and a matching public :Evidence node). Nothing is fabricated: severity is
only used when OSV/GitHub provides it, CVE ids only from OSV `aliases`,
and PackageVersion links are ONLY created via an explicit, deterministic
matching rule (exact version in OSV's affected list, or within the OSV
affected ECOSYSTEM range using PEP 440 semantics). No incidents are
auto-created: a vulnerability is not an incident.

Idempotent: every write uses MERGE (+ SET for updates), so re-running
updates instead of duplicating. Failure behavior: an OSV retrieval or
network error raises/records an error and NEVER deletes or mutates
existing graph data (the investigation/risk engines keep working).

Dependencies: ``packaging`` (PEP 440 version comparisons) — the only
new runtime dependency; HTTP uses the standard library ``urllib``.
"""
from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone

from packaging.version import InvalidVersion, Version

# ----------------------------------------------------------------------
# Configuration (deterministic subset)
# ----------------------------------------------------------------------
OSV_API_BASE = "https://api.osv.dev"
OSV_QUERY_PATH = "/v1/query"
OSV_SOURCE = "osv"
HTTP_TIMEOUT = 15          # seconds per request
HTTP_RETRIES = 2           # transient network retries (not hammering)
OSV_TARGETS = (            # the ONLY packages ingested — deliberately tiny
    {"ecosystem": "PyPI", "name": "pyyaml"},
)

# OSV/GitHub database_specific.severity -> AegisGraph vulnerability factor.
OSV_SEVERITY_ALIASES = {
    "critical": "critical",
    "high": "high",
    "moderate": "medium",
    "low": "low",
}

# Evidence/provenance node id prefix for public records (deterministic).
PUBLIC_EVIDENCE_PREFIX = "OSV-"


class OSVError(Exception):
    """Raised when OSV retrieval fails cleanly (never fabricates data)."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")


# ----------------------------------------------------------------------
# OSV retrieval (small request counts, timeouts, bounded retries)
# ----------------------------------------------------------------------
def _post_json(url: str, payload: dict) -> dict:
    body = json.dumps(payload).encode("utf-8")
    last_error = None
    for attempt in range(HTTP_RETRIES + 1):
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError,
                TimeoutError, OSError) as exc:
            last_error = exc
            if attempt < HTTP_RETRIES:
                time.sleep(0.5 * (attempt + 1))
    raise OSVError(f"OSV request failed: {last_error}")


def fetch_osv_package(ecosystem: str, name: str) -> list:
    """Fetch all current OSV records for one (ecosystem, package) pair.

    One POST /v1/query returns full vulnerability objects for the
    package; no per-record GET storm. Raises OSVError on failure.
    """
    data = _post_json(
        f"{OSV_API_BASE}{OSV_QUERY_PATH}",
        {"package": {"ecosystem": ecosystem, "name": name}},
    )
    return data.get("vulns", [])


# ----------------------------------------------------------------------
# Parsing / validation (pure; the public-data contract)
# ----------------------------------------------------------------------
def parse_severity(record: dict):
    """Severity from OSV database_specific.severity, or None.

    Never invented: OSV/GitHub category is mapped to the risk engine's
    set; anything else (or absent) stays None.
    """
    db = record.get("database_specific") or {}
    raw = db.get("severity")
    if not isinstance(raw, str):
        return None
    norm = raw.strip().lower()
    return OSV_SEVERITY_ALIASES.get(norm)


def principal_cve(record: dict):
    """First CVE alias (OSV `aliases`), or None."""
    for alias in record.get("aliases") or []:
        if isinstance(alias, str) and alias.startswith("CVE-"):
            return alias
    return None


@dataclass
class Affected:
    ecosystem: str
    package_name: str
    versions: frozenset          # explicit affected version strings
    introduced: str | None       # range start (None => "0")
    fixed: str | None            # range end (first fixed version)


@dataclass
class OSVVuln:
    id: str
    cve_id: str | None
    severity: str | None
    summary: str | None
    details: str | None
    published_at: str | None
    modified_at: str | None
    references: tuple = field(default_factory=tuple)   # (type, url)
    affected: tuple = field(default_factory=tuple)     # tuple[Affected]

    @property
    def source_url(self):
        for rtype, url in self.references:
            if rtype in ("ADVISORY", "WEB", "REPORT"):
                return url
        return None


def normalize_osv_record(record: dict) -> OSVVuln | None:
    """Extract the fields AegisGraph uses. None if structurally invalid."""
    if not isinstance(record, dict):
        return None
    vid = record.get("id")
    affected_raw = record.get("affected") or []
    if not isinstance(vid, str) or not vid or not affected_raw:
        return None

    affected = []
    for aff in affected_raw:
        pkg = aff.get("package") or {}
        eco = pkg.get("ecosystem")
        name = pkg.get("name")
        if not isinstance(eco, str) or not eco or not isinstance(name, str) or not name:
            continue
        versions = frozenset(
            str(v) for v in (aff.get("versions") or []) if isinstance(v, (str, int, float))
        )
        introduced, fixed = None, None
        for rng in aff.get("ranges") or []:
            if rng.get("type") != "ECOSYSTEM":
                continue
            for event in rng.get("events") or []:
                if "introduced" in event:
                    introduced = str(event["introduced"])
                elif "fixed" in event:
                    fixed = str(event["fixed"])
        affected.append(
            Affected(eco, name, versions, introduced, fixed)
        )
    if not affected:
        return None

    refs = tuple(
        (str(r.get("type", "WEB")), str(r.get("url", "")))
        for r in record.get("references") or []
        if isinstance(r, dict) and r.get("url")
    )
    return OSVVuln(
        id=vid,
        cve_id=principal_cve(record),
        severity=parse_severity(record),
        summary=record.get("summary"),
        details=record.get("details"),
        published_at=record.get("published"),
        modified_at=record.get("modified"),
        references=refs,
        affected=tuple(affected),
    )


def validate_osv_record(record: dict) -> list:
    """Return a list of validation errors (empty => record is valid).

    Malformed external records must not silently enter the graph.
    """
    errors = []
    if not isinstance(record, dict):
        return ["record is not a mapping"]
    vid = record.get("id")
    if not isinstance(vid, str) or not vid:
        errors.append("missing vulnerability id")
    affected = record.get("affected") or []
    if not isinstance(affected, list) or not affected:
        errors.append("missing affected list")
    for aff in affected:
        pkg = aff.get("package") or {}
        if not isinstance(pkg.get("name"), str) or not pkg.get("name"):
            errors.append("affected entry missing package name")
        if not isinstance(pkg.get("ecosystem"), str) or not pkg.get("ecosystem"):
            errors.append("affected entry missing ecosystem")
    for ts_key in ("published", "modified"):
        ts = record.get(ts_key)
        if ts is not None:
            if not isinstance(ts, str) or not ts:
                errors.append(f"invalid {ts_key} timestamp")
    return errors


def dedupe_records(records: list) -> list:
    """Collapse OSV records that describe the same CVE.

    OSV returns independent database entries (a GHSA copy AND a PYSEC
    copy) for the same CVE. The vulnerability we infer is the CVE, so we
    keep ONE record per CVE — deterministically preferring the record
    that carries severity (e.g. the GitHub advisory). Records without a
    CVE alias are keyed by their own id.
    """
    chosen = {}
    for record in sorted(records, key=lambda r: (r.get("id") or "")):
        key = principal_cve(record) or (record.get("id") or "")
        prev = chosen.get(key)
        if prev is None:
            chosen[key] = record
        elif parse_severity(record) is not None and parse_severity(prev) is None:
            chosen[key] = record
    return list(chosen.values())


# ----------------------------------------------------------------------
# Package mapping (deterministic rules only)
# ----------------------------------------------------------------------
def _version_parse(value: str):
    try:
        return Version(str(value))
    except InvalidVersion:
        return None


def package_version_in_affected(version_str, affected: Affected):
    """Is `version_str` inside this OSV affected entry?

    Returns (affected: bool, mapping_method: str | None).

    Rules (deterministic, no fuzzy matching, no fabrication):
      1. Exact string in OSV's explicit `versions` list -> TRUE,
         method "exact_package_version".
      2. Otherwise PEP 440 compare against the ECOSYSTEM range
         (introduced <= v < fixed) -> TRUE, method "ecosystem_range".
      3. Unparseable versions that are not in the explicit list ->
         FALSE (never assume).
      4. Missing <= introduced or >= fixed -> FALSE (out of range).
    """
    if version_str in affected.versions:
        return True, "exact_package_version"

    # Explicit versions list with NO range: the list is authoritative —
    # versions outside it must never be assumed affected.
    if affected.introduced is None and affected.fixed is None:
        return False, None

    v = _version_parse(version_str)
    if v is None:
        return False, None

    introduced = Version("0") if not affected.introduced else _version_parse(affected.introduced)
    fixed = _version_parse(affected.fixed) if affected.fixed else None
    if introduced is None:
        return False, None
    if v < introduced:
        return False, None
    if fixed is not None and v >= fixed:
        return False, None
    return True, "ecosystem_range"


def match_vulnerability(vuln: OSVVuln, known_versions):
    """Map a normalized OSV vuln to known PackageVersion nodes.

    `known_versions`: iterable of {"id", "name", "version", "ecosystem"}.
    Returns a list of matched {"package_id", "name", "version",
    "mapping_method"}. Unmatched vulns produce NO edge (see plan).
    """
    matches = []
    for target in known_versions or []:
        name = target.get("name")
        version = target.get("version")
        eco = target.get("ecosystem")
        if not name or version is None:
            continue
        for affected in vuln.affected:
            if affected.package_name != name:
                continue
            if eco and affected.ecosystem and affected.ecosystem.lower() != str(eco).lower():
                continue
            ok, method = package_version_in_affected(str(version), affected)
            if ok and method:
                matches.append({
                    "package_id": target.get("id"),
                    "name": name,
                    "version": str(version),
                    "mapping_method": method,
                })
                break
    return matches


# ----------------------------------------------------------------------
# Plan + apply (graph upsert)
# ----------------------------------------------------------------------
def evidence_id_for(vuln_id: str) -> str:
    return f"{PUBLIC_EVIDENCE_PREFIX}{vuln_id}"


def build_upsert_plan(vulns, known_versions=(), known_vuln_ids=(), known_evidence_ids=(),
                      now=None):
    """Deterministic plan of graph changes. Pure — no DB access.

    `known_*` come from the graph (empty => everything is a create).
    Re-running with the previous plan applied yields 0 creates (upsert).
    """
    now_iso = now or iso_now()
    known_vulns = set(known_vuln_ids or ())
    known_evids = set(known_evidence_ids or ())

    # Validate every input record FIRST, then collapse the OSV CVE
    # duplicates (GHSA + PYSEC twins) among the VALID records only.
    # This protects the plan against duplicate CVEs entering the graph
    # even if a caller forgets to dedupe upstream, and keeps rejection
    # counts honest (malformed input is rejected before dedupe).
    vuln_ops, evidence_ops, mappings, unmatched = [], [], [], []
    errors = []
    accepted = 0
    rejected = 0
    valid_records = []
    for record in vulns:
        errs = validate_osv_record(record)
        if errs:
            rejected += 1
            errors.append({"record_id": record.get("id"), "errors": errs})
            continue
        valid_records.append(record)

    for record in dedupe_records(valid_records):
        normalized = normalize_osv_record(record)
        if normalized is None:
            rejected += 1
            errors.append({"record_id": record.get("id"), "errors": ["cannot normalize"]})
            continue
        accepted += 1

        created = normalized.id not in known_vulns
        vuln_ops.append({
            "operation": "create" if created else "update",
            "id": normalized.id,
            "cve_id": normalized.cve_id,
            "severity": normalized.severity,
            "summary": normalized.summary,
            "description": normalized.details or normalized.summary or normalized.id,
            "source": OSV_SOURCE,
            "source_id": normalized.id,
            "source_url": normalized.source_url,
            "published_at": normalized.published_at,
            "modified_at": normalized.modified_at,
            "ingested_at": now_iso,
            "references": [{"type": t, "url": u} for t, u in normalized.references],
            "data_source": "public",
        })

        ev_created = evidence_id_for(normalized.id) not in known_evids
        evidence_ops.append({
            "operation": "create" if ev_created else "update",
            "id": evidence_id_for(normalized.id),
            "vuln_id": normalized.id,
            "title": normalized.summary or f"{normalized.id} advisory (OSV)",
            "source": OSV_SOURCE,
            "source_type": "public",
            "confidence": None,  # OSV defines no per-record confidence: never manufactured
            "observed_at": now_iso,
            "description": (normalized.details or normalized.summary or normalized.id)[:2000],
        })

        matched = match_vulnerability(normalized, known_versions)
        for m in matched:
            m = dict(m)
            m["vuln_id"] = normalized.id
            mappings.append(m)
        if not matched:
            unmatched.append({
                "vuln_id": normalized.id,
                "cve_id": normalized.cve_id,
                "severity": normalized.severity,
                "reason": "no exact package/version mapping to an existing PackageVersion",
            })

    return {
        "counts": {
            "records_retrieved": len(vulns),
            "records_accepted": accepted,
            "records_rejected": rejected,
            "vulnerabilities_created": sum(1 for o in vuln_ops if o["operation"] == "create"),
            "vulnerabilities_updated": sum(1 for o in vuln_ops if o["operation"] == "update"),
            "evidence_created": sum(1 for o in evidence_ops if o["operation"] == "create"),
            "evidence_updated": sum(1 for o in evidence_ops if o["operation"] == "update"),
            "package_mappings_created": len(mappings),
            "package_mappings_rejected": len(unmatched),
        },
        "vulnerabilities": vuln_ops,
        "evidence": evidence_ops,
        "mappings": mappings,
        "unmatched": unmatched,
        "errors": errors,
    }


def _node_snapshot(plan):
    """Nodes/edges the plan would write (for dry-run reporting)."""
    return {
        "vulnerabilities": len(plan["vulnerabilities"]),
        "evidence": len(plan["evidence"]),
        "has_vulnerability_edges": len(plan["mappings"]),
        "describes_edges": len(plan["evidence"]) + len(plan["mappings"]),
    }


def apply_plan(graph, plan, dry_run: bool = False) -> dict:
    """Write the plan to FalkorDB (MERGE/upsert). Returns write stats.

    Never called when dry_run=True or when no graph is available.
    """
    if dry_run:
        return {"mutated": False, "written": _node_snapshot(plan)}

    executed = {"vulnerability_nodes": 0, "evidence_nodes": 0,
                "has_vulnerability_edges": 0, "describes_edges": 0}

    for op in plan["vulnerabilities"]:
        graph.query(
            "MERGE (v:Vulnerability {id: $id})\n"
            "SET v.name = $id, v.severity = $severity, v.description = $description,\n"
            "    v.source = $source, v.source_id = $source_id, v.source_url = $source_url,\n"
            "    v.cve_id = $cve_id, v.published_at = $published_at,\n"
            "    v.modified_at = $modified_at, v.ingested_at = $ingested_at,\n"
            "    v.references = $references, v.data_source = $data_source",
            {
                "id": op["id"], "severity": op["severity"],
                "description": op["description"], "source": op["source"],
                "source_id": op["source_id"], "source_url": op["source_url"],
                "cve_id": op["cve_id"], "published_at": op["published_at"],
                "modified_at": op["modified_at"], "ingested_at": op["ingested_at"],
                "references": op["references"], "data_source": op["data_source"],
            },
        )
        executed["vulnerability_nodes"] += 1

    for ev in plan["evidence"]:
        graph.query(
            "MERGE (e:Evidence {id: $id})\n"
            "SET e.title = $title, e.source = $source, e.source_type = $source_type,\n"
            "    e.confidence = $confidence, e.observed_at = $observed_at,\n"
            "    e.description = $description",
            ev,
        )
        graph.query(
            "MATCH (e:Evidence {id: $eid}), (v:Vulnerability {id: $vid})\n"
            "MERGE (e)-[:DESCRIBES]->(v)",
            {"eid": ev["id"], "vid": ev["vuln_id"]},
        )
        executed["evidence_nodes"] += 1
        executed["describes_edges"] += 1

    for m in plan["mappings"]:
        graph.query(
            "MATCH (p {id: $pid}), (v:Vulnerability {id: $vid})\n"
            "MERGE (p)-[r:HAS_VULNERABILITY]->(v)\n"
            "SET r.mapping_method = $method, r.source = $source",
            {"pid": m["package_id"], "vid": m["vuln_id"],
             "method": m["mapping_method"], "source": OSV_SOURCE},
        )
        executed["has_vulnerability_edges"] += 1

    return {"mutated": True, "written": executed}


# ----------------------------------------------------------------------
# Orchestration
# ----------------------------------------------------------------------
def _known_targets(graph) -> list:
    res = graph.query(
        "MATCH (p:Package)-[:HAS_VERSION]->(pv:PackageVersion) "
        "RETURN pv.id AS id, p.name AS name, pv.version AS version, "
        "pv.ecosystem AS ecosystem"
    )
    targets = []
    if res and res.result_set:
        for cell in res.result_set:
            targets.append({
                "id": cell[0], "name": cell[1], "version": cell[2],
                "ecosystem": cell[3],
            })
    return targets


def _known_existing(graph) -> tuple:
    vuln_ids, evidence_ids = [], []
    res = graph.query("MATCH (v:Vulnerability {source: $src}) RETURN v.id", {"src": OSV_SOURCE})
    if res and res.result_set:
        vuln_ids = [cell[0] for cell in res.result_set]
    res = graph.query(
        "MATCH (e:Evidence) WHERE e.source_type = $st RETURN e.id", {"st": "public"}
    )
    if res and res.result_set:
        evidence_ids = [cell[0] for cell in res.result_set]
    return vuln_ids, evidence_ids


def ingest_public_vulnerabilities(graph=None, targets=None, dry_run=False,
                                  fetch_fn=None, now=None) -> dict:
    """Fetch, validate, map, plan and (optionally) upsert OSV records.

    Returns a full report. Guarantees:
    * dry_run or graph=None -> NEVER mutates FalkorDB.
    * An OSV/network failure is captured in the report and NEVER touches
      existing graph data (investigation/risk keep working).
    """
    targets = list(targets or OSV_TARGETS)
    fetch = fetch_fn or fetch_osv_package
    report = {
        "source": OSV_SOURCE,
        "targets": targets,
        "retrieval": [],
        "plan": None,
        "written": None,
        "errors": [],
        "dry_run": bool(dry_run),
    }

    records = []
    for target in targets:
        try:
            fetched = fetch(target["ecosystem"], target["name"])
            report["retrieval"].append(
                {"ecosystem": target["ecosystem"], "name": target["name"],
                 "retrieved": len(fetched), "status": "ok"}
            )
            records.extend(fetched)
        except Exception as exc:  # noqa: BLE001 — any failure is isolated
            report["retrieval"].append(
                {"ecosystem": target["ecosystem"], "name": target["name"],
                 "retrieved": 0, "status": "error", "error": str(exc)}
            )
            report["errors"].append(
                f"OSV retrieval failed for {target['ecosystem']}/{target['name']}: {exc}"
            )
    if records:
        records = dedupe_records(records)

    known_versions, known_vuln_ids, known_evidence_ids = [], [], []
    if graph is not None:
        known_versions = _known_targets(graph)
        known_vuln_ids, known_evidence_ids = _known_existing(graph)

    plan = build_upsert_plan(
        records,
        known_versions=known_versions,
        known_vuln_ids=known_vuln_ids,
        known_evidence_ids=known_evidence_ids,
        now=now,
    )
    report["plan"] = plan

    if graph is not None and not dry_run:
        report["written"] = apply_plan(graph, plan, dry_run=False)
    else:
        report["written"] = apply_plan(None, plan, dry_run=True)

    return report


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def _cli():
    parser = argparse.ArgumentParser(
        description="Ingest public OSV security intelligence into AegisGraph."
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="retrieve + validate + plan, but do NOT touch FalkorDB")
    parser.add_argument("--packages", action="append", nargs="*", default=[],
                        metavar="ECOSYSTEM:NAME",
                        help="override OSV_TARGETS, e.g. PyPI:pyyaml (repeatable)")
    args = parser.parse_args()

    targets = []
    for group in args.packages:
        for item in (group or []):
            if ":" in item:
                eco, name = item.split(":", 1)
                targets.append({"ecosystem": eco, "name": name})
    if not targets:
        targets = list(OSV_TARGETS)

    graph = None
    if not args.dry_run:
        try:
            try:
                from apps.api.db import get_graph
            except ImportError:
                from db import get_graph  # run from apps/api context
            graph = get_graph()
        except Exception as exc:  # noqa: BLE001
            print(json.dumps({"error": f"cannot connect to FalkorDB: {exc}",
                              "hint": "use --dry-run to test without a database"},
                             indent=2))
            return 1

    report = ingest_public_vulnerabilities(graph=graph, targets=targets,
                                           dry_run=args.dry_run)
    print(json.dumps(report, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())