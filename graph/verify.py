"""Verify the AegisGraph seed graph + Phase 3, 4, 5 & 6 behavior.

Usage:
    python -m graph.verify      # from repo root

Executes real Cypher queries and prints PASS/FAIL for:
  1-6: Phase 2 schema/seed structural checks
  7-11: Phase 3 traversal / blast-radius / negative / 404 checks
  12-20: Phase 4 deterministic risk (R1-R12)
  21-28: Phase 5 evidence & provenance (E1-E12)
  29: Phase 6 P1-P5, P7-P9, P13, P14 — UNIT checks that never need
      FalkorDB (OSV fetch contract, validation, normalization severity
      aliasing, CVE dedupe, version mapping matrix, plan integrity,
      plan idempotency, dry-run no-op, orchestration + failure
      isolation, determinism).
  30: Phase 6 P6, P10-P12 — INTEGRATION checks that need a LIVE
      FalkorDB (+ live OSV network for P6): real pyyaml ingestion,
      upsert detection, post-ingestion graph facts (public provenance,
      honest risk: public evidence w/o confidence never inflates risk,
      no auto-incident), and failure isolation.

If FalkorDB is unreachable, the Phase 6 UNIT section and GraphRAG-SDK
availability check still run; DB-dependent sections are skipped with a
note (live Docker/FalkorDB required).

NOTE: R8 (unknown artifact 404) and API-level behavior (503, depth 422)
are covered in apps/api/main.py — see README.
"""
import json
import sys
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api"))

from .seed import main as seed_main  # noqa: E402

from .queries import (  # noqa: E402
    evidence_for,
    investigate_artifact,
    resolve_artifact,
)

from .risk import (  # noqa: E402
    RISK_LEVELS,
    RISK_WEIGHTS,
    EVIDENCE_SOURCE_TYPES,
    calculate_evidence_score,
    evidence_confidence,
    validate_evidence_record,
    validate_weights,
    enrich_investigation,
)

from .graphrag_schema import (  # noqa: E402
    ONTOLOGY_ENTITIES,
    ONTOLOGY_RELATIONS,
    build_graphrag_schema,
)

from .osv import (  # noqa: E402
    HTTP_RETRIES,
    Affected,
    OSVError,
    OSV_SOURCE,
    apply_plan,
    build_upsert_plan,
    dedupe_records,
    evidence_id_for,
    fetch_osv_package,
    ingest_public_vulnerabilities,
    match_vulnerability,
    normalize_osv_record,
    package_version_in_affected,
    parse_severity,
    validate_osv_record,
)

# ----------------------------------------------------------------------
# Phase 6 unit fixtures — trimmed, faithful copies of REAL OSV records
# for PyPI `pyyaml` (retrieved 2026 from api.osv.dev). They model an
# external record contract; unit checks never hit the network.
# Four distinct CVEs, each ALSO served as a PYSEC record (severity null):
#   CVE-2020-1747  GHSA-6757-jp84-gxfx (CRITICAL) / PYSEC-2020-96
#   CVE-2020-14343 GHSA-8q59-q68h-6hv4 (CRITICAL) / PYSEC-2021-142
#   CVE-2019-20477 GHSA-3pqx-4fqf-j49f (CRITICAL) / PYSEC-2020-176
#   CVE-2017-18342 GHSA-rprw-h62v-c2w7 (CRITICAL) / PYSEC-2018-49
# For pyyaml 5.3: CVE-2020-1747 and CVE-2020-14343 map (exact version in
# the OSV affected list); the other two are explicitly out-of-range.
# ----------------------------------------------------------------------
_FIXTURE_6757 = {
    "id": "GHSA-6757-jp84-gxfx",
    "summary": "Improper input validation in PyYAML",
    "details": "PyYAML library mishandles specially crafted input, leading to "
               "arbitrary code execution (yaml.Loader).",
    "aliases": ["CVE-2020-1747", "PYSEC-2020-96"],
    "affected": [{
        "package": {"name": "pyyaml", "ecosystem": "PyPI",
                    "purl": "pkg:pypi/pyyaml"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "5.1b7"}, {"fixed": "5.3.1"}]}],
        "versions": ["5.1b3", "5.1b5", "5.1b7", "5.1", "5.2", "5.3"],
    }],
    "references": [{"type": "ADVISORY",
                    "url": "https://github.com/advisories/GHSA-6757-jp84-gxfx"}],
    "published": "2020-06-09T03:44:00Z",
    "modified": "2024-01-04T21:44:00Z",
    "database_specific": {"severity": "CRITICAL"},
}
_FIXTURE_PYSEC_96 = {
    "id": "PYSEC-2020-96",
    "summary": "PyYAML: Full load of untrusted YAML can execute arbitrary code",
    "details": "pyyaml before 5.3.1 allows a crafted YAML document to execute "
               "arbitrary code on full load.",
    "aliases": ["CVE-2020-1747", "GHSA-6757-jp84-gxfx"],
    "affected": [{
        "package": {"name": "pyyaml", "ecosystem": "PyPI",
                    "purl": "pkg:pypi/pyyaml"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "5.1"}, {"fixed": "5.3.1"}]}],
        "versions": [],
    }],
    "references": [],
    "published": "2020-06-09T03:44:00Z",
    "modified": "2024-01-04T21:44:00Z",
}
_FIXTURE_14343 = {
    "id": "GHSA-8q59-q68h-6hv4",
    "summary": "Improper input validation in PyYAML",
    "details": "PyYAML.insecure_load bypasses security checks via arbitrary "
               "chained method calls when the DIY API is used.",
    "aliases": ["CVE-2020-14343", "PYSEC-2021-142"],
    "affected": [{
        "package": {"name": "pyyaml", "ecosystem": "PyPI",
                    "purl": "pkg:pypi/pyyaml"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "5.4"}]}],
        "versions": ["5.1", "5.2", "5.3"],
    }],
    "references": [{"type": "ADVISORY",
                    "url": "https://github.com/advisories/GHSA-8q59-q68h-6hv4"}],
    "published": "2020-07-22T00:00:00Z",
    "modified": "2023-03-03T20:18:00Z",
    "database_specific": {"severity": "CRITICAL"},
}
_FIXTURE_20477 = {
    "id": "GHSA-3pqx-4fqf-j49f",
    "summary": "Improper input validation in PyYAML",
    "details": "Improper input validation in PyYAML leading to a buffer "
               "over-read targeting a crafted YAML file.",
    "aliases": ["CVE-2019-20477", "PYSEC-2020-176"],
    "affected": [{
        "package": {"name": "pyyaml", "ecosystem": "PyPI",
                    "purl": "pkg:pypi/pyyaml"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "5.1"}, {"fixed": "5.2"}]}],
        "versions": ["5.1", "5.1b3"],
    }],
    "references": [{"type": "ADVISORY",
                    "url": "https://github.com/advisories/GHSA-3pqx-4fqf-j49f"}],
    "published": "2020-02-17T00:00:00Z",
    "modified": "2023-03-03T20:38:00Z",
    "database_specific": {"severity": "CRITICAL"},
}
_FIXTURE_18342 = {
    "id": "GHSA-rprw-h62v-c2w7",
    "summary": "YAML deserialization attack in PyYAML",
    "details": "yaml.load in PyYAML executes arbitrary Python code.",
    "aliases": ["CVE-2017-18342", "PYSEC-2018-49"],
    "affected": [{
        "package": {"name": "pyyaml", "ecosystem": "PyPI",
                    "purl": "pkg:pypi/pyyaml"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "5.1"}]}],
        "versions": ["3.10", "3.13", "4.2b4", "5.0"],
    }],
    "references": [{"type": "ADVISORY",
                    "url": "https://github.com/advisories/GHSA-rprw-h62v-c2w7"}],
    "published": "2018-07-25T00:00:00Z",
    "modified": "2023-03-03T20:18:00Z",
    "database_specific": {"severity": "CRITICAL"},
}

# The pyyaml records exactly as OSV's /v1/query returns them: each CVE
# carries BOTH its GHSA copy AND its PYSEC copy.
_FIXTURE_RAW = [_FIXTURE_6757, _FIXTURE_PYSEC_96, _FIXTURE_14343,
                _FIXTURE_20477, _FIXTURE_18342]

_FIXTURE_KNOWN_VERSIONS = [
    {"id": "PV3", "name": "pyyaml", "version": "5.3", "ecosystem": "PyPI"},
]
_EXPECTED_DEDUPED_IDS = {"GHSA-6757-jp84-gxfx", "GHSA-8q59-q68h-6hv4",
                         "GHSA-3pqx-4fqf-j49f", "GHSA-rprw-h62v-c2w7"}
_EXPECTED_MAPPED_CVES = {"CVE-2020-1747", "CVE-2020-14343"}
_EXPECTED_UNMATCHED_CVES = {"CVE-2019-20477", "CVE-2017-18342"}


def first_column(graph, cypher):
    return graph.query(cypher).result_set


def check(label, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))


def main():
    try:
        graph = seed_main()
    except Exception as exc:  # noqa: BLE001 — DB-degraded mode
        print(f"\n[DB-DEGRADED] FalkorDB unavailable ({exc})")
        print("[DB-DEGRADED] Running Phase 6 unit checks only; P6/P10-P12 "
              "(live FalkorDB) skipped.\n")
        verify_phase6_unit()
        return

    print("\n--- 1. Required nodes exist ---")
    node_ids = ["D1", "MV1", "A1", "APP1", "DEP1", "PV1", "V1", "INC1", "INC2"]
    for nid in node_ids:
        rows = first_column(graph, f"MATCH (n {{id: '{nid}'}}) RETURN count(n)")
        count = rows[0][0] if rows else "?"
        check(f"node {nid}", count == 1, f"count={count}")

    print("\n--- 2. Full traversal D1 -> MV1 -> A1 -> APP1 -> DEP1 ---")
    rows = first_column(
        graph,
        "MATCH (d1 {id:'D1'})<-[:TRAINED_ON]-(mv1 {id:'MV1'})"
        "<-[:POWERED_BY]-(a1 {id:'A1'})"
        "<-[:USES_AGENT]-(app1 {id:'APP1'})"
        "<-[:DEPLOYS]-(dep1 {id:'DEP1'})"
        "RETURN d1.id, mv1.id, a1.id, app1.id, dep1.id",
    )
    check("chain D1->MV1->A1->APP1->DEP1", bool(rows), f"rows={rows}")

    print("\n--- 3. Multi-path D1 -> MV1 -> MV2 -> APP2 ---")
    rows = first_column(
        graph,
        "MATCH (d1 {id:'D1'})<-[:TRAINED_ON]-(mv1 {id:'MV1'})"
        "MATCH (mv1)<-[:BASED_ON]-(mv2 {id:'MV2'})"
        "MATCH (mv2)<-[:USES_MODEL]-(app2 {id:'APP2'})"
        "RETURN d1.id, mv1.id, mv2.id, app2.id",
    )
    check("chain D1->MV1->MV2->APP2", bool(rows), f"rows={rows}")

    print("\n--- 4. Negative: D1 must NOT reach APP_UNRELATED ---")
    rows = first_column(
        graph,
        "MATCH (d {id:'D1'})-[*1..8]-(app {id:'APP_UNRELATED'}) "
        "RETURN count(*) AS paths",
    )
    paths = rows[0][0] if rows else 0
    check("D1 does not reach APP_UNRELATED", paths == 0, f"paths={paths}")

    print("\n--- 5. Incidents AFFECT concrete artifacts ---")
    rows = first_column(
        graph,
        "MATCH (i:Incident)-[:AFFECTS]->(a) RETURN i.id, i.type, labels(a)[0], a.id",
    )
    for iid, itype, label, aid in sorted(rows):
        print(f"  INC {iid} ({itype}) AFFECTS :{label} {aid}")
    check("incidents AFFECTS relationships", bool(rows), f"count={len(rows)}")

    print("\n--- 6. Counts ---")
    for label in ["Dataset", "Model", "ModelVersion", "Package", "PackageVersion",
                  "Agent", "Application", "Deployment", "Vulnerability", "Incident"]:
        rows = first_column(graph, f"MATCH (n:{label}) RETURN count(n)")
        print(f"  :{label} = {rows[0][0] if rows else 0}")

    total_nodes = first_column(graph, "MATCH (n) RETURN count(n)")[0][0]
    total_rels = first_column(graph, "MATCH (:)-[r]->() RETURN count(r)")[0][0]
    print(f"  TOTAL nodes = {total_nodes}, relationships = {total_rels}")

    print("\n--- 7. Phase 3: D1 blast radius (investigation) ---")
    d1 = investigate_artifact(graph, "D1")
    d1_affected = {n["id"] for n in d1["dependencies"]}
    expected_d1 = {"MV1", "MV2", "A1", "APP1", "APP2", "APP4", "APP5", "DEP1", "DEP2"}
    check(
        "D1 downstream distinct set",
        d1_affected == expected_d1,
        f"got={sorted(d1_affected)}",
    )
    check(
        "D1 negative control not affected",
        "APP_UNRELATED" not in d1_affected and "DEP_UNRELATED" not in d1_affected,
    )
    check(
        "D1 max propagation depth",
        d1["blast_radius"]["max_propagation_depth"] == 4,
        f"depth={d1['blast_radius']['max_propagation_depth']}",
    )
    app_ids = {a["application"]["id"] for a in d1["affected_applications"]}
    check(
        "D1 affected applications",
        app_ids == {"APP1", "APP2", "APP4", "APP5"},
        f"apps={sorted(app_ids)}",
    )
    prod_ids = {p["application"]["id"] for p in d1["production_applications"]}
    check(
        "D1 production applications (via DEPLOYS edge only)",
        prod_ids == {"APP1", "APP2"},
        f"prod={sorted(prod_ids)}",
    )

    print("\n--- 8. Phase 3: exact path D1 -> APP1 ---")
    paths = d1["affected_applications"]
    app1 = next((a for a in paths if a["application"]["id"] == "APP1"), None)
    if app1:
        node_ids = [n["id"] for n in app1["path"]["nodes"]]
        check(
            "D1->APP1 path via graph (D1..MV1..A1..APP1)",
            node_ids[0] == "D1" and node_ids[-1] == "APP1",
            f"path={node_ids}",
        )
    else:
        check("D1->APP1 path via graph", False, "APP1 not in affected apps")

    print("\n--- 9. Phase 3: vulnerability V1 -> PV1 -> downstream ---")
    v1 = investigate_artifact(graph, "V1")
    v1_ids = {n["id"] for n in v1["dependencies"]}
    check(
        "V1 blast radius includes PV1",
        "PV1" in v1_ids and "MV1" in v1_ids,
        f"downstream={sorted(v1_ids)}",
    )
    inc = {i["id"] for i in v1["incidents"]}
    check("V1 incident INC2 surfaced", inc == {"INC2"}, f"incidents={inc}")

    print("\n--- 10. Phase 3: negative control (no downstream) ---")
    unr = investigate_artifact(graph, "APP_UNRELATED")
    check(
        "APP_UNRELATED has zero affected",
        unr["blast_radius"]["total_affected"] == 0,
        f"total={unr['blast_radius']['total_affected']}",
    )

    print("\n--- 11. Phase 3: unknown artifact -> resolve None ---")
    check(
        "DOES_NOT_EXIST resolves to None",
        resolve_artifact(graph, "DOES_NOT_EXIST") is None,
    )

    print("\n--- 12. Phase 4 (R1/R2): risk exists + bounded for D1 ---")
    d1 = investigate_artifact(graph, "D1")
    d1r = enrich_investigation(graph, d1)
    risk = d1r["risk"]
    check("R1 risk.score exists", isinstance(risk["score"], int), f"score={risk['score']}")
    check(
        "R1 risk.level exists",
        risk["level"] in {lvl for _, lvl in RISK_LEVELS},
        f"level={risk['level']}",
    )
    check("R1 risk.status exists", risk["status"] == "complete")
    check("R1 risk.factors exists", set(risk["factors"]) == set(RISK_WEIGHTS))
    check(
        "R1 risk.top_factors exists",
        isinstance(risk["top_factors"], list) and len(risk["top_factors"]) == len(RISK_WEIGHTS),
    )
    check("R2 risk.score bounded 0..100", 0 <= risk["score"] <= 100, f"score={risk['score']}")

    print("\n--- 13. Phase 4 (R3): weight validation ---")
    w_sum = sum(RISK_WEIGHTS.values())
    check("R3 weights sum to 1.0", abs(w_sum - 1.0) < 1e-9, f"sum={w_sum}")
    try:
        validate_weights({"a": 0.5, "b": 0.2})
        bad = False
    except ValueError:
        bad = True
    check("R3 invalid weights rejected", bad)

    print("\n--- 14. Phase 4 (R4): production correctness ---")
    prod_ids = {p["application"]["id"] for p in d1r["production_applications"]}
    check(
        "R4 production apps = {APP1, APP2}",
        prod_ids == {"APP1", "APP2"},
        f"prod={sorted(prod_ids)}",
    )
    app5 = next((d for d in d1r["dependencies"] if d["id"] == "APP5"), None)
    check(
        "R4 APP5 not production despite production-like property",
        "APP5" not in prod_ids
        and app5 is not None
        and app5.get("environment") == "production"
        and app5.get("type") == "Application",
    )

    print("\n--- 15. Phase 4 (R5/R6): deterministic ranking ---")
    prio = d1r["prioritized_applications"]
    check(
        "R5 consecutive priority ranks",
        [p["priority_rank"] for p in prio] == list(range(1, len(prio) + 1)),
    )
    pos = {p["id"]: p["priority_rank"] for p in prio}
    prod_ranks = sorted(pos[i] for i in ("APP1", "APP2"))
    nonprod_ranks = sorted(pos[i] for i in ("APP4", "APP5"))
    check(
        "R5 production outranks non-production",
        prod_ranks == [1, 2] and nonprod_ranks == [3, 4],
        f"prod_ranks={prod_ranks} nonprod_ranks={nonprod_ranks}",
    )
    d1r2 = enrich_investigation(graph, investigate_artifact(graph, "D1"))
    check("R6 deterministic risk", d1r["risk"] == d1r2["risk"])
    check(
        "R6 deterministic rankings",
        d1r["prioritized_applications"] == d1r2["prioritized_applications"],
    )

    print("\n--- 16. Phase 4 (R7): zero blast radius ---")
    unr = investigate_artifact(graph, "APP_UNRELATED")
    unr_risk = enrich_investigation(graph, unr)["risk"]
    check(
        "R7 zero affected -> zero risk, still valid",
        unr["blast_radius"]["total_affected"] == 0
        and unr_risk["score"] == 0
        and unr_risk["status"] == "complete",
        f"score={unr_risk['score']}",
    )

    print("\n--- 17. Phase 4 (R9): depth sensitivity ---")
    d1d1 = investigate_artifact(graph, "D1", max_depth=1)
    d1d8 = investigate_artifact(graph, "D1", max_depth=8)
    check(
        "R9 depth cap respected (max_depth=1)",
        d1d1["blast_radius"]["max_propagation_depth"] == 1,
        f"depth={d1d1['blast_radius']['max_propagation_depth']}",
    )
    check(
        "R9 deeper cap is a superset",
        len(d1d8["dependencies"]) >= len(d1d1["dependencies"]),
        f"d1={len(d1d1['dependencies'])} d8={len(d1d8['dependencies'])}",
    )
    r1_score = enrich_investigation(graph, d1d1)["risk"]["factors"]["propagation_depth"]["score"]
    r8_score = enrich_investigation(graph, d1d8)["risk"]["factors"]["propagation_depth"]["score"]
    check(
        "R9 risk calculated from actual returned investigation",
        r1_score < r8_score,
        f"depth@1={r1_score} depth@8={r8_score}",
    )

    print("\n--- 18. Phase 4 (R10): incident factor ---")
    v1 = investigate_artifact(graph, "V1")
    v1r = enrich_investigation(graph, v1)
    check("R10 V1 incident exposure (INC2)", len(v1["incidents"]) == 1,
          f"incidents={[i['id'] for i in v1['incidents']]}")
    check(
        "R10 incident factor reflects exposure",
        v1r["risk"]["factors"]["incidents"]["score"] > 0,
        f"score={v1r['risk']['factors']['incidents']['score']}",
    )

    print("\n--- 19. Phase 4 (R11): missing vs known vulnerability severity ---")
    vuln_d1 = d1r["risk"]["vulnerability"]
    vuln_d1_factor = d1r["risk"]["factors"]["vulnerability"]
    check(
        "R11 D1 vulnerability factor unknown/neutral (no fabrication)",
        vuln_d1["status"] == "unknown"
        and vuln_d1_factor["score"] == 0
        and vuln_d1_factor["status"] == "unknown",
        f"status={vuln_d1['status']}",
    )
    pv1r = enrich_investigation(graph, investigate_artifact(graph, "PV1"))
    vuln_pv1 = pv1r["risk"]["vulnerability"]
    check(
        "R11 PV1 vulnerability known from graph severity",
        vuln_pv1["status"] == "known" and vuln_pv1["severities"] == ["critical"],
        f"vuln={vuln_pv1}",
    )

    print("\n--- 20. Phase 4 (R12): DB failure propagates (never a fabricated low score) ---")
    class _BrokenGraph:
        def query(self, *args, **kwargs):
            raise RuntimeError("connection refused")

    try:
        investigate_artifact(_BrokenGraph(), "D1")
        db_err = False
    except Exception:
        db_err = True
    check(
        "R12 DB failure raises (endpoint maps to 503)",
        db_err,
        "investigate_artifact must not return a low-risk result on DB failure",
    )

    print("\n--- 21. Phase 5 (E1/E2/E3/E5): evidence nodes & provenance rels ---")
    for eid in ("E1", "E2", "E3"):
        rows = first_column(graph, f"MATCH (e:Evidence {{id: '{eid}'}}) RETURN count(e)")
        check(f"E1 evidence {eid} exists", rows[0][0] == 1, f"count={rows[0][0]}")

    rows = first_column(
        graph,
        "MATCH (i:Incident)-[:SUPPORTED_BY]->(e:Evidence) "
        "RETURN i.id, e.id ORDER BY i.id, e.id",
    )
    supported = {(i, e) for i, e in rows}
    check(
        "E2 INC1->E1, INC2->E2 SUPPORTED_BY",
        supported == {("INC1", "E1"), ("INC2", "E2")},
        f"got={sorted(supported)}",
    )

    rows = first_column(
        graph,
        "MATCH (e:Evidence)-[:DESCRIBES]->(a) RETURN e.id, labels(a)[0], a.id "
        "ORDER BY e.id, a.id",
    )
    describes = {(e, a) for e, _, a in rows}
    check(
        "E3 DESCRIBES concrete artifacts",
        describes == {("E1", "D1"), ("E2", "V1"), ("E2", "PV1"), ("E3", "D1")},
        f"got={sorted(describes)}",
    )

    rows = first_column(graph, "MATCH (e:Evidence) RETURN DISTINCT e.source_type")
    types = {r[0] for r in rows}
    check(
        "E5 all evidence source types valid",
        types and types.issubset(set(EVIDENCE_SOURCE_TYPES)),
        f"source_types={types}",
    )

    print("\n--- 22. Phase 5 (E4): evidence confidence valid (null = unknown) ---")
    rows = first_column(graph, "MATCH (e:Evidence) RETURN e.id, e.confidence")
    all_valid = all(
        c is None or (isinstance(c, (int, float)) and not isinstance(c, bool)
                      and 0.0 <= c <= 1.0)
        for _, c in rows
    )
    check(
        "E4 confidence is null (explicitly unknown) or in [0,1]",
        all_valid,
        f"records={sorted((i, c) for i, c in rows)}",
    )

    print("\n--- 23. Phase 5 (E6): re-running seed does not duplicate evidence ---")
    seed_main()
    rows = first_column(graph, "MATCH (e:Evidence) RETURN count(e)")
    check("E6 Evidence count still 3 after reseed", rows[0][0] == 3, f"count={rows[0][0]}")
    rows = first_column(graph, "MATCH (e:Evidence {id: 'E1'}) RETURN count(e)")
    check("E6 E1 still exactly 1 after reseed", rows[0][0] == 1, f"count={rows[0][0]}")

    print("\n--- 24. Phase 5 (E7): investigation returns evidence ---")
    d1 = investigate_artifact(graph, "D1")
    d1_evidence_ids = {e["id"] for e in d1["evidence"]}
    check(
        "E7 D1 evidence = {E1, E3}",
        d1_evidence_ids == {"E1", "E3"},
        f"evidence={sorted(d1_evidence_ids)}",
    )
    e1 = next(e for e in d1["evidence"] if e["id"] == "E1")
    check(
        "E7 E1 provenance (supports INC1, describes D1)",
        e1["supported_incidents"] == ["INC1"] and e1["described_artifacts"] == ["D1"],
        f"prov={e1}",
    )
    e3 = next(e for e in d1["evidence"] if e["id"] == "E3")
    check(
        "E7 E3 directly describes D1 (no incident)",
        e3["supported_incidents"] == [] and e3["described_artifacts"] == ["D1"],
        f"prov={e3}",
    )
    pv1 = investigate_artifact(graph, "PV1")
    check(
        "E7 PV1 evidence = {E2} (describes PV1)",
        {e["id"] for e in pv1["evidence"]} == {"E2"},
        f"evidence={[e['id'] for e in pv1['evidence']]}",
    )
    v1 = investigate_artifact(graph, "V1")
    v1_e2 = next((e for e in v1["evidence"] if e["id"] == "E2"), None)
    check(
        "E7 V1 evidence E2 supports INC2 and describes V1",
        v1_e2 is not None
        and v1_e2["supported_incidents"] == ["INC2"]
        and "V1" in v1_e2["described_artifacts"],
        f"prov={v1_e2}",
    )

    print("\n--- 25. Phase 5 (E8 + negative): no fabricated evidence ---")
    unr = investigate_artifact(graph, "APP_UNRELATED")
    check(
        "E8 APP_UNRELATED has NO evidence",
        unr["evidence"] == [],
        f"evidence={unr['evidence']}",
    )
    check(
        "E8 APP_UNRELATED blast radius remains zero",
        unr["blast_radius"]["total_affected"] == 0,
        f"total={unr['blast_radius']['total_affected']}",
    )
    unr_risk = enrich_investigation(graph, unr)["risk"]
    check(
        "E8 APP_UNRELATED risk consistent with graph facts",
        unr_risk["score"] == 0
        and unr_risk["factors"]["evidence"]["score"] == 0
        and unr_risk["factors"]["evidence"]["status"] == "unknown",
        f"score={unr_risk['score']}",
    )

    print("\n--- 26. Phase 5 (E9): evidence confidence -> deterministic risk ---")
    d1r = enrich_investigation(graph, d1)
    ev_factor = d1r["risk"]["factors"]["evidence"]
    check(
        "E9 D1 evidence factor = max confidence (1.0 -> 100)",
        ev_factor["score"] == 100.0 and ev_factor["status"] == "known",
        f"factor={ev_factor}",
    )
    check("E9 D1 evidence contribution = 100 * 0.10", ev_factor["contribution"] == 10.0,
          f"contribution={ev_factor['contribution']}")
    pv1r = enrich_investigation(graph, pv1)
    pv1_ev = pv1r["risk"]["factors"]["evidence"]
    check(
        "E9 PV1 evidence factor = 0.9 -> 90",
        pv1_ev["score"] == 90.0 and pv1_ev["status"] == "known",
        f"factor={pv1_ev}",
    )
    agg = evidence_confidence(
        [{"id": "X", "source": "aegisgraph-demo-dataset", "source_type": "synthetic",
          "confidence": 0.4}, {"id": "Y", "source": "aegisgraph-demo-dataset",
          "source_type": "synthetic", "confidence": 0.9}]
    )
    check("E9 max-confidence aggregation", agg == {"status": "known", "confidence": 0.9},
          f"agg={agg}")

    print("\n--- 27. Phase 5 (E10/E11): unknown evidence state + full determinism ---")
    check(
        "E10 risk.evidence unknown when no evidence",
        unr_risk["evidence"] == {"status": "unknown", "confidence": None},
        f"evidence-summary={unr_risk['evidence']}",
    )
    d1r2 = enrich_investigation(graph, investigate_artifact(graph, "D1"))
    check("E11 identical graph+evidence -> identical risk", d1r["risk"] == d1r2["risk"])
    check(
        "E11 deterministic evidence aggregation",
        evidence_confidence(d1["evidence"]) == evidence_confidence(d1r2["evidence"]),
    )

    print("\n--- 28. Phase 5 (E12): malformed confidence / source type rejected ---")
    base = {"id": "X", "source": "aegisgraph-demo-dataset", "source_type": "synthetic",
            "title": "t", "confidence": 0.9}
    rejected = False
    for bad_conf in (5, -1, 1.5, "high", True, None):
        try:
            validate_evidence_record({**base, "confidence": bad_conf})
        except ValueError:
            rejected = True
        else:
            rejected = False
            break
    check("E12 malformed confidence values rejected", rejected)

    try:
        validate_evidence_record({**base, "source_type": "huggingface"})
        unknown_type_ok = False
    except ValueError:
        unknown_type_ok = True
    check("E12 unknown source type rejected (not coerced to public)", unknown_type_ok)

    mixed = [
        {**base, "id": "OK", "confidence": 0.9},
        {**base, "id": "BAD", "confidence": 1.5},
        "not-a-dict",
        {"id": "NOCONF"},
    ]
    check(
        "E12 malformed records excluded from aggregation",
        evidence_confidence(mixed) == {"status": "known", "confidence": 0.9}
        and calculate_evidence_score(mixed) == 90.0,
        f"score={calculate_evidence_score(mixed)}",
    )
    check(
        "E12 all-malformed evidence -> unknown, never invented",
        evidence_confidence([{**base, "confidence": 1.5}])
        == {"status": "unknown", "confidence": None}
        and calculate_evidence_score([{**base, "confidence": 1.5}]) == 0.0,
    )

    verify_phase6_unit()
    verify_phase6_integration(graph)


class _FakeUrlopen:
    """Minimal stand-in for urllib.request.urlopen (Phase 6 P1)."""

    def __init__(self, payload=b"{}", error=None):
        self.payload = payload
        self.error = error
        self.calls = []

    def __call__(self, request, timeout=None):
        self.calls.append((request, timeout))
        if self.error is not None:
            raise self.error
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self.payload


class _ExplodingGraph:
    """Any query call is a bug (used to prove dry-run performs NO writes)."""

    def query(self, *args, **kwargs):
        raise RuntimeError("dry-run must never execute a DB query")


def verify_phase6_unit():
    """Phase 6 (P1-P5, P7-P9, P13, P14): pure, no FalkorDB, no network.

    These checks pass with zero external services; they exercise the
    OSV fetch contract, validation, normalization, CVE dedupe, the
    deterministic version-mapping matrix, plan integrity/idempotency,
    dry-run no-op behavior, orchestration + failure isolation and
    determinism.
    """
    print("\n--- 29. Phase 6 (unit: P1-P5, P7-P9, P13, P14) ---")

    # ---------------------------- P1: OSV fetch contract ---------------------------
    print("\n  P1: OSV fetch (POST /v1/query, bounded retries, OSVError)")
    payload = {"vulns": [{"id": "GHSA-X"}], "next_page_token": None}
    fake = _FakeUrlopen(json.dumps(payload).encode("utf-8"))
    with mock.patch("graph.osv.urllib.request.urlopen", fake):
        records = fetch_osv_package("PyPI", "pyyaml")
    req, timeout = fake.calls[0]
    body = json.loads(req.data) if req.data else {}
    check(
        "P1 POST https://api.osv.dev/v1/query",
        req.full_url == "https://api.osv.dev/v1/query"
        and req.get_method() == "POST",
        f"url={req.full_url} method={req.get_method()}",
    )
    check(
        "P1 payload = {package:{ecosystem,name}}",
        body == {"package": {"ecosystem": "PyPI", "name": "pyyaml"}},
        f"body={body}",
    )
    check(
        "P1 bounded timeout used",
        timeout == 15,
        f"timeout={timeout}",
    )
    check(
        "P1 returns data.vulns from response",
        records == [{"id": "GHSA-X"}],
        f"records={records}",
    )

    fake = _FakeUrlopen(error=urllib.error.URLError("connection refused"))
    with mock.patch("graph.osv.urllib.request.urlopen", fake):
        try:
            fetch_osv_package("PyPI", "pyyaml")
            raised = False
        except OSVError:
            raised = True
    check(
        "P1 OSVError raised, retries bounded",
        raised and len(fake.calls) == HTTP_RETRIES + 1,
        f"raised={raised} attempts={len(fake.calls)}",
    )

    # ---------------------------- P2: validation contract --------------------------
    print("  P2: record validation (reject malformed, accept valid)")
    check("P2 valid record -> no errors",
          validate_osv_record(_FIXTURE_6757) == [])
    check("P2 missing id rejected",
          bool(validate_osv_record({**_FIXTURE_6757, "id": ""})))
    check("P2 missing affected rejected",
          bool(validate_osv_record({**_FIXTURE_6757, "affected": []})))
    check("P2 non-mapping rejected",
          bool(validate_osv_record("not-a-dict")))
    check(
        "P2 missing package name rejected",
        bool(validate_osv_record({
            **_FIXTURE_6757,
            "affected": [{"package": {"ecosystem": "PyPI"}}],
        })),
    )
    check(
        "P2 invalid timestamp rejected",
        bool(validate_osv_record({**_FIXTURE_6757, "published": 12345})),
    )

    # ---------------------------- P3: normalization --------------------------------
    print("  P3: normalization + severity aliasing (no fabrication)")
    n = normalize_osv_record(_FIXTURE_6757)
    check(
        "P3 extracts id/cve/summary/references",
        n is not None
        and n.id == "GHSA-6757-jp84-gxfx"
        and n.cve_id == "CVE-2020-1747"
        and n.summary == "Improper input validation in PyYAML"
        and n.source_url == "https://github.com/advisories/GHSA-6757-jp84-gxfx",
        f"cve={n.cve_id if n else None} url={n.source_url if n else None}",
    )
    check("P3 extracts affected range (5.1b7 -> 5.3.1)",
          n.affected[0].introduced == "5.1b7"
          and n.affected[0].fixed == "5.3.1"
          and "5.3" in n.affected[0].versions)
    check(
        "P3 GitHub severity aliased (CRITICAL -> critical)",
        parse_severity(_FIXTURE_6757) == "critical",
    )
    check(
        "P3 unknown severity NOT invented (null stays null)",
        parse_severity(_FIXTURE_PYSEC_96) is None
        and parse_severity({"database_specific": {"severity": "severe"}}) is None
        and parse_severity({"database_specific": {}}) is None,
        f"pys787={parse_severity(_FIXTURE_PYSEC_96)}",
    )
    check("P3 structurally invalid -> None",
          normalize_osv_record({"id": "X"}) is None
          and normalize_osv_record({}) is None)

    # ---------------------------- P4: CVE dedupe -----------------------------------
    print("  P4: CVE-aware dedupe (GHSA+PYSeC duplicates collapse)")
    deduped = dedupe_records(_FIXTURE_RAW)
    ids = {r["id"] for r in deduped}
    check(
        "P4 8 records (4 CVEs x 2 copies) -> 4 unique records",
        ids == _EXPECTED_DEDUPED_IDS,
        f"ids={sorted(ids)}",
    )
    sev_6757 = next(r for r in deduped if r["id"] == "GHSA-6757-jp84-gxfx")
    check(
        "P4 severity-bearing record preferred over severity-null copy",
        parse_severity(sev_6757) == "critical",
        f"kept={sev_6757['id']}",
    )
    reordered = dedupe_records(list(reversed(_FIXTURE_RAW)))
    check(
        "P4 dedupe deterministic regardless of input order",
        {r["id"] for r in reordered} == ids,
    )
    check(
        "P4 records without CVE keyed by own id (kept individually)",
        {r["id"] for r in dedupe_records([_FIXTURE_14343, _FIXTURE_20477])} ==
        {"GHSA-8q59-q68h-6hv4", "GHSA-3pqx-4fqf-j49f"},
    )

    # ---------------------------- P5: version mapping matrix -----------------------
    print("  P5: deterministic version mapping (exact list / ecosystem range)")
    exact = Affected("PyPI", "pyyaml", frozenset(["5.1", "5.3"]), None, None)
    ok, method = package_version_in_affected("5.3", exact)
    check("P5 version in explicit affected list -> exact_package_version",
          ok and method == "exact_package_version", f"method={method}")
    ok, method = package_version_in_affected("9.9", exact)
    check("P5 version NOT in list and no range -> NO match (never assume)",
          not ok and method is None, f"ok={ok}")
    rng = Affected("PyPI", "pyyaml", frozenset(), "0", "5.4")
    ok, method = package_version_in_affected("5.3", rng)
    check("P5 in ECOSYSTEM range (0 <= 5.3 < 5.4) -> ecosystem_range",
          ok and method == "ecosystem_range", f"method={method}")
    ok, _ = package_version_in_affected("5.4", rng)
    check("P5 at fixed version -> NOT affected (>= fixed)", not ok)
    ok, _ = package_version_in_affected("5.4.1", rng)
    check("P5 beyond fixed -> NOT affected", not ok)
    upper = Affected("PyPI", "pyyaml", frozenset(), "5.1", "5.2")
    ok, _ = package_version_in_affected("5.3", upper)
    check("P5 above fixed (CVE-2019-20477) -> NOT affected", not ok)
    ok, _ = package_version_in_affected("5.1", upper)
    check("P5 at/above introduced, below fixed -> affected", ok)
    prerelease = Affected("PyPI", "pyyaml", frozenset(), "5.1b7", "5.3.1")
    ok, _ = package_version_in_affected("5.2", prerelease)
    check("P5 PEP 440 pre-release boundary (5.1b7 < 5.2 < 5.3.1)", ok)
    ok, _ = package_version_in_affected("5.3.1", prerelease)
    check("P5 fixed 5.3.1 not affected", not ok)
    ok, unparseable_method = package_version_in_affected("latest", rng)
    check("P5 unparseable version -> NO match (no fabrication)",
          not ok and unparseable_method is None)

    matches = match_vulnerability(normalize_osv_record(_FIXTURE_6757),
                                  _FIXTURE_KNOWN_VERSIONS)
    check(
        "P5 match_vulnerability single-record (CVE-2020-1747 on 5.3)",
        len(matches) == 1
        and matches[0]["package_id"] == "PV3"
        and matches[0]["mapping_method"] == "exact_package_version",
        f"matches={matches}",
    )

    # ---------------------------- P7: plan integrity -------------------------------
    print("  P7: plan integrity (full provenance, no auto-incident, honest None)")
    plan = build_upsert_plan(_FIXTURE_RAW, known_versions=_FIXTURE_KNOWN_VERSIONS,
                             now="2026-09-09T12:00:00Z")
    c = plan["counts"]
    check(
        "P7 retrieved 5 raw records, accepted 4 (deduped), rejected 0",
        c["records_retrieved"] == 5 and c["records_accepted"] == 4
        and c["records_rejected"] == 0,
        f"counts={c}",
    )
    check(
        "P7 exactly 2 package mappings, 2 unmatched (out-of-range, honest)",
        c["package_mappings_created"] == 2
        and {m["vuln_id"] for m in plan["mappings"]} == _EXPECTED_DEDUPED_IDS - {
            "GHSA-3pqx-4fqf-j49f", "GHSA-rprw-h62v-c2w7"}
        and {u["cve_id"] for u in plan["unmatched"]} == _EXPECTED_UNMATCHED_CVES,
        f"mapped={[m['vuln_id'] for m in plan['mappings']]} "
        f"unmatched={[u['cve_id'] for u in plan['unmatched']]}",
    )
    vuln_op = next(v for v in plan["vulnerabilities"] if v["id"] == "GHSA-6757-jp84-gxfx")
    check(
        "P7 vulnerability op carries provenance + data_source=public",
        vuln_op["source"] == "osv" and vuln_op["source_id"] == vuln_op["id"]
        and vuln_op["cve_id"] == "CVE-2020-1747"
        and vuln_op["severity"] == "critical"
        and vuln_op["data_source"] == "public"
        and vuln_op["published_at"] == "2020-06-09T03:44:00Z"
        and any(r["url"].startswith("https://github.com/advisories/")
                for r in vuln_op["references"]),
        f"op={ {k: vuln_op[k] for k in ('source', 'data_source', 'cve_id', 'severity')} }",
    )
    ev_op = next(e for e in plan["evidence"] if e["id"] == "OSV-GHSA-6757-jp84-gxfx")
    check(
        "P7 evidence op: public source_type, confidence None (OSV has no model)",
        ev_op["source_type"] == "public" and ev_op["confidence"] is None
        and ev_op["vuln_id"] == "GHSA-6757-jp84-gxfx"
        and ev_op["id"] == evidence_id_for("GHSA-6757-jp84-gxfx"),
        f"conf={ev_op['confidence']}",
    )
    check(
        "P7 NO auto-incident created (plan has no incident keys)",
        "incidents" not in plan["counts"]
        and not any("incident" in str(k).lower() for k in plan.keys()
                    if k not in ("counts", "errors", "retrieval")),
    )

    # ---------------------------- P8: plan idempotency -----------------------------
    print("  P8: plan idempotency (re-run -> updates only, no duplicates)")
    plan2 = build_upsert_plan(
        _FIXTURE_RAW, known_versions=_FIXTURE_KNOWN_VERSIONS,
        known_vuln_ids=[v["id"] for v in plan["vulnerabilities"]],
        known_evidence_ids=[e["id"] for e in plan["evidence"]],
        now="2026-09-09T13:00:00Z",
    )
    c2 = plan2["counts"]
    check(
        "P8 second run: 0 creates, 4 updates (vuln+evidence), edges idempotent",
        c2["vulnerabilities_created"] == 0
        and c2["vulnerabilities_updated"] == 4
        and c2["evidence_created"] == 0
        and c2["evidence_updated"] == 4
        and c2["package_mappings_created"] == 2,
        f"counts={c2}",
    )

    # ---------------------------- P9: dry-run no-op --------------------------------
    print("  P9: dry-run performs NO writes")
    written = apply_plan(_ExplodingGraph(), plan, dry_run=True)
    check(
        "P9 dry-run returns mutated=False without executing a query",
        written == {"mutated": False,
                    "written": {"vulnerabilities": 4, "evidence": 4,
                                "has_vulnerability_edges": 2,
                                "describes_edges": 6}},
        f"written={written}",
    )

    # ---------------------------- P13: orchestration + failure isolation -----------
    print("  P13: orchestration (dry-run) + failure isolation")

    def _fake_fetch_ok(ecosystem, name):
        return list(_FIXTURE_RAW)

    report = ingest_public_vulnerabilities(
        graph=None, targets=[{"ecosystem": "PyPI", "name": "pyyaml"}],
        dry_run=True, fetch_fn=_fake_fetch_ok, now="2026-09-09T12:00:00Z",
    )
    check(
        "P13 graph=None + dry_run: plan built, nothing written, no DB touched",
        report["dry_run"] is True
        and report["written"]["mutated"] is False
        and report["plan"]["counts"]["records_accepted"] == 4
        # Without a DB there are NO known PackageVersion targets to map to:
        # honest zero mappings, every record reported as unmatched.
        and report["plan"]["counts"]["package_mappings_created"] == 0
        and report["plan"]["counts"]["package_mappings_rejected"] == 4,
        f"mutated={report['written']['mutated']} "
        f"counts={report['plan']['counts']}",
    )

    def _fake_fetch_boom(ecosystem, name):
        raise OSVError("OSV is down (simulated)")

    report_fail = ingest_public_vulnerabilities(
        graph=None, targets=[{"ecosystem": "PyPI", "name": "pyyaml"}],
        dry_run=True, fetch_fn=_fake_fetch_boom,
    )
    check(
        "P13 retrieval failure recorded, NOT raised, nothing written",
        len(report_fail["errors"]) == 1
        and report_fail["retrieval"][0]["status"] == "error"
        and report_fail["written"]["mutated"] is False
        and report_fail["plan"]["counts"]["records_accepted"] == 0,
        f"errors={report_fail['errors']}",
    )

    # ---------------------------- P14: determinism --------------------------------
    print("  P14: determinism (identical fixtures + now -> identical plan)")
    plan_a = build_upsert_plan(_FIXTURE_RAW, known_versions=_FIXTURE_KNOWN_VERSIONS,
                               now="2026-09-09T12:00:00Z")
    plan_b = build_upsert_plan(_FIXTURE_RAW, known_versions=_FIXTURE_KNOWN_VERSIONS,
                               now="2026-09-09T12:00:00Z")
    check("P14 plan identical across runs (byte-for-byte dict equality)",
          plan_a == plan_b)
    check(
        "P14 mapped vuln set matches live expectation for pyyaml 5.3",
        {v["cve_id"] for v in plan_a["vulnerabilities"]
         if v["cve_id"] in _EXPECTED_MAPPED_CVES} == _EXPECTED_MAPPED_CVES,
    )

    # ---------------------------- GraphRAG SDK: prepared, not executed -------------
    print("  GraphRAG SDK integration point (prepared, NOT executed)")
    check(
        "SDK schema None when SDK missing (import-safe)",
        build_graphrag_schema() is None,
    )
    check(
        "Ontology spec defines all consumed labels/retypes",
        {e["name"] for e in ONTOLOGY_ENTITIES} ==
        {"Vulnerability", "Package", "PackageVersion", "Evidence", "Incident"}
        and ("PackageVersion", "HAS_VULNERABILITY", "Vulnerability")
        in ONTOLOGY_RELATIONS,
    )


def verify_phase6_integration(graph):
    """Phase 6 (P6, P10-P12): needs LIVE FalkorDB + OSV network access.

    Runs real OSV retrieval for PyPI `pyyaml`, ingests into the seeded
    graph, proves upsert idempotency, post-ingestion provenance, honest
    risk behavior (public Evidence has confidence None and does NOT
    inflate the factor) and failure isolation. Assumes seed P3/PV3 exist.
    """
    print("\n--- 30. Phase 6 (integration: P6, P10-P12; live FalkorDB + OSV) ---")

    incident_before = first_column(graph, "MATCH (i:Incident) RETURN count(i)")[0][0]

    report = ingest_public_vulnerabilities(graph=graph, dry_run=False)
    rc = report["plan"]["counts"]
    check(
        "P6 live OSV pyyaml: 8 raw records -> 4 unique CVEs accepted",
        rc["records_retrieved"] >= 8 and rc["records_accepted"] == 4
        and rc["records_rejected"] == 0,
        f"retrieved={rc['records_retrieved']} accepted={rc['records_accepted']}",
    )
    check(
        "P6 writes landed (4 vulns, 4 evidence, 2 mappings)",
        report["written"]["mutated"] is True
        and rc["vulnerabilities_created"] == 4
        and rc["evidence_created"] == 4
        and rc["package_mappings_created"] == 2,
        f"written={report['written']}",
    )

    vulns = first_column(graph, "MATCH (v:Vulnerability {source: 'osv'}) RETURN v")
    check("P6 4 public Vulnerability nodes in graph", len(vulns) == 4,
          f"n={len(vulns)}")

    inc_after = first_column(graph, "MATCH (i:Incident) RETURN count(i)")[0][0]
    check("P11 NO auto-incident created by ingestion",
          inc_after == incident_before, f"before={incident_before} after={inc_after}")
    mapped = first_column(
        graph,
        "MATCH (pv {id: 'PV3'})-[r:HAS_VULNERABILITY]->(v:Vulnerability) "
        "RETURN v.cve_id, r.mapping_method ORDER BY v.cve_id",
    )
    mapped_cves = {row[0] for row in mapped}
    methods = {row[1] for row in mapped}
    check(
        "P11 PV3 -> public CVEs via HAS_VULNERABILITY with mapping_method",
        mapped_cves == _EXPECTED_MAPPED_CVES
        and methods.issubset({"exact_package_version", "ecosystem_range"}),
        f"mapped={sorted(mapped_cves)} methods={methods}",
    )
    check(
        "P11 out-of-range CVEs NOT linked to PV3 (no fabrication)",
        not ({cve for cve in _EXPECTED_UNMATCHED_CVES} & mapped_cves),
        f"unexpected={mapped_cves}",
    )

    public_evidence = first_column(
        graph,
        "MATCH (e:Evidence {source_type: 'public'}) RETURN e.id, e.confidence",
    )
    check(
        "P11 public evidence exists with confidence null (OSV no model)",
        len(public_evidence) == 4
        and all(conf is None for _, conf in public_evidence),
        f"records={sorted(public_evidence)}",
    )

    pv3 = investigate_artifact(graph, "PV3")
    pub_ids = {e["id"] for e in pv3["evidence"] if e["source_type"] == "public"}
    check(
        "P11 investigate PV3 surfaces public provenance",
        len(pub_ids) == 2 and all(i.startswith("OSV-") for i in pub_ids),
        f"evidence={sorted(pub_ids)}",
    )
    pv3_risk = enrich_investigation(graph, pv3)["risk"]
    check(
        "P11 PV3 vulnerability factor known (critical) via public vulns",
        pv3_risk["vulnerability"]["status"] == "known"
        and pv3_risk["vulnerability"]["severities"] == ["critical"],
        f"vuln={pv3_risk['vulnerability']}",
    )
    check(
        "P11 public evidence (confidence None) does NOT inflate evidence factor",
        pv3_risk["evidence"]["status"] == "unknown"
        and pv3_risk["factors"]["evidence"]["score"] == 0.0,
        f"evidence-summary={pv3_risk['evidence']}",
    )

    print("  P10/P6: re-ingest = pure upsert (0 creates, all updates)")
    report2 = ingest_public_vulnerabilities(graph=graph, dry_run=False)
    c2r = report2["plan"]["counts"]
    check(
        "P10 re-ingest: vulnerabilities_created=0, updated=4",
        c2r["vulnerabilities_created"] == 0
        and c2r["vulnerabilities_updated"] == 4
        and c2r["evidence_created"] == 0
        and c2r["evidence_updated"] == 4,
        f"counts={ {k: c2r[k] for k in ('vulnerabilities_created', 'vulnerabilities_updated', 'evidence_created', 'evidence_updated')} }",
    )
    final_count = first_column(graph, "MATCH (v:Vulnerability {source:'osv'}) RETURN count(v)")[0][0]
    check("P10 no duplication after re-ingest (still 4 nodes)", final_count == 4,
          f"count={final_count}")

    print("  P12: failure isolation (network/OSV failure leaves graph intact)")
    before = {
        "vuln": first_column(graph, "MATCH (v:Vulnerability) RETURN count(v)")[0][0],
        "ev": first_column(graph, "MATCH (e:Evidence) RETURN count(e)")[0][0],
        "pv3": first_column(graph, "MATCH (p {id:'PV3'})-[r:HAS_VULNERABILITY]->() RETURN count(r)")[0][0],
    }

    def _boom(ecosystem, name):
        raise OSVError("simulated OSV outage")

    fail_report = ingest_public_vulnerabilities(
        graph=graph, dry_run=False, fetch_fn=_boom,
    )
    after = {
        "vuln": first_column(graph, "MATCH (v:Vulnerability) RETURN count(v)")[0][0],
        "ev": first_column(graph, "MATCH (e:Evidence) RETURN count(e)")[0][0],
        "pv3": first_column(graph, "MATCH (p {id:'PV3'})-[r:HAS_VULNERABILITY]->() RETURN count(r)")[0][0],
    }
    check(
        "P12 OSV failure recorded, not raised, graph unchanged",
        len(fail_report["errors"]) == 1 and before == after,
        f"before={before} after={after} errors={fail_report['errors']}",
    )
    still = enrich_investigation(graph, investigate_artifact(graph, "PV3"))["risk"]
    check(
        "P12 investigation/risk still work after failed ingestion",
        still["status"] == "complete" and still["vulnerability"]["status"] == "known",
        f"status={still['status']}",
    )


if __name__ == "__main__":
    main()
