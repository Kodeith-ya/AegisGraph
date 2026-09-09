"""Verify the AegisGraph seed graph + Phase 3, 4 & 5 queries.

Usage:
    python -m graph.verify      # from repo root

Executes real Cypher queries and prints PASS/FAIL for:
  1. Required nodes exist (D1, MV1, A1, APP1, DEP1, PV1, V1, INC1, INC2)
  2. Full traversal D1 -> MV1 -> A1 -> APP1 -> DEP1
  3. Multi-path: D1 -> MV1 -> MV2 -> APP2
  4. Negative test: D1 must NOT reach APP_UNRELATED
  5. Incident AFFECTS relationships exist
  6. Counts
  7. Phase 3: D1 blast radius (distinct set, negative control, max depth,
     affected + production applications)
  8. Phase 3: exact path D1 -> APP1
  9. Phase 3: vulnerability V1 -> PV1 -> downstream, incident surfaced
  10. Phase 3: negative control (no downstream) returns zero affected
  11. Phase 3: unknown artifact resolves to None (404 case)
  12. Phase 4 R1/R2: risk report exists, score bounded 0..100
  13. Phase 4 R3: risk weights sum to 1.0, invalid weights rejected
  14. Phase 4 R4: production = DEPLOYS edge only (APP5 not production)
  15. Phase 4 R5/R6: deterministic ranking; production outranks non-prod
  16. Phase 4 R7: zero blast radius -> zero risk, still complete
  17. Phase 4 R9: depth sensitivity (cap respected, superset, risk from
     actual returned investigation)
  18. Phase 4 R10: incident factor reflects real incident exposure
  19. Phase 4 R11: vulnerability unknown is neutral, not fabricated;
     known severity used from graph data
  20. Phase 4 R12: DB failure raises instead of fabricating a low score
  21. Phase 5 E1/E2/E3/E5: Evidence nodes, SUPPORTED_BY/DESCRIBES rels,
     valid source types
  22. Phase 5 E4: evidence confidence in [0.0, 1.0]
  23. Phase 5 E6: re-running seed does not duplicate evidence
  24. Phase 5 E7: investigation returns evidence (D1, V1, PV1)
  25. Phase 5 E8 + negative: APP_UNRELATED has NO evidence and stays zero
  26. Phase 5 E9: evidence confidence contributes deterministically to risk
  27. Phase 5 E10/E11: missing evidence is "unknown"; identical graph +
     evidence -> identical risk
  28. Phase 5 E12: malformed confidence / unknown source type rejected

NOTE: R8 (unknown artifact 404) and API-level behavior (503, depth 422)
are covered in apps/api/main.py — see README.
"""
import sys
from pathlib import Path

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


def first_column(graph, cypher):
    return graph.query(cypher).result_set


def check(label, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))


def main():
    graph = seed_main()

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

    print("\n--- 22. Phase 5 (E4): evidence confidence within [0.0, 1.0] ---")
    rows = first_column(graph, "MATCH (e:Evidence) RETURN e.id, e.confidence")
    all_valid = all(
        isinstance(c, (int, float)) and not isinstance(c, bool)
        and 0.0 <= c <= 1.0
        for _, c in rows
    )
    check(
        "E4 confidence in [0,1] for every evidence node",
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


if __name__ == "__main__":
    main()
