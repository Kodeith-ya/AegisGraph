"""Verify the AegisGraph seed graph and Phase 3 investigation queries.

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
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api"))

from .seed import main as seed_main  # noqa: E402

from .queries import (  # noqa: E402
    investigate_artifact,
    resolve_artifact,
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


if __name__ == "__main__":
    main()
