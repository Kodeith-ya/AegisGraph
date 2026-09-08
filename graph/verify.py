"""Verify the AegisGraph Phase 2 seed graph against FalkorDB.

Usage:
    python -m graph.verify      # from repo root

Executes real Cypher queries and prints PASS/FAIL for:
  1. Required nodes exist (D1, MV1, A1, APP1, DEP1, PV1, V1, INC1, INC2)
  2. Full traversal D1 -> MV1 -> A1 -> APP1 -> DEP1
  3. Multi-path: D1 -> MV1 -> MV2 -> APP2
  4. Negative test: D1 must NOT reach APP_UNRELATED
  5. Incident AFFECTS relationships exist
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api"))

from .seed import main as seed_main  # noqa: E402
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


if __name__ == "__main__":
    main()
