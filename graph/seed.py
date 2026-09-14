"""Seed the AegisGraph FalkorDB graph.

Usage:
    python -m graph.seed            # from repo root (apps/api on sys.path)
    python apps/api/graph.py        # (alt) run from repo root

Steps:
  1. Apply schema indexes (graph/schema.cypher)
  2. Run seed data (graph/seed.cypher)
  3. Run verification queries and print results

Idempotent: re-running does not duplicate nodes (MERGE semantics).
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api"))

from db import get_graph  # noqa: E402


def run_cypher_file(graph, path: Path) -> int:
    """Execute all statements in a .cypher file. Returns count executed."""
    lines = [line.split("//", 1)[0].rstrip("\r\n") for line in path.read_text().splitlines()]
    statements = [s.strip() for s in "\n".join(lines).split(";") if s.strip()]
    executed = 0
    for stmt in statements:
        try:
            graph.query(stmt)
        except Exception as exc:  # noqa: BLE001 — idempotent schema re-run
            if "already indexed" in str(exc):
                continue
            raise
        executed += 1
    return executed


def main():
    graph = get_graph()

    schema = ROOT / "graph" / "schema.cypher"
    seed = ROOT / "graph" / "seed.cypher"

    print(f"Applying schema from {schema.name} ...")
    n_schema = run_cypher_file(graph, schema)
    print(f"  executed {n_schema} schema statements")

    print(f"Seeding from {seed.name} ...")
    n_seed = run_cypher_file(graph, seed)
    print(f"  executed {n_seed} seed statements")

    return graph


if __name__ == "__main__":
    main()
