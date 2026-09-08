# AegisGraph — Graph Schema & Seed

## Purpose
Phase 2 establishes a small, deterministic, synthetic dependency/provenance graph in
FalkorDB that can answer the core investigation question:

> If artifact X becomes unsafe, which downstream systems are affected and through which paths?

## Node types (Phase 2)
| Label | Role | Example |
|-------|------|---------|
| `Dataset` | Training data | `D1` Atlas Vision Dataset |
| `Model` | Abstract model family | `M1` Atlas Base Model |
| `ModelVersion` | Version-specific deps (first-class) | `MV1` Atlas Base v1.0 |
| `Package` | Abstract package name | `P1` atlas-tokenizers |
| `PackageVersion` | Version-specific package | `PV1` 2.3.0 |
| `Agent` | AI agent | `A1` Atlas Fraud Assistant |
| `Application` | Downstream app | `APP1` |
| `Deployment` | Production deployment | `DEP1` |
| `Vulnerability` | CVE-like record | `V1` |
| `Incident` | Triggering event | `INC1` |

## Relationship types (Phase 2)
- `(:Model)-[:HAS_VERSION]->(:ModelVersion)`
- `(:ModelVersion)-[:BASED_ON]->(:ModelVersion)` — fine-tuned from
- `(:ModelVersion)-[:TRAINED_ON]->(:Dataset)`
- `(:ModelVersion)-[:DEPENDS_ON]->(:PackageVersion)`
- `(:Package)-[:HAS_VERSION]->(:PackageVersion)`
- `(:PackageVersion)-[:HAS_VULNERABILITY]->(:Vulnerability)`
- `(:Agent)-[:POWERED_BY]->(:ModelVersion)`
- `(:Agent)-[:USES_TOOL]->(:PackageVersion)`
- `(:Application)-[:USES_MODEL]->(:ModelVersion)`
- `(:Application)-[:USES_AGENT]->(:Agent)`
- `(:Deployment)-[:DEPLOYS]->(:Application)`
- `(:Incident)-[:AFFECTS]->(artifact label)`

## Why ModelVersion is first-class
Version-specific dependencies live on `ModelVersion`, not `Model`. This enables
"which applications use *this* vulnerable version?" instead of falsely assuming
every version is affected.

## Why no generic `:Artifact` node
Artifact is a conceptual abstraction. Incidents connect directly to the concrete
labels they affect (`:Dataset`, `:ModelVersion`, `:PackageVersion`, `:Vulnerability`),
which keeps investigation Cypher precise.

## Indexes
Range index on `id` for every label so `MATCH (n:Label {id: $id})` is efficient.
Created in `schema.cypher`. Unique constraints are intentionally skipped in Phase 2
to keep seeding idempotent (`MERGE` dedups) and the process simple.

## Synthetic data policy
All records are synthetic (`data_source = "synthetic"`). Names like
"Atlas Vision Dataset" do not represent real companies, systems, or incidents.
No fabricated public URLs or evidence are included (evidence arrives in a later phase).

## Files
- `schema.cypher` — indexes (model decisions/comments)
- `seed.cypher` — deterministic synthetic seed data (idempotent via `MERGE`)
- `seed.py` — applies schema + seed to FalkorDB
- `verify.py` — runs traversal / negative / incident checks + Phase 3 investigation tests
- `queries.py` — Phase 3 blast-radius investigation queries (see below)

## Phase 3 investigation engine
`queries.py` runs the graph-native blast-radius investigation:
- `investigate_artifact(graph, id, max_depth=8)` — full investigation report.
- `downstream_nodes(...)` — distinct reachable dependents + min-hop distance.
- `production_applications(...)` — downstream apps with an actual
  `(:Deployment {environment:'production'})-[:DEPLOYS]->` edge.
- `applications_paths(...)` — shortest graph path (returned by FalkorDB) to each affected
  application, `incidents_on(...)` — `(:Incident)-[:AFFECTS]->` the artifact.

The core traversal is a single bounded, variable-length pattern over the downstream edge
set — every relationship that flows *into* the investigated node:
`TRAINED_ON | BASED_ON | DEPENDS_ON | HAS_VULNERABILITY | POWERED_BY | USES_TOOL |
USES_MODEL | USES_AGENT | DEPLOYS*1..max_depth`. Relationship-type alternation (`|`) is
FalkorDB-supported. See the root `README.md` for the full Cypher and the
`GET /api/investigate/{artifact_id}` contract.

## Commands (from repo root, with FalkorDB running)
```
# start FalkorDB
docker compose up -d

# seed (idempotent)
python -m graph.seed

# verify the graph + investigation queries
python -m graph.verify
```
