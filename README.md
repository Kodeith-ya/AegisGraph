# AegisGraph — AI Artifact Blast-Radius Investigation

Trace the downstream impact of a compromised/unsafe AI artifact through a FalkorDB
dependency & provenance graph. All investigation reasoning (affected entities, paths,
counts, propagation depth) is computed **by the graph engine**, never fabricated by the
API.

## Phases
- **Phase 2** — schema + synthetic seed graph (below).
- **Phase 3** — graph-native blast-radius investigation engine + `GET /api/investigate/{artifact_id}`.

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
- `graph/queries.py` — Phase 3 blast-radius investigation queries
- `graph/schema.cypher` — indexes (model decisions/comments)
- `graph/seed.cypher` — deterministic synthetic seed data (idempotent via `MERGE`)
- `graph/seed.py` — applies schema + seed to FalkorDB
- `graph/verify.py` — runs traversal / negative / incident checks + Phase 3 investigation tests

## Commands (from repo root, with FalkorDB running)
```
# start FalkorDB
docker compose up -d

# seed (idempotent)
python -m graph.seed

# verify the graph + investigation queries
python -m graph.verify

# run the API (main.py adds the repo root to sys.path for graph.queries)
uvicorn main:app --reload --app-dir apps/api
```

## Investigation API (Phase 3)

### `GET /api/investigate/{artifact_id}`
Returns the blast radius computed by FalkorDB for any concrete artifact
(`Dataset`, `Model`, `ModelVersion`, `Package`, `PackageVersion`, `Agent`,
`Application`, `Deployment`, `Vulnerability`).

Query param `max_depth` bounds traversal (default `8`, max `20`).

```jsonc
{
  "artifact": { "id": "D1", "type": "Dataset", "name": "Atlas Vision Dataset" },
  "blast_radius": {
    "total_affected": 9,
    "max_propagation_depth": 4,
    "traversal_depth_cap": 8,
    "dependents_by_type": { "ModelVersion": 2, "Agent": 1, "Application": 4, "Deployment": 2 }
  },
  "affected_applications": [
    { "application": {"id":"APP1","type":"Application"}, "hops": 3,
      "path": { "nodes": [...], "edges": [...] } }
  ],
  "production_applications": [
    { "application": {"id":"APP1","type":"Application"}, "deployment": {"id":"DEP1"}, "hops": 4 }
  ],
  "incidents": [ { "id": "INC1", "type": "dataset_compromise" } ]
}
```

- **Affected applications** — every downstream `Application` + the shortest graph path
  from the investigated artifact (returned by FalkorDB, not rebuilt in Python).
- **Production applications** — downstream apps that have an actual
  `(:Deployment {environment:'production'})-[:DEPLOYS]->(:Application)` edge. An app
  merely tagged `environment='production'` without a Deployment edge is not counted.
- **Dependencies** — every distinct downstream node (with min-hop distance).

### API behavior
| Case | Result |
|------|--------|
| Unknown artifact id | `404` |
| FalkorDB down / query failure | `503` |
| Valid artifact, zero downstream | `200` with `blast_radius.total_affected = 0` |

## Investigation queries (Phase 3)
`graph/queries.py` owns the Cypher. The core traversal is a single bounded
variable-length pattern over the downstream edge set:

```cypher
MATCH (start {id: $id})
MATCH p=(start)<-[:TRAINED_ON|BASED_ON|DEPENDS_ON|HAS_VULNERABILITY|
                  POWERED_BY|USES_TOOL|USES_MODEL|USES_AGENT|DEPLOYS*1..8]-(dest)
RETURN dest, min(length(p)) AS hops
```

- **Downstream** means a node that *points into* the start node
  (`(start)<-[r]-(dependent)`), i.e. everything that consumes or depends on it.
- The relationship-type alternation (`|`) is supported by FalkorDB, so one bounded
  pattern covers the whole dependency lattice.
- `max_depth` is a validated server-side integer interpolated into the quantifier;
  the artifact `id` is always passed as a bind parameter (`$id`), never interpolated.
- `DISTINCT`/aggregation (`min(length(r))`) collapses cycles so each node appears once
  with its closest blast radius.
