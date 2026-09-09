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
- `verify.py` — runs traversal / negative / incident checks + Phase 3 & Phase 4 tests (R1–R12)
- `queries.py` — Phase 3 blast-radius investigation queries (see below)
- `risk.py` — Phase 4 deterministic risk & impact engine (see below)

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

## Phase 4 deterministic risk engine
`risk.py` consumes Phase 3 investigations (no duplicate traversal). FalkorDB performs the
only graph work (the 1-hop `HAS_VULNERABILITY` linkage lookup); Python does all scoring.

Architecture:
```
graph/risk.py
├── validate_weights()            sum(RISK_WEIGHTS) == 1.0 (raises otherwise)
├── calculate_blast_radius_score  min(total_affected / 10, 1) * 100
├── calculate_production_score    min(production_applications / 1, 1) * 100  (DEPLOYS edge only)
├── calculate_depth_score         min(max_propagation_depth / 8, 1) * 100
├── calculate_incident_score      min(len(incidents) / 2, 1) * 100
├── calculate_vulnerability_score severity map ({critical:100, high:75, medium:50, low:25})
├── calculate_risk_score          Σ factor × weight  (bounded 0..100, int(round()))
├── classify_risk_level           thresholds: 80 CRITICAL / 60 VERY_HIGH / 40 HIGH / 20 MODERATE / 0 LOW
├── build_risk_reasons            rule-based, fact-backed (no LLM/filler)
├── calculate_application_priority 0.6×production + 0.4×distance_score
├── prioritize_applications       rank: impact desc, then id asc
└── enrich_investigation          adds risk + prioritized_applications to the report
```

### Factor definitions & graph assumptions
- `blast_radius` — distinct downstream nodes from Phase 3 reachability.
- `production_impact` — count of `production_applications`; an app is production ONLY via
  `(:Deployment {environment:'production'})-[:DEPLOYS]->(:Application)`, never from
  `Application.environment`, names, or IDs. So `APP5` (property-marked production, no
  deployment edge) is NOT production.
- `propagation_depth` — Phase 3 `max_propagation_depth`; capped by the requested
  `max_depth` (never an independent traversal).
- `incidents` — real `(:Incident)-[:AFFECTS]->` facts only.
- `vulnerability` — validated `severity` from a direct `HAS_VULNERABILITY` linkage
  (or the artifact itself being a `:Vulnerability`). Absent → `status: "unknown"`,
  score `0`; never fabricated as CRITICAL.

### Test coverage (graph/verify.py)
R1 risk exists · R2 score 0..100 · R3 weights sum to 1.0 · R4 production correctness
(APP1/APP2 yes, APP5 no) · R5 ranking deterministic + production outranks non-production
· R6 repeat-determinism · R7 zero blast radius valid · R8 unknown artifact None ·
R9 depth sensitivity (cap respected, superset) · R10 incident factor ·
R11 missing vs known vulnerability severity · R12 DB failure raises (→503 at API).

## Commands (from repo root, with FalkorDB running)
```
# start FalkorDB
docker compose up -d

# seed (idempotent)
python -m graph.seed

# verify the graph + investigation + risk queries
python -m graph.verify
```
