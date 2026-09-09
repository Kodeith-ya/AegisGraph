# AegisGraph — Graph Schema & Seed

## Purpose
Phase 2 establishes a small, deterministic, synthetic dependency/provenance graph in
FalkorDB that can answer the core investigation question:

> If artifact X becomes unsafe, which downstream systems are affected and through which paths?

## Node types (Phase 2 + Phase 5)
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
| `Evidence` | Support/provenance record *(Phase 5)* | `E1` |

## Relationship types (Phase 2 + Phase 5)
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
- `(:Incident)-[:SUPPORTED_BY]->(:Evidence)` — incident supported by evidence *(Phase 5)*
- `(:Evidence)-[:DESCRIBES]->(:Dataset | :ModelVersion | :PackageVersion | :Vulnerability)`
  — evidence describes a concrete artifact *(Phase 5)*

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
Evidence records (Phase 5) are clearly labeled demo data: `source_type = "synthetic"`,
`source` prefixed `aegisgraph-demo-*`. No fabricated CVEs, URLs, or public-source
attributions are implied.

## Phase 5 evidence & provenance layer
The story: *incident INC1 affects D1; evidence E1 supports the incident; D1 propagates to
MV1, A1, APP1, DEP1.* Evidence is a distinct layer from the graph dependencies themselves
— `graph/queries.py::evidence_for` retrieves evidence that either **DESCRIBES** the
artifact or **SUPPORTS an incident affecting it**, and the risk engine only consumes
validated records.

```
INC1 ──SUPPORTED_BY──> E1 ──DESCRIBES──> D1
                            E3 ──DESCRIBES──> D1   (direct scan evidence, no incident)
INC2 ──SUPPORTED_BY──> E2 ──DESCRIBES──> V1, PV1
```

Node model: `id`, `title`, `source`, `source_type` (`synthetic`/`public`),
`confidence` (`[0.0, 1.0]`, validated), `observed_at`, `description`. Unknown source
types are rejected, malformed confidence is rejected (`validate_evidence_record`),
and malformed records never influence risk.

Confidence aggregation is **MAXIMUM** among valid supporting evidence
(`max_confidence × 100` → `risk.factors.evidence`): one strong authoritative source
establishes a fact without dilution. No evidence → factor `status: "unknown"`, score `0`,
and `risk.evidence = {status: "unknown", confidence: null}` — a graph edge is never
mistaken for evidence.

## Files
- `schema.cypher` — indexes (model decisions/comments)
- `seed.cypher` — deterministic synthetic seed data (idempotent via `MERGE`); incl.
  isolated `P3/PV3` (`pyyaml 5.3`, ecosystem `PyPI`) fixture for Phase 6
- `seed.py` — applies schema + seed to FalkorDB
- `verify.py` — traversal / negative / incident checks + Phase 3, 4 (R1–R12), 5 (E1–E12)
  & 6 (P1–P14) tests; Phase 6 unit checks run with NO database (DB-degraded mode)
- `queries.py` — Phase 3 blast-radius investigation + Phase 5 evidence queries (see below)
- `risk.py` — Phase 4 deterministic risk engine (see below) + Phase 5 evidence factor
- `osv.py` — Phase 6 public security-intelligence ingestion (OSV client, normalizer,
  PEP 440 version matcher, deterministic upsert plan, CLI) — see root README
- `graphrag_schema.py` — Phase 6 GraphRAG SDK integration point (ontology spec +
  import-safe `build_graphrag_schema()`, prepared but NOT executed)

## Phase 3 investigation engine
`queries.py` runs the graph-native blast-radius investigation:
- `investigate_artifact(graph, id, max_depth=8)` — full investigation report (now
  includes `evidence` from Phase 5).
- `downstream_nodes(...)` — distinct reachable dependents + min-hop distance.
- `production_applications(...)` — downstream apps with an actual
  `(:Deployment {environment:'production'})-[:DEPLOYS]->` edge.
- `applications_paths(...)` — shortest graph path (returned by FalkorDB) to each affected
  application, `incidents_on(...)` — `(:Incident)-[:AFFECTS]->` the artifact.
- `evidence_for(...)` — (Phase 5) evidence that DESCRIBES the artifact or SUPPORTS an
  incident affecting it (two bounded queries, id always a bind parameter).

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
├── evidence_confidence           (Phase 5) max valid confidence or {status: unknown}
├── calculate_evidence_score      (Phase 5) max_confidence × 100, else 0 (unknown)
├── _normalized_confidence        rejects bools, non-numeric, out-of-[0,1] values
├── validate_evidence_record      raises ValueError on malformed evidence
├── calculate_risk_score          Σ factor × weight  (bounded 0..100, int(round()))
├── classify_risk_level           thresholds: 80 CRITICAL / 60 VERY_HIGH / 40 HIGH / 20 MODERATE / 0 LOW
├── build_risk_reasons            rule-based, fact-backed (no LLM/filler)
├── calculate_application_priority 0.6×production + 0.4×distance_score
├── prioritize_applications       rank: impact desc, then id asc
└── enrich_investigation          adds risk + prioritized_applications to the report
```

Risk weights (validated to sum 1.0): `blast_radius 0.225`, `production_impact 0.315`,
`propagation_depth 0.135`, `incidents 0.135`, `vulnerability 0.09`, `evidence 0.10` —
the Phase 4 five-factor set scaled ×0.9 to make room for the Phase 5 `evidence` factor.

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
- `evidence` (Phase 5) — max validated `:Evidence` confidence. Present →
  `status: "known"`; absent/malformed → `status: "unknown"`, score `0`. The graph edge
  is never treated as evidence.

### Test coverage (graph/verify.py)
R1 risk exists · R2 score 0..100 · R3 weights sum to 1.0 · R4 production correctness
(APP1/APP2 yes, APP5 no) · R5 ranking deterministic + production outranks non-production
· R6 repeat-determinism · R7 zero blast radius valid · R8 unknown artifact None ·
R9 depth sensitivity (cap respected, superset) · R10 incident factor ·
R11 missing vs known vulnerability severity · R12 DB failure raises (→503 at API).

Phase 5 (E1–E12): E1 evidence nodes exist · E2 SUPPORTED_BY rels · E3 DESCRIBES rels ·
E4 confidence null (explicit unknown) or in [0,1] · E5 valid source types ·
E6 reseed idempotency · E7 investigation returns evidence (D1/V1/PV1) ·
E8 no fabricated evidence (APP_UNRELATED) · E9 evidence confidence → deterministic risk
factor · E10 missing evidence = unknown · E11 repeat determinism incl. evidence ·
E12 malformed confidence / unknown source type rejected and excluded from aggregation.

## Phase 6 public security intelligence ingestion
`osv.py` retrieves a small deterministic public subset (PyPI `pyyaml`) from the real
OSV API, validates + normalizes the records, collapses GHSA/PYSEC CVE duplicates
(preferring the severity-bearing record), maps `PackageVersion` nodes ONLY via exact
OSV affected-version lists or PEP 440 ECOSYSTEM ranges (never fuzzy, never fabricated),
and MERGE-upserts public `:Vulnerability` + `:Evidence` nodes (id `OSV-<id>`,
`source_type: "public"`, `confidence: None` — OSV has no per-record confidence model)
plus `DESCRIBES`/`HAS_VULNERABILITY` edges. No incidents are ever auto-created, and an
OSV failure is recorded without touching the graph. See the root README for the full
Phase 6 trust model, live `pyyaml 5.3` expectations, and the GraphRAG SDK note.

Phase 6 coverage (P1–P14): P1 OSV fetch contract · P2 record validation · P3 normalization
+ severity aliasing · P4 CVE dedupe · P5 version-mapping matrix (exact/range/PEP 440) ·
P6 live OSV ingestion · P7 plan integrity (provenance, no auto-incident, honest None) ·
P8 plan idempotency (0 creates on re-run) · P9 dry-run no-op · P10 upsert detection ·
P11 post-ingestion provenance + honest risk · P12 failure isolation · P13 orchestration +
failure reporting · P14 determinism. P1–P5/P7–P9/P13/P14 run with **no database**;
P6/P10–P12 need live FalkorDB + OSV network.

## Commands (from repo root, with FalkorDB running)
```
# start FalkorDB
docker compose up -d

# seed (idempotent; includes isolated P3/PV3 pyyaml fixture)
python -m graph.seed

# verify the graph + investigation + risk queries
python -m graph.verify

# Phase 6: plan public OSV ingestion WITHOUT touching the database
python -m graph.osv --dry-run

# Phase 6: full public ingestion (needs live FalkorDB)
python -m graph.osv
```
