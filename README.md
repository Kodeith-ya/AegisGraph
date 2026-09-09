# AegisGraph — AI Artifact Blast-Radius Investigation

Trace the downstream impact of a compromised/unsafe AI artifact through a FalkorDB
dependency & provenance graph. All investigation reasoning (affected entities, paths,
counts, propagation depth) is computed **by the graph engine**, never fabricated by the
API.

## Phases
- **Phase 2** — schema + synthetic seed graph (below).
- **Phase 3** — graph-native blast-radius investigation engine + `GET /api/investigate/{artifact_id}`.
- **Phase 4** — deterministic risk & impact intelligence engine (`graph/risk.py`) + `GET /api/risk/{artifact_id}`.
- **Phase 5** — evidence & provenance layer (`:Evidence`, `SUPPORTED_BY`/`DESCRIBES`, `risk.factors.evidence`) + `GET /api/evidence/{artifact_id}`.

> If artifact X becomes unsafe, which downstream systems are affected, through which paths,
> how severe is the impact, and what evidence supports the conclusions?

The Phase 5 pipeline:

```
Phase 3: graph-proven blast radius
                    ↓
Phase 5: evidence & provenance (:Evidence records, validated)
                    ↓
Phase 4: deterministic risk factors (incl. evidence confidence)
                    ↓
         weighted score (0–100)
                    ↓
         risk level
                    ↓
         prioritized applications
```

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
| `Evidence` | Support/provenance record | `E1` |

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
- `(:Incident)-[:SUPPORTED_BY]->(:Evidence)` — incident is supported by evidence *(Phase 5)*
- `(:Evidence)-[:DESCRIBES]->(:Dataset | :ModelVersion | :PackageVersion | :Vulnerability)` — evidence describes a concrete artifact *(Phase 5)*

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
Evidence records are clearly labeled demo data (`source` prefixed
`aegisgraph-demo-*`, `source_type = "synthetic"`) — no fabricated CVEs, URLs, or
public-source attributions (Phase 5).

## Files
- `graph/queries.py` — Phase 3 blast-radius investigation + Phase 5 evidence queries
- `graph/schema.cypher` — indexes (model decisions/comments)
- `graph/seed.cypher` — deterministic synthetic seed data (idempotent via `MERGE`)
- `graph/seed.py` — applies schema + seed to FalkorDB
- `graph/verify.py` — runs traversal / negative / incident checks + Phase 3/4/5 tests
- `graph/risk.py` — Phase 4 deterministic risk engine + Phase 5 evidence factor

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
  "incidents": [ { "id": "INC1", "type": "dataset_compromise" } ],
  "evidence": [
    { "id": "E1", "title": "...", "source": "aegisgraph-demo-dataset",
      "source_type": "synthetic", "confidence": 1.0, "observed_at": "2026-08-01",
      "description": "...", "supported_incidents": ["INC1"],
      "described_artifacts": ["D1"] }
  ]
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

## Deterministic Risk & Impact Intelligence (Phase 4)

`graph/risk.py` converts a Phase 3 investigation into an explainable, reproducible,
deterministic risk decision. It is a pure Python + FalkorDB layer — no LLM, no RAG, no
external threat intelligence, no fabricated facts, no hardcoded artifact results.

### Primary factors (weights validated to sum to 1.0)

| Factor | Weight | Source (Phase 3) | Normalization |
|--------|--------|------------------|---------------|
| `blast_radius`     | 0.225 | `blast_radius.total_affected` | `min(n / 10, 1) * 100` |
| `production_impact`| 0.315 | `production_applications` (DEPLOYS edge only) | `min(prod / 1, 1) * 100` |
| `propagation_depth`| 0.15 → 0.135 | `blast_radius.max_propagation_depth` | `min(depth / 8, 1) * 100` |
| `incidents`        | 0.15 → 0.135 | `incidents` (real `(:Incident)-[:AFFECTS]->` facts) | `min(inc / 2, 1) * 100` |
| `vulnerability`    | 0.10 → 0.09 | validated `severity` on linked `(:Vulnerability)` | severity map `critical 100 / high 75 / medium 50 / low 25` |
| `evidence`         | 0.10 | validated `:Evidence` confidence (Phase 5) | `max(confidence) * 100`, else `0` (unknown) |

**Phase 5 weight change:** the six factors above replace the Phase 4 five-factor set. The
original five weights were scaled uniformly by `0.9` to make room for `evidence = 0.10`,
preserving their ordering (production impact remains the largest factor). Sum still
validated to `1.0`.

Vulnerability severity is only used when it exists as validated graph data
(`HAS_VULNERABILITY` linkage, 1 hop, severity in the known set). When absent the
factor is `status: "unknown"` with score `0` — never assumed CRITICAL, never invented.

Evidence confidence is only used when validated evidence actually exists
(see [Evidence & Provenance](#evidence--provenance-phase-5) below). When absent the
factor is `status: "unknown"` with score `0` — a graph edge is never treated as evidence.

### Risk levels (0–100)
| Range | Level |
|-------|-------|
| 0–19   | `LOW` |
| 20–39  | `MODERATE` |
| 40–59  | `HIGH` |
| 60–79  | `VERY_HIGH` |
| 80–100 | `CRITICAL` |

### Composite score
```
final_score = blast_radius * 0.225 + production_impact * 0.315
            + propagation_depth * 0.135 + incidents * 0.135
            + vulnerability * 0.09 + evidence * 0.10
```
Computed from the named `RISK_WEIGHTS` dictionary (never inlined), rounded with
`int(round(x))`, always `0..100`.

### `GET /api/risk/{artifact_id}` (Phase 4)
Reuses the investigation + risk engines — no duplicated traversal. Returns only the
`risk` block.

### Added to `GET /api/investigate/{artifact_id}` (Phase 4 + 5)
- `evidence` — supporting/provenance records (see [Evidence & Provenance](#evidence--provenance-phase-5)).
- `risk` — `{ score, level, status, factors, top_factors, vulnerability, evidence }`.
  - `factors.<name>` → `{ score, weight, contribution, status }` (contribution =
    `score × weight`, rounded to 2dp).
  - `top_factors` → contributory factors sorted by contribution **desc**, ties broken
    by factor name ascending.
  - `status` → `"complete"` on success; DB/query failure never returns a normal score
    (maps to `503`).
  - `risk.evidence` → `{ status: "known"|"unknown", confidence }` — max validated
    confidence, or explicitly `unknown` when no valid evidence exists.
- `prioritized_applications` — every affected application ranked:
  - rank = impact score **desc**, then application **id asc** (deterministic).
  - `impact_priority_score` = `0.6 × production + 0.4 × distance_score` where
    `distance_score = (1 − min(distance,8)/8) × 100`. Any production app (min 60)
    always outranks any non-production app (max 40).
  - each entry: `{ id, is_production, distance, risk_score, risk_level, priority_rank,
    reasons }`.
- `reasons` are rule-based, each backed by a deterministic fact:
  `production deployment`, `close propagation path` (distance ≤ 3),
  `linked incident exposure` (incidents > 0), `vulnerability exposure` (severity known),
  `large downstream dependency surface` (total_affected ≥ 5). No LLM, no filler.

### Determinism guarantees
- Fixed FP arithmetic, fixed rounding (`round(x,2)` / `int(round(x))`).
- Ties broken by identifier ascending — repeated identical requests return byte-identical
  risk + rankings.

### Behavior preserved from Phase 3
- `GET /api/investigate/{artifact_id}` unchanged except additive `risk` +
  `prioritized_applications` fields.
- Unknown artifact → `404`; DB/query failure → `503`; zero downstream → `200` with
  `total_affected = 0` (risk score `0`, status `complete`).
- `max_depth` is bounded `1..20` and **rejected** (`422`) outside that range (ge/le in
  FastAPI `Query`). No unbounded traversal; artifact id always a bind parameter.

## Evidence & Provenance (Phase 5)

The investigation chain is now:

```
FalkorDB graph facts → Evidence / provenance → Deterministic risk
```

Evidence answers *"why do you believe this relationship/fact exists?"*. It is a
separate layer from the graph edges themselves, and risk only consumes evidence that
is stored in the graph — nothing is fabricated (no fake URLs, CVEs, or public sources).

### `:Evidence` node (schema.cypher)
| Property | Purpose | Validation |
|----------|---------|-----------|
| `id` | unique identifier | required non-empty string |
| `title` | human-readable summary | informational |
| `source` | source identifier (never fabricated) | required non-empty string |
| `source_type` | `synthetic` \| `public` | must be one of the known set |
| `confidence` | belief strength in `[0.0, 1.0]` | numeric, `0.0 <= c <= 1.0` (rejects `5`, `-1`, `1.5`) |
| `observed_at` | ISO-8601 observation date | informational |
| `description` | support note | informational |

### Provenance relationships
- `(:Incident)-[:SUPPORTED_BY]->(:Evidence)` — evidence supports an incident.
- `(:Evidence)-[:DESCRIBES]->(:Dataset | :ModelVersion | :PackageVersion | :Vulnerability)`
  — evidence describes a concrete artifact. There is **no** generic
  `Evidence -> Artifact` abstraction; concrete labels keep queries precise.

Chain example (seeded):

```
INC1 ──SUPPORTED_BY──> E1 ──DESCRIBES──> D1
```

So an investigation can explain: *Incident INC1 affects D1; evidence E1 (synthetic)
supports the incident; D1 propagates to MV1, A1, APP1, DEP1.*

### Source types
- `synthetic` — clearly-labeled demo data (`source` prefixed `aegisgraph-demo-*`).
- `public` — reserved for later-phase ingestion; no public sources are ingested now.
- Unknown types are **rejected** by validation, never silently converted to `public`.

### Synthetic evidence policy
The seeded evidence (E1/E2/E3) supports INC1/INC2 and describes D1/V1/PV1. Wording and
`source` values make it obvious this is demo data. No fabricated CVEs or external URLs
are implied.

### Evidence query (graph/queries.py — `evidence_for`)
Two bounded queries (no variable-length paths, id always a bind parameter):
1. `MATCH (a {id: $id})<-[:DESCRIBES]-(e:Evidence)` — direct descriptions.
2. `MATCH (a {id: $id})<-[:AFFECTS]-(i:Incident)-[:SUPPORTED_BY]->(e:Evidence)`
   — evidence supporting incidents that affect the artifact.

Records are merged by id and each carries `supported_incidents` / `described_artifacts`
provenance keys. No evidence graph is loaded wholesale.

### Confidence aggregation — MAXIMUM (documented)
`risk.factors.evidence` uses the **maximum confidence among valid supporting evidence**
(`max(confidence) * 100`). One strong authoritative source can establish a fact without
being diluted by weaker records — the simplest explainable rule for the MVP.

### Evidence → risk integration
- Valid evidence → factor `status: "known"`, score = `max_confidence × 100`
  (e.g. confidence `0.90` → factor `90`).
- No / all-malformed evidence → factor `status: "unknown"`, score `0` (neutral), and
  `risk.evidence = {status: "unknown", confidence: null}`.
- Malformed records (bad confidence, unknown source type, missing id/source) are
  **excluded** from aggregation; `validate_evidence_record()` hard-rejects malformed input.
- The existence of a graph edge is **never** treated as evidence confidence.

### `GET /api/evidence/{artifact_id}` (Phase 5)
Reuses `evidence_for` (no duplicated DB logic). Returns the resolved artifact + its
evidence/provenance records. Unknown artifact → `404`; DB failure → `503`.

### Limitations (Phase 5)
- Evidence is currently seeded synthetic data only; public ingestion is out of scope.
- No `inferred` source type yet (not needed by the schema).
- `risk.factors.evidence` cannot exceed 100 and is neutral (`0`) when evidence is
  missing — absence never inflates risk.
