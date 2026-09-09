// ============================================================
// AEGISGRAPH — Graph Schema (Phase 2)
// ============================================================
//
// Model decision: ModelVersion is FIRST-CLASS.
// All dependency relationships (TRAINED_ON, DEPENDS_ON, etc.)
// connect to ModelVersion, not to the abstract Model.
// This lets us answer:
//   "Which applications depend on vulnerable ModelVersion MV1?"
// rather than falsely treating every version as affected.
//
// Artifact is a conceptual abstraction — we deliberately do NOT
// create a generic :Artifact label. Incidents connect directly to
// the concrete artifact labels (:Dataset, :ModelVersion,
// :PackageVersion, :Package) that they affect. This keeps the
// Cypher investigation semantically precise.
//
// Data policy: every seeding node/edge is synthetic and carries
//   data_source = "synthetic"
// No fabricated public URLs or real entities are implied.
//
// ============================================================
// NODE LABELS
// ------------------------------------------------------------
// :Dataset            -> D1, Atlas Vision Dataset
// :Model              -> M1, Atlas Base Model
// :ModelVersion       -> MV1, MV2, MV3  (version-specific deps)
// :Package            -> P1 (common package name)
// :PackageVersion     -> PV1, PV2       (version-specific)
// :Agent              -> A1, A2
// :Application        -> APP1..APP6, APP_UNRELATED
// :Deployment         -> DEP1..DEP3, DEP_UNRELATED
// :Vulnerability      -> V1
// :Incident           -> INC1, INC2
// :Evidence           -> E1, E2, E3  (provenance/support records)
//
// ============================================================
// RELATIONSHIP TYPES
// ------------------------------------------------------------
// (:Model)-[:HAS_VERSION]->(:ModelVersion)
// (:ModelVersion)-[:BASED_ON]->(:ModelVersion)          # fine-tuned from
// (:ModelVersion)-[:TRAINED_ON]->(:Dataset)
// (:ModelVersion)-[:DEPENDS_ON]->(:PackageVersion)
// (:Package)-[:HAS_VERSION]->(:PackageVersion)
// (:PackageVersion)-[:HAS_VULNERABILITY]->(:Vulnerability)
// (:Agent)-[:POWERED_BY]->(:ModelVersion)
// (:Agent)-[:USES_TOOL]->(:PackageVersion)
// (:Application)-[:USES_MODEL]->(:ModelVersion)
// (:Application)-[:USES_AGENT]->(:Agent)
// (:Deployment)-[:DEPLOYS]->(:Application)
// (:Incident)-[:AFFECTS]->(artifact label)
// (:Incident)-[:SUPPORTED_BY]->(:Evidence)             # incident has evidence
// (:Evidence)-[:DESCRIBES]->(:Dataset | :ModelVersion | :PackageVersion
//                              | :Vulnerability)       # evidence describes artifact
//
// Evidence is a FIRST-CLASS provenance model. It deliberately does NOT
// link through a generic `Evidence -> Artifact` abstraction: each
// evidence record references concrete artifacts only, so a query can
// always tell exactly which artifact a record describes and which
// incident it supports.
//
// Evidence node properties (Phase 5):
//   id           unique identifier (e.g. E1)
//   title        human-readable summary
//   source       source identifier (never fabricated)
//   source_type  "synthetic" | "public"  (validated upstream)
//   confidence   in [0.0, 1.0], validated before risk use
//   observed_at  ISO-8601 date the record was observed/created
//   description  free-text requirement/support note
// These records are seeded as clearly-labeled SYNTHETIC demo evidence
// (source prefixes like "aegisgraph-demo-*"); public ingestion is a
// later phase and must leave the schema compatible (source_type =
// "public") without adding external API dependencies today.
// ============================================================
// INDEXES
// ------------------------------------------------------------
// Every important node has a stable unique property `id`.
// Range indexes on (label).id make
//   MATCH (n:Label {id: $id})
// efficient and deterministic.
// Note: FalkorDB indexes via "CREATE INDEX FOR", NOT Neo4j
// constraint syntax. Unique constraints (GRAPH.CONSTRAINT CREATE)
// are intentionally skipped for Phase 2 to keep seeding
// idempotent (MERGE dedups) and the process simple.
// ============================================================

CREATE INDEX FOR (n:Dataset) ON (n.id)
CREATE INDEX FOR (n:Model) ON (n.id)
CREATE INDEX FOR (n:ModelVersion) ON (n.id)
CREATE INDEX FOR (n:Package) ON (n.id)
CREATE INDEX FOR (n:PackageVersion) ON (n.id)
CREATE INDEX FOR (n:Agent) ON (n.id)
CREATE INDEX FOR (n:Application) ON (n.id)
CREATE INDEX FOR (n:Deployment) ON (n.id)
CREATE INDEX FOR (n:Vulnerability) ON (n.id)
CREATE INDEX FOR (n:Incident) ON (n.id)
CREATE INDEX FOR (n:Evidence) ON (n.id)
