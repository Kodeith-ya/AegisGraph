// ============================================================
// AEGISGRAPH — Seed Graph (Phase 2)
// ============================================================
// Deterministic synthetic demo graph.
// All records are clearly synthetic (data_source = "synthetic").
// No fabricated public URLs or real entities are implied.
//
// Idempotent: uses MERGE + ON CREATE SET so re-running does not
// duplicate nodes/relationships.
//
// Graph shape (multiple real dependency paths):
//   D1 -> MV1 -> A1 -> APP1 -> DEP1
//   D1 -> MV1 -> MV2 -> APP2 -> DEP2        (multi-hop)
//   D1 -> MV1 -> MV2 -> APP4 / APP5
//   PV2 -> MV3 -> A2 -> APP3 -> DEP3        (separate scenario)
//
// Incident subgraph:
//   INC1 -[:AFFECTS]-> D1                   (dataset compromise)
//   INC2 -[:AFFECTS]-> V1                   (vulnerability)
// ============================================================

// ---- Datasets ----
MERGE (d1:Dataset {id: 'D1'})
SET d1.name = 'Atlas Vision Dataset',
    d1.status = 'active',
    d1.data_source = 'synthetic';

// ---- Models & versions ----
MERGE (m1:Model {id: 'M1'})
SET m1.name = 'Atlas Base Model',
    m1.data_source = 'synthetic';

MERGE (m2:Model {id: 'M2'})
SET m2.name = 'Atlas Pro Model',
    m2.data_source = 'synthetic';

MERGE (mv1:ModelVersion {id: 'MV1'})
SET mv1.name = 'Atlas Base v1.0',
    mv1.version = '1.0',
    mv1.status = 'active',
    mv1.data_source = 'synthetic';

MERGE (mv2:ModelVersion {id: 'MV2'})
SET mv2.name = 'Atlas Pro v1.0',
    mv2.version = '1.0',
    mv2.status = 'active',
    mv2.data_source = 'synthetic';

MERGE (mv3:ModelVersion {id: 'MV3'})
SET mv3.name = 'Atlas Fraud v1.0',
    mv3.version = '1.0',
    mv3.status = 'active',
    mv3.data_source = 'synthetic';

// ---- Packages & versions ----
MERGE (p1:Package {id: 'P1'})
SET p1.name = 'atlas-tokenizers',
    p1.data_source = 'synthetic';

MERGE (p2:Package {id: 'P2'})
SET p2.name = 'atlas-validator',
    p2.data_source = 'synthetic';

MERGE (pv1:PackageVersion {id: 'PV1'})
SET pv1.name = 'atlas-tokenizers v2.3.0',
    pv1.version = '2.3.0',
    pv1.data_source = 'synthetic';

MERGE (pv2:PackageVersion {id: 'PV2'})
SET pv2.name = 'atlas-validator v1.1.0',
    pv2.version = '1.1.0',
    pv2.data_source = 'synthetic';

// ---- Public-intelligence fixture (Phase 6, intentionally isolated) ----
// P3/PV3 model a real public PyPI package (pyyaml 5.3) so Phase 6 OSV
// ingestion can map real public advisories onto an EXISTING
// PackageVersion node. The node stays disconnected from the rest of the
// synthetic graph: it has NO edge into or out of the D1 system, so it
// cannot change any Phase 2/3/4/5 result or test.
MERGE (p3:Package {id: 'P3'})
SET p3.name = 'pyyaml',
    p3.data_source = 'synthetic';

MERGE (pv3:PackageVersion {id: 'PV3'})
SET pv3.name = 'pyyaml 5.3',
    pv3.version = '5.3',
    pv3.ecosystem = 'PyPI',
    pv3.data_source = 'synthetic';

MERGE (p3)-[:HAS_VERSION]->(pv3);

// ---- Agents ----
MERGE (a1:Agent {id: 'A1'})
SET a1.name = 'Atlas Fraud Assistant',
    a1.data_source = 'synthetic';

MERGE (a2:Agent {id: 'A2'})
SET a2.name = 'Atlas Verification Agent',
    a2.data_source = 'synthetic';

// ---- Applications ----
MERGE (app1:Application {id: 'APP1'})
SET app1.name = 'Atlas Payments Fraud Screen',
    app1.criticality = 'high',
    app1.environment = 'production',
    app1.data_source = 'synthetic';

MERGE (app2:Application {id: 'APP2'})
SET app2.name = 'Atlas Loan Origination',
    app2.criticality = 'critical',
    app2.environment = 'production',
    app2.data_source = 'synthetic';

MERGE (app3:Application {id: 'APP3'})
SET app3.name = 'Atlas Identity Verification',
    app3.criticality = 'high',
    app3.environment = 'production',
    app3.data_source = 'synthetic';

MERGE (app4:Application {id: 'APP4'})
SET app4.name = 'Atlas Onboarding Assistant',
    app4.criticality = 'medium',
    app4.environment = 'staging',
    app4.data_source = 'synthetic';

MERGE (app5:Application {id: 'APP5'})
SET app5.name = 'Atlas Document Intake',
    app5.criticality = 'medium',
    app5.environment = 'production',
    app5.data_source = 'synthetic';

MERGE (app_unrelated:Application {id: 'APP_UNRELATED'})
SET app_unrelated.name = 'Atlas Unrelated App',
    app_unrelated.criticality = 'low',
    app_unrelated.environment = 'production',
    app_unrelated.data_source = 'synthetic';

// ---- Deployments ----
MERGE (dep1:Deployment {id: 'DEP1'})
SET dep1.environment = 'production',
    dep1.status = 'live',
    dep1.data_source = 'synthetic';

MERGE (dep2:Deployment {id: 'DEP2'})
SET dep2.environment = 'production',
    dep2.status = 'live',
    dep2.data_source = 'synthetic';

MERGE (dep3:Deployment {id: 'DEP3'})
SET dep3.environment = 'production',
    dep3.status = 'live',
    dep3.data_source = 'synthetic';

MERGE (dep_unrelated:Deployment {id: 'DEP_UNRELATED'})
SET dep_unrelated.environment = 'production',
    dep_unrelated.status = 'live',
    dep_unrelated.data_source = 'synthetic';

// ---- Vulnerabilities ----
MERGE (v1:Vulnerability {id: 'V1'})
SET v1.name = 'CVE-atlas-tokenizers-2026',
    v1.severity = 'critical',
    v1.description = 'Tokenization library allows arbitrary code execution',
    v1.data_source = 'synthetic';

// ---- Incidents ----
MERGE (inc1:Incident {id: 'INC1'})
SET inc1.type = 'dataset_compromise',
    inc1.status = 'open',
    inc1.description = 'Atlas Vision Dataset discovered to be poisoned',
    inc1.data_source = 'synthetic';

MERGE (inc2:Incident {id: 'INC2'})
SET inc2.type = 'vulnerability',
    inc2.status = 'open',
    inc2.description = 'Critical vulnerability disclosed in atlas-tokenizers',
    inc2.data_source = 'synthetic';

// ---- Relationships ----
MERGE (m1)-[:HAS_VERSION]->(mv1);
MERGE (m2)-[:HAS_VERSION]->(mv2);

MERGE (mv2)-[:BASED_ON]->(mv1);

MERGE (mv1)-[:TRAINED_ON]->(d1);
MERGE (mv2)-[:TRAINED_ON]->(d1);

MERGE (p1)-[:HAS_VERSION]->(pv1);
MERGE (p1)-[:HAS_VERSION]->(pv2);

MERGE (mv1)-[:DEPENDS_ON]->(pv1);
MERGE (mv2)-[:DEPENDS_ON]->(pv1);
MERGE (mv3)-[:DEPENDS_ON]->(pv2);

MERGE (pv1)-[:HAS_VULNERABILITY]->(v1);

MERGE (a1)-[:POWERED_BY]->(mv1);
MERGE (a1)-[:USES_TOOL]->(pv1);
MERGE (a2)-[:POWERED_BY]->(mv3);
MERGE (a2)-[:USES_TOOL]->(pv2);

MERGE (app1)-[:USES_MODEL]->(mv1);
MERGE (app1)-[:USES_AGENT]->(a1);
MERGE (app2)-[:USES_MODEL]->(mv2);
MERGE (app3)-[:USES_AGENT]->(a2);
MERGE (app4)-[:USES_MODEL]->(mv2);
MERGE (app5)-[:USES_MODEL]->(mv1);

MERGE (dep1)-[:DEPLOYS]->(app1);
MERGE (dep2)-[:DEPLOYS]->(app2);
MERGE (dep3)-[:DEPLOYS]->(app3);

// APP_UNRELATED + DEP_UNRELATED intentionally left without any
// edge to D1 so they can serve as negative-control nodes.

// ---- Incidents connect directly to concrete artifacts ----
MERGE (inc1)-[:AFFECTS]->(d1);
MERGE (inc2)-[:AFFECTS]->(v1);

// ============================================================
// Evidence & provenance (Phase 5)
// ============================================================
// Every record is clearly SYNTHETIC demo data — sources are prefixed
// "aegisgraph-demo-*". We do NOT pretend these came from NVD, OSV,
// GitHub, Hugging Face or any other public source, and we never
// fabricate CVEs or URLs. All records are deterministic so re-running
// the seed is idempotent (MERGE + ON CREATE SET).
//
// Provenance chain example:
//   (inc1:Incident)-[:SUPPORTED_BY]->(e1:Evidence)-[:DESCRIBES]->(d1:Dataset)
//
// ---- Evidence nodes ----
MERGE (e1:Evidence {id: 'E1'})
SET e1.title = 'Atlas Vision Dataset poisoning report (demo)',
    e1.source = 'aegisgraph-demo-dataset',
    e1.source_type = 'synthetic',
    e1.confidence = 1.0,
    e1.observed_at = '2026-08-01',
    e1.description = 'Synthetic incident report indicating the Atlas Vision Dataset (D1) was poisoned. Demo data, not a real public source.';

MERGE (e2:Evidence {id: 'E2'})
SET e2.title = 'Atlas Tokenizers vulnerability advisory (demo)',
    e2.source = 'aegisgraph-demo-advisory',
    e2.source_type = 'synthetic',
    e2.confidence = 0.9,
    e2.observed_at = '2026-08-15',
    e2.description = 'Synthetic advisory for the atlas-tokenizers vulnerability (V1) affecting package version PV1. Demo data, not a real public advisory.';

MERGE (e3:Evidence {id: 'E3'})
SET e3.title = 'Atlas Vision Dataset integrity scan anomalies (demo)',
    e3.source = 'aegisgraph-demo-scan',
    e3.source_type = 'synthetic',
    e3.confidence = 0.8,
    e3.observed_at = '2026-09-01',
    e3.description = 'Synthetic integrity scan flagging anomalies in the Atlas Vision Dataset (D1). Demo data, not a real public report.';

// ---- Incident -> Evidence (SUPPORTED_BY) ----
MERGE (inc1)-[:SUPPORTED_BY]->(e1);
MERGE (inc2)-[:SUPPORTED_BY]->(e2);

// ---- Evidence -> concrete artifact (DESCRIBES) ----
MERGE (e1)-[:DESCRIBES]->(d1);
MERGE (e2)-[:DESCRIBES]->(v1);
MERGE (e2)-[:DESCRIBES]->(pv1);
MERGE (e3)-[:DESCRIBES]->(d1);
