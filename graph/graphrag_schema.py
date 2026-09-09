"""AegisGraph — GraphRAG SDK integration point (Phase 6: prepared, not executed).

Why this module exists
----------------------
The official FalkorDB/GraphRAG-SDK provides schema-guided extraction from
UNSTRUCTURED text (advisories, SBOM notes, blog posts) into a live
FalkorDB graph via ``EntityType``/``RelationType`` declarations and
incremental ``apply_changes()`` writes. It requires a running FalkorDB
AND an LLM/embedder reachable through LiteLLM — neither is available or
wired up in this repository's environment (no Docker, no LLM credentials).

The Phase 6 decision:
* STRUCTURED security intelligence (OSV JSON) is handled by the
  deterministic normalizer in ``graph/osv.py``. That is the role GraphRAG
  would otherwise play, and it never invents data or auto-creates
  incidents.
* GraphRAG adds value only for unstructured advisories. It is a
  build-pipeline OPTION, not part of the runtime risk path.
* The SDK is NOT installed and NOT executed here. ``build_graphrag_schema()``
  is import-safe: it returns the SDK schema object ONLY when the SDK is
  present, otherwise ``None`` — importing this module never fails.
"""
from __future__ import annotations

# AegisGraph ontology that the GraphRAG SDK would be configured with.
# Mirrors graph/schema.cypher so extraction output lands on the same
# labels/properties the investigation & risk engines already consume.
ONTOLOGY_ENTITIES = [
    {
        "name": "Vulnerability",
        "properties": ["id", "name", "severity", "description", "cve_id",
                       "source", "source_id", "published_at", "ingested_at"],
    },
    {
        "name": "Package",
        "properties": ["id", "name"],
    },
    {
        "name": "PackageVersion",
        "properties": ["id", "name", "version", "ecosystem"],
    },
    {
        "name": "Evidence",
        "properties": ["id", "title", "source", "source_type", "confidence",
                       "observed_at", "description"],
    },
    {
        "name": "Incident",
        "properties": ["id", "type", "status", "description"],
    },
]

# (source_label, relation_name, target_label) — the edge set the SDK may emit.
ONTOLOGY_RELATIONS = [
    ("PackageVersion", "HAS_VULNERABILITY", "Vulnerability"),
    ("Evidence", "DESCRIBES", "Vulnerability"),
    ("Evidence", "DESCRIBES", "PackageVersion"),
    ("Incident", "AFFECTS", "Vulnerability"),
    ("Incident", "SUPPORTED_BY", "Evidence"),
]


def build_graphrag_schema():
    """Return a GraphRAG-SDK ``GraphSchema``, or None if the SDK is missing.

    Import-safe: the heavy ``graphrag_sdk`` import happens ONLY inside
    this call. Structured OSV ingestion (``graph/osv.py``) never depends
    on this function. When the SDK is not installed (the expected state
    of this repository) the return value is None and no extraction is
    advertised as available.
    """
    try:
        from graphrag_sdk import GraphSchema  # type: ignore[import-not-found]
        from graphrag_sdk.model import EntityType, RelationType  # type: ignore[import-not-found]
    except ImportError:
        return None

    entities = [
        EntityType(name=entity["name"], properties=entity["properties"])
        for entity in ONTOLOGY_ENTITIES
    ]
    relations = [
        RelationType(source, relation, target)
        for source, relation, target in ONTOLOGY_RELATIONS
    ]
    return GraphSchema(entities=entities, relations=relations)


def available() -> bool:
    """True only when the GraphRAG SDK is installed AND schema builds."""
    return build_graphrag_schema() is not None