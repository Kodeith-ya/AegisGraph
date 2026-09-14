"""AegisGraph — GraphRAG SDK integration point (Phase 6: prepared, not executed).

Why this module exists
----------------------
The official FalkorDB/GraphRAG-SDK (PyPI package ``graphrag-sdk``, import
namespace ``graphrag_sdk``) builds knowledge graphs from UNSTRUCTURED text
(advisories, SBOM notes, blog posts) with schema-guided extraction on a live
FalkorDB. Verified against the current official docs (docs.falkordb.com/graphrag):

    pip install graphrag-sdk[litellm]
    from graphrag_sdk import GraphRAG, ConnectionConfig, LiteLLM, LiteLLMEmbedder
    from graphrag_sdk import GraphSchema, EntityType, RelationType

    schema = GraphSchema(
        entities=[EntityType(label="Vulnerability", description="...")],
        relations=[RelationType(label="HAS_VULNERABILITY",
                                description="...",
                                patterns=[("PackageVersion", "Vulnerability")])],
    )
    rag = GraphRAG(connection=ConnectionConfig(host=..., graph_name="..."),
                   llm=LiteLLM(model="openai/gpt-4o-mini"),
                   embedder=LiteLLMEmbedder(model="openai/text-embedding-3-small", dimensions=...),
                   schema=schema, embedding_dimension=...)
    await rag.apply_changes(batch)   # incremental, schema-guided graph writes

The LEGACY release (0.5.0 .. 0.8.2, pin ``graphrag-sdk==0.8.2``) instead
exposed ``KnowledgeGraph``/``Ontology`` with ``EntityType(name=..., properties=...)``
and ``RelationType(source, relation, target)`` — the construction surface
``build_graphrag_schema()`` below targets and gracefully falls back across.

Runtime requirements (why this stays an OPTION here):
* Live FalkorDB; an LLM and an embedder reachable through LiteLLM
  (OpenAI-compatible); external credentials; ``embedding_dimension`` must
  match the embedder. None of these are configured in this repository's
  environment, and the SDK is NOT installed.

Phase 6 decision (unchanged by Phase 8):
* STRUCTURED security intelligence (OSV JSON) is handled by the deterministic
  normalizer in ``graph/osv.py`` — the role GraphRAG would otherwise play.
  It never invents data and never auto-creates incidents.
* GraphRAG adds value only for UNSTRUCTURED advisory content (OSV
  ``summary``/``details``, incident prose). It is a build-pipeline OPTION,
  not part of the runtime risk path, not part of the Phase 8 investigator
  (which consumes deterministic graph facts only).
* The SDK is NOT installed and NOT executed here. ``build_graphrag_schema()``
  is import-safe: it returns a schema object ONLY when the SDK is present,
  otherwise ``None`` — importing this module never fails.
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

    Import-safe: the heavy ``graphrag_sdk`` import happens ONLY inside this
    call. Structured OSV ingestion (``graph/osv.py``) and the Phase 8 AI
    investigator never depend on this function. When the SDK is not installed
    (the expected state of this repository) the return value is None and no
    extraction is advertised as available.

    Handles both SDK vintages without guessing: the legacy constructor
    (``EntityType(name=..., properties=...)`` / ``RelationType(source,
    relation, target)`` from ``graphrag_sdk.model``, used by 0.5.0..0.8.2)
    and the current one (``EntityType(label=..., description=...)`` /
    ``RelationType(label=..., description=..., patterns=[...])`` from
    ``graphrag_sdk``). Construction only runs when the SDK is installed.
    """
    try:
        from graphrag_sdk import GraphSchema  # type: ignore[import-not-found]
        from graphrag_sdk.model import EntityType, RelationType  # type: ignore[import-not-found]
    except ImportError:
        return None

    def entity(entity):
        try:
            return EntityType(name=entity["name"], properties=entity["properties"])
        except TypeError:
            return EntityType(
                label=entity["name"],
                description=f"AegisGraph {entity['name']} entity "
                            "captured from unstructured advisory text",
            )

    def relation(rel):
        try:
            return RelationType(rel[0], rel[1], rel[2])
        except TypeError:
            return RelationType(
                label=rel[1],
                description=f"AegisGraph relation from {rel[0]} to {rel[2]}",
                patterns=[(rel[0], rel[2])],
            )

    return GraphSchema(
        entities=[entity(e) for e in ONTOLOGY_ENTITIES],
        relations=[relation(r) for r in ONTOLOGY_RELATIONS],
    )


def available() -> bool:
    """True only when the GraphRAG SDK is installed AND schema builds."""
    return build_graphrag_schema() is not None