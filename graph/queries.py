"""AegisGraph — graph-native blast-radius investigation queries (Phase 3).

All reasoning is performed by FalkorDB via Cypher. This module only
orchestrates queries and structures results; it never fabricates
affected entities, paths, or counts.

Evidence & provenance (Phase 5)
-------------------------------
`evidence_for` retrieves evidence that either:

* DESCRIBES the investigated artifact directly
  ``(a)<-[:DESCRIBES]-(e:Evidence)``
* SUPPORTS an incident that AFFECTS the artifact
  ``(a)<-[:AFFECTS]-(i:Incident)-[:SUPPORTED_BY]->(e:Evidence)``

Both patterns are bounded (no variable-length paths) and use the
artifact id strictly as a bind parameter. Evidence records are returned
exactly as stored in the graph — the endpoint never invents support.

Downstream semantics
--------------------
A *downstream dependent* is reached with:

    (start)<-[r:REL ...]-(dependent)

i.e. a node that points toward `start`. The relationship set below
covers every dependency edge in the Phase 2 schema, so traversing them
inbound from the investigated artifact yields its blast radius.

Counterfactual exclusions (Phase 7)
-----------------------------------
Traversal functions accept an optional `blocked` iterable of artifact
ids. When non-empty, the query appends a path filter:

    WHERE all(n IN nodes(p) WHERE NOT n.id IN $blocked)

so paths passing through a blocked node disappear. This is PURELY a
query-time exclusion — the graph is never mutated (no DELETE / DETACH /
temporary properties). It is how Phase 7 simulates REMOVE/ISOLATE
remediations while FalkorDB still performs all reachability reasoning.

Traversal safety
----------------
Downstream traversals are bounded by max_depth (default DEFAULT_MAX_DEPTH).
max_depth is a server-controlled positive integer that is interpolated
directly into the relationship quantifier (validated by _clamp_depth);
the artifact `id` is ALWAYS passed as a bind parameter ($id).
"""

# Optional WHERE predicate used by Phase 7 to exclude nodes (by id) from
# a matched path without mutating the graph. Empty by default so every
# existing Phase 1-6 caller is byte-for-byte unaffected.
def _blocked_clause(blocked) -> str:
    if not blocked:
        return ""
    return "WHERE all(n IN nodes(p) WHERE NOT n.id IN $blocked)\n"

def _blocked_params(blocked) -> dict:
    """Bind-parameter dict for the blocked clause (list of ids)."""
    return {"blocked": list(blocked)} if blocked else {}
DEFAULT_MAX_DEPTH = 8
MAX_DEPTH_LIMIT = 20
PRODUCTION_ENVIRONMENT = "production"

# Dependency edges that flow INTO the artifact node. A downstream
# dependent is any node pointing toward `start` over these relations.
DOWNSTREAM_RELS = (
    "TRAINED_ON",
    "BASED_ON",
    "DEPENDS_ON",
    "HAS_VULNERABILITY",
    "POWERED_BY",
    "USES_TOOL",
    "USES_MODEL",
    "USES_AGENT",
    "DEPLOYS",
)

# Concrete labels a user may start an investigation from (indexed by id).
ARTIFACT_LABELS = (
    "Dataset",
    "Model",
    "ModelVersion",
    "Package",
    "PackageVersion",
    "Agent",
    "Application",
    "Deployment",
    "Vulnerability",
)

# Evidence node fields surfaced by the API (all stored on :Evidence).
EVIDENCE_FIELDS = (
    "id",
    "title",
    "source",
    "source_type",
    "confidence",
    "observed_at",
    "description",
)


def _rel_pattern(max_depth: int) -> str:
    """Return the inbound variable-length relationship pattern.

    `max_depth` is a validated integer (see _clamp_depth), so string
    interpolation here is safe. Uses FalkorDB's relationship-type
    alternation (pipe) over the downstream relation set.
    """
    rels = "|".join(DOWNSTREAM_RELS)
    return f"<-[:{rels}*1..{max_depth}]-"


def _clamp_depth(depth) -> int:
    if depth is None:
        return DEFAULT_MAX_DEPTH
    try:
        depth = int(depth)
    except (TypeError, ValueError):
        return DEFAULT_MAX_DEPTH
    if depth < 1:
        return DEFAULT_MAX_DEPTH
    if depth > MAX_DEPTH_LIMIT:
        return MAX_DEPTH_LIMIT
    return depth


def _node_dict(node) -> dict:
    """Flatten a FalkorDB Node into a JSON-safe dict."""
    if node is None:
        return {}
    props = dict(node.properties or {})
    label = node.labels[0] if node.labels else None
    out = {"id": props.get("id"), "type": label}
    for key in ("name", "version", "severity", "status",
                "environment", "criticality", "description"):
        if key in props:
            out[key] = props[key]
    return out


def _edge_dict(edge) -> dict:
    """Flatten a FalkorDB Edge into a JSON-safe dict."""
    return {
        "type": getattr(edge, "relation", None),
        "src": _node_dict(edge.src_node).get("id"),
        "dest": _node_dict(edge.dest_node).get("id"),
        "properties": dict(getattr(edge, "properties", None) or {}),
    }


def _path_dict(path) -> dict:
    """Flatten a FalkorDB Path into {nodes: [...], edges: [...]}.

    FalkorDB Path edges reference their endpoints by internal node id
    (int), not by Node objects. A path is always a chain
    n0 -e0- n1 -e1- n2 ... so we pair each edge's endpoints with the
    path's node list positionally instead of trusting edge.src_node /
    edge.dest_node types.
    """
    nodes = list(path.nodes())
    edges = []
    for i, e in enumerate(path.edges()):
        edge = {
            "type": getattr(e, "relation", None),
            "properties": dict(getattr(e, "properties", None) or {}),
        }
        if i < len(nodes):
            edge["src"] = _node_dict(nodes[i]).get("id")
        if i + 1 < len(nodes):
            edge["dest"] = _node_dict(nodes[i + 1]).get("id")
        edges.append(edge)
    return {"nodes": [_node_dict(n) for n in nodes], "edges": edges}


def resolve_artifact(graph, artifact_id: str):
    """Resolve an artifact id to its node across concrete labels.

    Returns a flattened dict or None if no concrete artifact exists.
    Iterates the indexed ARTIFACT_LABELS so lookups hit per-label
    range indexes instead of scanning the whole graph (`(n {id:...})`).
    """
    if not artifact_id:
        return None
    for label in ARTIFACT_LABELS:
        res = graph.query(
            f"MATCH (n:{label} {{id: $id}}) RETURN n", {"id": artifact_id}
        )
        rows = res.result_set if res else []
        if rows and rows[0]:
            return _node_dict(rows[0][0])
    return None


def downstream_nodes(graph, artifact_id: str, max_depth=None, blocked=None):
    """Every distinct downstream dependent of the artifact (with min hops).

    FalkorDB computes reachability + aggregation; the endpoint never
    invents members of the blast radius. `blocked` excludes paths that
    pass through the given artifact ids (Phase 7, non-mutating).
    """
    max_depth = _clamp_depth(max_depth)
    pattern = _rel_pattern(max_depth)
    params = {"id": artifact_id, **_blocked_params(blocked)}
    res = graph.query(
        f"MATCH (start {{id: $id}})\n"
        f"MATCH p=(start){pattern}(dest)\n"
        f"{_blocked_clause(blocked)}"
        f"RETURN dest, min(length(p)) AS hops\n"
        f"ORDER BY hops ASC",
        params,
    )
    affected = []
    if res and res.result_set:
        for cell in res.result_set:
            node = cell[0]
            hops = cell[1]
            d = _node_dict(node)
            d["hops"] = hops
            affected.append(d)
    return affected


def applications_paths(graph, artifact_id: str, max_depth=None, blocked=None):
    """Shortest downstream path from artifact to each affected Application.

    Returns {app_id: {"app": {...}, "path": {"nodes":[...], "edges":[...]}}}.
    All matching Application endpoints are requested in one query and the
    shortest path per application is chosen (FalkorDB returns the full path,
    which we consume rather than rebuild). `blocked` excludes paths that
    pass through the given artifact ids (Phase 7, non-mutating).
    """
    max_depth = _clamp_depth(max_depth)
    pattern = _rel_pattern(max_depth)
    params = {"id": artifact_id, **_blocked_params(blocked)}
    res = graph.query(
        f"MATCH (start {{id: $id}})\n"
        f"MATCH p=(start){pattern}(app:Application)\n"
        f"{_blocked_clause(blocked)}"
        f"RETURN app, p, length(p) AS hops\n"
        f"ORDER BY hops ASC",
        params,
    )
    best = {}
    if res and res.result_set:
        for cell in res.result_set:
            app_node = cell[0]
            path = cell[1]
            hops = cell[2]
            app_id = app_node.properties.get("id")
            if app_id is None:
                continue
            if app_id not in best or hops < best[app_id]["hops"]:
                best[app_id] = {
                    "app": _node_dict(app_node),
                    "path": _path_dict(path),
                    "hops": hops,
                }
    return best


def production_applications(graph, artifact_id: str, max_depth=None, blocked=None):
    """Downstream Applications that have a production Deployment.

    Production is a *graph* fact: an Application counts only when a
    (:Deployment {environment: 'production'})-[:DEPLOYS]->(:Application)
    exists. We deliberately do NOT trust application names, and we require
    the Deployment relationship rather than just the Application's
    `environment` property, so an app marked "production" but with no
    actual production deployment edge is not over-counted. `blocked`
    excludes paths that pass through the given ids (Phase 7, non-mutating).
    """
    max_depth = _clamp_depth(max_depth)
    pattern = _rel_pattern(max_depth)
    params = {"id": artifact_id, "env": PRODUCTION_ENVIRONMENT,
              **_blocked_params(blocked)}
    res = graph.query(
        f"MATCH (start {{id: $id}})\n"
        f"MATCH p=(start){pattern}(app:Application)\n"
        f"{_blocked_clause(blocked)}"
        f"MATCH (dep:Deployment {{environment: $env}})-[:DEPLOYS]->(app)\n"
        f"WITH app, dep, min(length(p)) AS hops\n"
        f"RETURN app, dep, hops\n"
        f"ORDER BY hops ASC",
        params,
    )
    result = []
    if res and res.result_set:
        for cell in res.result_set:
            result.append(
                {
                    "application": _node_dict(cell[0]),
                    "deployment": _node_dict(cell[1]),
                    "hops": cell[2],
                }
            )
    return result


def maximum_depth(graph, artifact_id: str, max_depth=None, blocked=None) -> int:
    """Maximum propagation depth across all affected downstream nodes.

    Computed from the graph-returned hops (min length per distinct node),
    not re-derived by the endpoint. `blocked` excludes paths that pass
    through the given artifact ids (Phase 7, non-mutating).
    """
    nodes = downstream_nodes(graph, artifact_id, max_depth=max_depth, blocked=blocked)
    if not nodes:
        return 0
    return max(n["hops"] for n in nodes)


def downstream_dependents(graph, artifact_id: str, max_depth=None, blocked=None):
    """Downstream dependent population: distinct affected IDs by type."""
    nodes = downstream_nodes(graph, artifact_id, max_depth=max_depth, blocked=blocked)
    by_type = {}
    for node in nodes:
        t = node.get("type") or "Unknown"
        by_type.setdefault(t, []).append(node)
    return {
        "total": len(nodes),
        "artifacts": nodes,
        "by_type": {k: len(v) for k, v in by_type.items()},
    }


def incidents_on(graph, artifact_id: str):
    """Incidents that AFFECT the resolved artifact node."""
    res = graph.query(
        "MATCH (i:Incident)-[:AFFECTS]->(a {id: $id}) "
        "RETURN i ORDER BY i.id",
        {"id": artifact_id},
    )
    incidents = []
    if res and res.result_set:
        for cell in res.result_set:
            incidents.append(_node_dict(cell[0]))
    return incidents


def _evidence_dict(node) -> dict:
    """Flatten an :Evidence node exactly as stored (no fabrication)."""
    props = dict(getattr(node, "properties", None) or {})
    return {field: props.get(field) for field in EVIDENCE_FIELDS}


def evidence_for(graph, artifact_id: str):
    """Evidence supporting an investigation of `artifact_id`.

    Collects evidence that DESCRIBES the artifact and evidence that
    SUPPORTS incidents affecting it, then merges by evidence id (two
    bounded queries; no variable-length traversal). Returns a list of
    evidence records (source fields + provenance keys) sorted by id,
    populated ONLY from graph facts.
    """
    merged = {}
    queries = (
        # Evidence that describes the artifact directly.
        ("MATCH (a {id: $id})<-[:DESCRIBES]-(e:Evidence) RETURN e, a.id AS aid",
         "described_artifacts"),
        # Evidence that describes a vulnerability linked FROM this artifact
        # via HAS_VULNERABILITY (e.g. public OSV evidence for a PackageVersion).
        ("MATCH (a {id: $id})-[:HAS_VULNERABILITY]->(v)<-[:DESCRIBES]-(e:Evidence) "
         "RETURN e, v.id AS vid",
         "described_artifacts"),
        # Evidence supporting an incident that affects the artifact.
        ("MATCH (a {id: $id})<-[:AFFECTS]-(i:Incident)-[:SUPPORTED_BY]->(e:Evidence) RETURN e, i.id AS iid",
         "supported_incidents"),
    )
    for cypher, key in queries:
        res = graph.query(cypher, {"id": artifact_id})
        if not res or not res.result_set:
            continue
        for cell in res.result_set:
            record = _evidence_dict(cell[0])
            eid = record.get("id")
            if eid is None:
                continue
            entry = merged.setdefault(
                eid, {"evidence": record, "supported_incidents": [], "described_artifacts": []}
            )
            entry[key].append(cell[1])

    return [
        {
            "id": entry["evidence"]["id"],
            "title": entry["evidence"]["title"],
            "source": entry["evidence"]["source"],
            "source_type": entry["evidence"]["source_type"],
            "confidence": entry["evidence"]["confidence"],
            "observed_at": entry["evidence"]["observed_at"],
            "description": entry["evidence"]["description"],
            "supported_incidents": sorted(set(entry["supported_incidents"])),
            "described_artifacts": sorted(set(entry["described_artifacts"])),
        }
        for _, entry in sorted(merged.items())
    ]


def investigate_artifact(graph, artifact_id: str, max_depth=None, blocked=None) -> dict:
    """Full investigation for a single artifact (pure graph reasoning).

    `blocked` excludes paths that pass through the given artifact ids
    (Phase 7, non-mutating query-time exclusion). Raises LookupError if
    the artifact does not exist in the graph.
    """
    artifact = resolve_artifact(graph, artifact_id)
    if artifact is None:
        raise LookupError(f"artifact {artifact_id} not found")

    max_depth = _clamp_depth(max_depth)
    apps = applications_paths(graph, artifact_id, max_depth=max_depth, blocked=blocked)
    prod = production_applications(graph, artifact_id, max_depth=max_depth, blocked=blocked)
    dependents = downstream_dependents(graph, artifact_id, max_depth=max_depth, blocked=blocked)
    incidents = incidents_on(graph, artifact_id)
    depth = maximum_depth(graph, artifact_id, max_depth=max_depth, blocked=blocked)
    evidence = evidence_for(graph, artifact_id)

    return {
        "artifact": artifact,
        "blast_radius": {
            "total_affected": dependents["total"],
            "max_propagation_depth": depth,
            "traversal_depth_cap": max_depth,
            "dependents_by_type": dependents["by_type"],
        },
        "affected_applications": [
            {"application": a["app"], "hops": a["hops"],
             "path": a["path"]}
            for a in apps.values()
        ],
        # Order by hops ascending, ties by application id for stability.
        "production_applications": [
            {"application": p["application"], "deployment": p["deployment"],
             "hops": p["hops"]}
            for p in sorted(prod, key=lambda x: (x["hops"], x["application"]["id"]))
        ],
        "incidents": incidents,
        "evidence": evidence,
        "dependencies": dependents["artifacts"],
    }
