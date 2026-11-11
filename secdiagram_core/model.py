"""Stable, serialisable graph model shared by every analyzer and renderer."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from . import SCHEMA_VERSION, __version__

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def stable_id(*parts: str) -> str:
    """Return a deterministic, collision-resistant identifier."""
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return digest[:12]


@dataclass(slots=True)
class Loc:
    """A source location used as evidence for a node, edge, or finding."""

    path: str
    line: int
    col: int = 0

    @property
    def ref(self) -> str:
        return f"{self.path}:{self.line}"

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "line": self.line, "col": self.col}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Loc:
        return cls(
            path=str(data.get("path", "")),
            line=int(data.get("line", 0)),
            col=int(data.get("col", 0)),
        )


@dataclass(slots=True)
class Node:
    id: str
    kind: str
    name: str
    qualname: str
    path: str | None = None
    line: int | None = None
    feature: str | None = None
    doc: str | None = None
    attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def evidence(self) -> Loc | None:
        if self.path and self.line:
            return Loc(self.path, self.line)
        return None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "kind": self.kind,
            "name": self.name,
            "qualname": self.qualname,
            "path": self.path,
            "line": self.line,
            "feature": self.feature,
            "doc": self.doc,
        }
        if self.attrs:
            out["attrs"] = self.attrs
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Node:
        return cls(
            id=str(data["id"]),
            kind=str(data.get("kind", "")),
            name=str(data.get("name", "")),
            qualname=str(data.get("qualname", "")),
            path=data.get("path"),
            line=data.get("line"),
            feature=data.get("feature"),
            doc=data.get("doc"),
            attrs=dict(data.get("attrs", {})),
        )


@dataclass(slots=True)
class Edge:
    src: str
    dst: str
    kind: str
    confidence: float = 1.0
    resolution: str = "exact"
    evidence: list[Loc] = field(default_factory=list)
    attrs: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "src": self.src,
            "dst": self.dst,
            "kind": self.kind,
            "confidence": round(float(self.confidence), 2),
            "resolution": self.resolution,
            "evidence": [loc.to_dict() for loc in self.evidence],
        }
        if self.attrs:
            out["attrs"] = self.attrs
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Edge:
        return cls(
            src=str(data["src"]),
            dst=str(data["dst"]),
            kind=str(data["kind"]),
            confidence=float(data.get("confidence", 1.0)),
            resolution=str(data.get("resolution", "exact")),
            evidence=[Loc.from_dict(loc) for loc in data.get("evidence", [])],
            attrs=dict(data.get("attrs", {})),
        )


@dataclass(slots=True)
class Feature:
    id: str
    name: str
    description: str = ""
    nodes: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "nodes": sorted(self.nodes),
            "files": sorted(self.files),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Feature:
        return cls(
            id=str(data["id"]),
            name=str(data.get("name", "")),
            description=str(data.get("description", "")),
            nodes=list(data.get("nodes", [])),
            files=list(data.get("files", [])),
        )


@dataclass(slots=True)
class Finding:
    id: str
    category: str
    severity: str
    title: str
    message: str
    node_id: str | None = None
    cwe: str | None = None
    confidence: float = 0.8
    evidence: list[Loc] = field(default_factory=list)
    recommendation: str = ""
    baseline: bool = False
    trace: list[Loc] = field(default_factory=list)
    source: str = "secdiagram"
    external_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "node_id": self.node_id,
            "cwe": self.cwe,
            "confidence": round(float(self.confidence), 2),
            "evidence": [loc.to_dict() for loc in self.evidence],
            "recommendation": self.recommendation,
        }
        if self.baseline:
            out["baseline"] = True
        if self.trace:
            out["trace"] = [loc.to_dict() for loc in self.trace]
        if self.source != "secdiagram":
            out["source"] = self.source
        if self.external_id:
            out["external_id"] = self.external_id
        if self.metadata:
            out["metadata"] = self.metadata
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            id=str(data["id"]),
            category=str(data.get("category", "")),
            severity=str(data.get("severity", "medium")),
            title=str(data.get("title", "")),
            message=str(data.get("message", "")),
            node_id=data.get("node_id"),
            cwe=data.get("cwe"),
            confidence=float(data.get("confidence", 0.8)),
            evidence=[Loc.from_dict(loc) for loc in data.get("evidence", [])],
            recommendation=str(data.get("recommendation", "")),
            baseline=bool(data.get("baseline", False)),
            trace=[Loc.from_dict(loc) for loc in data.get("trace", [])],
            source=str(data.get("source", "secdiagram")),
            external_id=data.get("external_id"),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass(slots=True)
class Graph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    features: list[Feature] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        if existing.feature is None and node.feature is not None:
            existing.feature = node.feature
        if existing.doc is None and node.doc is not None:
            existing.doc = node.doc
        for key, value in node.attrs.items():
            existing.attrs.setdefault(key, value)
        return existing

    def add_edge(
        self,
        src: str,
        dst: str,
        kind: str,
        *,
        confidence: float = 1.0,
        resolution: str = "exact",
        evidence: Iterable[Loc] = (),
        attrs: dict[str, Any] | None = None,
    ) -> Edge | None:
        if src not in self.nodes or dst not in self.nodes:
            return None
        edge = Edge(
            src=src,
            dst=dst,
            kind=kind,
            confidence=confidence,
            resolution=resolution,
            evidence=list(evidence),
            attrs=dict(attrs or {}),
        )
        self.edges.append(edge)
        return edge

    def find_node_by_qualname(self, qualname: str) -> Node | None:
        for node in self.nodes.values():
            if node.qualname == qualname:
                return node
        return None

    def sorted_nodes(self) -> list[Node]:
        return sorted(self.nodes.values(), key=lambda n: (n.feature or "", n.kind, n.qualname, n.path or ""))

    def sorted_edges(self) -> list[Edge]:
        return sorted(self.edges, key=lambda e: (e.kind, e.src, e.dst, e.resolution))

    def sorted_findings(self) -> list[Finding]:
        def key(f: Finding) -> tuple[Any, ...]:
            first = f.evidence[0] if f.evidence else None
            return (
                -SEVERITY_RANK.get(f.severity, 0),
                f.category,
                first.path if first else "",
                first.line if first else 0,
                f.id,
            )

        return sorted(self.findings, key=key)

    def dedupe_edges(self) -> None:
        merged: dict[tuple[str, str, str], Edge] = {}
        for edge in self.edges:
            key = (edge.src, edge.dst, edge.kind)
            current = merged.get(key)
            if current is None:
                merged[key] = edge
                continue
            current.confidence = max(current.confidence, edge.confidence)
            if edge.resolution == "exact":
                current.resolution = "exact"
            for loc in edge.evidence:
                if all(loc.ref != seen.ref for seen in current.evidence):
                    current.evidence.append(loc)
            for attr_key, value in edge.attrs.items():
                current.attrs.setdefault(attr_key, value)
        self.edges = sorted(merged.values(), key=lambda e: (e.kind, e.src, e.dst))

    def to_dict(self) -> dict[str, Any]:
        self.dedupe_edges()
        self.findings = self.sorted_findings()
        return {
            "schema_version": SCHEMA_VERSION,
            "meta": {
                **self.meta,
                "tool": "secdiagram",
                "tool_version": __version__,
                "node_count": len(self.nodes),
                "edge_count": len(self.edges),
                "feature_count": len(self.features),
                "finding_count": len(self.findings),
            },
            "features": [feature.to_dict() for feature in sorted(self.features, key=lambda f: f.name)],
            "nodes": [node.to_dict() for node in self.sorted_nodes()],
            "edges": [edge.to_dict() for edge in self.sorted_edges()],
            "findings": [finding.to_dict() for finding in self.findings],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Graph:
        graph = cls()
        graph.meta = dict(data.get("meta", {}))
        for node_data in data.get("nodes", []):
            node = Node.from_dict(node_data)
            graph.nodes[node.id] = node
        for edge_data in data.get("edges", []):
            graph.edges.append(Edge.from_dict(edge_data))
        for feat_data in data.get("features", []):
            graph.features.append(Feature.from_dict(feat_data))
        for finding_data in data.get("findings", []):
            graph.findings.append(Finding.from_dict(finding_data))
        return graph

    def has_taint_at(self, file_path: str, line: int | None = None) -> bool:
        """Returns True if any taint trace or finding evidence touches file_path[:line]."""
        for finding in self.findings:
            locs = list(finding.trace) if finding.trace else list(finding.evidence)
            for loc in locs:
                if _paths_match(loc.path, file_path):
                    if line is None or loc.line == line:
                        return True
        return False

    def get_taint_traces(self, file_path: str, line: int | None = None) -> list[TaintTrace]:
        """Returns all TaintTrace objects touching file_path[:line]."""
        traces: list[TaintTrace] = []
        for finding in self.findings:
            locs = list(finding.trace) if finding.trace else list(finding.evidence)
            matches = False
            for loc in locs:
                if _paths_match(loc.path, file_path):
                    if line is None or loc.line == line:
                        matches = True
                        break
            if matches:
                source = finding.trace[0] if finding.trace else None
                sink = (
                    finding.trace[-1]
                    if finding.trace
                    else (finding.evidence[0] if finding.evidence else None)
                )
                trace_locs = list(finding.trace) if finding.trace else list(finding.evidence)
                traces.append(
                    TaintTrace(
                        finding_id=finding.id,
                        category=finding.category,
                        severity=finding.severity,
                        cwe=finding.cwe,
                        source=source,
                        sink=sink,
                        trace=trace_locs,
                        message=finding.message,
                        rule_id=str(finding.metadata.get("rule_id", finding.category)),
                    )
                )
        return traces

    def get_entrypoint_nodes(self) -> list[Node]:
        """Return all entrypoint nodes (HTTP endpoints, RPC, tasks, CLI)."""
        entrypoints: list[Node] = []
        for node in self.nodes.values():
            if node.kind == "endpoint" or node.attrs.get("role") == "endpoint":
                entrypoints.append(node)
                continue
            tags = [str(t).lower() for t in node.attrs.get("tags", [])]
            if "endpoint" in tags or "route" in tags or "auth" in tags or "auth_dependency" in tags:
                entrypoints.append(node)
                continue
            if node.attrs.get("routes"):
                entrypoints.append(node)
                continue
        return entrypoints

    def get_reachable_nodes_from_entrypoints(self) -> set[str]:
        """Compute the set of node IDs reachable from exposed entrypoints via BFS."""
        entrypoints = self.get_entrypoint_nodes()
        if not entrypoints:
            return set()

        adj: dict[str, list[str]] = {node_id: [] for node_id in self.nodes}
        for edge in self.edges:
            if edge.src in adj:
                adj[edge.src].append(edge.dst)

        visited: set[str] = set()
        queue = [ep.id for ep in entrypoints if ep.id in self.nodes]
        for ep_id in queue:
            visited.add(ep_id)

        head = 0
        while head < len(queue):
            current = queue[head]
            head += 1
            for neighbor in adj.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
        return visited

    def is_reachable(self, file_path: str, symbol: str | None = None) -> bool:
        """Returns True if the file or symbol is reachable from an exposed entrypoint."""
        entrypoints = self.get_entrypoint_nodes()
        if not entrypoints:
            return False

        reachable_ids = self.get_reachable_nodes_from_entrypoints()

        for node_id in reachable_ids:
            node = self.nodes.get(node_id)
            if node is None or not node.path:
                continue
            if _paths_match(node.path, file_path):
                if symbol is None:
                    return True
                if (
                    node.name == symbol
                    or node.qualname == symbol
                    or node.qualname.endswith("." + symbol)
                    or node.qualname.endswith("::" + symbol)
                ):
                    return True
        return False


def _normalize_path_str(path: str) -> str:
    cleaned = path.replace("\\", "/").strip().lstrip("/")
    if cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned


def _paths_match(path_a: str, path_b: str) -> bool:
    norm_a = _normalize_path_str(path_a)
    norm_b = _normalize_path_str(path_b)
    if not norm_a or not norm_b:
        return False
    if norm_a == norm_b:
        return True
    return norm_a.endswith("/" + norm_b) or norm_b.endswith("/" + norm_a)


@dataclass(slots=True)
class TaintTrace:
    finding_id: str
    category: str
    severity: str
    cwe: str | None = None
    source: Loc | None = None
    sink: Loc | None = None
    trace: list[Loc] = field(default_factory=list)
    message: str = ""
    rule_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "severity": self.severity,
            "cwe": self.cwe,
            "source": self.source.to_dict() if self.source else None,
            "sink": self.sink.to_dict() if self.sink else None,
            "trace": [loc.to_dict() for loc in self.trace],
            "message": self.message,
            "rule_id": self.rule_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TaintTrace:
        return cls(
            finding_id=str(data.get("finding_id", "")),
            category=str(data.get("category", "")),
            severity=str(data.get("severity", "")),
            cwe=data.get("cwe"),
            source=Loc.from_dict(data["source"]) if data.get("source") else None,
            sink=Loc.from_dict(data["sink"]) if data.get("sink") else None,
            trace=[Loc.from_dict(loc) for loc in data.get("trace", [])],
            message=str(data.get("message", "")),
            rule_id=str(data.get("rule_id", "")),
        )


@dataclass(slots=True)
class DependencyReachabilitySummary:
    package_name: str
    imported: bool = False
    reachable_from_entrypoint: bool = False
    import_sites: list[Loc] = field(default_factory=list)
    entrypoints: list[str] = field(default_factory=list)
    call_paths: list[list[str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_name": self.package_name,
            "imported": self.imported,
            "reachable_from_entrypoint": self.reachable_from_entrypoint,
            "import_sites": [loc.to_dict() for loc in self.import_sites],
            "entrypoints": sorted(self.entrypoints),
            "call_paths": self.call_paths,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DependencyReachabilitySummary:
        return cls(
            package_name=str(data.get("package_name", "")),
            imported=bool(data.get("imported", False)),
            reachable_from_entrypoint=bool(data.get("reachable_from_entrypoint", False)),
            import_sites=[Loc.from_dict(loc) for loc in data.get("import_sites", [])],
            entrypoints=list(data.get("entrypoints", [])),
            call_paths=[list(path) for path in data.get("call_paths", [])],
        )
