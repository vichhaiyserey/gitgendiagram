"""SCA Bridge: dependency reachability and dead-code indexer for third-party packages."""

from __future__ import annotations

from typing import Any

from .ast_index import FileIndex
from .model import DependencyReachabilitySummary, Graph, Loc, _normalize_path_str, _paths_match


def _canonical_pkg_name(name: str) -> str:
    cleaned = name.strip().lower().replace("-", "_")
    if ":" in cleaned:
        cleaned = cleaned.split(":")[-1]
    if "." in cleaned:
        # e.g. com.fasterxml.jackson.core -> jackson or root
        parts = cleaned.split(".")
        if len(parts) >= 2 and parts[0] in {"org", "com", "io", "net"}:
            cleaned = parts[1]
        else:
            cleaned = parts[0]
    return cleaned


def build_dependency_reachability(
    graph: Graph,
    python_indexes: dict[str, FileIndex],
    java_index: Any = None,
) -> dict[str, DependencyReachabilitySummary]:
    """Build reverse import-to-sink reachability index for third-party dependencies."""
    entrypoints = graph.get_entrypoint_nodes()
    reachable_node_ids = graph.get_reachable_nodes_from_entrypoints()

    reachable_files: set[str] = set()
    for ep in entrypoints:
        if ep.path:
            reachable_files.add(_normalize_path_str(ep.path))
    for nid in reachable_node_ids:
        node = graph.nodes.get(nid)
        if node and node.path:
            reachable_files.add(_normalize_path_str(node.path))

    # Entrypoint names/IDs for evidence
    ep_identifiers = sorted(ep.qualname or ep.name or ep.id for ep in entrypoints)

    summaries: dict[str, DependencyReachabilitySummary] = {}

    def get_summary(pkg: str) -> DependencyReachabilitySummary:
        canon = _canonical_pkg_name(pkg)
        if canon not in summaries:
            summaries[canon] = DependencyReachabilitySummary(package_name=canon)
        return summaries[canon]

    # 1. Process Python imports
    for rel_path, index in python_indexes.items():
        norm_path = _normalize_path_str(rel_path)
        file_is_reachable = any(_paths_match(norm_path, rf) for rf in reachable_files)

        for imp in index.imports:
            packages: list[str] = []
            if imp.is_from:
                if imp.module:
                    packages.append(imp.module.split(".")[0])
            else:
                for name, _alias in imp.names:
                    if name:
                        packages.append(name.split(".")[0])

            loc = Loc(rel_path, imp.line)
            for pkg in packages:
                if not pkg or pkg.startswith("."):
                    continue
                summary = get_summary(pkg)
                summary.imported = True
                if all(loc.ref != seen.ref for seen in summary.import_sites):
                    summary.import_sites.append(loc)

                if file_is_reachable:
                    summary.reachable_from_entrypoint = True
                    for ep_id in ep_identifiers:
                        if ep_id not in summary.entrypoints:
                            summary.entrypoints.append(ep_id)

    # 2. Process external call edges reachable from entrypoints
    for nid in reachable_node_ids:
        node = graph.nodes.get(nid)
        if not node:
            continue
        # Check call edges from this node
        for edge in graph.edges:
            if edge.src == nid and edge.kind == "calls":
                target_node = graph.nodes.get(edge.dst)
                callee_name = target_node.qualname if target_node else edge.dst
                if "." in callee_name:
                    root_pkg = callee_name.split(".")[0]
                    canon = _canonical_pkg_name(root_pkg)
                    if canon in summaries:
                        summary = summaries[canon]
                        summary.reachable_from_entrypoint = True
                        path_chain = [node.qualname or node.name, callee_name]
                        if path_chain not in summary.call_paths:
                            summary.call_paths.append(path_chain)

    # 3. Process Java imports if present
    if java_index is not None and hasattr(java_index, "files"):
        for jpath, jfile in getattr(java_index, "files", {}).items():
            norm_path = _normalize_path_str(jpath)
            file_is_reachable = any(_paths_match(norm_path, rf) for rf in reachable_files)
            imports = getattr(jfile, "imports", [])
            for imp in imports:
                raw_pkg = str(imp).strip()
                if not raw_pkg:
                    continue
                summary = get_summary(raw_pkg)
                summary.imported = True
                loc = Loc(jpath, 1)
                if all(loc.ref != seen.ref for seen in summary.import_sites):
                    summary.import_sites.append(loc)
                if file_is_reachable:
                    summary.reachable_from_entrypoint = True
                    for ep_id in ep_identifiers:
                        if ep_id not in summary.entrypoints:
                            summary.entrypoints.append(ep_id)

    return summaries


def check_package_reachable(
    dependency_usage: dict[str, DependencyReachabilitySummary],
    package_name: str,
) -> bool:
    """Return True if package_name or its canonical variant is reachable from an entrypoint."""
    canon = _canonical_pkg_name(package_name)
    if canon in dependency_usage:
        return dependency_usage[canon].reachable_from_entrypoint
    for key, summary in dependency_usage.items():
        if key in canon or canon in key:
            if summary.reachable_from_entrypoint:
                return True
    return False
