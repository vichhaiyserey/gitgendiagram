"""End-to-end analysis pipeline."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .advisories import apply_advisories, load_advisories
from .ast_index import index_repo
from .cache import IndexCache
from .discover import RepoInfo, discover
from .external_reports import load_external_reports
from .features import assign_features
from .frameworks import annotate, load_frameworks_config
from .graph_builder import BuildStats, GraphBuilder
from .iac import analyze_iac
from .java_index import analyze_java_security, build_java_graph, index_java
from .model import DependencyReachabilitySummary, Finding, Graph, TaintTrace, stable_id
from .resolver import Resolver
from .sca import build_dependency_reachability, check_package_reachable
from .security import analyze as analyze_security

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".pyi": "python",
    ".java": "java",
    ".kt": "kotlin",
    ".groovy": "groovy",
    ".scala": "scala",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".cs": "csharp",
    ".fs": "fsharp",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
    ".swift": "swift",
}

SECURITY_LANGUAGES = ("java", "python")


@dataclass(slots=True)
class AnalysisConfig:
    root: Path
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    min_confidence: float = 0.5
    max_nodes: int = 2000
    security: bool = True
    sonarqube_report: Path | None = None
    xray_report: Path | None = None
    advisory_dbs: list[Path] = field(default_factory=list)
    jobs: int = 0
    cache_dir: Path | None = None


@dataclass(slots=True)
class AnalysisResult:
    repo: RepoInfo
    graph: Graph
    stats: BuildStats
    python_files: int
    parse_errors: list[str] = field(default_factory=list)
    java_files: int = 0
    cache_stats: dict[str, dict[str, int | bool | str]] = field(default_factory=dict)
    dependency_usage: dict[str, DependencyReachabilitySummary] = field(default_factory=dict)

    def has_taint_at(self, file_path: str, line: int | None = None) -> bool:
        """Returns True if any taint trace or finding touches file_path[:line]."""
        return self.graph.has_taint_at(file_path, line)

    def get_taint_traces(self, file_path: str, line: int | None = None) -> list[TaintTrace]:
        """Returns all TaintTrace objects touching file_path[:line]."""
        return self.graph.get_taint_traces(file_path, line)

    def is_reachable(self, file_path: str, symbol: str | None = None) -> bool:
        """Returns True if file_path or symbol is reachable from an exposed entrypoint."""
        return self.graph.is_reachable(file_path, symbol)

    def is_package_reachable(self, package_name: str) -> bool:
        """Returns True if any import from package_name is reachable from an exposed entrypoint."""
        return check_package_reachable(self.dependency_usage, package_name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo": {
                "root": str(self.repo.root),
                "name": self.repo.name,
                "rel_files": self.repo.rel_files,
                "is_git": self.repo.is_git,
                "commit": self.repo.commit,
                "branch": self.repo.branch,
                "dirty": self.repo.dirty,
                "skipped": self.repo.skipped,
            },
            "graph": self.graph.to_dict(),
            "stats": {
                "unresolved": self.stats.unresolved,
                "duplicate_modules": self.stats.duplicate_modules,
                "truncated": self.stats.truncated,
                "dropped_nodes": self.stats.dropped_nodes,
            },
            "python_files": self.python_files,
            "parse_errors": self.parse_errors,
            "java_files": self.java_files,
            "cache_stats": self.cache_stats,
            "dependency_usage": {k: v.to_dict() for k, v in self.dependency_usage.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AnalysisResult:
        repo_data = data.get("repo", {})
        repo = RepoInfo(
            root=Path(repo_data.get("root", ".")),
            name=str(repo_data.get("name", "repo")),
            rel_files=list(repo_data.get("rel_files", [])),
            is_git=bool(repo_data.get("is_git", False)),
            commit=repo_data.get("commit"),
            branch=repo_data.get("branch"),
            dirty=bool(repo_data.get("dirty", False)),
            skipped=list(repo_data.get("skipped", [])),
        )
        graph = Graph.from_dict(data.get("graph", {}))
        stats_data = data.get("stats", {})
        stats = BuildStats(
            unresolved=list(stats_data.get("unresolved", [])),
            duplicate_modules=dict(stats_data.get("duplicate_modules", {})),
            truncated=bool(stats_data.get("truncated", False)),
            dropped_nodes=int(stats_data.get("dropped_nodes", 0)),
        )
        dep_usage = {
            k: DependencyReachabilitySummary.from_dict(v)
            for k, v in data.get("dependency_usage", {}).items()
        }
        return cls(
            repo=repo,
            graph=graph,
            stats=stats,
            python_files=int(data.get("python_files", 0)),
            parse_errors=list(data.get("parse_errors", [])),
            java_files=int(data.get("java_files", 0)),
            cache_stats=dict(data.get("cache_stats", {})),
            dependency_usage=dep_usage,
        )

    def to_json(self, path: str | Path | None = None) -> str:
        """Serialize AnalysisResult to JSON string and optionally write to path atomically."""
        serialized = json.dumps(self.to_dict(), indent=2, sort_keys=False) + "\n"
        if path is not None:
            out_path = Path(path)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = out_path.with_suffix(f"{out_path.suffix}.tmp.{os.getpid()}")
            temp_path.write_text(serialized, encoding="utf-8")
            temp_path.replace(out_path)
        return serialized

    @classmethod
    def from_json(cls, source: str | Path) -> AnalysisResult:
        """Load AnalysisResult from a JSON file path or a JSON string."""
        source_path = Path(source) if not isinstance(source, Path) else source
        try:
            if source_path.is_file():
                content = source_path.read_text(encoding="utf-8")
                data = json.loads(content)
                return cls.from_dict(data)
        except OSError:
            pass
        if isinstance(source, str):
            data = json.loads(source)
            return cls.from_dict(data)
        raise ValueError(f"Could not load AnalysisResult from source: {source}")


def run_analysis(config: AnalysisConfig) -> AnalysisResult:
    load_frameworks_config(config.root)
    repo = discover(
        config.root,
        config.include,
        config.exclude,
        skip_paths=[config.cache_dir] if config.cache_dir is not None else None,
    )
    python_cache = IndexCache(config.cache_dir, "python", repo.commit) if config.cache_dir else None
    java_cache = IndexCache(config.cache_dir, "java", repo.commit) if config.cache_dir else None
    indexes = index_repo(repo.root, repo.python_files, jobs=config.jobs, cache=python_cache)
    annotate(indexes)

    resolver = Resolver(indexes)
    builder = GraphBuilder(indexes, resolver, max_nodes=config.max_nodes)
    graph = builder.build()

    java_index = index_java(repo.root, repo.rel_files, jobs=config.jobs, cache=java_cache)
    if java_index.files:
        build_java_graph(graph, java_index)

    findings: list[Finding] = []
    if config.security:
        findings.extend(analyze_iac(graph, repo))
        findings.extend(analyze_security(graph, indexes, resolver, repo.root, repo.rel_files))
        if java_index.files:
            findings.extend(analyze_java_security(graph, java_index, repo.root, repo.name))
        external, external_summaries = load_external_reports(
            repo.root,
            repo.rel_files,
            config.sonarqube_report,
            config.xray_report,
        )
        findings.extend(external)
        if external_summaries:
            graph.meta["external_reports"] = external_summaries
    merged: dict[str, Finding] = {}
    for finding in findings:
        merged.setdefault(finding.id, finding)
    graph.findings = list(merged.values())
    if config.advisory_dbs:
        advisory_index, advisory_summaries = load_advisories(config.advisory_dbs)
        validated = apply_advisories(graph.findings, advisory_index)
        graph.meta["advisory_sources"] = advisory_summaries
        graph.meta["advisory_validated_findings"] = validated
    graph.edges = [
        edge
        for edge in graph.edges
        if edge.confidence >= config.min_confidence or edge.kind in {"contains", "imports"}
    ]
    assign_features(graph)

    parse_errors = sorted(path for path, index in indexes.items() if index.error)
    languages: dict[str, int] = {}
    for rel in repo.rel_files:
        name = rel.rsplit("/", 1)[-1]
        if "." not in name:
            continue
        suffix = "." + name.rsplit(".", 1)[-1].lower()
        language = LANGUAGE_BY_SUFFIX.get(suffix)
        if language:
            languages[language] = languages.get(language, 0) + 1
    languages = dict(sorted(languages.items()))
    unsupported_languages = sorted(
        language for language in languages if language not in SECURITY_LANGUAGES
    )
    config_hash = stable_id(
        "config",
        ",".join(sorted(config.include)),
        ",".join(sorted(config.exclude)),
        str(config.min_confidence),
        str(config.max_nodes),
        str(config.security),
    )
    graph.meta.update(
        {
            "name": repo.name,
            "commit": repo.commit,
            "branch": repo.branch,
            "dirty": repo.dirty,
            "is_git": repo.is_git,
            "python_files": len(indexes),
            "java_files": len(java_index.files),
            "iac_files": len(repo.iac_files),
            "files_discovered": len(repo.rel_files),
            "files_skipped": len(repo.skipped),
            "skipped_samples": sorted(repo.skipped)[:20],
            "languages": languages,
            "security_languages": list(SECURITY_LANGUAGES),
            "unsupported_security_languages": unsupported_languages,
            "config_hash": config_hash,
            "security_enabled": config.security,
            "include": sorted(config.include),
            "exclude": sorted(config.exclude),
            "min_confidence": config.min_confidence,
            "analysis": {
                "unresolved_count": graph.meta.get("unresolved_count", 0),
                "truncated": graph.meta.get("truncated", False),
                "dropped_nodes": graph.meta.get("dropped_nodes", 0),
                "parse_errors": parse_errors,
            },
        }
    )
    cache_stats: dict[str, dict[str, int | bool | str]] = {}
    if python_cache is not None:
        cache_stats["python"] = python_cache.summary()
    if java_cache is not None:
        cache_stats["java"] = java_cache.summary()

    dependency_usage = build_dependency_reachability(graph, indexes, java_index)

    return AnalysisResult(
        repo=repo,
        graph=graph,
        stats=builder.stats,
        python_files=len(indexes),
        parse_errors=parse_errors,
        java_files=len(java_index.files),
        cache_stats=cache_stats,
        dependency_usage=dependency_usage,
    )


def analyze(
    root: str | Path | None = None,
    *,
    config: AnalysisConfig | None = None,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    min_confidence: float = 0.5,
    max_nodes: int = 2000,
    security: bool = True,
    sonarqube_report: Path | None = None,
    xray_report: Path | None = None,
    advisory_dbs: list[Path] | None = None,
    jobs: int = 0,
    cache_dir: Path | None = None,
    **kwargs: Any,
) -> AnalysisResult:
    """High-level analysis facade over run_analysis."""
    if config is not None:
        return run_analysis(config)
    if root is None:
        raise ValueError("Either 'root' or 'config' must be provided to analyze().")
    cfg = AnalysisConfig(
        root=Path(root),
        include=include or [],
        exclude=exclude or [],
        min_confidence=min_confidence,
        max_nodes=max_nodes,
        security=security,
        sonarqube_report=sonarqube_report,
        xray_report=xray_report,
        advisory_dbs=advisory_dbs or [],
        jobs=jobs,
        cache_dir=cache_dir,
    )
    return run_analysis(cfg)


def __getattr__(name: str) -> Any:
    """Backward compatibility shims for downstream tools importing across modules."""
    if name in {"build_high_level_architecture", "render_mermaid_highlevel", "HighLevelArchitecture", "Subsystem", "SubsystemConnection"}:
        from . import high_level as hl
        return getattr(hl, name)
    if name == "render_mermaid":
        from .render_mermaid import render_mermaid as rm
        return rm
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
