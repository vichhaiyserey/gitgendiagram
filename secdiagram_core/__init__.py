"""secdiagram: deterministic architecture and security graphs for Python, .NET, Node.js, and polyglot repositories."""

from __future__ import annotations

from typing import Any

__version__ = "0.2.1"
SCHEMA_VERSION = 1

from .analyzer import AnalysisConfig, AnalysisResult, analyze, run_analysis
from .config import SecdiagramConfig, load_config
from .frameworks import register_framework, register_sanitizer, register_sink
from .high_level import (
    HighLevelArchitecture,
    Subsystem,
    SubsystemConnection,
    build_high_level_architecture,
    render_mermaid_highlevel,
)
from .model import (
    DependencyReachabilitySummary,
    Edge,
    Finding,
    Graph,
    Loc,
    Node,
    TaintTrace,
)
from .render_image import ImageRenderError, render_image
from .render_mermaid import render_mermaid as _render_mermaid_graph
from .render_vex import render_vex
from .server import BasicAuthenticator, NoOpAuthenticator, create_server, serve


def render_mermaid(
    target: Any,
    *,
    direction: str = "TD",
    theme: str = "modern",
    detail: str = "architecture",
    link_base: str | None = None,
    max_diagram_nodes: int = 200,
    **kwargs: Any,
) -> str:
    """Polymorphic Mermaid renderer supporting AnalysisResult, HighLevelArchitecture, or Graph."""
    if isinstance(target, HighLevelArchitecture):
        return render_mermaid_highlevel(
            target,
            direction="TB" if direction in {"TB", "TD"} else "LR",
            theme=theme,
        )
    if hasattr(target, "graph") and isinstance(target.graph, Graph):
        return _render_mermaid_graph(
            target.graph,
            direction=direction,
            theme=theme,
            detail=detail,
            link_base=link_base,
            max_diagram_nodes=max_diagram_nodes,
        )
    if isinstance(target, Graph):
        return _render_mermaid_graph(
            target,
            direction=direction,
            theme=theme,
            detail=detail,
            link_base=link_base,
            max_diagram_nodes=max_diagram_nodes,
        )
    raise TypeError(
        f"render_mermaid expected Graph, AnalysisResult, or HighLevelArchitecture, got {type(target).__name__}"
    )


__all__ = [
    "__version__",
    "SCHEMA_VERSION",
    "analyze",
    "run_analysis",
    "AnalysisConfig",
    "AnalysisResult",
    "render_mermaid",
    "render_mermaid_highlevel",
    "render_vex",
    "render_image",
    "ImageRenderError",
    "HighLevelArchitecture",
    "Subsystem",
    "SubsystemConnection",
    "build_high_level_architecture",
    "Graph",
    "Node",
    "Edge",
    "Finding",
    "Loc",
    "TaintTrace",
    "DependencyReachabilitySummary",
    "register_framework",
    "register_sanitizer",
    "register_sink",
    "create_server",
    "serve",
    "load_config",
    "SecdiagramConfig",
    "BasicAuthenticator",
    "NoOpAuthenticator",
]
