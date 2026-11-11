"""Framework-aware annotation of Python callables (routes, tasks, CLI, auth)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .ast_index import FileIndex

ROUTE_RE = re.compile(
    r"^(?P<obj>[\w.]+)\.(?P<method>get|post|put|patch|delete|head|options|websocket|route|api_route)\s*\((?P<args>.*)\)$",
    re.S,
)
STRING_RE = re.compile(r"""(['"])(.*?)\1""", re.S)
METHODS_RE = re.compile(r"methods\s*=\s*[\[(](?P<body>[^\])]*)[\])]", re.S)
AUTH_WORDS = (
    "login_required",
    "requires_auth",
    "permission_required",
    "jwt_required",
    "authenticated",
    "auth_required",
    "requires_permission",
    "security",
)
CLI_WORDS = ("click.command", "click.group", "typer", ".command(", "argparse")


@dataclass(slots=True)
class FrameworkRule:
    name: str
    entrypoint_decorators: list[str] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)
    categories: dict[str, str] = field(default_factory=dict)
    severities: dict[str, str] = field(default_factory=dict)


_FRAMEWORKS: dict[str, FrameworkRule] = {}
_SANITIZERS: set[str] = set()
_SINKS: dict[str, tuple[str, str]] = {}


def register_framework(
    name: str,
    entrypoint_decorators: list[str] | None = None,
    sanitizers: list[str] | None = None,
    sinks: list[str] | None = None,
    *,
    categories: dict[str, str] | None = None,
    severities: dict[str, str] | None = None,
) -> None:
    """Register custom framework entrypoints, sanitizers, and sinks."""
    cats = categories or {}
    sevs = severities or {}
    rule = FrameworkRule(
        name=name,
        entrypoint_decorators=list(entrypoint_decorators or []),
        sanitizers=list(sanitizers or []),
        sinks=list(sinks or []),
        categories=cats,
        severities=sevs,
    )
    _FRAMEWORKS[name] = rule
    for s in rule.sanitizers:
        register_sanitizer(s)
    for sink in rule.sinks:
        cat = cats.get(sink, "injection")
        sev = sevs.get(sink, "high")
        register_sink(sink, category=cat, severity=sev)


def register_sanitizer(name: str) -> None:
    """Register a custom sanitizer function name."""
    clean = name.strip().lstrip("@")
    if clean:
        _SANITIZERS.add(clean)
        _SANITIZERS.add(clean.lower())


def register_sink(name: str, category: str = "injection", severity: str = "high") -> None:
    """Register a custom sink function name with category and severity."""
    clean = name.strip().lstrip("@")
    if clean:
        _SINKS[clean] = (category, severity)
        _SINKS[clean.lower()] = (category, severity)


def get_registered_frameworks() -> list[FrameworkRule]:
    return list(_FRAMEWORKS.values())


def get_registered_sanitizers() -> set[str]:
    return set(_SANITIZERS)


def get_registered_sinks() -> dict[str, tuple[str, str]]:
    return dict(_SINKS)


def reset_registry() -> None:
    """Reset all registered frameworks, sanitizers, and sinks."""
    _FRAMEWORKS.clear()
    _SANITIZERS.clear()
    _SINKS.clear()


def _parse_custom_yaml(text: str) -> dict[str, Any]:
    """Parse minimal YAML configurations for frameworks and sinks without external deps."""
    lines = [
        line.rstrip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    root: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, root)]

    for line in lines:
        indent = len(line) - len(line.lstrip())
        content = line.strip()
        while stack and stack[-1][0] >= indent:
            stack.pop()
        _parent_indent, parent_obj = stack[-1]

        if content.startswith("- "):
            item = content[2:].strip()
            if ":" in item:
                k, v = [x.strip() for x in item.split(":", 1)]
                new_dict: dict[str, Any] = {k: v.strip("\"'") if v else []}
                if isinstance(parent_obj, list):
                    parent_obj.append(new_dict)
                stack.append((indent, new_dict))
            else:
                if isinstance(parent_obj, list):
                    parent_obj.append(item.strip("\"'"))
        elif ":" in content:
            k, v = [x.strip() for x in content.split(":", 1)]
            val: Any = v.strip("\"'") if v else []
            if isinstance(parent_obj, dict):
                parent_obj[k] = val
                if not v:
                    stack.append((indent, val))
            elif isinstance(parent_obj, list) and parent_obj and isinstance(parent_obj[-1], dict):
                parent_obj[-1][k] = val
                if not v:
                    stack.append((indent, val))
    return root


def load_frameworks_config(root: Path) -> None:
    """Inspect repository root for .secdiagram.yml or .secdiagram.json framework rules."""
    config_paths = [
        root / ".secdiagram.yml",
        root / ".secdiagram.yaml",
        root / "secdiagram.yml",
        root / "secdiagram.yaml",
        root / ".secdiagram.json",
        root / "secdiagram.json",
    ]
    for path in config_paths:
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8")
            data: dict[str, Any] = {}
            if path.suffix == ".json":
                data = json.loads(content)
            else:
                data = _parse_custom_yaml(content)
            _apply_config_data(data)
            break
        except Exception:
            continue


def _apply_config_data(data: dict[str, Any]) -> None:
    if not isinstance(data, dict):
        return

    # Direct lists
    entrypoints = data.get("entrypoint_decorators") or data.get("entrypoints") or []
    sanitizers = data.get("sanitizers") or []
    sinks = data.get("sinks") or []
    if entrypoints or sanitizers or sinks:
        register_framework(
            name="file-config",
            entrypoint_decorators=entrypoints,
            sanitizers=sanitizers,
            sinks=sinks,
        )

    # List of frameworks
    frameworks = data.get("frameworks") or []
    if isinstance(frameworks, list):
        for fw in frameworks:
            if isinstance(fw, dict) and "name" in fw:
                register_framework(
                    name=str(fw["name"]),
                    entrypoint_decorators=list(fw.get("entrypoint_decorators") or fw.get("entrypoints") or []),
                    sanitizers=list(fw.get("sanitizers") or []),
                    sinks=list(fw.get("sinks") or []),
                )


def _first_string(text: str) -> str | None:
    match = STRING_RE.search(text)
    return match.group(2) if match else None


def _methods(text: str, default: str) -> list[str]:
    match = METHODS_RE.search(text)
    if not match:
        return [default]
    found = [item.upper() for _quote, item in STRING_RE.findall(match.group("body"))]
    return found or [default]


def annotate(indexes: dict[str, FileIndex]) -> None:
    custom_decorators = set()
    for fw in _FRAMEWORKS.values():
        for dec in fw.entrypoint_decorators:
            cleaned = dec.strip().lstrip("@")
            if cleaned:
                custom_decorators.add(cleaned)
                custom_decorators.add(cleaned.lower())

    for index in indexes.values():
        for definition in index.defs:
            if definition.kind not in {"function", "method"}:
                continue
            routes: list[dict[str, str]] = []
            tags: list[str] = []
            role: str | None = None
            for decorator in definition.decorators:
                lowered = decorator.lower()
                clean_dec = decorator.strip().lstrip("@").split("(", 1)[0].strip()
                clean_dec_lower = clean_dec.lower()

                if any(word in lowered for word in AUTH_WORDS):
                    tags.append("auth")
                if "depends(" in lowered and any(
                    word in lowered for word in ("auth", "user", "token", "security")
                ):
                    tags.append("auth_dependency")
                if lowered == "shared_task" or lowered.endswith(".task") or lowered.startswith("shared_task("):
                    role = role or "task"
                if any(word in lowered for word in CLI_WORDS):
                    role = role or "cli"

                # Check custom entrypoint decorators
                if clean_dec in custom_decorators or clean_dec_lower in custom_decorators:
                    role = "endpoint"
                    routes.append({"method": "RPC", "path": ""})

                match = ROUTE_RE.match(decorator)
                if not match:
                    if "api_view(" in lowered:
                        methods = _methods(decorator, "GET")
                        routes.append({"method": ",".join(methods), "path": ""})
                        role = "endpoint"
                    continue
                method = match.group("method")
                args = match.group("args")
                path = _first_string(args) or ""
                if method == "websocket":
                    routes.append({"method": "WS", "path": path})
                    role = "endpoint"
                elif method in {"route", "api_route"}:
                    for detected in _methods(args, "GET"):
                        routes.append({"method": detected, "path": path})
                    role = "endpoint"
                else:
                    routes.append({"method": method.upper(), "path": path})
                    role = "endpoint"
            if routes:
                definition.routes = routes
                definition.kind = "endpoint"
            elif role:
                definition.kind = role
            if tags:
                definition.tags = sorted(set(definition.tags + tags))
