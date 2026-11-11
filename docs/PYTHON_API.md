# 🐍 Python Public Facade & Developer API Guide

Downstream tools, automated DevSecOps pipelines, and custom Python scripts can interact directly with `secdiagram` via its stable public API facade.

---

## 1. Stable Public Facade (`secdiagram_core`)

All primary capabilities are exported directly at the top level of `secdiagram_core`:

```python
from secdiagram_core import (
    analyze,
    render_mermaid,
    AnalysisConfig,
    AnalysisResult,
)

# Configure analysis options:
config = AnalysisConfig(
    root=".",
    security=True,
    min_confidence=0.5,
)

# Run full analysis:
result = analyze(config)
```

> [!NOTE]
> For backward compatibility, legacy imports from `secdiagram_core.analyzer` (`AnalysisConfig`, `run_analysis`) and `secdiagram_core.high_level` (`build_high_level_architecture`, `render_mermaid_highlevel`) remain fully supported via internal re-exports and module shims.

---

## 2. Native Taint & Reachability Query API

`AnalysisResult` provides high-performance query helpers to eliminate manual loops over raw nodes and findings when triaging alerts or integrating with SAST/SCA tools:

### Taint Inspection
```python
# Check if a specific file or exact line contains active tainted dataflow:
if result.has_taint_at("app/controllers/orders.py", line=42):
    print("File and line are on a tainted source-to-sink path!")

# Retrieve the full trace objects for the target line:
traces = result.get_taint_traces("app/controllers/orders.py", line=42)
for trace in traces:
    print(f"Source: {trace.source} -> Sink: {trace.sink}")
    for hop in trace.path:
        print(f"  Hop: {hop}")
```

### Entrypoint Reachability Inspection
```python
# Check if a file or symbol is reachable from any exposed public entrypoint:
if not result.is_reachable("app/utils/legacy_crypto.py", symbol="decrypt_token"):
    print("Function is dead code / unreachable from any API controller or CLI entrypoint.")
```

### SCA Package Reachability Bridge
```python
# Query whether a third-party dependency is reachable from external inputs:
if result.is_package_reachable("pyyaml"):
    print("Vulnerable package is reachable from an exposed entrypoint!")
else:
    print("Package is imported only in dead/internal paths: P3_JUSTIFIED.")

# Inspect the complete reachability summary across all detected packages:
for pkg, summary in result.dependency_usage.items():
    print(f"{pkg}: reachable={summary.is_reachable}, imports={summary.import_count}, sinks={summary.sinks_invoked}")
```

---

## 3. Serialization & Caching (`to_dict` / `from_dict` / `to_json` / `from_json`)

Persist and restore entire analysis results between pipeline stages without re-running AST parsing:

```python
# Export result to disk as deterministic JSON:
result.to_json(".secdiagram/analysis_cache.json")

# In a later process or downstream CLI:
cached_result = AnalysisResult.from_json(".secdiagram/analysis_cache.json")

# Full query API functions identically on deserialized results:
assert cached_result.has_taint_at("app/controllers/orders.py", line=42)
```

---

## 4. Pluggable Framework, Sanitizer & Sink Registry

Register custom internal frameworks, proprietary authentication decorators, sanitizers, or database sinks before executing analysis:

```python
from secdiagram_core.frameworks import (
    register_framework,
    register_sanitizer,
    register_sink,
)

# Register custom microservice conventions:
register_framework(
    name="internal-microservice",
    entrypoint_decorators=["@route", "@rpc_handler", "@aba_authorized"],
    sanitizers=["escape_sql", "sanitize_input"],
    sinks=["internal_db_execute", "vault_secret_query"],
)

# Register individual sanitizers or sinks:
register_sanitizer("custom_safe_serializer")
register_sink("dispatch_system_worker")
```

---

## 5. Rendering Diagrams Programmatically

Generate Mermaid syntax directly in Python:

```python
# Render standard detailed architecture flowchart:
mermaid_text = render_mermaid(result.graph)

# Render high-level C4 tier diagram:
from secdiagram_core.high_level import build_high_level_architecture, render_mermaid_highlevel

high_level_arch = build_high_level_architecture(result.graph, repo_dir=".")
c4_mermaid_text = render_mermaid_highlevel(high_level_arch)
```
