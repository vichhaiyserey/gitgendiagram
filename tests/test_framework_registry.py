"""Tests for custom framework, sanitizer, and sink registry."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from secdiagram_core.ast_index import index_repo
from secdiagram_core.frameworks import (
    annotate,
    get_registered_frameworks,
    get_registered_sanitizers,
    get_registered_sinks,
    load_frameworks_config,
    register_framework,
    register_sanitizer,
    register_sink,
    reset_registry,
)
from secdiagram_core.model import Graph
from secdiagram_core.resolver import Resolver
from secdiagram_core.security import analyze as analyze_security


class FrameworkRegistryTests(unittest.TestCase):
    def tearDown(self) -> None:
        reset_registry()

    def test_register_framework_and_custom_entrypoint(self) -> None:
        """Verifies custom decorators register as entrypoints in AST annotation."""
        register_framework(
            name="internal-microservice",
            entrypoint_decorators=["@rpc_handler", "@aba_authorized"],
            sanitizers=["escape_sql", "sanitize_input"],
            sinks=["internal_db_execute", "vault_secret_query"],
        )

        self.assertIn("rpc_handler", [f.entrypoint_decorators[0].lstrip("@") for f in get_registered_frameworks()])
        self.assertIn("escape_sql", get_registered_sanitizers())
        self.assertIn("internal_db_execute", get_registered_sinks())

        # Test AST annotation with custom decorator
        with tempfile.TemporaryDirectory() as tmp:
            file_path = Path(tmp) / "service.py"
            file_path.write_text(
                "def not_an_endpoint():\n"
                "    pass\n\n"
                "@rpc_handler\n"
                "def custom_handler():\n"
                "    pass\n",
                encoding="utf-8",
            )
            indexes = index_repo(Path(tmp), ["service.py"])
            annotate(indexes)

            def_rec = next(d for d in indexes["service.py"].defs if d.name == "custom_handler")
            self.assertEqual(def_rec.kind, "endpoint")
            self.assertTrue(bool(def_rec.routes))

    def test_custom_sanitizer_clears_taint(self) -> None:
        """Verifies that registered custom sanitizers eliminate false positive taint alerts."""
        register_sanitizer("sanitize_cmd")

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "cmd.py"
            p.write_text(
                "import os\n"
                "def run_action():\n"
                "    cmd = request.args.get('c')\n"
                "    safe_cmd = sanitize_cmd(cmd)\n"
                "    os.system(safe_cmd)\n",
                encoding="utf-8",
            )
            indexes = index_repo(Path(tmp), ["cmd.py"])
            resolver = Resolver(indexes)
            graph = Graph()
            findings = analyze_security(graph, indexes, resolver, Path(tmp), ["cmd.py"])
            cmd_findings = [f for f in findings if f.category == "command"]
            self.assertEqual(len(cmd_findings), 0)

    def test_custom_sink_triggers_finding(self) -> None:
        """Verifies that tainted input flowing into a registered custom sink triggers a finding."""
        register_sink("internal_db_execute", category="sql", severity="critical")

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "api.py"
            p.write_text(
                "def api_action():\n"
                "    user_input = request.args.get('q')\n"
                "    internal_db_execute(user_input)\n",
                encoding="utf-8",
            )
            indexes = index_repo(Path(tmp), ["api.py"])
            resolver = Resolver(indexes)
            graph = Graph()
            findings = analyze_security(graph, indexes, resolver, Path(tmp), ["api.py"])
            custom_findings = [f for f in findings if "internal_db_execute" in f.title]
            self.assertGreater(len(custom_findings), 0)
            finding = custom_findings[0]
            self.assertEqual(finding.severity, "critical")
            self.assertEqual(finding.category, "sql")

    def test_load_frameworks_config_from_yaml_file(self) -> None:
        """Verifies loading .secdiagram.yml config file in repo root."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            yaml_content = (
                "# Custom config\n"
                "frameworks:\n"
                "  - name: my-framework\n"
                "    entrypoint_decorators:\n"
                "      - @my_route\n"
                "    sanitizers:\n"
                "      - my_escape\n"
                "    sinks:\n"
                "      - my_db_sink\n"
            )
            (root / ".secdiagram.yml").write_text(yaml_content, encoding="utf-8")

            load_frameworks_config(root)

            self.assertIn("my_escape", get_registered_sanitizers())
            self.assertIn("my_db_sink", get_registered_sinks())
