"""Tests for CycloneDX 1.6 VEX exporter and CLI --format vex."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from secdiagram_core import AnalysisConfig, render_vex, run_analysis
from secdiagram_core.cli import main
from secdiagram_core.model import Finding, Graph, Loc, Node

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
SAMPLE_APP_DIR = FIXTURES_DIR / "sample_app"


class VexExporterTests(unittest.TestCase):
    def test_render_vex_cyclonedx_1_6_schema(self) -> None:
        """Verifies that render_vex emits standard CycloneDX 1.6 VEX JSON."""
        result = run_analysis(AnalysisConfig(root=SAMPLE_APP_DIR, security=True))
        vex_json = render_vex(result)
        self.assertIsInstance(vex_json, str)

        data = json.loads(vex_json)
        self.assertEqual(data["bomFormat"], "CycloneDX")
        self.assertEqual(data["specVersion"], "1.6")
        self.assertEqual(data["version"], 1)
        self.assertTrue(data["serialNumber"].startswith("urn:uuid:"))
        self.assertEqual(data["metadata"]["tools"]["components"][0]["name"], "secdiagram")
        self.assertIsInstance(data["vulnerabilities"], list)

        # Check vulnerability entries
        if data["vulnerabilities"]:
            vuln = data["vulnerabilities"][0]
            self.assertTrue(vuln["id"])
            self.assertIn("analysis", vuln)
            self.assertIn("state", vuln["analysis"])
            self.assertIn(vuln["analysis"]["state"], {"exploitable", "in_triage", "not_affected", "false_positive"})

    def test_unreachable_code_vex_justification(self) -> None:
        """Verifies that unreachable findings are emitted with code_not_reachable justification."""
        graph = Graph()
        graph.meta["name"] = "test-repo"
        # Add public entrypoint
        graph.add_node(
            Node(
                id="ep1",
                kind="endpoint",
                name="get_user",
                qualname="app.main.get_user",
                path="app/main.py",
                line=10,
            )
        )
        # Add finding in an unreachable file without connection to entrypoint
        unreachable_finding = Finding(
            id="FINDING-UNREACHABLE-1",
            category="sql",
            severity="high",
            title="Unreachable SQL injection",
            message="Raw query executed in dead module",
            evidence=[Loc(path="dead_code/query.py", line=42)],
        )
        graph.findings.append(unreachable_finding)

        vex_json = render_vex(graph)
        data = json.loads(vex_json)
        vuln = next(v for v in data["vulnerabilities"] if v["id"] == "FINDING-UNREACHABLE-1")

        self.assertEqual(vuln["analysis"]["state"], "not_affected")
        self.assertEqual(vuln["analysis"]["justification"], "code_not_reachable")
        self.assertIn("no execution path", vuln["analysis"]["detail"])

    def test_cli_format_vex(self) -> None:
        """Verifies CLI flag --format vex writes vex.json to output directory."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["--dir", str(SAMPLE_APP_DIR), "--out", str(out), "--format", "vex,json", "--quiet"])
            self.assertEqual(code, 0)

            vex_file = out / "vex.json"
            self.assertTrue(vex_file.exists())
            data = json.loads(vex_file.read_text(encoding="utf-8"))
            self.assertEqual(data["bomFormat"], "CycloneDX")
            self.assertEqual(data["specVersion"], "1.6")
