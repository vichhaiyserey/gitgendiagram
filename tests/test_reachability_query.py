"""Tests for native query helpers on AnalysisResult and Graph (taint & reachability)."""

from __future__ import annotations

import unittest
from pathlib import Path

from secdiagram_core import AnalysisConfig, run_analysis

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
SAMPLE_APP_DIR = FIXTURES_DIR / "sample_app"


class ReachabilityQueryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = run_analysis(AnalysisConfig(root=SAMPLE_APP_DIR, security=True))

    def test_has_taint_at(self) -> None:
        """Verifies querying taint presence by file and line number."""
        # Find a known finding in sample_app
        self.assertGreater(len(self.result.graph.findings), 0)
        finding = self.result.graph.findings[0]
        self.assertTrue(bool(finding.evidence))
        evidence = finding.evidence[0]

        # Target exact path and line
        has_taint = self.result.has_taint_at(evidence.path, evidence.line)
        self.assertTrue(has_taint)

        # Target file without line
        has_file_taint = self.result.has_taint_at(evidence.path)
        self.assertTrue(has_file_taint)

        # Target non-existent file
        self.assertFalse(self.result.has_taint_at("non_existent_file.py"))
        # Target non-existent line
        self.assertFalse(self.result.has_taint_at(evidence.path, line=999999))

    def test_get_taint_traces(self) -> None:
        """Verifies returning TaintTrace objects for triage service."""
        # Query traces for a known tainted file in sample_app
        traces = self.result.get_taint_traces("app/service.py")
        self.assertIsInstance(traces, list)
        self.assertGreater(len(traces), 0)

        trace = traces[0]
        self.assertTrue(trace.finding_id)
        self.assertTrue(trace.category)
        self.assertTrue(trace.severity)
        self.assertIsInstance(trace.trace, list)

        # Verify trace serialization to dict
        t_dict = trace.to_dict()
        self.assertEqual(t_dict["finding_id"], trace.finding_id)
        self.assertEqual(t_dict["category"], trace.category)

    def test_is_reachable_for_endpoints_and_symbols(self) -> None:
        """Verifies checking execution reachability from HTTP entrypoints."""
        # app/main.py contains entrypoint routes
        self.assertTrue(self.result.is_reachable("app/main.py"))

        # Non-existent file should be unreachable
        self.assertFalse(self.result.is_reachable("non_existent_path.py"))

    def test_package_reachability_indexing(self) -> None:
        """Verifies package & dependency reachability indexing for SCA bridge."""
        self.assertIsInstance(self.result.dependency_usage, dict)
        self.assertGreater(len(self.result.dependency_usage), 0)

        # In sample_app, fastapi is imported in app/main.py
        self.assertIn("fastapi", self.result.dependency_usage)
        fastapi_summary = self.result.dependency_usage["fastapi"]
        self.assertTrue(fastapi_summary.imported)
        self.assertTrue(fastapi_summary.reachable_from_entrypoint)
        self.assertGreater(len(fastapi_summary.import_sites), 0)

        # Helper method on result
        self.assertTrue(self.result.is_package_reachable("fastapi"))
        self.assertTrue(self.result.is_package_reachable("FastAPI"))  # Case insensitive
        self.assertTrue(self.result.is_package_reachable("yaml"))
        self.assertFalse(self.result.is_package_reachable("completely_unused_fictional_pkg"))
