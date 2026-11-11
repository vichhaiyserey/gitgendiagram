"""Tests for AnalysisResult serialization and cache round-tripping."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from secdiagram_core import AnalysisConfig, AnalysisResult, run_analysis

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
SAMPLE_APP_DIR = FIXTURES_DIR / "sample_app"


class CacheSerializationTests(unittest.TestCase):
    def test_analysis_result_dict_and_json_roundtrip(self) -> None:
        """Verifies that AnalysisResult can be serialized to JSON/dict and restored losslessly."""
        original = run_analysis(AnalysisConfig(root=SAMPLE_APP_DIR, security=True))

        # 1. to_dict / from_dict
        data = original.to_dict()
        self.assertIsInstance(data, dict)
        self.assertEqual(data["repo"]["name"], original.repo.name)
        self.assertEqual(len(data["graph"]["nodes"]), len(original.graph.nodes))
        self.assertEqual(len(data["graph"]["edges"]), len(original.graph.edges))
        self.assertEqual(len(data["graph"]["findings"]), len(original.graph.findings))

        restored_from_dict = AnalysisResult.from_dict(data)
        self.assertEqual(restored_from_dict.repo.name, original.repo.name)
        self.assertEqual(len(restored_from_dict.graph.nodes), len(original.graph.nodes))
        self.assertEqual(len(restored_from_dict.graph.edges), len(original.graph.edges))
        self.assertEqual(len(restored_from_dict.graph.findings), len(original.graph.findings))

        # Query methods work on restored object
        self.assertEqual(
            restored_from_dict.has_taint_at("app.py"),
            original.has_taint_at("app.py"),
        )
        self.assertEqual(
            restored_from_dict.is_package_reachable("flask"),
            original.is_package_reachable("flask"),
        )

        # 2. to_json / from_json with file path
        with tempfile.TemporaryDirectory() as tmp:
            json_path = Path(tmp) / "cache" / "analysis_result.json"
            original.to_json(json_path)
            self.assertTrue(json_path.exists())

            restored_from_file = AnalysisResult.from_json(json_path)
            self.assertEqual(len(restored_from_file.graph.nodes), len(original.graph.nodes))
            self.assertEqual(len(restored_from_file.graph.findings), len(original.graph.findings))

            # 3. from_json with string payload
            raw_json = json_path.read_text(encoding="utf-8")
            restored_from_str = AnalysisResult.from_json(raw_json)
            self.assertEqual(len(restored_from_str.graph.nodes), len(original.graph.nodes))
