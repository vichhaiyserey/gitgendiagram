"""Consumer Contract Test Suite.

Verifies that all classes, functions, attributes, and shapes consumed by downstream
toolkits (such as devsecops-toolkit) remain stable and backward-compatible.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from secdiagram_core import (
    AnalysisResult as FacadeAnalysisResult,
)
from secdiagram_core import (
    analyze,
    render_mermaid,
)
from secdiagram_core.analyzer import (
    AnalysisConfig,
    AnalysisResult,
    run_analysis,
)
from secdiagram_core.high_level import (
    HighLevelArchitecture,
    build_high_level_architecture,
    render_mermaid_highlevel,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
SAMPLE_APP_DIR = FIXTURES_DIR / "sample_app"


class ConsumerContractTests(unittest.TestCase):
    def test_downstream_consumer_contract(self) -> None:
        """Verifies that attributes consumed by devsecops-toolkit remain present and valid."""
        # 1. AnalysisConfig constructor contract
        config = AnalysisConfig(
            root=SAMPLE_APP_DIR,
            security=True,
            include=[],
            exclude=[],
        )
        self.assertIsInstance(config, AnalysisConfig)
        self.assertEqual(config.root, SAMPLE_APP_DIR)
        self.assertTrue(config.security)

        # 2. run_analysis contract
        result = run_analysis(config)
        self.assertIsInstance(result, AnalysisResult)
        self.assertIsInstance(result, FacadeAnalysisResult)

        # 3. graph.nodes contract
        self.assertIsInstance(result.graph.nodes, dict)
        self.assertGreater(len(result.graph.nodes), 0)
        sample_node = next(iter(result.graph.nodes.values()))
        self.assertTrue(hasattr(sample_node, "id"))
        self.assertTrue(hasattr(sample_node, "kind"))
        self.assertTrue(hasattr(sample_node, "name"))
        self.assertTrue(hasattr(sample_node, "qualname"))
        self.assertTrue(hasattr(sample_node, "path"))
        self.assertTrue(hasattr(sample_node, "line"))

        # 4. graph.edges contract
        self.assertIsInstance(result.graph.edges, list)
        self.assertGreater(len(result.graph.edges), 0)
        sample_edge = result.graph.edges[0]
        self.assertTrue(hasattr(sample_edge, "src"))
        self.assertTrue(hasattr(sample_edge, "dst"))
        self.assertTrue(hasattr(sample_edge, "kind"))
        self.assertTrue(hasattr(sample_edge, "confidence"))

        # 5. graph.findings contract (loc.path, loc.line, finding.trace)
        self.assertIsInstance(result.graph.findings, list)
        self.assertGreater(len(result.graph.findings), 0)
        for finding in result.graph.findings:
            self.assertTrue(hasattr(finding, "id"))
            self.assertTrue(hasattr(finding, "category"))
            self.assertTrue(hasattr(finding, "severity"))
            self.assertTrue(hasattr(finding, "evidence"))
            self.assertTrue(hasattr(finding, "trace"))
            self.assertIsInstance(finding.trace, list)
            if finding.evidence:
                loc = finding.evidence[0]
                self.assertTrue(hasattr(loc, "path"))
                self.assertTrue(hasattr(loc, "line"))
                self.assertIsInstance(loc.path, str)
                self.assertIsInstance(loc.line, int)

        # 6. High-level architecture compilation and rendering contract
        hla = build_high_level_architecture(SAMPLE_APP_DIR, result.graph)
        self.assertIsInstance(hla, HighLevelArchitecture)
        self.assertTrue(hasattr(hla, "subsystems"))
        self.assertTrue(hasattr(hla, "connections"))

        mermaid_hl = render_mermaid_highlevel(hla)
        self.assertIsInstance(mermaid_hl, str)
        self.assertIn("flowchart", mermaid_hl)

        # 7. Facade polymorphic render_mermaid contract
        rendered_from_result = render_mermaid(result)
        self.assertIsInstance(rendered_from_result, str)
        self.assertIn("flowchart", rendered_from_result)

        rendered_from_hla = render_mermaid(hla)
        self.assertIsInstance(rendered_from_hla, str)
        self.assertIn("flowchart", rendered_from_hla)

        rendered_from_graph = render_mermaid(result.graph)
        self.assertIsInstance(rendered_from_graph, str)

        # 8. Facade analyze() wrapper contract
        analyzed = analyze(SAMPLE_APP_DIR)
        self.assertIsInstance(analyzed, AnalysisResult)
        self.assertEqual(len(analyzed.graph.nodes), len(result.graph.nodes))

    def test_backward_compatibility_cross_module_shims(self) -> None:
        """Verifies that imports across analyzer and high_level modules continue working via shims."""
        from secdiagram_core.analyzer import (  # type: ignore[attr-defined]
            analyze as analyzer_analyze,
        )
        from secdiagram_core.analyzer import (
            build_high_level_architecture as shim_bhla,
        )
        from secdiagram_core.analyzer import (
            render_mermaid_highlevel as shim_rmhl,
        )
        from secdiagram_core.high_level import (  # type: ignore[attr-defined]
            AnalysisConfig as hl_AnalysisConfig,
        )
        from secdiagram_core.high_level import (
            AnalysisResult as hl_AnalysisResult,
        )
        from secdiagram_core.high_level import (
            analyze as hl_analyze,
        )
        from secdiagram_core.high_level import (
            run_analysis as hl_run_analysis,
        )

        self.assertIs(analyzer_analyze, analyze)
        self.assertIs(shim_bhla, build_high_level_architecture)
        self.assertIs(shim_rmhl, render_mermaid_highlevel)
        self.assertIs(hl_AnalysisConfig, AnalysisConfig)
        self.assertIs(hl_AnalysisResult, AnalysisResult)
        self.assertIs(hl_run_analysis, run_analysis)
        self.assertIs(hl_analyze, analyze)
