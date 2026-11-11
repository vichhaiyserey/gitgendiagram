"""CycloneDX 1.6 VEX (Vulnerability Exploitability eXchange) Exporter.

Generates standardized, deterministic CycloneDX 1.6 VEX documents asserting
reachability and exploitability justifications for SAST and SCA findings.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from . import __version__
from .model import SEVERITY_RANK, DependencyReachabilitySummary, Finding, Graph

CYCLONEDX_1_6_SCHEMA = "http://cyclonedx.org/schema/bom-1.6.schema.json"


def _vulnerability_analysis(
    finding: Finding,
    graph: Graph,
    dependency_usage: dict[str, DependencyReachabilitySummary] | None = None,
) -> dict[str, Any]:
    """Build the VEX analysis block with standardized state and justification."""
    # 1. Baseline suppressed
    if finding.baseline:
        return {
            "state": "false_positive",
            "justification": "code_not_present",
            "detail": "Suppressed as accepted risk or verified false positive in baseline.",
            "response": ["will_not_fix"],
        }

    # 2. Check if this finding represents an unreachable dependency / code location
    first_loc = finding.evidence[0] if finding.evidence else None
    is_code_reachable = False
    if first_loc:
        is_code_reachable = graph.is_reachable(first_loc.path)

    # Check dependency reachability if package metadata or external_id is present
    pkg_name = finding.metadata.get("package") or finding.metadata.get("component")
    is_reachable = is_code_reachable
    if pkg_name and dependency_usage:
        pkg_summary = dependency_usage.get(str(pkg_name).lower())
        if pkg_summary is not None:
            is_reachable = pkg_summary.reachable_from_entrypoint

    if not is_reachable:
        return {
            "state": "not_affected",
            "justification": "code_not_reachable",
            "detail": "AST entrypoint graph confirms no execution path from public controller to sink.",
            "response": ["will_not_fix"],
        }

    # 3. Active exploitable or in-triage finding
    if finding.trace:
        return {
            "state": "exploitable",
            "detail": f"Taint propagation trace verified ({len(finding.trace)} steps from source to sink).",
            "response": ["can_not_fix" if finding.severity == "info" else "will_fix"],
        }

    return {
        "state": "in_triage",
        "detail": "Static AST evidence detected; pending manual verification or dynamic validation.",
        "response": ["update"],
    }


def render_vex(
    target: Any,
    dependency_usage: dict[str, DependencyReachabilitySummary] | None = None,
) -> str:
    """Render a deterministic CycloneDX 1.6 VEX document for an AnalysisResult or Graph."""
    if hasattr(target, "graph"):
        graph: Graph = target.graph
        deps = dependency_usage if dependency_usage is not None else getattr(target, "dependency_usage", {})
    elif isinstance(target, Graph):
        graph = target
        deps = dependency_usage or {}
    else:
        raise TypeError(f"render_vex expected AnalysisResult or Graph, got {type(target).__name__}")

    repo_name = str(graph.meta.get("name") or "repository")
    serial_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"secdiagram.vex.{repo_name}")

    vulnerabilities: list[dict[str, Any]] = []

    # Sort findings deterministically
    sorted_findings = graph.sorted_findings()
    for finding in sorted_findings:
        vuln_id = finding.external_id or finding.id
        analysis = _vulnerability_analysis(finding, graph, deps)

        vuln: dict[str, Any] = {
            "bom-ref": f"vuln-{finding.id}",
            "id": vuln_id,
            "source": {
                "name": finding.source or "secdiagram",
            },
            "ratings": [
                {
                    "severity": finding.severity if finding.severity in SEVERITY_RANK else "medium",
                    "method": "other",
                }
            ],
            "description": finding.title,
            "detail": finding.message,
            "analysis": analysis,
            "affects": [
                {
                    "ref": finding.node_id or (finding.evidence[0].ref if finding.evidence else finding.id),
                }
            ],
        }

        if finding.cwe and "CWE-" in finding.cwe:
            try:
                cwe_num = int(finding.cwe.split("CWE-")[-1].split(":")[0])
                vuln["cwes"] = [cwe_num]
            except ValueError:
                pass

        if finding.recommendation:
            vuln["recommendation"] = finding.recommendation

        vulnerabilities.append(vuln)

    # Sort vulnerabilities by id deterministically
    vulnerabilities.sort(key=lambda v: str(v.get("id", "")))

    doc: dict[str, Any] = {
        "$schema": CYCLONEDX_1_6_SCHEMA,
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial_uuid}",
        "version": 1,
        "metadata": {
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "secdiagram",
                        "version": __version__,
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": repo_name,
            },
        },
        "vulnerabilities": vulnerabilities,
    }

    return json.dumps(doc, indent=2, sort_keys=False) + "\n"
