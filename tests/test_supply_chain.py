from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXACT_PIN = re.compile(r"[A-Za-z0-9_.-]+(?:\[[^\]]+\])?==[0-9][^\s]*")
SHA_PIN = re.compile(r"[^@\s]+@[0-9a-f]{40}")
DIGEST_PIN = re.compile(r"[^@\s]+:[\w.-]+@sha256:[0-9a-f]{64}")


class SupplyChainPinTests(unittest.TestCase):
    def test_python_dependencies_are_exact_pins(self) -> None:
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        build = re.search(r"\[build-system\](.*?)(?:\n\[|\Z)", text, re.S)
        self.assertIsNotNone(build)
        requires_block = re.search(r"requires\s*=\s*\[(.*?)\]", build.group(1), re.S)
        self.assertIsNotNone(requires_block)
        build_requires = re.findall(r'"([^"]+)"', requires_block.group(1))
        self.assertTrue(build_requires)
        for requirement in build_requires:
            self.assertRegex(requirement.split(";", 1)[0].strip(), EXACT_PIN)

        dev = re.search(r"dev\s*=\s*\[(.*?)\n\]", text, re.S)
        self.assertIsNotNone(dev)
        dev_requires = re.findall(r'"([^"]+)"', dev.group(1))
        self.assertTrue(dev_requires)
        for requirement in dev_requires:
            self.assertRegex(requirement.split(";", 1)[0].strip(), EXACT_PIN)

    def test_github_actions_are_commit_pinned(self) -> None:
        workflows = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
        self.assertTrue(workflows)
        for workflow in workflows:
            for line in workflow.read_text(encoding="utf-8").splitlines():
                if "uses:" not in line:
                    continue
                reference = line.split("uses:", 1)[1].split("#", 1)[0].strip()
                self.assertRegex(reference, SHA_PIN, f"{workflow.name}: {line.strip()}")

    def test_container_images_are_digest_pinned(self) -> None:
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        from_lines = [line for line in dockerfile.splitlines() if line.startswith("FROM ")]
        self.assertTrue(from_lines)
        for line in from_lines:
            self.assertRegex(line.split()[1], DIGEST_PIN, line)

        for name in ("docker-compose.yml", "docker-compose.ollama.yml"):
            text = (ROOT / name).read_text(encoding="utf-8")
            images = re.findall(r"^\s*image:\s*(\S+)", text, re.M)
            for image in images:
                if image.startswith("secdiagram:"):
                    continue
                self.assertRegex(image, DIGEST_PIN, f"{name}: {image}")

    def test_mermaid_cli_uses_committed_lockfile(self) -> None:
        lock_path = ROOT / "docker" / "mermaid" / "package-lock.json"
        self.assertTrue(lock_path.exists())
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        self.assertEqual(lock["packages"][""]["dependencies"]["@mermaid-js/mermaid-cli"], "12.2.0")
        for name, package in lock["packages"].items():
            if not name:
                continue
            self.assertTrue(package.get("integrity"), name)
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("npm ci --omit=dev", dockerfile)
        self.assertNotIn("npm install -g", dockerfile)

    def test_agent_rule_enforces_image_vulnerability_gating(self) -> None:
        agents_text = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        self.assertIn("Rule 7: Mandatory Container Image Vulnerability Gating & Reachability Analysis", agents_text)
        self.assertIn("vserey/secdiagram", agents_text)
        self.assertIn("CRITICAL", agents_text)
        self.assertIn("HIGH", agents_text)
        self.assertIn("Contextual Reachability and Exploitability Analysis", agents_text)
        self.assertIn("not actually reachable and not exploitable", agents_text)

        contrib_text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        self.assertIn("Container Security & Image Vulnerability Gating", contrib_text)
        self.assertIn("vserey/secdiagram", contrib_text)

    def test_verification_includes_containerized_run_and_trivy_scan(self) -> None:
        agents_text = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        self.assertIn("Step 4: Run Containerized Build & Smoke Test Verification", agents_text)
        self.assertIn("docker run --rm secdiagram:verify --help", agents_text)
        self.assertIn("Step 5: Run Container Image Vulnerability Scan with Trivy", agents_text)
        self.assertIn("trivy image --severity CRITICAL,HIGH", agents_text)

        contrib_text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        self.assertIn("docker run --rm secdiagram:verify --help", contrib_text)
        self.assertIn(
            "trivy image --severity CRITICAL,HIGH --ignorefile .trivyignore.yaml "
            "--exit-code 1 secdiagram:verify",
            contrib_text,
        )

        docker_yml = (ROOT / ".github" / "workflows" / "docker.yml").read_text(encoding="utf-8")
        self.assertIn("Smoke test CLI", docker_yml)
        self.assertIn("Verify containerized diagram generation", docker_yml)
        self.assertIn("Trivy image scan", docker_yml)

        release_yml = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn("Smoke test CLI", release_yml)
        self.assertIn("Verify containerized diagram generation", release_yml)
        self.assertIn("Trivy image scan", release_yml)


    def test_trivy_scans_use_blocking_baseline(self) -> None:
        for name in ("docker.yml", "release.yml"):
            text = (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
            self.assertIn("trivyignores: .trivyignore.yaml", text, name)
            self.assertIn('exit-code: "1"', text, name)
            self.assertNotIn('exit-code: "0"', text, name)
            self.assertNotIn("ignore-unfixed", text, name)

    def test_trivy_baseline_entries_are_documented_and_expiring(self) -> None:
        text = (ROOT / ".trivyignore.yaml").read_text(encoding="utf-8")
        entries = re.findall(
            r"^\s*-\s*id:\s*(\S+)(.*?)(?=^\s*-\s*id:|\Z)", text, re.M | re.S
        )
        self.assertGreater(len(entries), 0)
        ids = [cve for cve, _ in entries]
        self.assertEqual(len(ids), len(set(ids)), "duplicate baseline entries")
        for cve, block in entries:
            self.assertRegex(cve, r"^CVE-\d{4}-\d+$")
            self.assertIn("statement:", block, cve)
            self.assertRegex(block, r"expired_at:\s*\d{4}-\d{2}-\d{2}", cve)

    def test_scheduled_image_scan_exists(self) -> None:
        text = (ROOT / ".github" / "workflows" / "image-scan.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("schedule:", text)
        self.assertIn("cron:", text)
        self.assertIn("vserey/secdiagram:latest", text)
        self.assertIn("trivyignores: .trivyignore.yaml", text)
        self.assertIn('exit-code: "1"', text)

    def test_refresh_script_refuses_fixable_findings(self) -> None:
        report = {
            "Results": [
                {
                    "Target": "image",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2099-0001",
                            "PkgName": "zlib1g",
                            "Severity": "HIGH",
                            "FixedVersion": "1.2.3-1",
                            "Status": "fixed",
                        }
                    ],
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "scan.json"
            output = Path(tmp) / ".trivyignore.yaml"
            source.write_text(json.dumps(report), encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "refresh_image_baseline.py"),
                    str(source),
                    "--expires",
                    "2099-01-01",
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("Refusing to baseline fixable", proc.stderr)
            self.assertFalse(output.exists())

    def test_refresh_script_writes_unfixed_baseline(self) -> None:
        report = {
            "Results": [
                {
                    "Target": "image",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2099-0002",
                            "PkgName": "perl",
                            "Severity": "HIGH",
                            "Status": "affected",
                        }
                    ],
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "scan.json"
            output = Path(tmp) / ".trivyignore.yaml"
            source.write_text(json.dumps(report), encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "refresh_image_baseline.py"),
                    str(source),
                    "--expires",
                    "2099-01-01",
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            text = output.read_text(encoding="utf-8")
            self.assertIn("CVE-2099-0002", text)
            self.assertIn("statement:", text)
            self.assertIn("expired_at: 2099-01-01", text)

    def test_dependabot_ignores_node_major_updates(self) -> None:
        text = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
        self.assertIn('dependency-name: "node"', text)
        self.assertIn('"version-update:semver-major"', text)


if __name__ == "__main__":
    unittest.main()
