# 🛡️ Security & IaC Static Analysis Guide

`secdiagram` provides deterministic static security analysis across application code, third-party dependencies, and infrastructure configurations without running or executing any untrusted code.

---

## 1. Application Security Rules (SAST)

The static analysis engine inspects Python and Java/Spring ASTs to detect security vulnerabilities, untrusted source-to-sink dataflows, and dangerous configurations:

| Category | CWE | Patterns Detected | Default Severity |
| :--- | :--- | :--- | :--- |
| **Command Injection** | CWE-78 | `subprocess` with `shell=True`, `os.system`, `os.popen`, `eval`, `exec` with tainted variables | Critical / High |
| **SQL Injection** | CWE-89 | Raw SQL string interpolation, f-strings, `%` formatting in DB executions | High |
| **Unsafe Deserialization** | CWE-502 | `pickle.loads`, `yaml.load` without `SafeLoader` | Critical / High |
| **Path Traversal** | CWE-22 | Unsanitized file path joins (`os.path.join`, `open`, `Path`) with user inputs | High |
| **Weak Cryptography** | CWE-327 | Use of `MD5`, `SHA1` for security contexts, hardcoded AES ECB mode | Medium |
| **Hardcoded Secrets** | CWE-798 | Embedded API keys, AWS tokens, private keys, populated `.env` files | High / Medium |
| **SSRF** | CWE-918 | Outgoing HTTP requests using unvalidated user input | High |
| **Cross-Site Scripting** | CWE-79 | Rendering raw user input into HTML/templates without escaping | High / Medium |

Findings carry full source-to-sink taint paths (`codeFlows`), exact `path:line` citations, and stable partial fingerprints.

---

## 2. Infrastructure-as-Code (IaC) Rules

The engine audits infrastructure files for security misconfigurations:

- **Dockerfile**:
  - Root user execution (`USER root` or missing non-root `USER` directive).
  - Unpinned base image tags (e.g. `:latest`).
  - Sensitive files copied into image contexts.
  - Exposed privileged ports.
- **Kubernetes Manifests**:
  - Containers running without `runAsNonRoot: true`.
  - Privileged containers (`privileged: true`).
  - Dangerous capabilities (e.g. `SYS_ADMIN`).
  - Missing CPU and memory resource limits.
- **Terraform**:
  - S3 buckets configured with public read/write ACLs.
  - Unrestricted security group ingress (`0.0.0.0/0`).
  - Unencrypted storage volumes or databases.
- **GitHub Actions Workflows**:
  - `pull_request_target` triggers combined with explicit repository checkouts of untrusted code.
  - Inline script executions referencing untrusted pull request title/body expressions.

---

## 3. External Scanner Import (SonarQube & JFrog Xray)

Merge existing scanner findings into `secdiagram`'s deterministic graph, SARIF output, and architecture overlays:

```bash
# Import SonarQube issues and JFrog Xray violations with local CISA KEV validation:
secdiagram --sonarqube-report sonar-issues.json \
  --xray-report xray-violations.json \
  --advisory-db cisa-kev.json \
  --format json,md,sarif
```

- **SonarQube**: Tolerates both `{"issues": [...]}` wrappers and bare issue arrays. Security vulnerabilities and hotspots are mapped; closed, false-positive, and won't-fix issues are skipped.
- **JFrog Xray**: Accepts `violations` wrappers or component/artifact maps. Preserves package, version, CVSS score, fixed versions, and CVE identifiers.
- **Advisory Database Validation**: Corroborates CVEs against local CISA KEV, NVD, or OSV JSON files. KEV matches force `critical` severity (confidence `0.98`); multi-source matches elevate confidence to `0.97`. No outbound network calls are made.

---

## 4. Standalone Security Review (`--security-report`)

Generate a print-first security review artifact that is separate from the architectural diagram:

```bash
secdiagram --dir . --security-report both --format sarif --fail-on high
```

This writes:
- `security-report.html` — Static, A4-printable HTML report with no CDN or JavaScript dependency.
- `SECURITY_REVIEW.md` — The same review formatted in GitHub-flavored Markdown.
- `security.sarif` — OASIS SARIF v2.1.0 machine-readable export.

### Transparent Risk Index
Calculated as:
$$\text{Risk Index} = \min(100, 20 \times \text{critical} + 8 \times \text{high} + 3 \times \text{medium} + 1 \times \text{low})$$
The risk label floors at **High** for any critical finding and **Moderate** for any high finding. Baseline-suppressed findings are excluded from the risk index but retained in the evidence appendix.

---

## 5. CycloneDX 1.6 VEX Export (`--format vex`)

Generate machine-readable Vulnerability Exploitability eXchange (VEX) documents under the **CycloneDX 1.6** specification:

```bash
secdiagram --dir . --format vex --out .secdiagram
```

When a vulnerability or finding is located in code or dependencies that are unreachable from any exposed entrypoint (e.g. dead code or internal non-invoked modules), `secdiagram` automatically exports:

```json
{
  "analysis": {
    "state": "not_affected",
    "justification": "code_not_reachable",
    "detail": "AST entrypoint graph confirms no execution path from public controller to sink."
  }
}
```

This allows downstream triage tools and SBOM scanners to automatically justify non-exploitable findings without manual analyst overhead.

---

## 6. Pluggable Framework, Sanitizer & Sink Registry

Extend `secdiagram`'s detection heuristics to recognize internal microservice frameworks, custom authentication decorators, or proprietary sanitization functions.

### Configuration via `.secdiagram.yml`

Create a `.secdiagram.yml` file in the repository root:

```yaml
frameworks:
  - name: "internal-rpc"
    entrypoint_decorators:
      - "@rpc_handler"
      - "@microservice_endpoint"
    sanitizers:
      - "sanitize_db_input"
      - "clean_sql"
    sinks:
      - "internal_db_execute"
      - "vault_secret_query"

sanitizers:
  - "custom_html_escape"
  - "safe_str"

sinks:
  - "raw_system_call"
  - "dispatch_untrusted_command"
```

### Programmatic Python Registry

You can also register custom rules programmatically:

```python
from secdiagram_core.frameworks import register_framework, register_sanitizer, register_sink

register_framework(
    name="custom-gateway",
    entrypoint_decorators=["@route", "@api_action"],
    sanitizers=["escape_sql", "strip_tags"],
    sinks=["query_db", "exec_cmd"],
)

register_sanitizer("my_custom_sanitizer")
register_sink("my_custom_sink")
```

---

## 7. Security Baseline (`security.baseline.json`)

Establish a baseline of known, accepted findings to prevent breaking CI on legacy issues:

```bash
# 1. Create baseline from current scan:
secdiagram --dir . --create-baseline

# 2. In CI: fail only if NEW findings are introduced:
secdiagram --dir . --baseline .secdiagram/security.baseline.json --fail-on high
```

The baseline uses deterministic location and finding fingerprints. Suppressed counts are reported in all output artifacts.
