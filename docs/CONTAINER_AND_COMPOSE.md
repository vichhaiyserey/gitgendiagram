# 🐳 Container & Docker Compose Guide

`secdiagram` provides an enterprise-ready, hardened multi-stage container image built on digest-pinned base images (`python:3.12-slim` and `node:24-slim`). It executes securely as an unprivileged non-root user (`secdiagram`, `uid=10001`) with dropped Linux capabilities and comes pre-bundled with `@mermaid-js/mermaid-cli` and Chromium for **100% offline diagram image rendering**.

---

## 1. Standalone Container Execution (Docker & Podman)

Mount your target project to `/repo` (the container's default `WORKDIR`).

### Build Local Candidate Image
```bash
docker build -t secdiagram:local .
```

### OS & Shell Command Matrix

| Operating System / Shell | Command |
| :--- | :--- |
| **Linux & macOS (bash / zsh)** | `docker run --rm -v "$(pwd):/repo" secdiagram:local --image` |
| **Windows PowerShell** | `docker run --rm -v "${PWD}:/repo" secdiagram:local --image` |
| **Windows Command Prompt (CMD)** | `docker run --rm -v "%cd%:/repo" secdiagram:local --image` |
| **RHEL / Fedora / CentOS (SELinux)** | `docker run --rm -v "$(pwd):/repo:z" secdiagram:local --image` |
| **Podman (Rootless)** | `podman run --rm -v "$(pwd):/repo:z" secdiagram:local --image` |

### Windows Git Bash Path Auto-Recovery

Git Bash on Windows translates POSIX-style paths (such as `/repo` to `C:/Program Files/Git/repo`), which can break volume mounts in some container engines.
`secdiagram` has built-in MSYS path auto-recovery. You can:
1. Omit `--dir` entirely (the container defaults to the mounted repository `/repo` as working directory).
2. Or use double slashes:
```bash
docker run --rm -v "/$(pwd):/repo" secdiagram:local --dir //repo --image
```

---

## 2. Multi-Service Docker Compose with Local Ollama (Qwen)

Run `secdiagram` alongside a companion Ollama container over an isolated internal bridge network for offline, evidence-grounded AI architectural reviews:

### Step 1: Start Ollama
```bash
docker compose up -d ollama
```

### Step 2: Pull the Coding Model
```bash
docker compose exec ollama ollama pull qwen2.5-coder
```

### Step 3: Run Architecture & Threat Modeling Review
```bash
docker compose run --rm secdiagram --ollama qwen2.5-coder --llm-template comprehensive --image
```

### Specialized LLM Review Profiles (`--llm-template`)

- **`comprehensive` (default)**:
  1. Executive Summary & Security Posture Scorecard
  2. Attack Surface Catalog & Ingress Points (`path:line`)
  3. Trust Boundaries & Component Data Flow Analysis
  4. Deep-Dive Threat Modeling (STRIDE / CWE)
  5. Infrastructure, Supply Chain & IaC Posture
  6. Prioritized Remediation Roadmap (P0 / P1 / P2)
- **`threat-model`**: Formal STRIDE threat matrix and trust-boundary crossings.
- **`remediation`**: Vulnerability fix guide with secure drop-in code replacements.
- **`compliance`**: Formal audit mapping against OWASP Top 10 (2021) and CIS Software Benchmarks.

> [!NOTE]
> **Strict Anti-Hallucination Guardrails**: The LLM prompt enforces that every finding, component, and flow must cite an exact `path:line` present in the deterministic graph.

---

## 3. Container Security & Hardening Properties

- **Non-Root Execution**: Runs as user `secdiagram` (`uid=10001`, `gid=10001`).
- **Read-Only Compatibility**: Container filesystem can be mounted read-only with ephemeral writable `/tmp` for Chromium renderer caches.
- **Vulnerability Gating**: Strict policy against Critical and High vulnerabilities (scanned via Trivy).
- **Offline Operation**: Pre-bundled Chromium and `@mermaid-js/mermaid-cli` eliminate any internet connectivity requirement during diagram generation.
