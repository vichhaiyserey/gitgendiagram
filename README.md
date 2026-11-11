<div align="center">

# ⚡ secdiagram

### *Small but Gold* — Deterministic Architecture Diagrams, Polyglot System Mapping, and Security Intelligence.

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Standard%20Library%20Only-success.svg?style=flat-square)](pyproject.toml)
[![Tests](https://img.shields.io/badge/Tests-254%2F254%20Passing-brightgreen.svg?style=flat-square)](tests/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?style=flat-square&logo=docker&logoColor=white)](Dockerfile)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Cross Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Ubuntu%20%7C%20RHEL%20%7C%20Windows-blueviolet.svg?style=flat-square)](docs/CONTAINER_AND_COMPOSE.md)

<p align="center">
  <b>Transform codebases into clear, human-friendly system architecture diagrams, publication-quality images, security threat models, and AI reviews.</b><br>
  <i>100% offline-first. Zero external Python runtime dependencies. Polyglot support across <b>.NET (C#)</b>, <b>Java / Spring Boot</b>, <b>Node.js / TypeScript</b>, <b>Python</b>, and <b>Docker / Kubernetes / Terraform</b>.</i>
</p>

---

</div>

## 🌟 Key Highlights

- **Pure Python Standard Library (`zero dependencies`)**: Runs instantly without downloading hundreds of megabytes of third-party wheels. Zero supply chain attack surface.
- **High-Level C4 System Diagrams**: Automatically compiles clean C4 tier diagrams (`diagram-highlevel.mmd` & `diagram-highlevel.png`) showing Ingress, Gateways, Core Services, Databases, Caches, Brokers, and External APIs.
- **Multi-Format Image Rendering**: Export diagrams directly to **PNG**, **SVG**, or **PDF** offline via bundled Mermaid CLI (`mmdc`) or zero-dependency HTTP fallbacks (Kroki, mermaid.ink).
- **Security & IaC SAST Overlay**: Discovers entrypoints, traces taint dataflows to dangerous sinks (CWE-78, CWE-89, CWE-502), catches hardcoded secrets, and audits Dockerfile, Kubernetes, Terraform, and GitHub Actions configurations.
- **CycloneDX 1.6 VEX & SARIF Export**: Generates industry-standard `security.sarif` and CycloneDX 1.6 VEX documents (`vex.json`) with automated reachability justifications (`code_not_reachable`) for dead/internal code.
- **AI Architectural & Threat Modeling Reviews**: Integrates with local/containerized **Ollama (Qwen, LLaMA, DeepSeek)** or OpenAI endpoints to generate evidence-grounded architectural reviews citing exact `path:line` with zero hallucinations.
- **100% Deterministic & Air-Gapped**: Byte-for-byte reproducible outputs across runs. Fully functional in offline, isolated, or air-gapped environments.

---

## 🚀 Quick Start

### 1. Instant Run (Python 3.10+)

Because `secdiagram` requires **only the Python standard library**, run it directly without installing third-party dependencies:

```bash
# Analyze current repository and generate detailed architecture diagrams:
python secdiagram.py --dir="."

# Generate both detailed and high-level C4 system diagrams with PNG images:
python secdiagram.py --dir="." --image

# Generate high-level system overview as primary diagram:
python secdiagram.py --dir="." --high-level --image
```

### 2. Standalone Container Execution (Docker / Podman)

Run using the pre-built, hardened non-root container with bundled Chromium and Mermaid CLI:

```bash
# Linux / macOS:
docker run --rm -v "$(pwd):/repo" secdiagram:local --image

# Windows PowerShell:
docker run --rm -v "${PWD}:/repo" secdiagram:local --image

# RHEL / Fedora (SELinux mode):
docker run --rm -v "$(pwd):/repo:z" secdiagram:local --image
```

### 3. Python Public Facade

Integrate directly into custom automation scripts or DevSecOps pipelines:

```python
from secdiagram_core import analyze, render_mermaid, AnalysisConfig

result = analyze(AnalysisConfig(root=".", security=True))
print(f"Discovered {len(result.graph.nodes)} nodes and {len(result.graph.findings)} findings.")

# Native taint and package reachability query:
if result.has_taint_at("app/api.py", line=42):
    print("Tainted dataflow detected at line 42!")
```

---

## 🔀 Supported Ecosystems

| Ecosystem | Manifests Inspected | Architectural & Security Elements Detected |
| :--- | :--- | :--- |
| **.NET (C# / F#)** | `*.sln`, `*.csproj`, `*.fsproj` | Project dependencies, ASP.NET Core controllers, Minimal APIs, EF Core DbContexts, MediatR CQRS, MassTransit/RabbitMQ, Redis, Cloud SDKs |
| **Node.js / TypeScript** | `package.json`, workspaces, `schema.prisma` | Express, Fastify, NestJS, Next.js, Hono; Prisma, TypeORM, Mongoose; Redis, BullMQ, Kafka; Stripe, OpenAI SDK |
| **Java / Spring Boot** | `pom.xml`, `build.gradle(.kts)` | Stereotypes (`@RestController`, `@Service`, `@Repository`), DI (`@Autowired`), injection/call edges; SQLi, command injection, deserialization, SSRF, XSS |
| **Python** | `pyproject.toml`, `requirements.txt`, `*.py` AST | FastAPI, Flask, Django, Celery; SQLAlchemy, Tortoise-ORM, asyncpg, pymongo; AST taint tracking from sources to dangerous execution sinks |
| **Infrastructure & IaC** | `docker-compose.yml`, `Dockerfile`, K8s, Terraform | Compose service ports & links; Dockerfile unpinned tags & root user; Kubernetes capabilities & security contexts; Terraform public ACLs |

---

## 📦 Generated Artifacts

By default, all outputs are written deterministically to `<repo>/.secdiagram/`:

- `diagram-highlevel.mmd` / `.png` — High-level C4 system tier diagram (`secdiagram.com` style).
- `diagram.mmd` / `.png` — Detailed architecture flowchart and component relationships.
- `ARCHITECTURE.md` — Complete markdown architecture report with embedded diagrams.
- `graph.json` — Machine-readable graph schema (nodes, edges, confidence, features, findings).
- `security.sarif` — OASIS SARIF v2.1.0 code-scanning report with taint `codeFlows`.
- `vex.json` — CycloneDX 1.6 VEX document with automated reachability justifications.
- `report.html` — Zero-dependency interactive HTML report with dark mode and filtering.

---

## 📚 Documentation Index

For comprehensive guides, references, and deployment patterns, see:

| Guide | Description |
| :--- | :--- |
| [**Architecture Diagrams & Image Rendering**](docs/ARCHITECTURE_DIAGRAMS.md) | C4 high-level diagrams, visual tiering, detail modes, PNG/SVG/PDF rendering, and providers. |
| [**Container & Docker Compose Guide**](docs/CONTAINER_AND_COMPOSE.md) | Standalone Docker & Podman, Windows Git Bash tips, SELinux mode, and local Ollama Compose. |
| [**Security & IaC Static Analysis**](docs/SECURITY_AND_IAC.md) | SAST rules, IaC checks, SonarQube/Xray import, CycloneDX VEX, and custom framework registries. |
| [**Hardened Platform Server & REST API**](docs/SERVER_API.md) | Daemon mode (`secdiagram serve`), authentication, rate limits, request caps, and config schema. |
| [**CLI Reference Manual**](docs/CLI_REFERENCE.md) | Complete command-line syntax, options breakdown table, and exit codes. |
| [**Python Public Facade & Developer API**](docs/PYTHON_API.md) | Stable facade (`secdiagram_core`), taint/reachability queries, SCA bridge, and cache serialization. |
| [**Task Tracking Guide**](docs/TASK_TRACKING.md) | GitHub Issues & Projects v2 task lifecycle tracking with `taskctl.py`. |

---

## 🧪 Verification & Testing

`secdiagram` maintains a comprehensive test suite (250+ unit tests) covering AST indexers, graph builders, security heuristics, image rendering, and deterministic CLI behaviors:

```bash
# Run unit test suite:
python -m unittest discover -s tests -v
```

---

## 🤝 Contributing & License

- **Contributing**: Please review [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`AGENTS.md`](AGENTS.md) for architectural guardrails and commit conventions.
- **License**: Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.
