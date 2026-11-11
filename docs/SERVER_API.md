# 🖥️ Hardened Platform Server & REST API Guide

`secdiagram` includes a hardened, zero-dependency platform server and REST API daemon that serves interactive reports, architectural graphs, and triggers scans on demand.

---

## 1. Starting the Server

The server runs via the `serve` subcommand:

```bash
# Recommended: authenticated, loopback-only server
secdiagram serve --dir . --user analyst --password 'change-me'

# Local-only development without authentication (explicitly insecure):
secdiagram serve --dir . --insecure-no-auth

# Remote binding (0.0.0.0): authentication is strictly enforced
secdiagram serve --dir . --host 0.0.0.0 --user analyst --password 'change-me'
```

---

## 2. Security Defaults & Hardening Rules

- **Loopback Binding by Default**: Binds to `127.0.0.1` unless `--host` is specified.
- **Mandatory Authentication**: Basic Authentication is enforced by default. `--insecure-no-auth` is rejected if `--host` is bound to any non-loopback interface.
- **Per-Client Rate Limiting**: Controlled via `--rate-limit` (default: 240 requests/minute). Set to `0` to disable.
- **Bounded Request Bodies**: Controlled via `--max-request-bytes` (default: 1 MiB / 1,048,576 bytes) to prevent resource exhaustion attacks.
- **Bounded Concurrency**: `--max-concurrent-scans` limits parallel scans (default: `1`). Requests exceeding the limit return HTTP `429 Too Many Requests`.
- **Path Traversal & Scan Root Containment**: Scans are strictly restricted to the served repository directory and any paths specified in `--scan-root`. Requests targeting paths outside allowlisted roots are rejected with HTTP `403 Forbidden`.
- **Credential & Host Path Scrubbing**: Absolute host paths, secret tokens, and sensitive environment variables are automatically scrubbed from responses, graph exports, and audit logs.
- **Structured JSON Audit Logging**: Security events (auth failures, scan requests, rejected paths, rate limits, SARIF downloads, server lifecycle) are emitted to stderr or `--audit-log FILE` as structured JSON Lines (`audit.jsonl`).

---

## 3. Configuration File (`secdiagram.config.json`)

Server options can be configured in a `secdiagram.config.json` file in your repository root or server working directory:

```json
{
  "server": {
    "host": "127.0.0.1",
    "port": 8080,
    "auth_mode": "basic",
    "auth_username": "analyst",
    "auth_password": "change-me",
    "read_only": false,
    "max_request_bytes": 1048576,
    "rate_limit_per_minute": 240,
    "max_concurrent_scans": 1,
    "scan_roots": ["."],
    "audit_log": "audit.jsonl"
  }
}
```

---

## 4. REST API Endpoints

All endpoints require Basic Authentication unless the server was explicitly started with `--insecure-no-auth`.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Interactive self-contained HTML report (`report.html`) |
| `GET` | `/api/status` | Server health, version, scan queue status, and active configuration |
| `GET` | `/api/graph` | Deterministic graph JSON (`graph.json`) |
| `GET` | `/api/sarif` | OASIS SARIF v2.1.0 security report (`security.sarif`) |
| `GET` | `/api/diagram.mmd` | Mermaid detailed architecture flowchart |
| `GET` | `/api/diagram-highlevel.mmd` | Mermaid high-level C4 tier diagram |
| `POST` | `/api/scan` | Trigger a new scan. Body accepts JSON options (`{"dir": "...", "security": true}`). Disabled when `read_only: true`. |

---

## 5. Production & Reverse Proxy Deployment

> [!WARNING]
> The internal server engine speaks unencrypted HTTP. When deploying to remote hosts or shared environments:
> 1. Always terminate TLS using a trusted reverse proxy (e.g. NGINX, Caddy, Envoy, or Traefik).
> 2. Keep Basic Authentication enabled with a strong password.
> 3. Use `read_only: true` if the server is only intended to publish existing analysis reports.
