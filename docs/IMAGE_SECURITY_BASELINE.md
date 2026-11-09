# Container Image Security Baseline

This document records the contextual reachability and exploitability analysis
required by Rule 7 of `AGENTS.md` for the `vserey/secdiagram` image. It is
reviewed on every release and superseded whenever a newer scan is published.

## Release under review

| Field | Value |
| --- | --- |
| Package version | `0.2.1` |
| Base images | `python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b`, `node:24-slim@sha256:01d566e8d94d8c619591d78652babfccd3c6992a3dffa9ed5ab39e11cf6c70e9` |
| Runtime user | `secdiagram` (`uid 10001`), non-root |
| Default command | `secdiagram --dir .` (one-shot CLI) |
| Scan command | `trivy image --severity CRITICAL,HIGH --scanners vuln secdiagram:verify` |
| Scan date | 2026-11-09 |

## Result summary

- **Fixable CRITICAL/HIGH: 0** (`--ignore-unfixed` scan exits `0` with no findings).
- **Unfixed upstream findings: 1 CRITICAL, 252 HIGH**, all reported by Debian or
  Chromium upstream with no available fixed package version at scan time.
- The `0.2.0` image carried six *fixable* HIGH findings (apt, zlib/minizip).
  This release clears all of them by refreshing the base-image digests and
  installing the security-updated `zlib1g`.

### Critical finding

| CVE | Package | Installed | Fixed | Status | CVSS |
| --- | --- | --- | --- | --- | --- |
| CVE-2026-6653 | `libxml2` | `2.12.7+dfsg+really2.9.14-2.1+deb13u3` | none | affected | 9.8 (NVD) |

### High findings by component

| Component | Count | Upstream status |
| --- | --- | --- |
| `chromium`, `chromium-common` | 168 | affected |
| `libxml2` | 7 | affected |
| util-linux family (`mount`, `login`, `bsdutils`, `libblkid1`, `libmount1`, `libuuid1`, `libsmartcols1`, `liblastlog2-2`) | 28 | affected |
| `libexpat1`, `libsqlite3-0`, `curl`/`libcurl*`, `libtiff6`, `libcups2t64`, `libxi6`, `libsndfile1`, remainder | 49 | affected / fix_deferred / will_not_fix |

## Reachability and exploitability analysis

1. **Execution path.** The image entrypoint is the `secdiagram` Python CLI. The
   analysis pipeline uses only Python's `ast` and static manifest parsing; it
   never executes analyzed repository code (`AGENTS.md` Rule 3). The CLI does
   not import `libxml2`, Perl, systemd, util-linux, `libexpat`, `libsqlite3`, or
   `libtiff`. Those libraries are present only as transitive Debian packages of
   `chromium` and the base OS and are never loaded by the CLI process.
2. **Chromium scope.** Chromium is spawned only by `mmdc` for local Mermaid
   rendering, as unprivileged `uid 10001`. It renders text produced by the
   deterministic analyzer, not attacker-supplied web pages, and it never
   browses external URLs. The vulnerable Chromium XML/HTML parsing surface is
   therefore not exposed to remote ingress. Sandboxing is disabled
   (`--no-sandbox`) for container compatibility, which is why Chromium findings
   remain a documented residual risk rather than a proven-exploitable path.
3. **Attack surface and ingress.** The default image command is a one-shot CLI;
   it opens no listening sockets or network daemons. The optional `serve`
   command is never started by `ENTRYPOINT`/`CMD` and requires an explicit user
   invocation. There is no unauthenticated network service exposed by default.
4. **Privilege and sandboxing.** The container runs as non-root `uid 10001`,
   writes only to the mounted `/repo` volume, and holds no elevated
   capabilities. Successful exploitation would still be confined to the
   ephemeral, unprivileged container context.
5. **Input trust.** Repositories analyzed by `secdiagram` are treated as
   untrusted data and are never imported, compiled, or evaluated. The analyzer
   is offline-first; remote rendering and LLM calls are opt-in.

## Disposition

The residual unfixed findings are upstream Debian/Chromium issues that cannot
be remediated from this repository at scan time. They are not reachable through
the CLI execution path, are not exposed via a default network service, and run
under an unprivileged container user. The image may therefore be published for
`v0.2.1` with this baseline recorded. Each subsequent release must re-run the
scan and update this document; a fixable CRITICAL/HIGH finding continues to
block publication by default.

Upstream tracking: <https://security-tracker.debian.org/tracker/CVE-2026-6653>
and the Debian/Chromium security advisories for the packages listed above.
