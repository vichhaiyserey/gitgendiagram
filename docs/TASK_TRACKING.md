# Task Tracking

`secdiagram` tracks every feature, bug, refactor, CI change, documentation update, and security fix on **GitHub Issues** and a **Projects v2 board**. GitHub is the source of truth. A deterministic local cache under `.secdiagram/tasks/` gives humans and AI agents offline visibility without creating a second status system.

---

## Lifecycle

```text
Backlog -> Ready -> In Progress -> In Review -> Done
                         |
                         +--> Blocked -> In Progress
```

| Status | Meaning | Set by |
|---|---|---|
| `Backlog` | Captured but not yet triaged | Issue opened |
| `Ready` | Triaged, scoped, and ready to start | `taskctl new` or manual board edit |
| `In Progress` | Actively being worked | `taskctl start` / `taskctl unblock` |
| `Blocked` | Waiting on a dependency or decision | `taskctl block --reason ...` |
| `In Review` | Pull request is open | `taskctl review` |
| `Done` | Merged and verified | `taskctl done` / issue closed |

Every issue carries:

- A `type:*` label (`feature`, `bug`, `refactor`, `ci`, `docs`, `test`, `security`).
- A `priority:*` label (`P0` to `P3`).
- An optional `area:*` label (`discovery`, `ast`, `graph`, `security`, `render`, `iac`, `cli`, `docs`, `ci`).
- A milestone for the target release.
- A spec body with goal, scope, acceptance criteria, and verification checklist.
- Append-only progress comments written by `taskctl`.

---

## Commands

All commands run from the repository root:

```bash
# Create a task and add it to the board
python scripts/taskctl.py new --type feature --title "Add Go manifest detection" \
  --priority P1 --area discovery --milestone 0.3.0

# Move through the lifecycle
python scripts/taskctl.py start 12
python scripts/taskctl.py block 12 --reason "waiting on upstream API"
python scripts/taskctl.py unblock 12
python scripts/taskctl.py review 12
python scripts/taskctl.py done 12 --evidence-file /tmp/evidence.md

# Inspect work
python scripts/taskctl.py list
python scripts/taskctl.py list --status "In Progress"
python scripts/taskctl.py list --mine --json

# Refresh the offline cache and index
python scripts/taskctl.py sync
python scripts/taskctl.py sync --offline
python scripts/taskctl.py validate --offline

# Sync one issue to the board (used by the project sync workflow)
python scripts/taskctl.py project-sync 12 --status "Backlog"
```

`new` prints the issue number and a suggested branch name. Use `--dry-run` to preview without changing GitHub.

### `done` evidence

Record the verification commands you actually ran and their results:

```text
python -m unittest discover -s tests -v  -> 230 tests OK
ruff check .                            -> clean
mypy                                    -> clean
python -m bandit -r secdiagram_core -lll -> no high/critical findings
docker build -t secdiagram:verify .     -> success
trivy image --severity CRITICAL,HIGH    -> no unresolved findings
```

---

## Local cache

`python scripts/taskctl.py sync` writes:

```text
.secdiagram/tasks/
  INDEX.md                 # deterministic board snapshot
  0012-add-go-manifest-detection.md
```

The cache is **read-only** and gitignored. Do not edit it by hand. Regenerate it with `sync`; `validate --offline` fails if the index is stale or a snapshot is malformed.

Offline agents can read `.secdiagram/tasks/INDEX.md` and the per-issue snapshots without network access. Creating or updating tasks still requires an authenticated `gh` CLI.

---

## One-time setup

1. Authenticate `gh` with Projects v2 scope:

   ```bash
   gh auth refresh -s project,read:project
   ```

2. Add a repository secret named `TASKS_PROJECT_TOKEN`. Use a classic PAT with `repo`, `project`, and `read:org` scopes, or a fine-grained token with Issues and Projects read/write access. The built-in `GITHUB_TOKEN` cannot update Projects v2 items.

3. Bootstrap labels, milestones, the project, and fields:

   ```bash
   python scripts/taskctl.py bootstrap
   ```

   Preview first with `--dry-run`. The project number is written back to `.github/tasks.json`. If Projects v2 scope is not available yet, run `python scripts/taskctl.py bootstrap --skip-project` to create labels and milestones only.

4. Recommended board views:

   | View | Layout | Group / sort |
   |---|---|---|
   | Roadmap | Roadmap | Group by milestone, date by target |
   | Board | Board | Column by Status |
   | Triage | Table | Filter `status:Backlog` |
   | My work | Table | Filter assignee `@me`, sort priority |

---

## CI integration

| Workflow | Trigger | Behavior |
|---|---|---|
| `tasks-pr-check.yml` | Pull requests to `develop` or `main` | Fails if the PR does not reference an issue; warns when `type:*` or `priority:*` labels are missing |
| `tasks-project-sync.yml` | Issue opened, reopened, closed, or edited | Adds the issue to the board and syncs status and fields; skips with a warning when `TASKS_PROJECT_TOKEN` is absent |
| `ci.yml` quality job | Push or pull request | Runs `tests.test_taskctl`, `ruff`, `mypy`, and `taskctl validate --offline` |

---

## Agent workflow

1. Create or locate the task before editing code:

   ```bash
   python scripts/taskctl.py new --type feature --title "..."
   ```

2. Move it to `In Progress` and create the branch:

   ```bash
   python scripts/taskctl.py start 12
   git checkout -b feat/<slug>-12
   ```

3. Open the pull request with `Closes #12`. Move the task to `In Review`:

   ```bash
   python scripts/taskctl.py review 12
   ```

4. Run the full verification suite. Record evidence, close the task, and refresh the cache:

   ```bash
   python scripts/taskctl.py done 12 --evidence-file /tmp/evidence.md
   python scripts/taskctl.py sync
   ```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `authentication token is missing required scopes [read:project]` | Run `gh auth refresh -s project,read:project` |
| `TASKS_PROJECT_TOKEN is not configured` warning in Actions | Add the repository secret described above |
| `no project configured` | Run `python scripts/taskctl.py bootstrap` |
| `INDEX.md is stale` | Run `python scripts/taskctl.py sync --offline` |
| `unknown status` or `unknown priority` | Use the values in `.github/tasks.json` |
| PR check fails with no linked issue | Add `Closes #N` to the PR body or end the branch name with the issue number |

---

## Design notes

- **Standard library only**: `scripts/taskctl.py` uses `argparse`, `json`, `subprocess`, and `pathlib`. It invokes `gh` with an argument list, never `shell=True`, and applies a timeout.
- **Deterministic cache**: snapshots sort by issue number; the index sorts by configured status order, then priority, then issue number. Metadata is base64-encoded JSON with sorted keys.
- **No token leakage**: tokens are supplied through the `gh` environment and never printed or stored in the cache.
- **No runtime dependency impact**: the tracking tool is developer tooling and does not add anything to `dependencies = []`.
