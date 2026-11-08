#!/usr/bin/env python3
"""GitHub-native task tracking for secdiagram.

The GitHub Issues API and a Projects v2 board are the source of truth. This
tool is standard-library only and shells out to the GitHub CLI (``gh``) for all
remote operations. It also maintains a deterministic, read-only cache under
``.secdiagram/tasks`` so humans and AI agents can inspect task state offline.

Usage:
    python scripts/taskctl.py new --type feature --title "..."
    python scripts/taskctl.py start 12
    python scripts/taskctl.py block 12 --reason "waiting on review"
    python scripts/taskctl.py review 12
    python scripts/taskctl.py done 12 --evidence-file evidence.md
    python scripts/taskctl.py list --status "In Progress"
    python scripts/taskctl.py sync
    python scripts/taskctl.py validate --offline
    python scripts/taskctl.py bootstrap --dry-run
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / ".github" / "tasks.json"
DEFAULT_CACHE_DIR = ROOT / ".secdiagram" / "tasks"
INDEX_NAME = "INDEX.md"
GH_TIMEOUT = 30

TYPE_COLORS = {
    "type:feature": "0e8a16",
    "type:bug": "d73a4a",
    "type:refactor": "fbca04",
    "type:ci": "1d76db",
    "type:docs": "0075ca",
    "type:test": "5319e7",
    "type:security": "b60205",
}
PRIORITY_COLORS = {
    "priority:P0": "b60205",
    "priority:P1": "d93f0b",
    "priority:P2": "fbca04",
    "priority:P3": "0e8a16",
}
AREA_COLOR = "c2e0c6"
STATUS_COLOR = "GRAY"

REQUIRED_META_KEYS = (
    "number",
    "title",
    "url",
    "state",
    "status",
    "priority",
    "type",
    "area",
    "milestone",
    "assignees",
    "labels",
    "updated_at",
)


class TaskError(RuntimeError):
    """Raised when a task operation cannot be completed."""


@dataclass
class TaskRecord:
    number: int
    title: str
    url: str
    state: str
    status: str
    priority: str
    type: str
    area: str | None
    milestone: str | None
    assignees: list[str]
    labels: list[str]
    updated_at: str
    body: str = ""

    def meta(self) -> dict[str, Any]:
        return {
            "number": self.number,
            "title": self.title,
            "url": self.url,
            "state": self.state,
            "status": self.status,
            "priority": self.priority,
            "type": self.type,
            "area": self.area,
            "milestone": self.milestone,
            "assignees": sorted(self.assignees),
            "labels": sorted(self.labels),
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_meta(cls, data: dict[str, Any]) -> TaskRecord:
        return cls(
            number=int(data["number"]),
            title=str(data["title"]),
            url=str(data["url"]),
            state=str(data.get("state", "OPEN")),
            status=str(data["status"]),
            priority=str(data["priority"]),
            type=str(data["type"]),
            area=str(data["area"]) if data.get("area") else None,
            milestone=str(data["milestone"]) if data.get("milestone") else None,
            assignees=sorted(str(item) for item in data.get("assignees", [])),
            labels=sorted(str(item) for item in data.get("labels", [])),
            updated_at=str(data.get("updated_at", "")),
        )

    @property
    def filename(self) -> str:
        return f"{self.number:04d}-{slugify(self.title)}.md"


def load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise TaskError(f"missing config file: {path}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TaskError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise TaskError(f"config must be a JSON object: {path}")
    return data


def save_config(config: dict[str, Any], path: Path = CONFIG_PATH) -> None:
    path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def cache_dir(config: dict[str, Any]) -> Path:
    configured = str(config.get("cache_dir", ".secdiagram/tasks"))
    path = Path(configured)
    return path if path.is_absolute() else ROOT / path


def slugify(text: str, max_length: int = 60) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:max_length].strip("-") or "task"


def issue_number_from_url(url: str) -> int:
    match = re.search(r"/issues/(\d+)(?:$|[/?#])", url)
    if not match:
        raise TaskError(f"could not parse issue number from URL: {url}")
    return int(match.group(1))


def run_gh(
    args: list[str],
    *,
    check: bool = True,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        proc = subprocess.run(
            ["gh", *args],
            capture_output=True,
            text=True,
            timeout=GH_TIMEOUT,
            input=input_text,
            check=False,
        )
    except FileNotFoundError as exc:
        raise TaskError("GitHub CLI 'gh' is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise TaskError(f"gh command timed out after {GH_TIMEOUT}s: {args[0]}") from exc
    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise TaskError(f"gh command failed: {detail}")
    return proc


def gh_json(args: list[str]) -> Any:
    proc = run_gh(args)
    try:
        return json.loads(proc.stdout or "null")
    except json.JSONDecodeError as exc:
        raise TaskError(f"gh returned invalid JSON for {args[0]}: {exc}") from exc


def repo_slug(config: dict[str, Any]) -> str:
    configured = config.get("repo")
    if configured:
        return str(configured)
    proc = run_gh(["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"])
    return proc.stdout.strip()


def project_owner(config: dict[str, Any]) -> str:
    project = config.get("project", {})
    configured = project.get("owner")
    if configured:
        return str(configured)
    return repo_slug(config).split("/", 1)[0]


def project_number(config: dict[str, Any]) -> int | None:
    number = config.get("project", {}).get("number")
    return int(number) if number else None


def normalize_field_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("name", "title", "value"):
            candidate = value.get(key)
            if isinstance(candidate, str):
                return candidate
        return None
    return None


def field_value(item: dict[str, Any], name: str) -> str | None:
    values = item.get("fieldValues")
    if isinstance(values, dict):
        return normalize_field_value(values.get(name))
    if isinstance(values, list):
        for entry in values:
            if not isinstance(entry, dict):
                continue
            field_info = entry.get("field")
            field_name = entry.get("name")
            if field_name is None and isinstance(field_info, dict):
                field_name = field_info.get("name")
            if field_name == name:
                return normalize_field_value(entry.get("value"))
    return None


def label_names(issue: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for label in issue.get("labels") or []:
        name = label.get("name") if isinstance(label, dict) else label
        if name:
            names.append(str(name))
    return sorted(set(names))


def project_items(config: dict[str, Any]) -> dict[int, dict[str, Any]]:
    number = project_number(config)
    if not number:
        return {}
    try:
        payload = gh_json(
            [
                "project",
                "item-list",
                str(number),
                "--owner",
                project_owner(config),
                "--format",
                "json",
                "--limit",
                "500",
            ]
        )
    except TaskError:
        return {}
    items = payload.get("items", []) if isinstance(payload, dict) else payload
    mapping: dict[int, dict[str, Any]] = {}
    if not isinstance(items, list):
        return mapping
    for item in items:
        if not isinstance(item, dict):
            continue
        content = item.get("content")
        if not isinstance(content, dict):
            content = item
        if content.get("type") not in (None, "Issue"):
            continue
        number_value = content.get("number")
        if isinstance(number_value, int):
            mapping[number_value] = item
    return mapping


def task_from_issue(
    issue: dict[str, Any],
    project_item: dict[str, Any] | None = None,
) -> TaskRecord:
    labels = label_names(issue)
    label_priority = next(
        (label.split(":", 1)[1] for label in labels if label.startswith("priority:")),
        None,
    )
    label_type = next(
        (label.split(":", 1)[1] for label in labels if label.startswith("type:")),
        None,
    )
    label_area = next(
        (label.split(":", 1)[1] for label in labels if label.startswith("area:")),
        None,
    )
    status = None
    priority = label_priority
    task_type = label_type
    area = label_area
    if project_item is not None:
        status = field_value(project_item, "Status")
        priority = field_value(project_item, "Priority") or priority
        task_type = field_value(project_item, "Type") or task_type
        area = field_value(project_item, "Area") or area
    if not status:
        status = "Done" if str(issue.get("state", "")).upper() == "CLOSED" else "Ready"
    milestone = issue.get("milestone")
    milestone_title = milestone.get("title") if isinstance(milestone, dict) else None
    assignees = sorted(
        str(entry.get("login"))
        for entry in issue.get("assignees") or []
        if isinstance(entry, dict) and entry.get("login")
    )
    return TaskRecord(
        number=int(issue["number"]),
        title=str(issue.get("title", "")),
        url=str(issue.get("url", "")),
        state=str(issue.get("state", "OPEN")),
        status=status,
        priority=priority or "P2",
        type=task_type or "feature",
        area=area,
        milestone=str(milestone_title) if milestone_title else None,
        assignees=assignees,
        labels=labels,
        updated_at=str(issue.get("updatedAt", "")),
        body=str(issue.get("body") or ""),
    )


def fetch_tasks(config: dict[str, Any], state: str = "all") -> list[TaskRecord]:
    payload = gh_json(
        [
            "issue",
            "list",
            "--repo",
            repo_slug(config),
            "--state",
            state,
            "--limit",
            "500",
            "--json",
            "number,title,state,labels,assignees,milestone,updatedAt,url,body",
        ]
    )
    if not isinstance(payload, list):
        raise TaskError("unexpected response from gh issue list")
    items = project_items(config)
    records = [task_from_issue(issue, items.get(int(issue["number"]))) for issue in payload]
    return sorted(records, key=lambda record: record.number)


def render_snapshot(record: TaskRecord) -> str:
    meta = json.dumps(record.meta(), sort_keys=True, separators=(",", ":"))
    encoded = base64.b64encode(meta.encode("utf-8")).decode("ascii")
    owners = ", ".join(f"@{login}" for login in record.assignees) or "unassigned"
    labels = ", ".join(record.labels) or "none"
    lines = [
        "<!-- task-meta-b64",
        encoded,
        "-->",
        "",
        f"# #{record.number} {record.title}",
        "",
        f"- Status: {record.status}",
        f"- Priority: {record.priority}",
        f"- Type: {record.type}",
        f"- Area: {record.area or 'none'}",
        f"- Owner: {owners}",
        f"- Milestone: {record.milestone or 'none'}",
        f"- Labels: {labels}",
        f"- Updated: {record.updated_at or 'unknown'}",
        f"- URL: {record.url}",
    ]
    if record.body.strip():
        lines.extend(["", "## Description", "", record.body.strip()])
    lines.append("")
    return "\n".join(lines)


def parse_snapshot(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    match = re.search(r"<!-- task-meta-b64\n([A-Za-z0-9+/=\s]+?)\n-->", text)
    if not match:
        raise TaskError(f"missing task metadata in {path.name}")
    try:
        raw = base64.b64decode("".join(match.group(1).split())).decode("utf-8")
        data = json.loads(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        raise TaskError(f"invalid task metadata in {path.name}: {exc}") from exc
    if not isinstance(data, dict):
        raise TaskError(f"task metadata must be an object in {path.name}")
    return data


def render_index(records: list[TaskRecord], config: dict[str, Any]) -> str:
    statuses = [str(item) for item in config.get("statuses", [])]
    priorities = [str(item) for item in config.get("priorities", [])]
    status_rank = {name: index for index, name in enumerate(statuses)}
    priority_rank = {name: index for index, name in enumerate(priorities)}
    ordered = sorted(
        records,
        key=lambda record: (
            status_rank.get(record.status, len(statuses)),
            priority_rank.get(record.priority, len(priorities)),
            record.number,
        ),
    )
    counts: dict[str, int] = {status: 0 for status in statuses}
    for record in ordered:
        counts[record.status] = counts.get(record.status, 0) + 1
    lines = [
        "# Task Index",
        "",
        "Generated by `python scripts/taskctl.py sync`. Do not edit by hand.",
        "",
    ]
    summary = ", ".join(f"{status}: {counts.get(status, 0)}" for status in statuses)
    if summary:
        lines.extend([f"Summary: {summary}", ""])
    if not ordered:
        lines.extend(["No cached tasks. Run `python scripts/taskctl.py sync`.", ""])
        return "\n".join(lines)
    lines.extend(
        [
            "| Status | ID | Priority | Type | Area | Title | Owner | Updated |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for record in ordered:
        owners = ", ".join(f"@{login}" for login in record.assignees) or "-"
        title = record.title.replace("|", "\\|")
        lines.append(
            "| "
            + " | ".join(
                [
                    record.status,
                    f"[#{record.number}]({record.filename})",
                    record.priority,
                    record.type,
                    record.area or "-",
                    title,
                    owners,
                    record.updated_at or "-",
                ]
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def load_cache(config: dict[str, Any]) -> list[TaskRecord]:
    directory = cache_dir(config)
    if not directory.exists():
        return []
    records: list[TaskRecord] = []
    for path in sorted(directory.glob("*.md")):
        if path.name == INDEX_NAME:
            continue
        records.append(TaskRecord.from_meta(parse_snapshot(path)))
    return sorted(records, key=lambda record: record.number)


def write_cache(
    config: dict[str, Any],
    records: list[TaskRecord],
    *,
    prune: bool = False,
) -> list[Path]:
    directory = cache_dir(config)
    directory.mkdir(parents=True, exist_ok=True)
    expected: set[str] = set()
    written: list[Path] = []
    for record in sorted(records, key=lambda item: item.number):
        path = directory / record.filename
        path.write_text(render_snapshot(record), encoding="utf-8")
        expected.add(record.filename)
        written.append(path)
    if prune:
        for path in directory.glob("*.md"):
            if path.name == INDEX_NAME:
                continue
            if path.name not in expected:
                path.unlink()
    index_path = directory / INDEX_NAME
    index_path.write_text(render_index(records, config), encoding="utf-8")
    written.append(index_path)
    return written


def sync_tasks(config: dict[str, Any], *, offline: bool = False, prune: bool = False) -> int:
    if offline:
        records = load_cache(config)
        if not records:
            print("No cached tasks to re-index.")
            return 0
    else:
        records = fetch_tasks(config, state="all")
    written = write_cache(config, records, prune=prune)
    print(f"Wrote {len(written)} file(s) under {cache_dir(config)}")
    return 0


def validate_tasks(config: dict[str, Any], *, offline: bool = False) -> int:
    errors: list[str] = []
    for key in ("repo", "statuses", "priorities", "types", "areas"):
        if key not in config:
            errors.append(f"config missing required key: {key}")
    statuses = {str(item) for item in config.get("statuses", [])}
    priorities = {str(item) for item in config.get("priorities", [])}
    types = set(config.get("types", {}) or {})
    areas = {str(item) for item in config.get("areas", [])}

    directory = cache_dir(config)
    if not directory.exists():
        if offline:
            print(f"No task cache found at {directory}; nothing to validate.")
            return 1 if errors else 0
        errors.append(f"task cache not found: {directory}")

    records: list[TaskRecord] = []
    seen: dict[int, str] = {}
    if directory.exists():
        for path in sorted(directory.glob("*.md")):
            if path.name == INDEX_NAME:
                continue
            try:
                data = parse_snapshot(path)
            except TaskError as exc:
                errors.append(str(exc))
                continue
            missing = [key for key in REQUIRED_META_KEYS if key not in data]
            if missing:
                errors.append(f"{path.name}: missing metadata keys: {', '.join(missing)}")
                continue
            try:
                record = TaskRecord.from_meta(data)
            except (KeyError, TypeError, ValueError) as exc:
                errors.append(f"{path.name}: invalid metadata: {exc}")
                continue
            if record.status not in statuses:
                errors.append(f"{path.name}: unknown status '{record.status}'")
            if record.priority not in priorities:
                errors.append(f"{path.name}: unknown priority '{record.priority}'")
            if record.type not in types:
                errors.append(f"{path.name}: unknown type '{record.type}'")
            if record.area and record.area not in areas:
                errors.append(f"{path.name}: unknown area '{record.area}'")
            expected_prefix = f"{record.number:04d}-"
            if not path.name.startswith(expected_prefix):
                errors.append(f"{path.name}: filename must start with '{expected_prefix}'")
            if record.number in seen:
                errors.append(f"duplicate issue #{record.number}: {seen[record.number]} and {path.name}")
            seen[record.number] = path.name
            records.append(record)

    index_path = directory / INDEX_NAME
    if index_path.exists():
        expected_index = render_index(sorted(records, key=lambda item: item.number), config)
        if index_path.read_text(encoding="utf-8") != expected_index:
            errors.append(f"{INDEX_NAME} is stale; run `python scripts/taskctl.py sync --offline`")

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"Validated {len(records)} cached task(s).")
    return 0


def print_table(records: list[TaskRecord]) -> None:
    headers = ("Status", "ID", "P", "Type", "Area", "Title", "Owner")
    rows = [
        (
            record.status,
            str(record.number),
            record.priority,
            record.type,
            record.area or "-",
            record.title,
            ", ".join(f"@{login}" for login in record.assignees) or "-",
        )
        for record in records
    ]
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))
    print("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))


def list_tasks(
    config: dict[str, Any],
    *,
    status: str | None = None,
    mine: bool = False,
    as_json: bool = False,
) -> int:
    records = fetch_tasks(config, state="all")
    if status:
        wanted = status.lower()
        records = [record for record in records if record.status.lower() == wanted]
    if mine:
        proc = run_gh(["api", "user", "--jq", ".login"])
        login = proc.stdout.strip()
        records = [record for record in records if login in record.assignees]
    if as_json:
        print(json.dumps([record.meta() for record in records], indent=2, sort_keys=True))
        return 0
    if not records:
        print("No matching tasks.")
        return 0
    print_table(records)
    return 0


def project_meta(config: dict[str, Any]) -> tuple[str, dict[str, dict[str, Any]]]:
    number = project_number(config)
    if not number:
        raise TaskError("no project configured; run `python scripts/taskctl.py bootstrap`")
    owner = project_owner(config)
    view = gh_json(["project", "view", str(number), "--owner", owner, "--format", "json"])
    project_id = str(view.get("id", ""))
    if not project_id:
        raise TaskError("could not resolve project id")
    payload = gh_json(
        ["project", "field-list", str(number), "--owner", owner, "--format", "json"]
    )
    fields = payload.get("fields", []) if isinstance(payload, dict) else payload
    mapping: dict[str, dict[str, Any]] = {}
    if isinstance(fields, list):
        for entry in fields:
            if isinstance(entry, dict) and entry.get("name"):
                mapping[str(entry["name"])] = entry
    return project_id, mapping


def set_single_select(
    config: dict[str, Any],
    item_id: str,
    field_name: str,
    value: str,
) -> None:
    project_id, fields = project_meta(config)
    field = fields.get(field_name)
    if not field:
        raise TaskError(f"project field '{field_name}' not found")
    option_id = None
    for option in field.get("options", []) or []:
        if isinstance(option, dict) and str(option.get("name", "")).lower() == value.lower():
            option_id = str(option.get("id", ""))
            break
    if not option_id:
        raise TaskError(f"option '{value}' not found in project field '{field_name}'")
    run_gh(
        [
            "project",
            "item-edit",
            "--project-id",
            project_id,
            "--id",
            item_id,
            "--field-id",
            str(field.get("id", "")),
            "--single-select-option-id",
            option_id,
        ]
    )


def find_project_item(config: dict[str, Any], number: int) -> str | None:
    item = project_items(config).get(number)
    if not item:
        return None
    item_id = item.get("id")
    return str(item_id) if item_id else None


def ensure_project_item(config: dict[str, Any], number: int) -> str:
    existing = find_project_item(config, number)
    if existing:
        return existing
    project = project_number(config)
    if not project:
        raise TaskError("no project configured; run `python scripts/taskctl.py bootstrap`")
    issue = gh_json(
        ["issue", "view", str(number), "--repo", repo_slug(config), "--json", "url"]
    )
    url = str(issue.get("url", ""))
    if not url:
        raise TaskError(f"could not resolve URL for issue #{number}")
    proc = run_gh(
        [
            "project",
            "item-add",
            str(project),
            "--owner",
            project_owner(config),
            "--url",
            url,
            "--format",
            "json",
        ],
        check=False,
    )
    if proc.returncode != 0:
        existing = find_project_item(config, number)
        if existing:
            return existing
        detail = (proc.stderr or proc.stdout or "").strip()
        raise TaskError(f"could not add issue #{number} to the project: {detail}")
    try:
        payload = json.loads(proc.stdout or "null")
    except json.JSONDecodeError as exc:
        raise TaskError(f"invalid project item response for issue #{number}: {exc}") from exc
    item_id = payload.get("id") if isinstance(payload, dict) else None
    if not item_id:
        raise TaskError(f"could not add issue #{number} to the project")
    return str(item_id)


def set_status(config: dict[str, Any], number: int, status: str) -> None:
    if not project_number(config):
        print("warning: no project configured; status not updated", file=sys.stderr)
        return
    item_id = ensure_project_item(config, number)
    set_single_select(config, item_id, "Status", status)


def set_task_fields(
    config: dict[str, Any],
    number: int,
    *,
    status: str,
    priority: str,
    task_type: str,
    area: str | None,
) -> None:
    if not project_number(config):
        print("warning: no project configured; project fields not updated", file=sys.stderr)
        return
    item_id = ensure_project_item(config, number)
    set_single_select(config, item_id, "Status", status)
    set_single_select(config, item_id, "Priority", priority)
    type_option = str(config.get("types", {}).get(task_type, {}).get("title", task_type))
    set_single_select(config, item_id, "Type", type_option)
    if area:
        set_single_select(config, item_id, "Area", area_title(area))


def comment_issue(config: dict[str, Any], number: int, body: str) -> None:
    run_gh(
        ["issue", "comment", str(number), "--repo", repo_slug(config), "--body", body]
    )


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_text_argument(value: str | None, path: str | None) -> str:
    if value:
        return value
    if path:
        return Path(path).read_text(encoding="utf-8")
    return ""


def new_task(config: dict[str, Any], args: argparse.Namespace) -> int:
    types = config.get("types", {})
    if args.type not in types:
        raise TaskError(f"unknown type '{args.type}'; choose from: {', '.join(sorted(types))}")
    if args.priority not in config.get("priorities", []):
        raise TaskError(f"unknown priority '{args.priority}'")
    if args.area and args.area not in config.get("areas", []):
        raise TaskError(f"unknown area '{args.area}'")
    if args.status not in config.get("statuses", []):
        raise TaskError(f"unknown status '{args.status}'")

    type_info = types[args.type]
    labels = [str(type_info["label"]), f"priority:{args.priority}"]
    if args.area:
        labels.append(f"area:{args.area}")
    body = read_text_argument(args.body, args.body_file) or default_body()
    repo = repo_slug(config)
    command = ["issue", "create", "--repo", repo, "--title", args.title, "--body", body]
    for label in labels:
        command.extend(["--label", label])
    if args.milestone:
        command.extend(["--milestone", args.milestone])

    if args.dry_run:
        print("Would run:")
        print("  gh " + " ".join(command))
        print(f"Would set status={args.status}, priority={args.priority}, type={args.type}")
        if args.area:
            print(f"Would set area={args.area}")
        branch = str(type_info.get("branch", "feat"))
        print(f"Suggested branch: {branch}/{slugify(args.title)}-<issue-number>")
        return 0

    proc = run_gh(command)
    url = next(
        (line.strip() for line in reversed(proc.stdout.splitlines()) if line.strip()),
        "",
    )
    number = issue_number_from_url(url)
    set_task_fields(
        config,
        number,
        status=args.status,
        priority=args.priority,
        task_type=args.type,
        area=args.area,
    )
    branch = str(type_info.get("branch", "feat"))
    print(f"Created #{number}: {url}")
    print(f"Suggested branch: {branch}/{slugify(args.title)}-{number}")
    return 0


def default_body() -> str:
    return (
        "## Goal\n\n<!-- What should change and why? -->\n\n"
        "## Scope\n\n- [ ] ...\n\n"
        "## Acceptance criteria\n\n- [ ] ...\n\n"
        "## Verification\n\n"
        "- [ ] `python -m unittest discover -s tests -v`\n"
        "- [ ] `ruff check .`\n"
        "- [ ] `mypy`\n"
        "- [ ] `python -m bandit -r secdiagram_core -lll`\n"
        "- [ ] `python scripts/taskctl.py validate --offline`\n"
    )


def ensure_open(config: dict[str, Any], number: int) -> None:
    payload = gh_json(
        ["issue", "view", str(number), "--repo", repo_slug(config), "--json", "state,url"]
    )
    if str(payload.get("state", "")).upper() == "CLOSED":
        raise TaskError(f"issue #{number} is already closed")


def start_task(config: dict[str, Any], args: argparse.Namespace) -> int:
    ensure_open(config, args.number)
    run_gh(
        [
            "issue",
            "edit",
            str(args.number),
            "--repo",
            repo_slug(config),
            "--add-assignee",
            "@me",
        ]
    )
    set_status(config, args.number, "In Progress")
    comment_issue(config, args.number, f"Started work at {timestamp()}.")
    print(f"#{args.number} is now In Progress.")
    return 0


def block_task(config: dict[str, Any], args: argparse.Namespace) -> int:
    ensure_open(config, args.number)
    set_status(config, args.number, "Blocked")
    comment_issue(
        config,
        args.number,
        f"Blocked at {timestamp()}.\n\nReason: {args.reason}",
    )
    print(f"#{args.number} is now Blocked.")
    return 0


def unblock_task(config: dict[str, Any], args: argparse.Namespace) -> int:
    ensure_open(config, args.number)
    set_status(config, args.number, "In Progress")
    comment_issue(config, args.number, f"Unblocked at {timestamp()}.")
    print(f"#{args.number} is now In Progress.")
    return 0


def review_task(config: dict[str, Any], args: argparse.Namespace) -> int:
    ensure_open(config, args.number)
    set_status(config, args.number, "In Review")
    comment_issue(
        config,
        args.number,
        f"Ready for review at {timestamp()}.\n\nLink the pull request with `Closes #{args.number}`.",
    )
    print(f"#{args.number} is now In Review.")
    return 0


def done_task(config: dict[str, Any], args: argparse.Namespace) -> int:
    evidence = read_text_argument(args.evidence, args.evidence_file).strip()
    if not evidence:
        evidence = "No verification evidence supplied."
    body = (
        f"Completed at {timestamp()}.\n\n"
        "### Verification evidence\n\n"
        f"{evidence}\n"
    )
    run_gh(
        [
            "issue",
            "close",
            str(args.number),
            "--repo",
            repo_slug(config),
            "--comment",
            body,
        ]
    )
    if project_number(config):
        set_status(config, args.number, "Done")
    print(f"#{args.number} is now Done.")
    return 0


def project_sync_task(config: dict[str, Any], args: argparse.Namespace) -> int:
    if not project_number(config):
        print("warning: no project configured; skipping project sync", file=sys.stderr)
        return 0
    issue = gh_json(
        [
            "issue",
            "view",
            str(args.number),
            "--repo",
            repo_slug(config),
            "--json",
            "number,title,state,labels,assignees,milestone,updatedAt,url,body",
        ]
    )
    record = task_from_issue(issue)
    item_id = ensure_project_item(config, args.number)
    if args.status:
        set_single_select(config, item_id, "Status", args.status)
    labels = set(record.labels)
    if any(label.startswith("priority:") for label in labels):
        set_single_select(config, item_id, "Priority", record.priority)
    if any(label.startswith("type:") for label in labels):
        type_option = str(config.get("types", {}).get(record.type, {}).get("title", record.type))
        set_single_select(config, item_id, "Type", type_option)
    if record.area:
        set_single_select(config, item_id, "Area", area_title(record.area))
    print(f"Synced #{args.number} to the project board.")
    return 0


def ensure_labels(config: dict[str, Any], *, dry_run: bool) -> None:
    repo = repo_slug(config)
    payload = gh_json(["label", "list", "--repo", repo, "--limit", "200", "--json", "name"])
    existing = {
        str(item["name"])
        for item in payload
        if isinstance(item, dict) and item.get("name")
    }
    wanted: dict[str, tuple[str, str]] = {}
    for name, info in config.get("types", {}).items():
        label = str(info["label"])
        wanted[label] = (TYPE_COLORS.get(label, "ededed"), f"Task type: {name}")
    for priority in config.get("priorities", []):
        label = f"priority:{priority}"
        wanted[label] = (PRIORITY_COLORS.get(label, "ededed"), f"Priority {priority}")
    for area in config.get("areas", []):
        wanted[f"area:{area}"] = (AREA_COLOR, f"Area: {area}")
    for name, (color, description) in sorted(wanted.items()):
        if name in existing:
            continue
        if dry_run:
            print(f"Would create label: {name}")
            continue
        run_gh(
            [
                "label",
                "create",
                name,
                "--repo",
                repo,
                "--color",
                color,
                "--description",
                description,
            ]
        )
        print(f"Created label: {name}")


def ensure_milestones(config: dict[str, Any], *, dry_run: bool) -> None:
    repo = repo_slug(config)
    payload = gh_json(["api", f"repos/{repo}/milestones?state=all&per_page=100"])
    existing = {
        str(item["title"])
        for item in payload
        if isinstance(item, dict) and item.get("title")
    }
    for milestone in config.get("milestones", []):
        name = str(milestone)
        if name in existing:
            continue
        if dry_run:
            print(f"Would create milestone: {name}")
            continue
        run_gh(
            [
                "api",
                f"repos/{repo}/milestones",
                "--method",
                "POST",
                "-f",
                f"title={name}",
                "-f",
                "state=open",
            ]
        )
        print(f"Created milestone: {name}")


def ensure_project(config: dict[str, Any], *, dry_run: bool) -> int | None:
    project = config.setdefault("project", {})
    number = project.get("number")
    if number:
        return int(number)
    owner = project_owner(config)
    title = str(project.get("title", "secdiagram Roadmap"))
    if dry_run:
        print(f"Would create project: {title} (owner {owner})")
        return None
    payload = gh_json(["project", "create", "--owner", owner, "--title", title, "--format", "json"])
    created = payload.get("number") if isinstance(payload, dict) else None
    if not created:
        raise TaskError("could not create project")
    project["number"] = int(created)
    save_config(config)
    print(f"Created project: {title} (#{created})")
    return int(created)


def update_status_options(config: dict[str, Any], project_id: str, field_id: str) -> None:
    options = [str(item) for item in config.get("statuses", [])]
    query = (
        "mutation($fieldId: ID!, $options: [ProjectV2SingleSelectFieldOptionInput!]!) {"
        "  updateProjectV2Field(input: {fieldId: $fieldId, singleSelectOptions: $options}) {"
        "    projectV2Field { ... on ProjectV2SingleSelectField { id name options { id name } } }"
        "  }"
        "}"
    )
    variables = {
        "fieldId": field_id,
        "options": [
            {"name": name, "color": STATUS_COLOR, "description": ""} for name in options
        ],
    }
    payload = json.dumps({"query": query, "variables": variables})
    run_gh(["api", "graphql", "--input", "-"], input_text=payload)


def ensure_fields(config: dict[str, Any], project: int, *, dry_run: bool) -> None:
    owner = project_owner(config)
    view = gh_json(["project", "view", str(project), "--owner", owner, "--format", "json"])
    project_id = str(view.get("id", ""))
    payload = gh_json(
        ["project", "field-list", str(project), "--owner", owner, "--format", "json"]
    )
    fields = payload.get("fields", []) if isinstance(payload, dict) else payload
    by_name = {
        str(entry["name"]): entry
        for entry in fields
        if isinstance(entry, dict) and entry.get("name")
    }
    if "Status" in by_name:
        field_id = str(by_name["Status"].get("id", ""))
        if dry_run:
            print(f"Would update Status options: {', '.join(config.get('statuses', []))}")
        elif field_id:
            update_status_options(config, project_id, field_id)
            print("Updated Status options.")
    else:
        if dry_run:
            print("Would create Status field")
        else:
            run_gh(
                [
                    "project",
                    "field-create",
                    str(project),
                    "--owner",
                    owner,
                    "--name",
                    "Status",
                    "--data-type",
                    "SINGLE_SELECT",
                    "--single-select-options",
                    ",".join(str(item) for item in config.get("statuses", [])),
                ]
            )
            print("Created Status field.")

    type_titles = [str(info.get("title", key)) for key, info in config.get("types", {}).items()]
    specs = {
        "Priority": [str(item) for item in config.get("priorities", [])],
        "Type": type_titles,
        "Area": [area_title(str(item)) for item in config.get("areas", [])],
        "Size": [str(item) for item in config.get("sizes", [])],
    }
    for name, options in specs.items():
        if name in by_name or not options:
            continue
        if dry_run:
            print(f"Would create field: {name} ({', '.join(options)})")
            continue
        run_gh(
            [
                "project",
                "field-create",
                str(project),
                "--owner",
                owner,
                "--name",
                name,
                "--data-type",
                "SINGLE_SELECT",
                "--single-select-options",
                ",".join(options),
            ]
        )
        print(f"Created field: {name}")


def area_title(area: str) -> str:
    special = {"iac": "IaC", "ast": "AST", "cli": "CLI", "ci": "CI"}
    return special.get(area, area.capitalize())


def bootstrap(config: dict[str, Any], args: argparse.Namespace) -> int:
    ensure_labels(config, dry_run=args.dry_run)
    ensure_milestones(config, dry_run=args.dry_run)
    if args.skip_project:
        print("Skipped project setup (--skip-project).")
        return 0
    project = ensure_project(config, dry_run=args.dry_run)
    if project:
        ensure_fields(config, project, dry_run=args.dry_run)
    print("Bootstrap complete.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="taskctl",
        description="GitHub-native task tracking for secdiagram.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    new = subparsers.add_parser("new", help="Create a task issue and add it to the board.")
    new.add_argument("--type", required=True, help="Task type, e.g. feature or bug.")
    new.add_argument("--title", required=True, help="Issue title.")
    new.add_argument("--body", help="Issue body text.")
    new.add_argument("--body-file", help="Read the issue body from a file.")
    new.add_argument("--priority", default="P2", help="Priority (default: P2).")
    new.add_argument("--area", help="Area label, e.g. ast or security.")
    new.add_argument("--milestone", help="Milestone title.")
    new.add_argument("--status", default="Ready", help="Initial status (default: Ready).")
    new.add_argument("--dry-run", action="store_true", help="Print actions without changing GitHub.")
    new.set_defaults(handler=new_task)

    start = subparsers.add_parser("start", help="Move a task to In Progress.")
    start.add_argument("number", type=int)
    start.set_defaults(handler=start_task)

    block = subparsers.add_parser("block", help="Mark a task as Blocked.")
    block.add_argument("number", type=int)
    block.add_argument("--reason", required=True)
    block.set_defaults(handler=block_task)

    unblock = subparsers.add_parser("unblock", help="Return a blocked task to In Progress.")
    unblock.add_argument("number", type=int)
    unblock.set_defaults(handler=unblock_task)

    review = subparsers.add_parser("review", help="Move a task to In Review.")
    review.add_argument("number", type=int)
    review.set_defaults(handler=review_task)

    done = subparsers.add_parser("done", help="Close a task as Done with evidence.")
    done.add_argument("number", type=int)
    done.add_argument("--evidence", help="Verification evidence text.")
    done.add_argument("--evidence-file", help="Read verification evidence from a file.")
    done.set_defaults(handler=done_task)

    project_sync = subparsers.add_parser(
        "project-sync", help="Sync one issue's labels and status to the board."
    )
    project_sync.add_argument("number", type=int)
    project_sync.add_argument("--status", help="Optionally set the Status field.")
    project_sync.set_defaults(handler=project_sync_task)

    list_parser = subparsers.add_parser("list", help="List tasks.")
    list_parser.add_argument("--status", help="Filter by status.")
    list_parser.add_argument("--mine", action="store_true", help="Only tasks assigned to you.")
    list_parser.add_argument("--json", action="store_true", help="Emit JSON.")
    list_parser.set_defaults(handler=lambda config, args: list_tasks(
        config, status=args.status, mine=args.mine, as_json=args.json
    ))

    sync = subparsers.add_parser("sync", help="Refresh the local task cache and index.")
    sync.add_argument("--offline", action="store_true", help="Re-index from the local cache.")
    sync.add_argument("--prune", action="store_true", help="Remove snapshots for deleted issues.")
    sync.set_defaults(handler=lambda config, args: sync_tasks(
        config, offline=args.offline, prune=args.prune
    ))

    validate = subparsers.add_parser("validate", help="Validate config and cached task metadata.")
    validate.add_argument("--offline", action="store_true", help="Skip network access.")
    validate.set_defaults(handler=lambda config, args: validate_tasks(
        config, offline=args.offline
    ))

    boot = subparsers.add_parser("bootstrap", help="Create labels, milestones, project, and fields.")
    boot.add_argument("--dry-run", action="store_true")
    boot.add_argument(
        "--skip-project",
        action="store_true",
        help="Create labels and milestones only; skip Projects v2 setup.",
    )
    boot.set_defaults(handler=bootstrap)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = load_config()
        return int(args.handler(config, args))
    except TaskError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
