from __future__ import annotations

import argparse
import base64
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import taskctl


def sample_config(tmp: Path) -> dict[str, object]:
    return {
        "repo": "owner/repo",
        "project": {"owner": "owner", "number": None, "title": "Roadmap"},
        "statuses": ["Backlog", "Ready", "In Progress", "Blocked", "In Review", "Done"],
        "priorities": ["P0", "P1", "P2", "P3"],
        "types": {
            "feature": {"label": "type:feature", "branch": "feat", "title": "Feature"},
            "bug": {"label": "type:bug", "branch": "fix", "title": "Bug"},
        },
        "areas": ["ast", "security"],
        "sizes": ["XS", "S", "M", "L", "XL"],
        "milestones": ["0.3.0"],
        "cache_dir": str(tmp / "tasks"),
    }


def record(number: int = 1, status: str = "Ready", priority: str = "P2") -> taskctl.TaskRecord:
    return taskctl.TaskRecord(
        number=number,
        title="Add Go manifest detection",
        url=f"https://github.com/owner/repo/issues/{number}",
        state="OPEN",
        status=status,
        priority=priority,
        type="feature",
        area="ast",
        milestone="0.3.0",
        assignees=["alice"],
        labels=["priority:P2", "type:feature"],
        updated_at="2026-11-08T00:00:00Z",
        body="Goal body",
    )


def write_raw_snapshot(directory: Path, name: str, meta: dict[str, object]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    encoded = base64.b64encode(
        json.dumps(meta, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    (directory / name).write_text(
        f"<!-- task-meta-b64\n{encoded}\n-->\n\n# task\n", encoding="utf-8"
    )


class HelperTests(unittest.TestCase):
    def test_slugify(self) -> None:
        self.assertEqual(taskctl.slugify("Add Go manifest detection"), "add-go-manifest-detection")
        self.assertEqual(taskctl.slugify("  ...  "), "task")
        self.assertEqual(len(taskctl.slugify("x" * 200)), 60)

    def test_issue_number_from_url(self) -> None:
        self.assertEqual(
            taskctl.issue_number_from_url("https://github.com/owner/repo/issues/42"), 42
        )
        self.assertEqual(
            taskctl.issue_number_from_url("https://github.com/owner/repo/issues/42#issuecomment-1"),
            42,
        )
        with self.assertRaises(taskctl.TaskError):
            taskctl.issue_number_from_url("https://github.com/owner/repo/pull/42")

    def test_field_value_supports_dict_and_list_shapes(self) -> None:
        self.assertEqual(
            taskctl.field_value({"fieldValues": {"Status": "In Progress"}}, "Status"),
            "In Progress",
        )
        self.assertEqual(
            taskctl.field_value(
                {"fieldValues": [{"name": "Status", "value": {"name": "Done"}}]},
                "Status",
            ),
            "Done",
        )
        self.assertIsNone(taskctl.field_value({}, "Status"))

    def test_task_from_issue_uses_labels_and_project(self) -> None:
        issue = {
            "number": 7,
            "title": "Fix parser",
            "url": "https://github.com/owner/repo/issues/7",
            "state": "OPEN",
            "labels": [{"name": "type:bug"}, {"name": "priority:P1"}],
            "assignees": [{"login": "bob"}],
            "milestone": {"title": "0.3.0"},
            "updatedAt": "2026-11-08T00:00:00Z",
            "body": "body",
        }
        item = {"fieldValues": {"Status": "In Review"}}
        result = taskctl.task_from_issue(issue, item)
        self.assertEqual(result.status, "In Review")
        self.assertEqual(result.priority, "P1")
        self.assertEqual(result.type, "bug")
        self.assertEqual(result.assignees, ["bob"])

    def test_run_gh_uses_argument_list_and_timeout(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="ok", stderr=""
        )
        with mock.patch("scripts.taskctl.subprocess.run", return_value=completed) as runner:
            taskctl.run_gh(["issue", "list"])
        args, kwargs = runner.call_args
        self.assertEqual(args[0], ["gh", "issue", "list"])
        self.assertEqual(kwargs["timeout"], taskctl.GH_TIMEOUT)
        self.assertNotIn("shell", kwargs)

    def test_run_gh_reports_missing_binary(self) -> None:
        with mock.patch("scripts.taskctl.subprocess.run", side_effect=FileNotFoundError):
            with self.assertRaises(taskctl.TaskError):
                taskctl.run_gh(["issue", "list"])


class SnapshotTests(unittest.TestCase):
    def test_snapshot_roundtrip(self) -> None:
        original = record()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / original.filename
            path.write_text(taskctl.render_snapshot(original), encoding="utf-8")
            parsed = taskctl.parse_snapshot(path)
        self.assertEqual(parsed["number"], original.number)
        self.assertEqual(parsed["status"], original.status)
        self.assertNotIn("body", parsed)

    def test_render_index_is_deterministic(self) -> None:
        config = sample_config(Path("."))
        first = record(1, "In Progress", "P1")
        second = record(2, "Ready", "P2")
        one = taskctl.render_index([first, second], config)
        two = taskctl.render_index([second, first], config)
        self.assertEqual(one, two)
        self.assertLess(one.index("#2"), one.index("#1"))
        self.assertIn("In Progress: 1", one)

    def test_render_index_empty(self) -> None:
        text = taskctl.render_index([], sample_config(Path(".")))
        self.assertIn("No cached tasks", text)


class ValidateTests(unittest.TestCase):
    def _run(self, config: dict[str, object]) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = taskctl.validate_tasks(config, offline=True)
        return code, out.getvalue(), err.getvalue()

    def test_valid_cache_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = sample_config(Path(tmp))
            taskctl.write_cache(config, [record(1), record(2, "Done", "P0")])
            code, _, err = self._run(config)
        self.assertEqual(code, 0, err)

    def test_unknown_status_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = sample_config(Path(tmp))
            bad = record(1).meta()
            bad["status"] = "Doing"
            write_raw_snapshot(Path(str(config["cache_dir"])), "0001-add-go-manifest-detection.md", bad)
            code, _, err = self._run(config)
        self.assertEqual(code, 1)
        self.assertIn("unknown status", err)

    def test_duplicate_ids_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = sample_config(Path(tmp))
            meta = record(1).meta()
            directory = Path(str(config["cache_dir"]))
            write_raw_snapshot(directory, "0001-one.md", meta)
            write_raw_snapshot(directory, "0001-two.md", meta)
            code, _, err = self._run(config)
        self.assertEqual(code, 1)
        self.assertIn("duplicate issue #1", err)

    def test_stale_index_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = sample_config(Path(tmp))
            taskctl.write_cache(config, [record(1)])
            index = Path(str(config["cache_dir"])) / taskctl.INDEX_NAME
            index.write_text("stale\n", encoding="utf-8")
            code, _, err = self._run(config)
        self.assertEqual(code, 1)
        self.assertIn("stale", err)

    def test_missing_cache_is_not_an_error_offline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = sample_config(Path(tmp))
            code, out, err = self._run(config)
        self.assertEqual(code, 0, err)
        self.assertIn("No task cache found", out)


class CommandTests(unittest.TestCase):
    def test_new_task_dry_run_prints_command(self) -> None:
        config = sample_config(Path("."))
        args = argparse.Namespace(
            type="feature",
            title="Add parser",
            body=None,
            body_file=None,
            priority="P1",
            area="ast",
            milestone="0.3.0",
            status="Ready",
            dry_run=True,
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = taskctl.new_task(config, args)
        text = out.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("gh issue create", text)
        self.assertIn("Suggested branch: feat/add-parser", text)
        self.assertIn("priority:P1", text)

    def test_new_task_rejects_unknown_type(self) -> None:
        config = sample_config(Path("."))
        args = argparse.Namespace(
            type="chore",
            title="x",
            body=None,
            body_file=None,
            priority="P2",
            area=None,
            milestone=None,
            status="Ready",
            dry_run=True,
        )
        with self.assertRaises(taskctl.TaskError):
            taskctl.new_task(config, args)

    def test_set_single_select_builds_item_edit(self) -> None:
        config = sample_config(Path("."))
        fields = {
            "Status": {
                "id": "FIELD_1",
                "options": [{"id": "OPT_1", "name": "In Progress"}],
            }
        }
        with mock.patch.object(taskctl, "project_meta", return_value=("PROJECT_1", fields)):
            with mock.patch.object(taskctl, "run_gh") as runner:
                taskctl.set_single_select(config, "ITEM_1", "Status", "In Progress")
        command = runner.call_args[0][0]
        self.assertEqual(command[0], "project")
        self.assertEqual(command[1], "item-edit")
        self.assertIn("--single-select-option-id", command)
        self.assertIn("OPT_1", command)

    def test_set_single_select_rejects_unknown_option(self) -> None:
        config = sample_config(Path("."))
        fields = {"Status": {"id": "FIELD_1", "options": [{"id": "OPT_1", "name": "Done"}]}}
        with mock.patch.object(taskctl, "project_meta", return_value=("PROJECT_1", fields)):
            with self.assertRaises(taskctl.TaskError):
                taskctl.set_single_select(config, "ITEM_1", "Status", "Blocked")

    def test_project_sync_sets_fields_from_labels(self) -> None:
        config = sample_config(Path("."))
        config["project"]["number"] = 5
        issue = {
            "number": 7,
            "title": "Fix parser",
            "url": "https://github.com/owner/repo/issues/7",
            "state": "OPEN",
            "labels": [{"name": "type:bug"}, {"name": "priority:P1"}, {"name": "area:ast"}],
            "assignees": [],
            "milestone": None,
            "updatedAt": "2026-11-08T00:00:00Z",
            "body": "",
        }
        args = argparse.Namespace(number=7, status="Backlog")
        with mock.patch.object(taskctl, "gh_json", return_value=issue):
            with mock.patch.object(taskctl, "ensure_project_item", return_value="ITEM_1"):
                with mock.patch.object(taskctl, "set_single_select") as setter:
                    code = taskctl.project_sync_task(config, args)
        self.assertEqual(code, 0)
        fields = [call.args[2] for call in setter.call_args_list]
        self.assertEqual(fields, ["Status", "Priority", "Type", "Area"])

    def test_project_sync_skips_without_project(self) -> None:
        config = sample_config(Path("."))
        args = argparse.Namespace(number=7, status="Backlog")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = taskctl.project_sync_task(config, args)
        self.assertEqual(code, 0)
        self.assertIn("no project configured", err.getvalue())


if __name__ == "__main__":
    unittest.main()
