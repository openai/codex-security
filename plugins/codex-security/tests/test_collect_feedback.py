from __future__ import annotations

import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import collect_feedback as collector

STARTED = "2026-08-11T12:00:00.900Z"
FINISHED = "2026-08-11T12:02:00.000Z"


class CollectFeedbackTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.home = self.root / "codex-home"
        self.state = self.root / "workbench"
        self.state.mkdir()
        self.database = self.state / "workbench.sqlite3"
        self.environment = {
            "CODEX_HOME": str(self.home),
            "CODEX_SECURITY_STATE_DIR": str(self.state),
            "CODEX_SQLITE_HOME": str(self.root / "sqlite"),
            "CODEX_STATE_DB": "",
        }
        environment_patch = patch.dict(os.environ, self.environment)
        environment_patch.start()
        self.addCleanup(environment_patch.stop)
        with sqlite3.connect(self.database) as connection:
            connection.executescript(
                """
                PRAGMA user_version = 1;
                CREATE TABLE workspaces (id TEXT PRIMARY KEY, thread_id TEXT);
                CREATE TABLE scans (
                    id TEXT PRIMARY KEY, workspace_id TEXT, mode TEXT, status TEXT,
                    phase TEXT, failure_message TEXT, scan_dir TEXT,
                    started_at TEXT, completed_at TEXT, updated_at TEXT,
                    continuation_thread_id TEXT, deep_scan_owner_thread_id TEXT,
                    parent_scan_id TEXT, handoff_claim_token TEXT, recipe_json TEXT
                );
                CREATE TABLE deep_scan_runs (
                    scan_id TEXT, status TEXT, phase TEXT, error_message TEXT,
                    publication_error_message TEXT
                );
                CREATE TABLE deep_scan_workers (
                    scan_id TEXT, id TEXT, kind TEXT, status TEXT, merge_state TEXT,
                    attempt INTEGER, sdk_thread_id TEXT, error_message TEXT,
                    created_at TEXT, started_at TEXT, completed_at TEXT, updated_at TEXT
                );
                CREATE TABLE deep_scan_worker_attempts (
                    scan_id TEXT, worker_id TEXT, attempt INTEGER, sdk_thread_id TEXT,
                    status TEXT, error_message TEXT, created_at TEXT, started_at TEXT,
                    completed_at TEXT, updated_at TEXT
                );
                """
            )

    def scan(
        self,
        scan_id: str = "scan",
        *,
        thread_id: str | None = "owner",
        continuation: str | None = None,
        deep_owner: str | None = None,
        mode: str = "standard",
        directory: Path | None = None,
        parent: str | None = None,
    ) -> Path:
        directory = directory or self.root / "scans" / scan_id
        with sqlite3.connect(self.database) as connection:
            connection.execute("INSERT INTO workspaces VALUES (?, ?)", (scan_id, thread_id))
            connection.execute(
                "INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    scan_id,
                    mode,
                    "failed",
                    "discovery",
                    "synthetic scan failure",
                    str(directory),
                    STARTED,
                    FINISHED,
                    FINISHED,
                    continuation,
                    deep_owner,
                    parent,
                    "SYNTHETIC_CLAIM_SECRET",
                    '{"apiKey":"SYNTHETIC_CONFIG_SECRET"}',
                ),
            )
        return directory

    def rollout(
        self,
        thread_id: str,
        *,
        parent: str | None = None,
        timestamp: str = "2026-08-11T12:01:00.000Z",
        cwd: Path | None = None,
        directory: Path | None = None,
        events: list[dict] | None = None,
    ) -> Path:
        directory = directory or self.home / "sessions" / "2026" / "08" / "11"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"rollout-{thread_id}.jsonl"
        metadata = {"id": thread_id, "timestamp": timestamp}
        if parent is not None:
            metadata["source"] = {"subagent": {"thread_spawn": {"parent_thread_id": parent}}}
        if cwd is not None:
            metadata["cwd"] = str(cwd)
        records = [
            {"type": "session_meta", "payload": metadata},
            *(
                events
                if events is not None
                else [
                    {
                        "type": "event_msg",
                        "payload": {"type": "agent_message", "message": thread_id},
                    },
                ]
            ),
        ]
        path.write_text("\n".join(json.dumps(record) for record in records), encoding="utf-8")
        return path

    def bundle(self, request: dict | None = None) -> dict:
        output = io.StringIO()
        self.assertTrue(collector.write_feedback(request or {"scanIds": ["scan"]}, output))
        return json.loads(output.getvalue())

    def state_graph(self, rollouts: dict[str, Path], edges: list[tuple[str, str]]) -> None:
        state_path = self.home / "state_5.sqlite"
        state_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(state_path) as connection:
            connection.execute("CREATE TABLE threads (id TEXT, rollout_path TEXT)")
            connection.execute(
                "CREATE TABLE thread_spawn_edges (parent_thread_id TEXT, child_thread_id TEXT)"
            )
            connection.executemany(
                "INSERT INTO threads VALUES (?, ?)",
                [(key, str(value)) for key, value in rollouts.items()],
            )
            connection.executemany("INSERT INTO thread_spawn_edges VALUES (?, ?)", edges)

    def test_no_matching_scan_leaves_stdout_and_state_unchanged(self) -> None:
        before = self.database.read_bytes()
        output = io.StringIO()
        self.assertFalse(collector.write_feedback({"threadIds": ["ordinary-thread"]}, output))
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(before, self.database.read_bytes())
        with patch.dict(os.environ, {"CODEX_SECURITY_STATE_DIR": str(self.root / "absent")}):
            self.assertEqual(collector.collect_feedback({"scanIds": ["missing"]}), [])
        self.assertFalse((self.root / "absent").exists())

    def test_selectors_find_all_owner_bindings_without_other_scans_or_reruns(self) -> None:
        self.scan("workspace", thread_id="workspace-owner")
        self.scan("continued", thread_id=None, continuation="continued-owner")
        self.scan("deep", thread_id=None, deep_owner="deep-owner", mode="deep")
        self.scan("unrelated", thread_id="elsewhere")
        self.scan("rerun", thread_id="rerun-owner", parent="workspace")
        before = self.database.read_bytes()
        bundle = self.bundle(
            {"threadIds": ["workspace-owner", "continued-owner", "deep-owner", "workspace-owner"]}
        )
        self.assertEqual(
            [scan["scanId"] for scan in bundle["scans"]], ["workspace", "continued", "deep"]
        )
        self.assertEqual(
            [scan["scanId"] for scan in self.bundle({"scanIds": ["workspace"]})["scans"]],
            ["workspace"],
        )
        self.assertEqual(before, self.database.read_bytes())
        encoded = json.dumps(bundle)
        self.assertNotIn("SYNTHETIC_CLAIM_SECRET", encoded)
        self.assertNotIn("SYNTHETIC_CONFIG_SECRET", encoded)
        self.assertIn("synthetic scan failure", encoded)

    def test_default_workbench_location_and_old_schema_are_read_only(self) -> None:
        self.scan()
        default = self.home / "state" / "plugins" / "codex-security"
        default.mkdir(parents=True)
        default_database = default / "workbench.sqlite3"
        with sqlite3.connect(self.database) as connection:
            connection.executescript(
                "DROP TABLE deep_scan_worker_attempts; DROP TABLE deep_scan_workers; DROP TABLE deep_scan_runs;"
            )
        default_database.write_bytes(self.database.read_bytes())
        before = default_database.read_bytes()
        with patch.dict(os.environ, {"CODEX_SECURITY_STATE_DIR": ""}):
            self.assertEqual(self.bundle()["scans"][0]["scanId"], "scan")
        self.assertEqual(default_database.read_bytes(), before)

    def test_parent_and_nested_archived_workers_skip_unrelated_event_bodies(self) -> None:
        self.scan()
        self.rollout("owner")
        self.rollout("worker", parent="owner", directory=self.home / "archived_sessions")
        self.rollout("nested", parent="worker")
        self.rollout(
            "unrelated",
            events=[{"type": "event_msg", "payload": {"message": "UNRELATED_EVENT_BODY"}}],
        )
        original_loads = json.loads

        def check_loads(value, *args, **kwargs):
            if isinstance(value, bytes):
                self.assertNotIn(b"UNRELATED_EVENT_BODY", value)
            return original_loads(value, *args, **kwargs)

        with patch.object(collector.json, "loads", side_effect=check_loads):
            plans = collector.collect_feedback({"scanIds": ["scan"]})
            events = list(plans[0].events())
        self.assertEqual(
            [session.thread_id for session in plans[0].sessions], ["owner", "worker", "nested"]
        )
        self.assertEqual(set(events[0]), {"threadId", "event"})
        self.assertEqual({event["threadId"] for event in events}, {"owner", "worker", "nested"})

    def test_missing_parent_and_child_rollouts_keep_remaining_state_descendants(self) -> None:
        self.scan()
        outside = self.root / "relocated-rollouts"
        grandchild = self.rollout("grandchild", parent="missing-child", directory=outside)
        self.rollout("sibling", parent="owner")
        self.state_graph(
            {"owner": self.root / "missing-parent.jsonl", "grandchild": grandchild},
            [("owner", "missing-child"), ("missing-child", "grandchild")],
        )
        scan = self.bundle()["scans"][0]
        self.assertEqual(
            {session["threadId"] for session in scan["sessions"]}, {"grandchild", "sibling"}
        )
        self.assertEqual({event["threadId"] for event in scan["events"]}, {"grandchild", "sibling"})

    def test_saved_deep_attempts_recover_independent_roots_and_prethread_errors(self) -> None:
        self.scan(mode="deep")
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO deep_scan_runs VALUES (?, ?, ?, ?, ?)",
                ("scan", "failed", "terminal", "coordinator failure", "publication failure"),
            )
            connection.execute(
                "INSERT INTO deep_scan_workers (scan_id, id, kind, status, attempt, sdk_thread_id, error_message) VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("scan", "worker", "discovery", "failed", 2, "current-attempt", "current failure"),
            )
            connection.executemany(
                "INSERT INTO deep_scan_worker_attempts (scan_id, worker_id, attempt, sdk_thread_id, status, error_message) VALUES (?, ?, ?, ?, ?, ?)",
                [
                    ("scan", "worker", 1, "old-attempt", "failed", "old failure"),
                    ("scan", "worker", 2, "current-attempt", "failed", "current failure"),
                    ("scan", "early-worker", 1, None, "failed", "failed before thread"),
                ],
            )
        self.rollout("old-attempt", directory=self.home / "archived_sessions")
        self.rollout("old-child", parent="old-attempt")
        self.rollout("current-attempt")
        self.rollout("unrelated")
        scan = self.bundle()["scans"][0]
        self.assertEqual(
            {session["threadId"] for session in scan["sessions"]},
            {"old-attempt", "old-child", "current-attempt"},
        )
        self.assertEqual(scan["deepScan"]["error"], "coordinator failure")
        self.assertEqual(scan["workers"][0]["error"], "current failure")
        self.assertEqual(scan["workerAttempts"][-1]["error"], "failed before thread")

    def test_legacy_deep_attempts_respect_artifact_paths_and_scan_window(self) -> None:
        directory = self.scan(mode="deep")
        self.rollout("owner", timestamp=STARTED, cwd=directory)
        artifacts = directory / "artifacts"
        self.rollout("setup", cwd=artifacts)
        self.rollout(
            "old-attempt", cwd=artifacts / "deep_discovery" / "workers" / "worker" / "output"
        )
        self.rollout("nested", parent="old-attempt")
        for name, cwd, timestamp in (
            ("before", artifacts, "2026-08-11T12:00:00.100Z"),
            ("replacement", artifacts, FINISHED),
            ("target-session", self.root / "target", STARTED),
            ("wrong-layout", artifacts / "deep_discovery" / "old", STARTED),
            ("other-scan", self.root / "other" / "artifacts", STARTED),
        ):
            self.rollout(name, cwd=cwd, timestamp=timestamp)
        self.assertEqual(
            {session["threadId"] for session in self.bundle()["scans"][0]["sessions"]},
            {"owner", "setup", "old-attempt", "nested"},
        )

    def test_archived_legacy_deep_paths_require_matching_original_owner(self) -> None:
        original = self.root / "scans" / "results"
        archived = original.with_name(original.name + ".previous-fixture")
        self.scan(mode="deep", directory=archived)
        self.rollout("owner", timestamp=STARTED, cwd=original)
        self.rollout("old", cwd=original / "artifacts")
        self.rollout("replacement", timestamp=FINISHED, cwd=original / "artifacts")
        self.assertEqual(
            {session["threadId"] for session in self.bundle()["scans"][0]["sessions"]},
            {"owner", "old"},
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE scans SET scan_dir = ?", (str(self.root / "unrelated.previous-fixture"),)
            )
        self.assertEqual(
            [session["threadId"] for session in self.bundle()["scans"][0]["sessions"]], ["owner"]
        )

    def test_inherited_replay_is_removed_and_large_current_events_are_preserved(self) -> None:
        self.scan()
        timestamp = "2026-08-11T12:01:00.900Z"
        started = collector._timestamp(timestamp).timestamp()
        large_output = "x" * (2 * 1024 * 1024 + 1)
        path = self.rollout(
            "owner",
            timestamp=timestamp,
            events=[
                {"type": "session_meta", "payload": {"id": "inherited"}},
                {
                    "type": "event_msg",
                    "payload": {"type": "task_started", "started_at": started - 30},
                },
                {"type": "event_msg", "payload": {"message": "INHERITED_HISTORY"}},
                {
                    "type": "event_msg",
                    "payload": {"type": "task_started", "started_at": int(started)},
                },
                {"type": "response_item", "payload": {"output": large_output}},
            ],
        )
        path.write_bytes(b"bad json\n42\n" + path.read_bytes())
        events = self.bundle()["scans"][0]["events"]
        self.assertNotIn("INHERITED_HISTORY", json.dumps(events))
        self.assertEqual(events[-1]["event"]["payload"]["output"], large_output)

    def test_deleted_selected_rollout_does_not_discard_other_events(self) -> None:
        self.scan()
        path = self.rollout("owner")
        self.rollout("child", parent="owner")
        plan = collector.collect_feedback({"scanIds": ["scan"]})[0]
        path.unlink()
        self.assertEqual({event["threadId"] for event in plan.events()}, {"child"})

    def test_stdin_entrypoint_emits_json_or_empty_stdout(self) -> None:
        self.scan()
        script = SCRIPTS / "collect_feedback.py"
        for request, expected in (
            ({"scanIds": ["scan"]}, "scan"),
            ({"threadIds": ["other"]}, None),
        ):
            completed = subprocess.run(
                [sys.executable, "-B", str(script)],
                input=json.dumps(request),
                text=True,
                capture_output=True,
                check=True,
            )
            self.assertEqual(completed.stderr, "")
            if expected is None:
                self.assertEqual(completed.stdout, "")
            else:
                self.assertEqual(json.loads(completed.stdout)["scans"][0]["scanId"], expected)

    def test_entrypoint_finishes_after_one_request_line_without_stdin_eof(self) -> None:
        self.scan()
        with subprocess.Popen(
            [sys.executable, "-B", str(SCRIPTS / "collect_feedback.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ) as process:
            try:
                process.stdin.write('{"scanIds":["scan"]}\n')
                process.stdin.flush()
                self.assertEqual(process.wait(timeout=10), 0)
                self.assertEqual(json.loads(process.stdout.read())["scans"][0]["scanId"], "scan")
                self.assertEqual(process.stderr.read(), "")
            finally:
                if process.poll() is None:
                    process.kill()

    def test_database_uri_supports_spaces_unicode_and_fragment_characters(self) -> None:
        self.scan()
        special_name = "state # café" + (" ? query" if os.name != "nt" else "")
        renamed = self.root / special_name
        self.state.rename(renamed)
        owner = self.rollout("owner", directory=self.root / "relocated-rollouts")
        self.state_graph({"owner": owner}, [])
        state_database = renamed / (special_name + ".sqlite")
        (self.home / "state_5.sqlite").rename(state_database)
        with patch.dict(
            os.environ,
            {
                "CODEX_SECURITY_STATE_DIR": str(renamed),
                "CODEX_STATE_DB": str(state_database),
            },
        ):
            scan = self.bundle()["scans"][0]
            self.assertEqual(scan["scanId"], "scan")
            self.assertEqual([session["threadId"] for session in scan["sessions"]], ["owner"])


if __name__ == "__main__":
    unittest.main()
