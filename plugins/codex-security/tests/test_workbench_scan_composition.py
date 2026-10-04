from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from unittest import mock

import pytest
from workbench_test_support import (
    SCRIPT,
    checkpoint,
    recipe,
    register,
    run_workbench,
    write_completed_contract,
)

CHECKPOINT = "artifacts/deep-scan/checkpoint.json"
EXECUTION_THREADS = "artifacts/deep-scan/execution-threads.json"


def _scan_workspace(tmp_path: Path, source: str = "print('fixture')\n") -> tuple[Path, Path]:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text(source)
    return tmp_path / "state", target


@pytest.mark.parametrize("name", ["current", "legacy"])
def test_checkpoint_reads_shared_sdk_fixtures(tmp_path, workbench_api, monkeypatch, name):
    state, target = _scan_workspace(tmp_path)
    scan = register(state, target, tmp_path / "scan", mode="deep")
    fixture = Path(__file__).parent / "fixtures/composition-checkpoints" / f"{name}.json"
    original = json.loads(fixture.read_text())
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        scan["scanId"],
        "--artifact-path",
        CHECKPOINT,
        input_text=fixture.read_text(),
    )
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    stored = {"id": scan["scanId"], "scan_dir": scan["scanDir"]}
    loaded = workbench_api["load_composition"].__globals__["read_composition_checkpoint"](stored)
    assert loaded == original
    encoded = json.dumps(
        loaded, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()
    assert json.loads(encoded) == original
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        scan["scanId"],
        "--artifact-path",
        CHECKPOINT,
        input_text=encoded.decode(),
    )
    assert (
        workbench_api["load_composition"].__globals__["read_composition_checkpoint"](stored)
        == original
    )


def test_checkpoint_read_blocks_other_threads_and_atomic_writers(
    tmp_path: Path, workbench_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, target = _scan_workspace(tmp_path)
    scan = register(state, target, tmp_path / "scan", mode="deep")
    original = checkpoint(state, scan)
    updated = {**original, "noNewStreak": 1}
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    read_checkpoint = workbench_api["load_composition"].__globals__["read_composition_checkpoint"]
    reading, release_read, thread_waiting, thread_acquired = (Event() for _ in range(4))

    def paused_read(scan_dir: Path, relative: str, context: str) -> dict:
        descriptor = workbench_api["open_scan_local_file_descriptor"](scan_dir, relative, context)
        with os.fdopen(descriptor, "rb") as source:
            reading.set()
            assert release_read.wait(10)
            return json.load(source)

    def competing_thread() -> None:
        thread_waiting.set()
        with workbench_api["scan_completion_lock"](scan["scanId"]):
            thread_acquired.set()

    writer_script = """
import runpy, sys
sys.path.insert(0, sys.argv[1])
from workbench import storage
acquire = storage.acquire_completion_file_lock
def announce_acquire(descriptor):
    print("waiting", flush=True)
    acquire(descriptor)
storage.acquire_completion_file_lock = announce_acquire
sys.argv = sys.argv[2:]
runpy.run_path(sys.argv[0], run_name="__main__")
"""
    with (
        mock.patch.dict(read_checkpoint.__globals__, _read_scan_local_json=paused_read),
        ThreadPoolExecutor(max_workers=3) as executor,
    ):
        reader = executor.submit(
            read_checkpoint, {"id": scan["scanId"], "scan_dir": scan["scanDir"]}
        )
        writer = None
        try:
            assert reading.wait(5)
            contender = executor.submit(competing_thread)
            assert thread_waiting.wait(5)
            assert not thread_acquired.wait(0.1)
            writer = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    writer_script,
                    str(SCRIPT.parent),
                    str(SCRIPT),
                    "save-scan-artifact",
                    "--scan-id",
                    scan["scanId"],
                    "--artifact-path",
                    CHECKPOINT,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            writer.stdin.write(json.dumps(updated))
            writer.stdin.close()
            writer.stdin = None
            assert executor.submit(writer.stdout.readline).result(timeout=5).strip() == "waiting"
            with pytest.raises(subprocess.TimeoutExpired):
                writer.wait(timeout=0.1)
            assert json.loads((Path(scan["scanDir"]) / CHECKPOINT).read_text()) == original
        finally:
            release_read.set()
            if writer is not None:
                try:
                    stdout, stderr = writer.communicate(timeout=10)
                finally:
                    if writer.poll() is None:
                        writer.kill()
                        writer.communicate()
        assert reader.result(timeout=5) == original
        contender.result(timeout=5)
        assert writer.returncode == 0, stderr
        assert json.loads(stdout)["scanId"] == scan["scanId"]
    assert json.loads((Path(scan["scanDir"]) / CHECKPOINT).read_text()) == updated


@pytest.mark.parametrize("missing", ["checkpoint", "output"])
def test_history_hides_composition_children_without_parent_artifacts(
    tmp_path: Path, missing: str
) -> None:
    state, target = _scan_workspace(tmp_path)
    parent_dir = tmp_path / "scan"
    parent = register(state, target, parent_dir, mode="deep")
    rerun = register(state, target, tmp_path / "rerun", parent=parent["scanId"])
    child_path = "artifacts/deep-scan/passes/pass-1"
    child = register(
        state, target, parent_dir / child_path, parent=parent["scanId"], role="deep_pass"
    )
    checkpoint(state, parent, passes=[{"directory": child_path, "scanId": child["scanId"]}])
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        for day, scan in enumerate((parent, rerun, child), 1):
            connection.execute(
                "UPDATE scans SET started_at = ? WHERE id = ?",
                (f"2026-01-0{day}T00:00:00Z", scan["scanId"]),
            )
    for scan in (rerun, child):
        write_completed_contract(
            Path(scan["scanDir"]), scan["scanId"], target, relative_path="app.py"
        )
        run_workbench(state, "complete-scan", "--scan-id", scan["scanId"])
    if missing == "checkpoint":
        (parent_dir / CHECKPOINT).unlink()
    else:
        parent_dir.rename(tmp_path / "removed-output")

    assert {scan["scanId"] for scan in run_workbench(state, "list-scans")["scans"]} == {
        parent["scanId"],
        rerun["scanId"],
    }
    assert (
        run_workbench(state, "list-scans", "--status", "complete", "--limit", "1")["scans"][0][
            "scanId"
        ]
        == rerun["scanId"]
    )
    indexed = run_workbench(state, "list-global-findings")["findings"]
    assert len(indexed) == 1
    assert indexed[0]["scanId"] == rerun["scanId"]
    assert indexed[0]["occurrenceCount"] == 1
    assert indexed[0]["knownScanIds"] == [rerun["scanId"]]
    visible = run_workbench(state, "get-scan", "--scan-id", rerun["scanId"])["scan"]
    assert "knownScanIds" not in visible["findings"][0]
    assert "matches" not in visible["findings"][0]
    repository = run_workbench(state, "list-repositories")["repositories"][0]
    assert repository["scanCount"] == 2
    assert repository["latestScan"]["scanId"] == rerun["scanId"]
    explicit = run_workbench(state, "list-scans", "--scan-root", child["scanDir"])["scans"]
    assert [scan["scanId"] for scan in explicit] == [child["scanId"]]
    assert (
        run_workbench(state, "get-scan", "--scan-id", child["scanId"])["scan"]["findingCount"] == 1
    )


def test_archive_rejects_a_running_child_of_a_stopped_parent(tmp_path: Path) -> None:
    state, target = _scan_workspace(tmp_path)
    directory = tmp_path / "scan"
    parent = register(state, target, directory, mode="deep")
    child_dir = directory / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("UPDATE scans SET status = 'failed' WHERE id = ?", (parent["scanId"],))
    archived = tmp_path / "scan.previous-test"
    directory.rename(archived)
    directory.mkdir(mode=0o700)
    response = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(target),
        "--scan-dir",
        str(directory),
        "--recipe-json",
        json.dumps(recipe(target, "deep")),
        "--archive-existing",
        "--archived-scan-dir",
        str(archived),
        check=False,
    )
    assert response["returncode"] != 0
    assert "child scan is running" in response["stderr"]
    saved = run_workbench(state, "get-scan", "--scan-id", child["scanId"])["scan"]
    assert saved["scanDir"] == str(child_dir)
    assert saved["progress"]["status"] == "running"


def test_archiving_composition_preserves_children_and_reuses_pass_directories(
    tmp_path: Path,
) -> None:
    state, target = _scan_workspace(tmp_path)
    directory = tmp_path / "scan"
    parent = register(state, target, directory, mode="deep")
    child_path = "artifacts/deep-scan/passes/pass-1"
    child = register(
        state, target, directory / child_path, parent=parent["scanId"], role="deep_pass"
    )
    checkpoint(state, parent, passes=[{"directory": child_path}])
    unrelated = register(state, target, tmp_path / "rerun", parent=parent["scanId"])
    for scan in (child, unrelated):
        write_completed_contract(
            Path(scan["scanDir"]),
            scan["scanId"],
            target,
            relative_path="app.py",
            identity_anchor=scan["scanId"],
        )
        run_workbench(state, "complete-scan", "--scan-id", scan["scanId"])
    run_workbench(
        state, "fail-scan", "--scan-id", parent["scanId"], "--message", "Synthetic interruption."
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        old_scans = {row["id"]: dict(row) for row in connection.execute("SELECT * FROM scans")}
        old_artifacts = [dict(row) for row in connection.execute("SELECT * FROM scan_artifacts")]
        old_findings = connection.execute("SELECT * FROM finding_occurrences").fetchall()
    child_manifest = (directory / child_path / "scan-manifest.json").read_bytes()
    archived = tmp_path / "scan.previous-test"
    directory.rename(archived)
    directory.mkdir(mode=0o700)
    current = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(target),
        "--scan-dir",
        str(directory),
        "--recipe-json",
        json.dumps(recipe(target, "deep")),
        "--archive-existing",
        "--archived-scan-dir",
        str(archived),
    )

    archived_child = run_workbench(state, "get-scan", "--scan-id", child["scanId"])
    assert archived_child["scan"]["scanDir"] == str(archived / child_path)
    assert archived_child["scan"]["findingCount"] == 1
    assert (archived / child_path / "scan-manifest.json").read_bytes() == child_manifest
    context = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])
    assert "compositionCheckpoint" not in context
    assert context["scan"]["progress"]["independentReviews"]["completed"] == 1
    assert {scan["scanId"] for scan in run_workbench(state, "list-scans")["scans"]} == {
        parent["scanId"],
        current["scanId"],
        unrelated["scanId"],
    }
    assert {
        finding["scanId"] for finding in run_workbench(state, "list-global-findings")["findings"]
    } == {unrelated["scanId"]}
    assert run_workbench(state, "list-repositories")["repositories"][0]["scanCount"] == 3
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        for scan_id, old in old_scans.items():
            if scan_id != unrelated["scanId"]:
                old["scan_dir"] = str(archived / Path(old["scan_dir"]).relative_to(directory))
                old.pop("updated_at")
            actual = dict(
                connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            )
            assert {key: actual[key] for key in old} == old
        for artifact in old_artifacts:
            if artifact["scan_id"] != unrelated["scanId"]:
                artifact["path"] = str(archived / Path(artifact["path"]).relative_to(directory))
            actual = connection.execute(
                "SELECT * FROM scan_artifacts WHERE scan_id = ? AND kind = ?",
                (artifact["scan_id"], artifact["kind"]),
            ).fetchone()
            assert dict(actual) == artifact
            assert Path(actual["path"]).is_file()
        assert connection.execute("SELECT * FROM finding_occurrences").fetchall() == old_findings
    replacement = register(
        state, target, directory / child_path, parent=current["scanId"], role="deep_pass"
    )
    assert replacement["scanId"] != child["scanId"]
    assert replacement["scanDir"] == str(directory / child_path)


@pytest.mark.parametrize("legacy_reviews,saved_maximum_only", [(0, False), (3, False), (3, True)])
@pytest.mark.parametrize("with_child", [False, True])
def test_get_scan_counts_saved_reviews_without_reading_composition_checkpoint(
    tmp_path: Path,
    workbench_api,
    monkeypatch,
    legacy_reviews: int,
    with_child: bool,
    saved_maximum_only: bool,
) -> None:
    state, target = _scan_workspace(tmp_path)
    parent = register(state, target, tmp_path / "parent", mode="deep")
    if with_child:
        child = register(
            state,
            target,
            tmp_path / "parent/artifacts/deep-scan/passes/pass-1",
            parent=parent["scanId"],
            role="deep_pass",
        )
        write_completed_contract(
            Path(child["scanDir"]), child["scanId"], target, relative_path="app.py"
        )
        run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
    value = checkpoint(state, parent, passes=[{"directory": "artifacts/deep-scan/passes/pass-1"}])
    if legacy_reviews:
        value["legacy"] = {"discoveryRuns": legacy_reviews, "coverage": {"completeness": "partial"}}
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute(
                "INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, status, "
                "phase, workers, subagents, stop_after_no_new, max_discovery_runs, "
                "completion_sequence, created_at, updated_at) "
                "SELECT id, 1, 'synthetic-legacy', 'succeeded', 'terminal', 1, 0, 3, 8, ?, "
                "started_at, updated_at FROM scans WHERE id = ?",
                (legacy_reviews, parent["scanId"]),
            )
    if saved_maximum_only:
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE scans SET recipe_json = json_remove(recipe_json, '$.deepScan') WHERE id = ?",
                (parent["scanId"],),
            )
    path = Path(parent["scanDir"]) / CHECKPOINT
    path.write_text(json.dumps(value))
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    load = workbench_api["load_composition"]
    reader = load.__globals__["read_composition_checkpoint"]
    with mock.patch.dict(load.__globals__, read_composition_checkpoint=mock.Mock(wraps=reader)):
        with workbench_api["connect"]() as connection:
            context = workbench_api["scan_context"](connection, parent["scanId"])
        load.__globals__["read_composition_checkpoint"].assert_not_called()
    assert context["scan"]["progress"]["independentReviews"] == {
        "active": 0,
        "completed": legacy_reviews + int(with_child),
        "maximum": 8,
        "consolidating": False,
    }
    assert "compositionCheckpoint" not in context
    assert json.loads(path.read_text()) == value
    assert {scan["scanId"] for scan in run_workbench(state, "list-scans")["scans"]} == {
        parent["scanId"]
    }


def test_failed_deep_scan_keeps_followup_thread_before_composition_checkpoint(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    scan = register(state, target, tmp_path / "scan", mode="deep")
    run_workbench(
        state, "fail-scan", "--scan-id", scan["scanId"], "--message", "Synthetic failure."
    )
    for thread_id in ["failed-follow-up", "repeated-follow-up"]:
        run_workbench(
            state, "set-scan-thread", "--scan-id", scan["scanId"], "--thread-id", thread_id
        )
    context = run_workbench(state, "get-scan", "--scan-id", scan["scanId"])
    assert "compositionCheckpoint" not in context
    assert context["scan"]["continuationThreadId"] == "repeated-follow-up"
    assert context["scan"]["progress"]["status"] == "failed"
    assert set(context["scan"]["threadIds"]) == {"failed-follow-up", "repeated-follow-up"}
    assert context["scan"]["executionThreadIds"] == context["scan"]["threadIds"]


@pytest.mark.parametrize("migrate", [False, True])
def test_artifact_thread_ids_do_not_become_execution_log_roots(
    tmp_path: Path, migrate: bool
) -> None:
    state, target = _scan_workspace(tmp_path)
    scan = register(state, target, tmp_path / "scan", mode="deep")
    run_workbench(
        state, "set-scan-thread", "--scan-id", scan["scanId"], "--thread-id", "owned-thread"
    )
    metadata = Path(scan["scanDir"]) / EXECUTION_THREADS
    metadata.parent.mkdir(parents=True, exist_ok=True)
    metadata.write_text(json.dumps(["unrelated-conversation"]))
    if migrate:
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute("DROP TABLE scan_execution_threads")
            connection.execute("DELETE FROM schema_migrations WHERE version = 45")
    saved = run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]
    assert saved["threadIds"] == ["owned-thread"]
    assert saved["executionThreadIds"] == ["owned-thread"]


@pytest.mark.parametrize("child_first", [False, True])
def test_related_findings_hide_internal_passes(tmp_path: Path, child_first: bool) -> None:
    state, target = _scan_workspace(tmp_path)
    parent = register(state, target, tmp_path / "parent", mode="deep")
    public = register(state, target, tmp_path / "public")
    related_public = register(state, target, tmp_path / "related-public")
    child = register(
        state,
        target,
        Path(parent["scanDir"]) / "artifacts/deep-scan/passes/pass-1",
        parent=parent["scanId"],
        role="deep_pass",
    )
    for index, scan in enumerate((public, related_public, child)):
        write_completed_contract(
            Path(scan["scanDir"]),
            scan["scanId"],
            target,
            identity_anchor=f"synthetic-distinct-{index}",
            relative_path="app.py",
        )
        run_workbench(state, "complete-scan", "--scan-id", scan["scanId"])
    for other in (related_public, child):
        before, after = (other, public) if child_first else (public, other)
        finding_ids = [
            run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0][
                "occurrenceId"
            ]
            for scan in (before, after)
        ]
        run_workbench(
            state,
            "save-scan-comparison",
            "--before-scan-id",
            before["scanId"],
            "--after-scan-id",
            after["scanId"],
            "--matches-json",
            json.dumps(
                {
                    "matches": [],
                    "uncertain": [],
                    "related": [
                        {
                            "beforeOccurrenceId": finding_ids[0],
                            "afterOccurrenceId": finding_ids[1],
                            "reason": "Related synthetic findings.",
                        }
                    ],
                }
            ),
        )
    saved = run_workbench(state, "get-scan", "--scan-id", public["scanId"])["scan"]
    listed = run_workbench(state, "list-findings", "--scan-id", public["scanId"])["findingsPage"]
    for finding in (saved["findings"][0], listed["findings"][0]):
        assert {related["scanId"] for related in finding["related"]} == {related_public["scanId"]}


@pytest.mark.parametrize("bridge", ["two-links", "shared-source", "shared-neighbor"])
def test_public_finding_history_does_not_traverse_internal_passes(
    tmp_path: Path, bridge: str
) -> None:
    state, target = _scan_workspace(tmp_path)
    parent = register(state, target, tmp_path / "parent", mode="deep")
    before = register(state, target, tmp_path / "before")
    child = register(
        state,
        target,
        Path(parent["scanDir"]) / "artifacts/deep-scan/passes/pass-1",
        parent=parent["scanId"],
        role="deep_pass",
    )
    after = register(state, target, tmp_path / "after")
    child_anchor = {
        "two-links": "internal-observation",
        "shared-source": "public-before",
        "shared-neighbor": "public-after",
    }[bridge]
    findings = {}
    for scan, anchor in [(before, "public-before"), (after, "public-after"), (child, child_anchor)]:
        write_completed_contract(
            Path(scan["scanDir"]),
            scan["scanId"],
            target,
            identity_anchor=anchor,
            relative_path="app.py",
        )
        completed = run_workbench(state, "complete-scan", "--scan-id", scan["scanId"])["scan"]
        findings[scan["scanId"]] = completed["findings"][0]

    def save_matches(left: dict, right: dict) -> None:
        run_workbench(
            state,
            "save-scan-comparison",
            "--before-scan-id",
            left["scanId"],
            "--after-scan-id",
            right["scanId"],
            "--matches-json",
            json.dumps(
                {
                    "matches": [
                        {
                            "beforeOccurrenceIds": [findings[left["scanId"]]["occurrenceId"]],
                            "afterOccurrenceIds": [findings[right["scanId"]]["occurrenceId"]],
                            "confidence": "high",
                            "reason": "Synthetic confirmed match.",
                        }
                    ],
                    "uncertain": [],
                }
            ),
        )

    if bridge != "shared-source":
        save_matches(before, child)
    if bridge != "shared-neighbor":
        save_matches(child, after)
    compared = run_workbench(
        state,
        "compare-scans",
        "--before-scan-id",
        before["scanId"],
        "--after-scan-id",
        after["scanId"],
        "--include-matching-inputs",
    )
    assert not compared["matchingInputs"].get("knownFindingGroups")
    assert compared["summary"]["persisting"] == 0
    assert compared["summary"]["new"] == 1
    assert compared["summary"]["resolved"] == 1
    assert len(run_workbench(state, "list-global-findings")["findings"]) == 2
    for scan in (before, after):
        saved = run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]
        listed = run_workbench(state, "list-findings", "--scan-id", scan["scanId"])["findingsPage"]
        for finding in [saved["findings"][0], listed["findings"][0]]:
            assert "matches" not in finding
            assert "knownScanIds" not in finding
    explicit_child = run_workbench(state, "get-scan", "--scan-id", child["scanId"])["scan"]
    assert after["scanId"] in {
        match["scanId"] for match in explicit_child["findings"][0]["matches"]
    }
    save_matches(before, after)
    matched = run_workbench(state, "get-scan", "--scan-id", before["scanId"])["scan"]
    assert {match["scanId"] for match in matched["findings"][0]["matches"]} == {after["scanId"]}
    assert len(run_workbench(state, "list-global-findings")["findings"]) == 1


@pytest.mark.parametrize("missing_outputs", [False, True])
@pytest.mark.parametrize("already_applied", [False, True])
def test_membership_migration_backfills_stored_paths_once(
    tmp_path: Path, missing_outputs: bool, already_applied: bool
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    parent_dir = tmp_path / "parent.previous-synthetic"
    parent = register(state, target, parent_dir, mode="deep")
    child = register(
        state, target, parent_dir / "artifacts/deep-scan/passes/pass-1", parent=parent["scanId"]
    )
    rerun = register(state, target, tmp_path / "rerun", parent=parent["scanId"])
    database = state / "workbench.sqlite3"
    marker = parent_dir / "saved-output.txt"
    marker.write_bytes(b"Saved outputs must not change during migration.")
    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM schema_migrations WHERE version = 48")
        if already_applied:
            connection.execute("UPDATE scans SET parent_scan_role = NULL")
        else:
            connection.execute("DROP INDEX scans_by_composition_parent")
            connection.execute("ALTER TABLE scans DROP COLUMN parent_scan_role")
            connection.execute("DELETE FROM schema_migrations WHERE version = 43")
        before = connection.execute(
            "SELECT id, parent_scan_id, scan_dir, status FROM scans ORDER BY id"
        ).fetchall()
    if missing_outputs:
        parent_dir.rename(tmp_path / "removed-output")
    run_workbench(state, "database-info")
    run_workbench(state, "database-info")
    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT id, parent_scan_id, scan_dir, status FROM scans ORDER BY id"
            ).fetchall()
            == before
        )
        assert dict(connection.execute("SELECT id, parent_scan_role FROM scans")) == {
            parent["scanId"]: None,
            child["scanId"]: "deep_pass",
            rerun["scanId"]: None,
        }
        assert connection.execute(
            "SELECT version, COUNT(*) FROM schema_migrations WHERE version IN (43, 48) "
            "GROUP BY version ORDER BY version"
        ).fetchall() == [(43, 1), (48, 1)]
    saved_marker = tmp_path / "removed-output/saved-output.txt" if missing_outputs else marker
    assert saved_marker.read_bytes() == b"Saved outputs must not change during migration."
    assert {scan["scanId"] for scan in run_workbench(state, "list-scans")["scans"]} == {
        parent["scanId"],
        rerun["scanId"],
    }


@pytest.mark.parametrize("already_applied", [False, True])
def test_membership_migration_rebuilds_public_finding_projections(
    tmp_path: Path, workbench_api, already_applied: bool
) -> None:
    from workbench_dashboard import dashboard
    from workbench_findings import list_stored_findings, store_findings

    state, target = _scan_workspace(tmp_path)
    other_target = tmp_path / "other-target"
    other_target.mkdir()
    parent = register(state, target, tmp_path / "parent", mode="deep")
    child = register(
        state,
        target,
        tmp_path / "parent/artifacts/deep-scan/passes/pass-1",
        parent=parent["scanId"],
    )
    public = register(state, other_target, tmp_path / "public")

    def finding(identifier: str, source: str) -> dict:
        return {
            "findingId": identifier,
            "occurrenceId": f"{source}-{identifier}",
            "fingerprints": {"primary": identifier},
            "ruleId": "synthetic-rule",
            "identity": {"anchor": identifier},
            "title": f"{source} {identifier}",
            "summary": "Synthetic finding",
            "severity": {"level": "high"},
            "confidence": {"level": "high"},
            "remediation": "Apply the fixture repair",
            "locations": [{"path": "app.py", "startLine": 1}],
        }

    child_findings = [
        finding(identifier, "child")
        for identifier in (
            "child-only",
            "shared",
            "imported",
            "edited",
            "other-repository",
            "imported-before-child",
        )
    ]
    public_finding = finding("shared", "public")
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        targets = dict(connection.execute("SELECT id, target_id FROM scans"))
        # Historical indexing published passes before durable membership existed.
        connection.execute("UPDATE scans SET parent_scan_role = NULL")
        index = workbench_api["index_findings"]
        index(connection, public["scanId"], {"findings": [public_finding]}, "2026-01-01")
        connection.commit()
        store_findings(
            connection,
            [
                {
                    "finding": finding("other-repository", "import"),
                    "embedding": {"model": "synthetic", "vector": [1.0]},
                }
            ],
            "2026-01-01",
            "independent-repository",
        )
        store_findings(
            connection,
            [
                {
                    "finding": finding("imported-before-child", "import"),
                    "embedding": {"model": "synthetic", "vector": [1.0]},
                }
            ],
            "2026-01-01",
            targets[child["scanId"]],
        )
        index(connection, child["scanId"], {"findings": child_findings}, "2026-01-02")
        # Reindexing changes the occurrence and invalidates the imported embedding.
        assert (
            connection.execute(
                "SELECT 1 FROM finding_embeddings WHERE finding_id = 'imported-before-child'"
            ).fetchone()
            is None
        )
        connection.commit()
        imported = child_findings[2]
        edited = {**child_findings[3], "title": "Independent updated finding"}
        store_findings(
            connection,
            [
                {"finding": value, "embedding": {"model": "synthetic", "vector": [1.0]}}
                for value in (imported, edited)
            ],
            "2026-01-03",
            targets[child["scanId"]],
        )
        occurrences = connection.execute("SELECT * FROM finding_occurrences ORDER BY id").fetchall()
        locations = connection.execute(
            "SELECT * FROM finding_locations ORDER BY occurrence_id"
        ).fetchall()
        connection.execute("DELETE FROM schema_migrations WHERE version = 48")
        if not already_applied:
            connection.execute("DROP INDEX scans_by_composition_parent")
            connection.execute("ALTER TABLE scans DROP COLUMN parent_scan_role")
            connection.execute("DELETE FROM schema_migrations WHERE version = 43")
        connection.commit()
        assert list_stored_findings(connection, limit=20, offset=0)["total"] == 6
        for _ in range(2):
            workbench_api["apply_migrations"](connection)
            visible = list_stored_findings(connection, limit=20, offset=0)
            assert {value["findingId"]: value for value in visible["findings"]} == {
                "shared": public_finding,
                "imported": imported,
                "edited": edited,
                "other-repository": child_findings[4],
                "imported-before-child": child_findings[5],
            }
            projected = dashboard(
                connection, {"view": "findings", "sort": "activity", "limit": 20, "offset": 0}
            )
            assert projected["overview"]["findings"] == 5
            assert {item["id"]: item["repositoryIds"] for item in projected["items"]} == {
                "shared": [targets[public["scanId"]]],
                "imported": [targets[child["scanId"]]],
                "edited": [targets[child["scanId"]]],
                "other-repository": sorted(["independent-repository", targets[child["scanId"]]]),
                "imported-before-child": [targets[child["scanId"]]],
            }
        assert (
            connection.execute("SELECT * FROM finding_occurrences ORDER BY id").fetchall()
            == occurrences
        )
        assert (
            connection.execute("SELECT * FROM finding_locations ORDER BY occurrence_id").fetchall()
            == locations
        )


@pytest.mark.parametrize("command", ["fail-scan", "cancel-scan"])
def test_stopping_parent_stops_registered_passes_before_archiving(tmp_path, command):
    state, target = _scan_workspace(tmp_path)
    directory = tmp_path / "scan"
    parent = register(state, target, directory, mode="deep")
    active = register(
        state,
        target,
        directory / "artifacts/deep-scan/passes/active",
        parent=parent["scanId"],
        role="deep_pass",
    )
    completed = register(
        state,
        target,
        directory / "artifacts/deep-scan/passes/completed",
        parent=parent["scanId"],
        role="deep_pass",
    )
    unrelated = register(state, target, tmp_path / "rerun", parent=parent["scanId"])
    for child in (active, completed):
        write_completed_contract(
            Path(child["scanDir"]),
            child["scanId"],
            target,
            relative_path="app.py",
            identity_anchor=child["scanId"],
        )
    run_workbench(state, "complete-scan", "--scan-id", completed["scanId"])
    completed_manifest = (Path(completed["scanDir"]) / "scan-manifest.json").read_bytes()
    arguments = ["--message", "Synthetic parent interruption."] if command == "fail-scan" else []
    run_workbench(state, command, "--scan-id", parent["scanId"], *arguments)
    stopped = run_workbench(state, "get-scan", "--scan-id", active["scanId"])["scan"]
    assert stopped["progress"]["status"] == "failed"
    assert stopped["findingCount"] == 1
    assert (
        run_workbench(state, "get-scan", "--scan-id", completed["scanId"])["scan"]["progress"][
            "status"
        ]
        == "complete"
    )
    assert (Path(completed["scanDir"]) / "scan-manifest.json").read_bytes() == completed_manifest
    assert (
        run_workbench(state, "get-scan", "--scan-id", unrelated["scanId"])["scan"]["progress"][
            "status"
        ]
        == "running"
    )
    late = run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        active["scanId"],
        "--artifact-path",
        "artifacts/late.txt",
        input_text="Synthetic late output.",
        check=False,
    )
    assert late["returncode"] != 0
    assert not (Path(active["scanDir"]) / "artifacts/late.txt").exists()
    archived = tmp_path / "scan.previous-stopped"
    directory.rename(archived)
    directory.mkdir(mode=0o700)
    current = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(target),
        "--scan-dir",
        str(directory),
        "--recipe-json",
        json.dumps(recipe(target, "deep")),
        "--archive-existing",
        "--archived-scan-dir",
        str(archived),
    )
    assert current["scanId"] != parent["scanId"]
    assert run_workbench(state, "get-scan", "--scan-id", active["scanId"])["scan"][
        "scanDir"
    ] == str(archived / "artifacts/deep-scan/passes/active")


@pytest.mark.parametrize("already_applied", [False, True])
@pytest.mark.parametrize("missing_outputs", [False, True])
def test_membership_upgrade_recovers_children_archived_by_legacy_parent_only_move(
    tmp_path,
    already_applied,
    missing_outputs,
):
    state, target = _scan_workspace(tmp_path)
    directory = tmp_path / "scan"
    parent = register(state, target, directory, mode="deep")
    child_path = "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, directory / child_path, parent=parent["scanId"])
    unrelated = register(state, target, tmp_path / "rerun", parent=parent["scanId"])
    write_completed_contract(
        Path(child["scanDir"]),
        child["scanId"],
        target,
        relative_path="app.py",
    )
    run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
    run_workbench(state, "fail-scan", "--scan-id", parent["scanId"], "--message", "Synthetic stop.")
    archived = tmp_path / "scan.previous-legacy"
    directory.rename(archived)
    # Legacy archival updated only the parent row; nested pass rows and paths stayed behind.
    database = state / "workbench.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE scans SET scan_dir = ? WHERE id = ?", (str(archived), parent["scanId"])
        )
        connection.execute("DELETE FROM schema_migrations WHERE version = 49")
        if not already_applied:
            connection.execute("DELETE FROM schema_migrations WHERE version IN (43, 48)")
            connection.execute("DROP INDEX scans_by_composition_parent")
            connection.execute("ALTER TABLE scans DROP COLUMN parent_scan_role")
    original = {
        path.relative_to(archived): path.read_bytes()
        for path in archived.rglob("*")
        if path.is_file()
    }
    retained = archived
    if missing_outputs:
        retained = tmp_path / "unavailable-output"
        archived.rename(retained)
    run_workbench(state, "database-info")
    run_workbench(state, "database-info")
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT parent_scan_role, scan_dir FROM scans WHERE id = ?", (child["scanId"],)
        ).fetchone() == ("deep_pass", str(archived / child_path))
        assert connection.execute(
            "SELECT parent_scan_role, scan_dir FROM scans WHERE id = ?", (unrelated["scanId"],)
        ).fetchone() == (None, unrelated["scanDir"])
        artifacts = connection.execute(
            "SELECT path FROM scan_artifacts WHERE scan_id = ?", (child["scanId"],)
        ).fetchall()
        assert artifacts
        assert all(Path(path).is_relative_to(archived / child_path) for (path,) in artifacts)
        assert connection.execute(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 49"
        ).fetchone() == (1,)
    assert {scan["scanId"] for scan in run_workbench(state, "list-scans")["scans"]} == {
        parent["scanId"],
        unrelated["scanId"],
    }
    assert run_workbench(state, "list-global-findings")["findings"] == []
    assert all((retained / path).read_bytes() == contents for path, contents in original.items())
    if not missing_outputs:
        saved = run_workbench(state, "get-scan", "--scan-id", child["scanId"])["scan"]
        assert saved["scanDir"] == str(archived / child_path)
        assert saved["findingCount"] == 1
