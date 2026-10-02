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
    metadata = Path(scan["scanDir"]) / EXECUTION_THREADS
    metadata.parent.mkdir(parents=True, exist_ok=True)
    metadata.write_text(json.dumps(["failed-follow-up", "repeated-follow-up"]))
    context = run_workbench(state, "get-scan", "--scan-id", scan["scanId"])
    assert "compositionCheckpoint" not in context
    assert context["scan"]["continuationThreadId"] is None
    assert context["scan"]["progress"]["status"] == "failed"
    assert context["scan"]["threadIds"] == ["failed-follow-up", "repeated-follow-up"]
    assert context["scan"]["executionThreadIds"] == context["scan"]["threadIds"]
