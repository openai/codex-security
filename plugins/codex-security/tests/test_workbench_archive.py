from __future__ import annotations

import argparse
import json
import runpy
import signal
import sqlite3
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from workbench_test_support import SCRIPT, run_workbench


def recipe(target: Path) -> str:
    return json.dumps(
        {
            "repository": str(target),
            "target": {"kind": "repository", "paths": []},
            "mode": "standard",
            "config": {},
        }
    )


def register(state: Path, target: Path, output: Path, *args: str) -> dict:
    return run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(target),
        "--scan-dir",
        str(output),
        "--recipe-json",
        recipe(target),
        *args,
    )


@pytest.fixture
def previous_scan(tmp_path):
    state, target, output = (tmp_path / name for name in ("state", "target", "scan"))
    target.mkdir()
    (target / "fixture.py").write_text("value = 1\n")
    output.mkdir(mode=0o700)
    previous = register(state, target, output)
    (output / "report.md").write_text("previous scan\n")
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "INSERT INTO scan_artifacts VALUES (?, 'markdownReport', ?, 'before')",
            (previous["scanId"], str(output / "report.md")),
        )
    return state, target, output, previous["scanId"]


def mark_stopped(state, scan_id):
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("UPDATE scans SET status = 'failed' WHERE id = ?", (scan_id,))


def stored_paths(state, scan_id):
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        return (
            connection.execute("SELECT scan_dir FROM scans WHERE id = ?", (scan_id,)).fetchone()[0],
            connection.execute(
                "SELECT path FROM scan_artifacts WHERE scan_id = ?", (scan_id,)
            ).fetchone()[0],
        )


def workflow(state, workflow_id="synthetic-workflow", **payload):
    return run_workbench(
        state,
        "finding-workflow",
        input_text=json.dumps({"id": workflow_id, "action": "get", **payload}),
    )["workflow"]


@pytest.fixture
def workflow_scan(previous_scan):
    state, _, output, scan_id = previous_scan
    workflow(state, action="bind", binding={"scanId": scan_id, "scanDir": str(output)})
    workflow(
        state,
        action="complete",
        stage="scan",
        result={"sarifPath": str(output / "exports" / "results.sarif"), "threadId": "synthetic"},
    )
    return previous_scan


def test_concurrent_registration_keeps_running_scan_output(previous_scan):
    state, target, output, scan_id = previous_scan

    def attempt(_):
        with pytest.raises(subprocess.CalledProcessError) as error:
            register(state, target, output, "--archive-existing")
        assert "Cannot archive the output of a running scan" in error.value.stderr

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(attempt, range(2)))
    assert (output / "report.md").read_text() == "previous scan\n"
    assert list(output.parent.glob("scan.previous-*")) == []
    assert stored_paths(state, scan_id) == (str(output), str(output / "report.md"))


def test_only_one_concurrent_registration_archives_previous_output(workflow_scan):
    state, target, output, scan_id = workflow_scan
    mark_stopped(state, scan_id)
    saved_workflow = workflow(state)

    def attempt(_):
        try:
            return register(state, target, output, "--archive-existing")
        except subprocess.CalledProcessError as error:
            assert "Cannot archive the output of a running scan" in error.stderr
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [result for result in pool.map(attempt, range(2)) if result is not None]
    assert len(results) == 1
    archive = Path(results[0]["archivedScanDir"])
    assert (archive / "report.md").read_text() == "previous scan\n"
    assert list(output.iterdir()) == []
    assert stored_paths(state, scan_id) == (str(archive), str(archive / "report.md"))
    saved_workflow["scanDir"] = str(archive)
    saved_workflow["stages"]["scan"]["result"]["sarifPath"] = str(archive / "exports/results.sarif")
    assert workflow(state) == saved_workflow
    assert (
        workflow(state, action="bind", binding={"scanId": scan_id, "scanDir": str(archive)})
        == saved_workflow
    )


@pytest.mark.parametrize("result", [None, {}, {"sarifPath": None}, {"sarifPath": "unrelated"}])
def test_archiving_preserves_other_workflow_bindings_and_result_metadata(previous_scan, result):
    state, target, output, scan_id = previous_scan
    mark_stopped(state, scan_id)
    bindings = {
        "matching": {"scanId": scan_id, "scanDir": str(output)},
        "copied-directory": {"scanId": scan_id, "scanDir": str(output.with_name("copy"))},
        "other-scan": {"scanId": str(uuid.uuid4()), "scanDir": str(output)},
    }
    before = {}
    for workflow_id, binding in bindings.items():
        workflow(state, workflow_id, action="bind", binding=binding)
        before[workflow_id] = workflow(
            state, workflow_id, action="complete", stage="scan", result=result
        )
    registered = register(state, target, output, "--archive-existing")
    before["matching"]["scanDir"] = registered["archivedScanDir"]
    assert {workflow_id: workflow(state, workflow_id) for workflow_id in bindings} == before


def test_registration_rejection_restores_files_and_database(previous_scan):
    state, target, output, scan_id = previous_scan
    mark_stopped(state, scan_id)
    with pytest.raises(subprocess.CalledProcessError):
        register(state, target, output, "--archive-existing", "--parent-scan-id", str(uuid.uuid4()))
    assert (output / "report.md").read_text() == "previous scan\n"
    assert list(output.parent.glob("scan.previous-*")) == []
    assert stored_paths(state, scan_id) == (str(output), str(output / "report.md"))


def test_commit_failure_restores_archived_output(workflow_scan, monkeypatch):
    state, target, output, scan_id = workflow_scan
    mark_stopped(state, scan_id)
    saved_workflow = workflow(state)
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    module = runpy.run_path(str(SCRIPT))
    connection = module["connect"]()

    class FailedCommit:
        def __getattr__(self, name):
            return getattr(connection, name)

        def commit(self):
            raise sqlite3.OperationalError("fixture commit failed")

    args = argparse.Namespace(
        repository=str(target),
        scan_dir=str(output),
        archive_existing=True,
        archived_scan_dir=None,
        recipe_json=recipe(target),
        recipe_json_stdin=False,
        registration_json_stdin=False,
        parent_scan_id=None,
    )
    try:
        with pytest.raises(sqlite3.OperationalError, match="fixture commit failed"):
            module["register_cli_scan"](FailedCommit(), args)
    finally:
        connection.close()
    assert (output / "report.md").read_text() == "previous scan\n"
    assert list(output.parent.glob("scan.previous-*")) == []
    assert stored_paths(state, scan_id) == (str(output), str(output / "report.md"))
    assert workflow(state) == saved_workflow


def test_legacy_caller_can_supply_already_archived_output(previous_scan):
    state, target, output, scan_id = previous_scan
    mark_stopped(state, scan_id)
    archive = output.with_name("scan.previous-fixture")
    output.rename(archive)
    output.mkdir(mode=0o700)
    registered = register(
        state, target, output, "--archive-existing", "--archived-scan-dir", str(archive)
    )
    assert registered["archivedScanDir"] == str(archive)
    assert (archive / "report.md").read_text() == "previous scan\n"
    assert stored_paths(state, scan_id) == (str(archive), str(archive / "report.md"))


def test_registration_does_not_archive_an_ancestor_of_its_repository(tmp_path):
    state = tmp_path / "state"
    output = tmp_path / "output"
    target = output / "repository"
    target.mkdir(parents=True)
    output.chmod(0o700)
    source = target / "fixture.py"
    source.write_text("preserved source\n")
    with pytest.raises(subprocess.CalledProcessError) as error:
        register(state, target, output, "--archive-existing")
    assert "selected target" in error.value.stderr
    assert source.read_text() == "preserved source\n"
    assert list(tmp_path.glob("output.previous-*")) == []
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0


@pytest.mark.parametrize("committed", [False, True])
def test_interrupted_commit_keeps_files_at_their_saved_paths(previous_scan, monkeypatch, committed):
    state, target, output, scan_id = previous_scan
    mark_stopped(state, scan_id)
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    module = runpy.run_path(str(SCRIPT))
    connection = module["connect"]()

    class InterruptedCommit:
        def __getattr__(self, name):
            return getattr(connection, name)

        def commit(self):
            if committed:
                connection.commit()
            else:
                # SQLite can end a failed transaction itself before reporting its error.
                connection.rollback()
            signal.raise_signal(signal.SIGINT)

    args = argparse.Namespace(
        repository=str(target),
        scan_dir=str(output),
        archive_existing=True,
        archived_scan_dir=None,
        recipe_json=recipe(target),
        recipe_json_stdin=False,
        registration_json_stdin=False,
        parent_scan_id=None,
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            module["register_cli_scan"](InterruptedCommit(), args)
    finally:
        connection.close()
    saved_directory, saved_report = stored_paths(state, scan_id)
    assert Path(saved_report).read_text() == "previous scan\n"
    assert (Path(saved_directory) / "report.md").read_text() == "previous scan\n"
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1 + committed
    assert list(output.iterdir()) == ([] if committed else [output / "report.md"])


@pytest.mark.parametrize("layout", ["same", "nested", "alias"])
def test_registration_does_not_archive_its_active_workbench_state(tmp_path, layout):
    target = tmp_path / "target"
    target.mkdir()
    (target / "fixture.py").write_text("preserved source\n")
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    state = output if layout == "same" else output / "state"
    state.mkdir(mode=0o700, exist_ok=True)
    if layout == "alias":
        alias = tmp_path / "state-alias"
        try:
            alias.symlink_to(state, target_is_directory=True)
        except OSError:
            pytest.skip("Directory symlinks are unavailable")
        state = alias
    saved = tmp_path / "saved"
    saved.mkdir(mode=0o700)
    previous = register(state, target, saved)
    (saved / "report.md").write_text("saved report\n")
    with pytest.raises(subprocess.CalledProcessError) as error:
        register(state, target, output, "--archive-existing")
    assert "workbench state" in error.value.stderr
    assert list(tmp_path.glob("output.previous-*")) == []
    assert (saved / "report.md").read_text() == "saved report\n"
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT id FROM scans").fetchall() == [(previous["scanId"],)]
