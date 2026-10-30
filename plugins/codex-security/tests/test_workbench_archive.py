from __future__ import annotations

import argparse
import io
import json
import os
import runpy
import signal
import sqlite3
import subprocess
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from threading import Event
from unittest.mock import Mock

import pytest
from workbench_test_support import (
    SCRIPT,
    request_remediation,
    run_workbench,
    scan_command,
    write_completed_contract,
)


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


@pytest.fixture
def pending_patch(previous_scan, workbench_api, monkeypatch):
    state, target, output, scan_id = previous_scan
    write_completed_contract(output, scan_id, target, relative_path="fixture.py")
    completed = scan_command(state, "complete-scan", scan_id)["scan"]
    occurrence = completed["findings"][0]["occurrenceId"]
    request, token = str(uuid.uuid4()), str(uuid.uuid4())
    request_remediation(state, occurrence, request, token)
    patch = b"--- a/fixture.py\n+++ b/fixture.py\n@@ -1 +1 @@\n-value = 1\n+value = 2\n"
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    monkeypatch.setattr(sys, "stdin", Mock(buffer=io.BytesIO(patch)))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT),
            "set-finding-remediation",
            "--occurrence-id",
            occurrence,
            "--request-id",
            request,
            "--action-token",
            token,
            "--expected-version",
            "1",
            "--state",
            "generated",
            "--patch-stdin",
        ],
    )
    return workbench_api["parse_args"](""), patch


@pytest.mark.cross_platform
@pytest.mark.parametrize(
    ("archive", "legacy"),
    [
        ("same-state", False),
        ("same-state", True),
        ("same-state-before-stage", False),
        ("same-state-staged", False),
        ("same-state-before-digest", False),
        ("other-state", False),
        ("other-state", True),
        ("before-write", False),
        ("after-write", False),
        ("after-digest", False),
    ],
)
def test_generate_patch_keeps_completed_scan_identity_during_archive(
    previous_scan, pending_patch, workbench_api, monkeypatch, capsys, archive, legacy
):
    state, target, output, scan_id = previous_scan
    args, patch = pending_patch
    occurrence, request, token = args.occurrence_id, args.request_id, args.action_token
    archived = False

    def archive_output():
        nonlocal archived
        if archived:
            return
        owner = state if archive.startswith("same-state") else state.with_name("other-state")
        replacement = register(owner, target, output, "--archive-existing")
        archived = True
        if owner != state:
            write_completed_contract(
                output, replacement["scanId"], target, relative_path="fixture.py"
            )
            scan_command(owner, "complete-scan", replacement["scanId"])

    def archive_while_reading_patch():
        if archive in {"same-state", "other-state"}:
            archive_output()
        return patch

    if legacy:
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE scans SET seal_manifest_digest = NULL WHERE id = ?", (scan_id,)
            )
    if archive in {"before-write", "after-write", "same-state-before-stage", "same-state-staged"}:
        remediation = workbench_api["remediation_state"]
        stage = remediation.stage_scan_local_bytes

        @contextmanager
        def stage_with_archive(*args, **kwargs):
            if archive in {"before-write", "same-state-before-stage"}:
                archive_output()
            with stage(*args, **kwargs) as publish:
                if archive == "same-state-staged":
                    archive_output()
                yield publish
            if archive == "after-write":
                archive_output()

        monkeypatch.setattr(remediation, "stage_scan_local_bytes", stage_with_archive)
    elif archive in {"same-state-before-digest", "after-digest"}:
        patch_path = output / "artifacts" / "remediation" / occurrence / request / f"{token}.patch"
        patch_path.parent.mkdir(parents=True)
        patch_path.write_bytes(patch)
        db = workbench_api["_WORKBENCH_DB_CONTEXT"]
        open_file = db.open_scan_local_file

        @contextmanager
        def open_with_archive(directory, relative, **options):
            is_patch = Path(relative).suffix == ".patch"
            if is_patch and archive == "same-state-before-digest":
                archive_output()
            with open_file(directory, relative, **options) as source:
                yield source
            if is_patch and archive == "after-digest":
                archive_output()

        monkeypatch.setattr(db, "open_scan_local_file", open_with_archive)

    monkeypatch.setattr(sys, "stdin", Mock(buffer=Mock(read=archive_while_reading_patch)))
    if not archive.startswith("same-state"):
        with pytest.raises(SystemExit, match="Could not save the remediation patch"):
            workbench_api["main"]()
        assert not list(output.rglob("*.patch"))
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            assert connection.execute(
                "SELECT state, version, patch_path FROM finding_remediation_attempts WHERE request_id = ?",
                (request,),
            ).fetchone() == ("requested", 1, None)
        return
    workbench_api["main"]()
    result = json.loads(capsys.readouterr().out)["scan"]
    patch_path = result["findings"][0]["remediationState"]["patchPath"]
    assert not (output / patch_path).exists()
    assert (Path(result["scanDir"]) / patch_path).read_bytes() == patch


@pytest.mark.cross_platform
@pytest.mark.parametrize("rollback", [False, True], ids=["commit", "rollback"])
@pytest.mark.parametrize("phase", ["before-seal", "after-root-sample", "before-stage"])
def test_generate_waits_for_the_archive_transaction(
    previous_scan, pending_patch, workbench_api, monkeypatch, rollback, phase
):
    state, target, output, _ = previous_scan
    args, patch = pending_patch
    database = state / "workbench.sqlite3"
    start_archive, moved, finish_archive = Event(), Event(), Event()

    class PausedArchive(sqlite3.Connection):
        def execute(self, sql, *args):
            result = super().execute(sql, *args)
            if sql.startswith("UPDATE scans SET scan_dir"):
                moved.set()
                assert finish_archive.wait(10)
            return result

    def archive():
        assert start_archive.wait(10)
        with sqlite3.connect(database, factory=PausedArchive) as connection:
            connection.row_factory = sqlite3.Row
            args = argparse.Namespace(
                repository=str(target),
                scan_dir=str(output),
                archive_existing=True,
                archived_scan_dir=None,
                recipe_json=recipe(target),
                recipe_json_stdin=False,
                registration_json_stdin=False,
                parent_scan_id=str(uuid.uuid4()) if rollback else None,
            )
            if rollback:
                with pytest.raises(SystemExit, match="not found"):
                    workbench_api["register_cli_scan"](connection, args)
                return output
            return Path(workbench_api["register_cli_scan"](connection, args)["archivedScanDir"])

    def pause_for_archive():
        start_archive.set()
        assert moved.wait(10)

    if phase == "before-stage":
        remediation = workbench_api["remediation_state"]
        stage = remediation.stage_scan_local_bytes

        def stage_during_archive(*args, **kwargs):
            pause_for_archive()
            return stage(*args, **kwargs)

        monkeypatch.setattr(remediation, "stage_scan_local_bytes", stage_during_archive)
    else:

        def read_patch():
            pause_for_archive()
            return patch

        monkeypatch.setattr(sys, "stdin", Mock(buffer=Mock(read=read_patch)))
    with ThreadPoolExecutor(max_workers=1) as pool, sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        connection.set_trace_callback(
            lambda sql: (
                finish_archive.set() if sql == "BEGIN IMMEDIATE" and moved.is_set() else None
            )
        )
        registered = pool.submit(archive)
        if phase == "after-root-sample":
            remediation = workbench_api["remediation_state"]
            sample = remediation.scan_root_identity

            def sample_then_finish_archive(directory):
                observed = sample(directory)
                if not finish_archive.is_set():
                    assert moved.is_set()
                    finish_archive.set()
                    registered.result(timeout=10)
                return observed

            monkeypatch.setattr(remediation, "scan_root_identity", sample_then_finish_archive)
        try:
            result = workbench_api["set_finding_remediation"](connection, args)["scan"]
        finally:
            finish_archive.set()
        destination = registered.result()
    relative = result["findings"][0]["remediationState"]["patchPath"]
    assert Path(result["scanDir"]) == destination
    assert (destination / relative).read_bytes() == patch
    if not rollback:
        assert not (output / relative).exists()


@pytest.mark.cross_platform
@pytest.mark.parametrize("replace", [False, True])
def test_generate_hashes_and_rechecks_the_manifest(
    previous_scan, pending_patch, workbench_api, monkeypatch, replace
):
    state, _, output, _ = previous_scan
    args, patch = pending_patch
    database = state / "workbench.sqlite3"
    manifest = output / "scan-manifest.json"
    original = manifest.stat()
    opened = os.fdopen
    reads = []

    def check_manifest_reads(fd, *options, **kwargs):
        stream = opened(fd, *options, **kwargs)
        if os.path.samestat(original, os.fstat(fd)):
            read = stream.read

            def read_without_writer(*args):
                with sqlite3.connect(database, timeout=0) as writer:
                    writer.execute("BEGIN IMMEDIATE")
                    reads.append(True)
                    return read(*args)

            stream.read = read_without_writer
        return stream

    monkeypatch.setattr(os, "fdopen", check_manifest_reads)
    if replace:
        remediation = workbench_api["remediation_state"]
        stage = remediation.stage_scan_local_bytes

        @contextmanager
        def stage_and_replace(*args, **kwargs):
            with stage(*args, **kwargs) as publish:
                replacement = manifest.with_suffix(".new")
                replacement.write_bytes(manifest.read_bytes())
                os.utime(replacement, ns=(original.st_atime_ns, original.st_mtime_ns))
                replacement.replace(manifest)
                yield publish

        monkeypatch.setattr(remediation, "stage_scan_local_bytes", stage_and_replace)
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        generate = workbench_api["set_finding_remediation"]
        if replace:
            with pytest.raises(SystemExit, match="sealed scan manifest changed"):
                generate(connection, args)
            row = connection.execute(
                "SELECT state, version, patch_path FROM finding_remediation_attempts WHERE request_id = ?",
                (args.request_id,),
            ).fetchone()
            assert tuple(row) == ("requested", 1, None)
            assert not list(output.rglob("*.patch"))
        else:
            result = generate(connection, args)["scan"]
            relative = result["findings"][0]["remediationState"]["patchPath"]
            assert (output / relative).read_bytes() == patch
    assert reads


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


def test_registration_waits_for_in_progress_archive_rename(workflow_scan, monkeypatch):
    state, target, output, scan_id = workflow_scan
    mark_stopped(state, scan_id)
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    module = runpy.run_path(str(SCRIPT))
    connection = module["connect"]()
    ready, renamed, attempted = Event(), Event(), Event()
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

    def competing_registration():
        other = module["connect"]()
        other.set_trace_callback(lambda sql: attempted.set() if sql == "BEGIN IMMEDIATE" else None)
        try:
            ready.set()
            assert renamed.wait(5)
            with pytest.raises(SystemExit) as error:
                module["register_cli_scan"](other, args)
            return str(error.value)
        finally:
            attempted.set()
            other.close()

    rename = Path.rename

    def pause_after_rename(path, destination):
        result = rename(path, destination)
        if path == output:
            # The second caller reaches registration while output is absent.
            # It must wait for the writer before inspecting the replacement.
            renamed.set()
            assert attempted.wait(5)
        return result

    monkeypatch.setattr(Path, "rename", pause_after_rename)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            competing = pool.submit(competing_registration)
            assert ready.wait(5)
            registered = module["register_cli_scan"](connection, args)
            assert competing.result(timeout=5) == "Cannot archive the output of a running scan."
        archive = Path(registered["archivedScanDir"])
        assert (archive / "report.md").read_text() == "previous scan\n"
        assert list(output.iterdir()) == []
        assert stored_paths(state, scan_id) == (str(archive), str(archive / "report.md"))
    finally:
        renamed.set()
        connection.close()


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


def test_registration_does_not_archive_state_reached_through_an_external_alias(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    nested_state = output / "state"
    nested_state.mkdir(mode=0o700)
    state = tmp_path / "state-alias"
    try:
        state.symlink_to(nested_state, target_is_directory=True)
    except OSError:
        pytest.skip("Directory symlinks are unavailable")
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
