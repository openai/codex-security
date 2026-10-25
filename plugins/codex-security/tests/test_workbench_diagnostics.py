from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

import pytest
from workbench_test_support import (
    begin_deep_scan,
    create_saved_workspace,
    fail_scan,
    get_deep_scan,
    get_scan,
    resume_deep_scan,
    scan_command,
    start_delivered_scan,
    upsert_deep_worker,
    worker_paths,
)

LONG_ERROR = "Synthetic diagnostic detail.\n" * 200 + "Final diagnostic cause."
LEGACY_ERROR = "Saved diagnostic. " * 100 + "\n...[truncated; sha256:" + "0" * 64 + "]"


@pytest.fixture
def deep_scan(tmp_path: Path):
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    environment = {"CODEX_HOME": str(tmp_path / "codex-home")}
    started = begin_deep_scan(
        state_dir,
        "diagnostic-parent",
        "--target-path",
        str(target),
        "--scan-root",
        str(tmp_path / "scans"),
        environment=environment,
    )["deepScan"]
    return state_dir, str(started["scanId"]), Path(str(started["scanDir"])), environment


@pytest.mark.parametrize("message", [LONG_ERROR, LEGACY_ERROR])
def test_scan_failure_keeps_complete_diagnostic_and_existing_terminal_value(
    tmp_path: Path, message: str
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        str(workspace["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )["results"]
    scan_id = str(started["scanId"])

    failed = fail_scan(state_dir, scan_id, message)["scan"]
    assert failed["progress"]["status"] == "failed"
    assert failed["failureMessage"] == message
    assert get_scan(state_dir, scan_id)["scan"]["failureMessage"] == message
    replayed = fail_scan(state_dir, scan_id, "A different later error.")["scan"]
    assert replayed["failureMessage"] == message


@pytest.mark.parametrize("status", ["failed", "canceled"])
@pytest.mark.parametrize("message", [LONG_ERROR, LEGACY_ERROR])
def test_worker_failure_keeps_complete_diagnostic_and_exact_terminal_replay(
    deep_scan, status: str, message: str
) -> None:
    state_dir, scan_id, scan_dir, environment = deep_scan
    worker_id = str(uuid.uuid4())
    prompt, artifact_dir, _ = worker_paths(scan_dir, "diagnostic-worker")
    worker_args = (state_dir, scan_id, worker_id, "discovery")
    paths = (str(prompt), str(artifact_dir))
    upsert_deep_worker(*worker_args, "running", *paths, environment=environment)
    failure_args = (
        *worker_args,
        status,
        *paths,
        "--error-message",
        message,
        *(("--replaceable-failure-kind", "transient_error") if status == "canceled" else ()),
    )

    failed = upsert_deep_worker(*failure_args, environment=environment)["deepScan"]
    assert failed["workers"][0]["error"] == message
    assert failed["attempts"][0]["error"] == message
    replayed = upsert_deep_worker(*failure_args, environment=environment)["deepScan"]
    assert replayed["workers"] == failed["workers"]
    resumed = resume_deep_scan(state_dir, scan_id, "diagnostic-parent", environment=environment)[
        "deepScan"
    ]
    assert resumed["workers"][0]["error"] == message
    assert resumed["attempts"][0]["error"] == message
    rejected = upsert_deep_worker(
        *worker_args,
        status,
        *paths,
        "--error-message",
        message + " Extra detail.",
        environment=environment,
        check=False,
    )
    assert rejected["returncode"] != 0
    assert "terminal state is immutable" in rejected["stderr"]


@pytest.mark.parametrize("message", [LONG_ERROR, LEGACY_ERROR])
def test_deep_failure_keeps_complete_diagnostic_and_existing_terminal_value(
    deep_scan, message: str
) -> None:
    state_dir, scan_id, _, environment = deep_scan
    failure_args = (state_dir, "fail-deep-scan", scan_id, "--message", message)
    failed = scan_command(*failure_args, environment=environment)["deepScan"]
    assert failed["status"] == "failed"
    assert failed["error"] == message
    assert get_scan(state_dir, scan_id, environment=environment)["scan"]["failureMessage"] == (
        message
    )
    replayed = scan_command(*failure_args, environment=environment)["deepScan"]
    assert replayed == failed
    resumed = resume_deep_scan(state_dir, scan_id, "diagnostic-parent", environment=environment)[
        "deepScan"
    ]
    assert resumed["error"] == message
    rejected = scan_command(
        state_dir,
        "fail-deep-scan",
        scan_id,
        "--message",
        message + " Extra detail.",
        environment=environment,
        check=False,
    )
    assert rejected["returncode"] != 0
    assert "terminal failure state is immutable" in rejected["stderr"]


def test_publication_failure_keeps_both_complete_diagnostics(deep_scan) -> None:
    state_dir, scan_id, _, environment = deep_scan
    scan_command(
        state_dir, "fail-deep-scan", scan_id, "--message", LONG_ERROR, environment=environment
    )
    publication = "Synthetic publication detail.\n" * 200 + "Final publication cause."
    recorded = scan_command(
        state_dir,
        "record-deep-scan-publication-failure",
        scan_id,
        "--message",
        publication,
        environment=environment,
    )["deepScan"]
    expected = publication + "\nOriginal Deep Scan failure:\n" + LONG_ERROR
    assert recorded["error"] == expected
    fetched = get_deep_scan(state_dir, scan_id, "diagnostic-parent", environment=environment)
    assert fetched["deepScan"]["error"] == expected
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT error_message, publication_error_message FROM deep_scan_runs WHERE scan_id = ?",
            (scan_id,),
        ).fetchone() == (LONG_ERROR, publication)
