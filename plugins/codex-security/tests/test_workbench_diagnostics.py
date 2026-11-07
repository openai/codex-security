"""Check that workbench failures retain their full diagnostics through terminal updates and replay."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from workbench_test_support import (
    checkpoint,
    create_saved_workspace,
    empty_target_paths,
    fail_scan,
    get_scan,
    register,
    start_delivered_scan,
)

LONG_ERROR = "Synthetic diagnostic detail.\n" * 200 + "Final diagnostic cause."
LEGACY_ERROR = "Saved diagnostic. " * 100 + "\n...[truncated; sha256:" + "0" * 64 + "]"


@pytest.mark.parametrize("message", [LONG_ERROR, LEGACY_ERROR], ids=["long", "legacy-truncated"])
def test_scan_failure_keeps_complete_diagnostic_and_existing_terminal_value(
    tmp_path: Path, message: str
) -> None:
    state_dir, target = empty_target_paths(tmp_path)
    workspace = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(
        state_dir,
        str(workspace["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["scanId"])

    failed = fail_scan(state_dir, scan_id, message)["scan"]
    assert failed["progress"]["status"] == "failed"
    assert failed["failureMessage"] == message
    assert get_scan(state_dir, scan_id)["scan"]["failureMessage"] == message
    replayed = fail_scan(state_dir, scan_id, "A different later error.")["scan"]
    assert replayed["failureMessage"] == message


@pytest.mark.parametrize("child", [False, True], ids=["parent", "discovery-pass"])
@pytest.mark.parametrize("message", [LONG_ERROR, LEGACY_ERROR], ids=["long", "legacy-truncated"])
def test_composed_scan_failure_keeps_complete_diagnostic_and_exact_terminal_replay(
    tmp_path: Path, child: bool, message: str
) -> None:
    state, target = empty_target_paths(tmp_path)
    parent_dir = tmp_path / "scan"
    parent = register(state, target, parent_dir, mode="deep")
    scan_id = parent["scanId"]
    if child:
        directory = "artifacts/deep-scan/passes/pass-1"
        scan_id = register(state, target, parent_dir / directory, parent=scan_id, role="deep_pass")[
            "scanId"
        ]
        checkpoint(state, parent, passes=[{"directory": directory, "scanId": scan_id}])

    failed = fail_scan(state, scan_id, message)["scan"]
    assert failed["progress"]["status"] == "failed"
    assert failed["failureMessage"] == message
    assert get_scan(state, scan_id)["scan"]["failureMessage"] == message
    assert fail_scan(state, scan_id, "Later failure.")["scan"]["failureMessage"] == message


def test_publication_failure_keeps_both_complete_diagnostics(
    tmp_path: Path, monkeypatch, workbench_api
) -> None:
    state, target = empty_target_paths(tmp_path)
    scan_id = register(state, target, tmp_path / "scan", mode="deep")["scanId"]
    fail_scan(state, scan_id, LONG_ERROR, "--defer-publication")
    publication = "Synthetic publication detail.\n" * 200 + "Final publication cause."

    def interrupted_publication(*args, **kwargs):
        raise OSError(publication)

    saved = workbench_api["saved_results"]
    monkeypatch.setattr(saved, "preserve_scan_results_locked", interrupted_publication)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        saved.preserve_stopped_results_after_transition(
            workbench_api["_WORKBENCH_DB_CONTEXT"],
            connection,
            scan_id,
        )
    scan = get_scan(state, scan_id)["scan"]
    assert scan["failureMessage"] == LONG_ERROR
    assert any(warning.endswith(publication) for warning in scan["warnings"])
