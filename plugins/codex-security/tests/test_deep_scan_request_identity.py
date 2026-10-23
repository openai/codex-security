from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from workbench_test_support import (
    mark_deep_aggregate_ready,
    run_workbench,
    write_completed_contract,
)


@pytest.mark.parametrize(
    ("first_context", "next_context"),
    (
        ("Review authentication only.", "Review SQL injection only."),
        ("Review authentication only.", None),
        (None, "Review SQL injection only."),
    ),
)
def test_target_request_does_not_reuse_different_user_context(
    tmp_path: Path, first_context: str | None, next_context: str | None
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    scan_root = tmp_path / "scans"
    first = begin_target_scan(state_dir, codex_home, target, scan_root, user_context=first_context)
    first_scan_id = str(first["scan"]["scanId"])
    scan_dir = Path(str(first["scan"]["scanDir"]))
    mark_deep_aggregate_ready(state_dir, first_scan_id, scan_dir)
    write_completed_contract(scan_dir, first_scan_id, target, coverage_mode="deep_repository")
    run_workbench(
        state_dir,
        "complete-scan",
        "--scan-id",
        first_scan_id,
        "--claim-token",
        first["scan"]["handoffClaimToken"],
    )

    requested = begin_target_scan(
        state_dir,
        codex_home,
        target,
        scan_root,
        thread_id="thread-new-request",
        user_context=next_context,
    )

    assert requested["startDisposition"] == "created"
    assert requested["scan"]["scanId"] != first_scan_id
    assert requested["scan"]["userContext"] == next_context
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert dict(connection.execute("SELECT id, user_context FROM scans")) == {
            first_scan_id: first_context,
            requested["scan"]["scanId"]: next_context,
        }


def begin_target_scan(
    state_dir, codex_home, target, scan_root, *, thread_id="thread-deep-scan", user_context=None
):
    return run_workbench(
        state_dir,
        "begin-deep-scan",
        "--thread-id",
        thread_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--scan-root",
        str(scan_root),
        *(("--user-context-stdin",) if user_context is not None else ()),
        input_text=user_context,
        environment={"CODEX_HOME": str(codex_home)},
    )
