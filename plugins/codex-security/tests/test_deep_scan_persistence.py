from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest
from test_workbench_deep_scan import begin_target_scan, dispatch_discovery_worker


def test_state_snapshot_does_not_mix_concurrent_acceptance(
    tmp_path: Path, workbench_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_dir, codex_home, target = tmp_path / "state", tmp_path / "codex", tmp_path / "target"
    target.mkdir()
    initial = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")["deepScan"]
    scan_id = initial["scanId"]
    worker_id, _, _, _ = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=Path(initial["scanDir"]),
        name="discovery-1",
        succeed=False,
    )
    database = state_dir / "workbench.sqlite3"
    deep_scan = sys.modules["deep_scan_workbench"]
    monkeypatch.setattr(deep_scan, "require_scan", workbench_api["require_scan"])
    original = deep_scan.require_deep_scan_run

    def accept_after_read(connection, requested_scan_id):
        run = original(connection, requested_scan_id)
        with sqlite3.connect(database) as writer:
            writer.execute(
                "UPDATE deep_scan_runs SET completion_sequence = 1 WHERE scan_id = ?", (scan_id,)
            )
            writer.execute(
                "UPDATE deep_scan_workers SET status = 'succeeded', completion_sequence = 1 "
                "WHERE id = ?",
                (worker_id,),
            )
        return run

    monkeypatch.setattr(deep_scan, "require_deep_scan_run", accept_after_read)
    with sqlite3.connect(database) as reader:
        reader.row_factory = sqlite3.Row
        snapshot = deep_scan.deep_scan_state(reader, scan_id)
        assert snapshot["completionSequence"] == 0
        assert snapshot["workers"][0]["status"] == "running"
        assert not reader.in_transaction


def test_state_snapshot_preserves_its_callers_transaction(
    tmp_path: Path, workbench_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    initial = begin_target_scan(tmp_path / "state", tmp_path / "codex", target, tmp_path / "scans")
    scan_id = initial["deepScan"]["scanId"]
    deep_scan = sys.modules["deep_scan_workbench"]
    monkeypatch.setattr(deep_scan, "require_scan", workbench_api["require_scan"])
    with sqlite3.connect(tmp_path / "state" / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "UPDATE deep_scan_runs SET consecutive_errors = 2 WHERE scan_id = ?", (scan_id,)
        )
        snapshot = deep_scan.deep_scan_state(connection, scan_id)
        assert snapshot["consecutiveErrors"] == 2
        assert connection.in_transaction
        connection.rollback()
        assert deep_scan.deep_scan_state(connection, scan_id)["consecutiveErrors"] == 0
