from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path, PureWindowsPath

import pytest
from test_workbench_scan_checkpoints import scan_fixture
from workbench_test_support import run_workbench, write_completed_contract


def test_registered_severity_source_preserves_a_case_distinct_copy(
    tmp_path: Path, workbench_api, monkeypatch
):
    state, repository, original, scan_id = scan_fixture(tmp_path)
    copy = original.with_name(original.name.upper())
    if copy.exists():
        pytest.skip("The fixture filesystem does not support case-distinct directories")
    write_completed_contract(original, scan_id, repository, relative_path="clean.ts")
    run_workbench(state, "prepare-scan-completion", "--scan-id", scan_id)
    run_workbench(state, "complete-scan", "--scan-id", scan_id)
    shutil.copytree(original, copy)
    assert PureWindowsPath(original) == PureWindowsPath(copy)
    assert not original.samefile(copy)
    severity = workbench_api["severity"]
    # Exercise Windows lexical comparison against real case-distinct directories
    # even when this regression runs on a Unix host.
    monkeypatch.setattr(severity, "Path", PureWindowsPath)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row

        def registered(directory: Path) -> bool:
            return severity.checkpoint(
                connection,
                {
                    "action": "source",
                    "scanId": scan_id,
                    "scanDirectory": str(directory),
                },
                "2026-09-09T00:00:00Z",
            )["registeredScan"]

        assert registered(original) is True
        assert registered(copy) is False
        # The explicit copy stays usable after the registered output disappears.
        shutil.rmtree(original)
        assert registered(copy) is False
