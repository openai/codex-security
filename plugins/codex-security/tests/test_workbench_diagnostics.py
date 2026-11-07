"""Check that workbench failures retain their full diagnostics through terminal updates and replay."""

from __future__ import annotations

from pathlib import Path

import pytest
from workbench_test_support import (
    empty_target_paths,
    fail_scan,
    get_scan,
    register,
)

LONG_ERROR = "Synthetic diagnostic detail.\n" * 200 + "Final diagnostic cause."
LEGACY_ERROR = "Saved diagnostic. " * 100 + "\n...[truncated; sha256:" + "0" * 64 + "]"


@pytest.mark.parametrize("message", [LONG_ERROR, LEGACY_ERROR], ids=["long", "legacy-truncated"])
@pytest.mark.parametrize("mode", ["standard", "deep"])
def test_scan_failure_keeps_complete_diagnostic_and_existing_terminal_value(
    tmp_path: Path, message: str, mode: str
) -> None:
    state_dir, target = empty_target_paths(tmp_path)
    started = register(state_dir, target, tmp_path / "scan", mode=mode)
    scan_id = str(started["scanId"])

    failed = fail_scan(state_dir, scan_id, message)["scan"]
    assert failed["progress"]["status"] == "failed"
    assert failed["failureMessage"] == message
    assert get_scan(state_dir, scan_id)["scan"]["failureMessage"] == message
    replayed = fail_scan(state_dir, scan_id, "A different later error.")["scan"]
    assert replayed["failureMessage"] == message
