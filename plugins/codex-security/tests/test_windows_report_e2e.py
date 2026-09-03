from __future__ import annotations

import json
import os
import runpy
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from workbench_test_support import (
    SCRIPT,
    create_saved_workspace,
    start_delivered_scan,
    write_completed_contract,
)


def test_workbench_completion_and_exports_use_windows_file_backend(tmp_path: Path) -> None:
    """Exercise report orchestration through the Windows backend dispatch path.

    The fake backend uses ordinary local file operations. Native Windows tests
    separately cover the Win32 handle semantics.
    """

    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    source = target / "src" / "extract.py"
    source.parent.mkdir()
    source.write_text("".join(f"line {line}\n" for line in range(1, 46)))
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        str(saved["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target)
    (scan_dir / "report.html").write_text("stale report")
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_db")
    finalizer = sys.modules[namespace["finalize_scan"].__module__]
    backend = mock.Mock()

    def open_read_fd(root: Path, relative_path: str, _context: str) -> int:
        return os.open(root / relative_path, os.O_RDONLY)

    def atomic_write(
        root: Path,
        relative_path: str,
        payload: bytes,
        *,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> None:
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    backend.open_read_fd.side_effect = open_read_fd
    backend.atomic_write.side_effect = atomic_write
    backend.unlink_if_exists.side_effect = lambda root, relative_path: (
        root / relative_path
    ).unlink(missing_ok=True)

    with (
        mock.patch.object(finalizer.os, "supports_dir_fd", set()),
        mock.patch.object(finalizer, "_is_windows", return_value=True),
        mock.patch.object(finalizer, "_windows_scan_local_files", return_value=backend),
        mock.patch.dict(os.environ, {"CODEX_SECURITY_STATE_DIR": str(state_dir)}),
        sqlite3.connect(state_dir / "workbench.sqlite3") as connection,
    ):
        connection.row_factory = sqlite3.Row
        completed = namespace["complete_scan"](
            connection,
            SimpleNamespace(claim_token=None, cost_json=None, scan_id=scan_id),
        )["scan"]
        exported = namespace["export_findings"](
            connection, SimpleNamespace(scan_id=scan_id, format="csv")
        )

    assert completed["progress"]["status"] == "complete"
    assert completed["findingCount"] == 1
    assert completed["artifacts"]["markdownReport"] == str(scan_dir / "report.md")
    assert completed["artifacts"]["sarifReport"] == str(scan_dir / "exports" / "results.sarif")
    assert "Unsafe archive extraction" in (scan_dir / "report.md").read_text()
    assert not (scan_dir / "report.html").exists()
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["sealedAt"]
    sarif = json.loads((scan_dir / "exports" / "results.sarif").read_text())
    assert len(sarif["runs"][0]["results"]) == 1
    assert exported["export"] == {
        "format": "csv",
        "path": str(scan_dir / "exports" / "findings.csv"),
    }
    assert (
        (scan_dir / "exports" / "findings.csv")
        .read_text()
        .startswith("occurrence_id,finding_id,title,summary")
    )
    assert backend.open_read_fd.called
    assert backend.atomic_write.called
