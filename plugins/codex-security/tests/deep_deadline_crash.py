"""Test child that exits after deadline publication, immediately before SQLite commits."""

import os
import runpy
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

COMMIT_EXIT = 23


class CrashBeforeCommit(sqlite3.Connection):
    def commit(self):
        os._exit(COMMIT_EXIT)


def finish_until_commit(deep_scan, database, scan_id, scan_dir):
    with sqlite3.connect(database, factory=CrashBeforeCommit) as connection:
        connection.row_factory = sqlite3.Row
        deep_scan.finish_deep_scan(
            connection,
            SimpleNamespace(
                scan_id=scan_id,
                terminal_reason="capped",
                manifest_path=str(scan_dir / "scan-manifest.json"),
                staged_manifest_path=None,
                omitted_worker_id=[],
            ),
        )
    raise AssertionError("Deadline publication returned without committing")


if __name__ == "__main__":
    database, scan_id, scan_dir = sys.argv[1:]
    script = Path(__file__).resolve().parents[1] / "scripts" / "workbench_db.py"
    api = runpy.run_path(str(script), run_name="deadline_crash_test")
    deep_scan = api["deep_scan"]
    deep_scan.configure(
        SimpleNamespace(
            **api, preserve_stopped_results=api["preserve_stopped_results_after_transition"]
        )
    )
    finish_until_commit(deep_scan, database, scan_id, Path(scan_dir))
