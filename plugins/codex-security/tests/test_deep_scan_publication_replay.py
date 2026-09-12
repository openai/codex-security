from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from argparse import Namespace
from pathlib import Path

import pytest
from test_deep_scan_publication_authority import stage_publication
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan

_CRASH_PUBLICATION = """
import json, os, runpy, sqlite3, sys
from argparse import Namespace

api = runpy.run_path(sys.argv[1], run_name="publication_crash_test")
args = Namespace(**json.loads(sys.argv[3]))
boundary = sys.argv[4]

class CrashConnection(sqlite3.Connection):
    def commit(self):
        completing = self.execute(
            "SELECT status FROM scans WHERE id = ?", (args.scan_id,)
        ).fetchone()[0] == "complete"
        if completing and boundary == "sqlite-before":
            os._exit(72)
        super().commit()
        if completing and boundary == "sqlite-after":
            os._exit(73)

connection = sqlite3.connect(sys.argv[2], factory=CrashConnection)
connection.row_factory = sqlite3.Row
connection.execute("PRAGMA foreign_keys = ON")
if boundary.startswith("sqlite-"):
    api["complete_scan"](connection, Namespace(
        scan_id=args.scan_id, claim_token=None, cost_json=None
    ))
else:
    saved = api["saved_results"]
    original_write = saved.write_scan_local_bytes
    def crash_after_write(root, relative, contents):
        original_write(root, relative, contents)
        if relative == boundary:
            os._exit(71)
    saved.write_scan_local_bytes = crash_after_write
    api["write_scan_draft"](connection, args)
raise AssertionError("publication never reached the requested crash boundary")
"""


@pytest.mark.parametrize(
    "boundary",
    ["findings.json", "coverage.json", "scan-manifest.json", "sqlite-before", "sqlite-after"],
)
def test_publication_crash_replays_selected_input_without_stale_overwrite(
    workbench_api, workbench_db, publication_scan, tmp_path, boundary
):
    scan = publication_scan()
    result_path = add_worker(workbench_db, scan)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET coordinator_generation = 3 WHERE scan_id = ?",
            (scan.scan_id,),
        )
        workbench_db.execute(
            "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' WHERE scan_id = ?",
            (scan.scan_id,),
        )
    current = stage_publication(
        scan, generation=3, result_path=result_path, title="Selected aggregate"
    )
    stale = stage_publication(
        scan, generation=2, result_path=result_path, title="Obsolete coordinator draft"
    )
    database_path = tmp_path / "publication.sqlite3"
    with sqlite3.connect(database_path) as connection:
        workbench_db.backup(connection)
        connection.row_factory = sqlite3.Row
        if boundary.startswith("sqlite-"):
            workbench_api["write_scan_draft"](connection, current)

    child = subprocess.run(
        [
            sys.executable,
            "-c",
            _CRASH_PUBLICATION,
            str(Path(__file__).resolve().parents[1] / "scripts" / "workbench_db.py"),
            str(database_path),
            json.dumps(vars(current)),
            boundary,
        ],
        capture_output=True,
        text=True,
    )
    assert child.returncode == {"sqlite-before": 72, "sqlite-after": 73}.get(boundary, 71), (
        child.stdout,
        child.stderr,
    )
    interrupted = {
        path: path.read_bytes()
        for path in scan.scan_dir.rglob("*")
        if path.is_file() and "drafts" not in path.parts
    }
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan.scan_id,)).fetchone()
        assert row["status"] == ("complete" if boundary == "sqlite-after" else "running")
        assert bool(row["seal_manifest_digest"]) == (boundary == "sqlite-after")
        run_before = dict(connection.execute("SELECT * FROM deep_scan_runs").fetchone())
        workers_before = [
            dict(row) for row in connection.execute("SELECT * FROM deep_scan_workers")
        ]

        with pytest.raises(SystemExit, match="coordinator|stopped"):
            workbench_api["write_scan_draft"](connection, stale)
        assert all(path.read_bytes() == contents for path, contents in interrupted.items())

        if not boundary.startswith("sqlite-"):
            workbench_api["write_scan_draft"](connection, current)
        completed = workbench_api["complete_scan"](
            connection, Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
        )["scan"]
        assert completed["progress"]["status"] == "complete"
        assert completed["findingCount"] == 1
        assert dict(connection.execute("SELECT * FROM deep_scan_runs").fetchone()) == run_before
        assert [
            dict(row) for row in connection.execute("SELECT * FROM deep_scan_workers")
        ] == workers_before
        assert connection.execute("SELECT COUNT(*) FROM finding_occurrences").fetchone()[0] == 1
        published = {
            path: path.read_bytes()
            for path in scan.scan_dir.rglob("*")
            if path.is_file() and "drafts" not in path.parts
        }
        workbench_api["complete_scan"](
            connection, Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
        )
        assert all(path.read_bytes() == contents for path, contents in published.items())
        if boundary.startswith("sqlite-"):
            assert published == interrupted
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert findings[0]["title"] == "Selected aggregate"
