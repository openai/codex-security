from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
from argparse import Namespace

import pytest
from test_accepted_publication_references import accept_reducer
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan


@pytest.mark.parametrize("recorded", [True, False], ids=["accepted-receipt", "legacy"])
@pytest.mark.parametrize("changed", [False, True], ids=["original", "changed"])
@pytest.mark.parametrize("historical", [False, True], ids=["current-attempt", "prior-attempt"])
def test_stopped_recovery_checks_recorded_accepted_bytes(
    workbench_api, workbench_db, publication_scan, tmp_path, recorded, changed, historical
):
    scan = publication_scan()
    result, accepted, _ = accept_reducer(workbench_db, scan)
    checkpoint = result.parent / "checkpoints" / accepted.name
    checkpoint.parent.mkdir()
    accepted.rename(checkpoint)
    original = checkpoint.read_bytes()
    digest = hashlib.sha256(original).hexdigest()
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_attempts SET accepted_result_path = ? WHERE worker_id = ?",
            (str(checkpoint), result.parent.name),
        )
        if not recorded:
            workbench_db.execute(
                "DELETE FROM deep_scan_attempts WHERE worker_id = ?", (result.parent.name,)
            )
        if historical:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET attempt = 2, status = 'running' WHERE id = ?",
                (result.parent.name,),
            )
    if changed:
        damaged = json.loads(original)
        damaged["findings"][0]["summary"] = "Unaccepted changed evidence."
        checkpoint.write_text(json.dumps(damaged))
    accepted_bytes = checkpoint.read_bytes()
    # An unrelated valid source must still survive stopped partial preservation.
    healthy = add_worker(workbench_db, scan)
    finding = copy.deepcopy(scan.findings[0])
    finding["summary"] = "Independent preserved evidence."
    finding["identity"]["anchor"] += ".independent"
    finding["locations"][0]["startLine"] = 2
    finding["locations"][0]["endLine"] = 2
    healthy.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [finding],
                "coverage": scan.coverage,
            }
        )
    )
    healthy_bytes = healthy.read_bytes()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    database = tmp_path / "accepted-digests.sqlite3"
    with sqlite3.connect(database) as connection:
        workbench_db.backup(connection)
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        stopped = workbench_api["fail_scan"](
            connection,
            Namespace(
                scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."
            ),
        )["scan"]
        summaries = {finding["summary"] for finding in stopped["findings"]}
        assert "Independent preserved evidence." in summaries
        assert ("Unaccepted changed evidence." in summaries) == (changed and not recorded)
        if not changed:
            assert scan.findings[0]["summary"] in summaries
        if recorded:
            assert (
                connection.execute(
                    "SELECT accepted_result_sha256 FROM deep_scan_attempts WHERE worker_id = ?",
                    (result.parent.name,),
                ).fetchone()[0]
                == digest
            )
        if recorded and changed:
            warnings = json.loads(
                connection.execute("SELECT completion_warnings_json FROM scans").fetchone()[0]
            )
            assert any("changed after acceptance" in warning for warning in warnings)
    assert checkpoint.read_bytes() == accepted_bytes
    assert healthy.read_bytes() == healthy_bytes
