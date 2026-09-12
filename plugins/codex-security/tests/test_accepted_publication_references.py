from __future__ import annotations

import hashlib
import json
from argparse import Namespace

import pytest
from test_deep_scan_publication_authority import stage_publication
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan


def accept_reducer(connection, scan):
    result = add_worker(connection, scan)
    worker_id = result.parent.name
    coverage = {
        **scan.coverage,
        "completeness": "partial",
        "deferred": [{"id": "accepted-follow-up", "reason": "Accepted unresolved review."}],
        "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "partial"}],
    }
    contents = json.dumps(
        {
            "scanId": scan.scan_id,
            "complete": True,
            "findings": scan.findings,
            "sourceCoverage": coverage,
        }
    ).encode()
    digest = hashlib.sha256(contents).hexdigest()
    result.write_bytes(contents)
    accepted = result.parent / "accepted" / f"{digest}.json"
    accepted.parent.mkdir()
    accepted.write_bytes(contents)
    result.unlink()
    with connection:
        connection.execute(
            "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' WHERE id = ?",
            (worker_id,),
        )
        connection.execute(
            "INSERT INTO deep_scan_attempts (scan_id, worker_id, attempt, status, started_at, "
            "completed_at, accepted_result_path, accepted_result_sha256) "
            "VALUES (?, ?, 1, 'succeeded', ?, ?, ?, ?)",
            (scan.scan_id, worker_id, scan.timestamp, scan.timestamp, str(accepted), digest),
        )
        connection.execute(
            "UPDATE deep_scan_runs SET coordinator_generation = 3 WHERE scan_id = ?",
            (scan.scan_id,),
        )
    return result, accepted, coverage


@pytest.mark.parametrize("selected", [True, False], ids=["accepted", "replaceable-output"])
def test_legacy_publication_compares_registered_accepted_reference(
    workbench_api, workbench_db, publication_scan, selected
):
    scan = publication_scan()
    result, accepted, _ = accept_reducer(workbench_db, scan)
    staged = stage_publication(
        scan, generation=3, result_path=accepted if selected else result, title="Accepted aggregate"
    )
    before = {path: path.read_bytes() for path in scan.scan_dir.rglob("*.json")}

    if selected:
        workbench_api["write_scan_draft"](workbench_db, staged)
    else:
        with pytest.raises(SystemExit, match="aggregate"):
            workbench_api["write_scan_draft"](workbench_db, staged)
        assert {path: path.read_bytes() for path in scan.scan_dir.rglob("*.json")} == before


def test_stopped_recovery_uses_accepted_bytes_after_replaceable_output_disappears(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    _, accepted, coverage = accept_reducer(workbench_db, scan)
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    contents = accepted.read_bytes()

    stopped = workbench_api["fail_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."),
    )["scan"]

    assert stopped["findingCount"] == 1
    published = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert published["reviews"] == coverage["reviews"]
    assert coverage["deferred"][0] in published["deferred"]
    manifest = (scan.scan_dir / "scan-manifest.json").read_bytes()
    workbench_api["preserve_scan_results"](
        workbench_db,
        Namespace(
            scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
        ),
    )
    assert (scan.scan_dir / "scan-manifest.json").read_bytes() == manifest
    assert accepted.read_bytes() == contents
