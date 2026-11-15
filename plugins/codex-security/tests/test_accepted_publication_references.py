from __future__ import annotations

import hashlib
import json
from argparse import Namespace

import pytest
from publication_fixtures import worker_finding
from test_deep_scan_publication_authority import stage_publication
from workbench_test_support import read_review_state, select_checkpoint, write_checkpoint


def accept_reducer(connection, scan):
    result = scan.add_worker(connection)
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


@pytest.mark.parametrize("claim_only", [False, True], ids=["attempt", "historical-claim"])
@pytest.mark.parametrize("selected", [True, False], ids=["accepted", "replaceable-output"])
def test_legacy_publication_compares_registered_accepted_reference(
    workbench_api, workbench_db, publication_scan, selected, claim_only
):
    scan = publication_scan()
    result, accepted, _ = accept_reducer(workbench_db, scan)
    if claim_only:
        # This reducer predates attempt receipts. A later interrupted reducer froze its input.
        successor = scan.add_worker(workbench_db, status="canceled").parent.name
        with workbench_db:
            workbench_db.execute(
                "DELETE FROM deep_scan_attempts WHERE worker_id = ?", (result.parent.name,)
            )
            workbench_db.execute(
                "UPDATE deep_scan_workers SET kind = 'dedup' WHERE id = ?", (successor,)
            )
            workbench_db.execute(
                "INSERT INTO deep_scan_merge_claims "
                "(worker_id, scan_id, previous_worker_id, previous_result_path, previous_result_sha256) "
                "VALUES (?, ?, ?, ?, ?)",
                (successor, scan.scan_id, result.parent.name, str(accepted), accepted.stem),
            )
    staged = stage_publication(
        scan, generation=3, result_path=accepted if selected else result, title="Accepted aggregate"
    )
    before = {path: path.read_bytes() for path in scan.scan_dir.rglob("*.json")}

    def publish():
        return workbench_api["saved_results"].write_scan_draft(
            workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, staged
        )

    if selected:
        publish()
        accepted.write_bytes(accepted.read_bytes() + b" ")
        with pytest.raises(
            workbench_api["RecoverableContractError"], match="changed after acceptance"
        ):
            publish()
        with pytest.raises(SystemExit, match="changed after acceptance"):
            scan.complete()
    else:
        with pytest.raises(SystemExit, match="aggregate"):
            publish()
        assert {path: path.read_bytes() for path in scan.scan_dir.rglob("*.json")} == before


def test_stopped_recovery_uses_accepted_bytes_after_replaceable_output_disappears(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    _, accepted, coverage = accept_reducer(workbench_db, scan)
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    contents = accepted.read_bytes()

    stopped = workbench_api["saved_results"].fail_scan(
        workbench_api["_WORKBENCH_DB_CONTEXT"],
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."),
    )["scan"]

    assert stopped["findingCount"] == 1
    published = read_review_state(workbench_db, scan.scan_dir)
    assert published["reviews"] == coverage["reviews"]
    assert coverage["deferred"][0] in published["deferred"]
    manifest = (scan.scan_dir / "scan-manifest.json").read_bytes()
    workbench_api["saved_results"].preserve_scan_results(
        workbench_api["_WORKBENCH_DB_CONTEXT"],
        workbench_db,
        Namespace(
            scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
        ),
    )
    assert (scan.scan_dir / "scan-manifest.json").read_bytes() == manifest
    assert accepted.read_bytes() == contents


@pytest.mark.parametrize("source", ["frozen", "alias", "both", "neither", "legacy"])
def test_stopped_discovery_retains_only_bound_attempt_output(
    workbench_db, publication_scan, source
):
    scan = publication_scan()
    result = scan.add_worker()
    worker_id = result.parent.name
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))

    def draft(label):
        return scan.worker_draft(
            [worker_finding(scan, label)],
            deferred=[{"id": label, "reason": label}],
        )

    contents = json.dumps(draft("accepted-review")).encode()
    digest = hashlib.sha256(contents).hexdigest()
    frozen = result.parent / f"accepted-{digest}.json"
    frozen.write_bytes(contents if source in {"frozen", "both"} else b"{}")
    result.write_bytes(
        contents if source in {"alias", "both"} else json.dumps(draft("changed-alias")).encode()
    )
    with workbench_db:
        workbench_db.execute("UPDATE deep_scan_workers SET attempt = 2 WHERE id = ?", (worker_id,))
        if source != "legacy":
            workbench_db.execute(
                "INSERT INTO deep_scan_attempts (scan_id, worker_id, attempt, status, started_at, "
                "completed_at, accepted_result_path, accepted_result_sha256) "
                "VALUES (?, ?, 2, 'succeeded', ?, ?, ?, ?)",
                (scan.scan_id, worker_id, scan.timestamp, scan.timestamp, str(frozen), digest),
            )
    current = write_checkpoint(result.parent / "checkpoints", draft("changed-checkpoint"))
    select_checkpoint(result.parent, current)
    previous = result.parent / "attempts" / "attempt-1"
    prior = write_checkpoint(previous / "checkpoints", draft("previous-attempt"))
    with workbench_db:
        workbench_db.execute(
            "INSERT INTO deep_scan_attempts (scan_id, worker_id, attempt, status, started_at, "
            "completed_at, accepted_result_path, accepted_result_sha256) "
            "VALUES (?, ?, 1, 'succeeded', ?, ?, ?, ?)",
            (scan.scan_id, worker_id, scan.timestamp, scan.timestamp, str(prior), prior.stem),
        )
    _, partial = scan.canceled_discovery_output()
    write_checkpoint(partial / "checkpoints", draft("independent-partial"))

    scan.fail()

    assert (
        json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]["status"] == "failed"
    )
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    titles = {finding["title"] for finding in findings}
    reasons = {
        item["reason"] for item in read_review_state(workbench_db, scan.scan_dir)["deferred"]
    }
    expected = {"previous-attempt", "independent-partial"}
    if source in {"frozen", "alias", "both"}:
        expected.add("accepted-review")
    if source == "legacy":
        expected.update({"changed-alias", "changed-checkpoint"})
    assert titles == expected
    assert "independent-partial" in reasons
    assert ("accepted-review" in reasons) == (source in {"frozen", "alias", "both"})
    assert ("changed-alias" in reasons) == (source == "legacy")
    assert ("changed-checkpoint" in reasons) == (source == "legacy")
    manifest = (scan.scan_dir / "scan-manifest.json").read_bytes()
    scan.preserve()
    assert (scan.scan_dir / "scan-manifest.json").read_bytes() == manifest

    if source == "both":
        sources = json.loads(manifest)["scan"]["preservedSources"]
        assert frozen.relative_to(scan.scan_dir).as_posix() in sources
        assert result.relative_to(scan.scan_dir).as_posix() not in sources
        result.write_text(json.dumps(draft("changed-after-stop")))
        write_checkpoint(partial / "checkpoints", draft("new-partial"))
        scan.recover()
        recovered = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
        assert {finding["title"] for finding in recovered} == expected | {"new-partial"}
