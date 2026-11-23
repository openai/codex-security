from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
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

    if source in {"both", "alias"}:
        sources = json.loads(manifest)["scan"]["preservedSources"]
        assert (frozen.relative_to(scan.scan_dir).as_posix() in sources) == (source == "both")
        assert (result.relative_to(scan.scan_dir).as_posix() in sources) == (source == "alias")
        if source == "both":
            result.write_text(json.dumps(draft("changed-after-stop")))
        else:
            frozen.write_bytes(contents)
        write_checkpoint(partial / "checkpoints", draft("new-partial"))
        scan.recover()
        recovered = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
        assert {finding["title"] for finding in recovered} == expected | {"new-partial"}


@pytest.mark.parametrize("source", ["matching", "changed", "unselected-checkpoint"])
def test_recover_previously_frozen_discovery_alias(workbench_db, publication_scan, source):
    scan = publication_scan()
    result = scan.add_worker()
    contents = json.dumps(scan.worker_draft(scan.findings)).encode()
    digest = hashlib.sha256(contents).hexdigest()
    frozen = result.with_name(f"accepted-{digest}.json")
    frozen.write_bytes(contents)
    result.write_bytes(contents)
    # Older stopped reports selected the replaceable name alongside the registered result.
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET result_manifest_path = ? WHERE id = ?",
            (str(frozen), result.parent.name),
        )
    if source == "unselected-checkpoint":
        write_checkpoint(
            result.parent / "checkpoints", scan.worker_draft([worker_finding(scan, "unselected")])
        )
    scan.fail()
    manifest = (scan.scan_dir / "scan-manifest.json").read_bytes()
    sources = json.loads(manifest)["scan"]["preservedSources"]
    assert all(path.relative_to(scan.scan_dir).as_posix() in sources for path in (result, frozen))
    with workbench_db:
        workbench_db.execute(
            "INSERT INTO deep_scan_attempts (scan_id, worker_id, attempt, status, started_at, "
            "completed_at, accepted_result_path, accepted_result_sha256) "
            "VALUES (?, ?, 1, 'succeeded', ?, ?, ?, ?)",
            (scan.scan_id, result.parent.name, scan.timestamp, scan.timestamp, str(frozen), digest),
        )
    if source == "changed":
        result.write_bytes(contents + b" ")
    _, independent = scan.canceled_discovery_output()
    write_checkpoint(
        independent / "checkpoints", scan.worker_draft([worker_finding(scan, "late-partial")])
    )
    if source == "matching":
        scan.recover()
        findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
        assert "late-partial" in {finding["title"] for finding in findings}
    else:
        with pytest.raises(scan.api["ContractError"], match="checkpoint set is incomplete"):
            scan.recover()
        assert (scan.scan_dir / "scan-manifest.json").read_bytes() == manifest


@pytest.mark.parametrize("publication", ["selected", "mutable", "stale-generation", "unfenced"])
def test_publication_uses_committed_finalization_selection(
    workbench_api, workbench_db, publication_scan, publication
):
    scan = publication_scan()
    result = scan.add_worker()
    contents = json.dumps(
        {
            "scanId": scan.scan_id,
            "complete": True,
            "findings": scan.findings,
            "coverage": scan.coverage,
        }
    ).encode()
    digest = hashlib.sha256(contents).hexdigest()
    accepted = result.parent / "accepted" / f"{digest}.json"
    accepted.parent.mkdir()
    accepted.write_bytes(contents)
    selection = {
        "version": 1,
        "resultPath": accepted.relative_to(scan.scan_dir).as_posix(),
        "resultSha256": digest,
        "terminalReason": "saturated",
        "omittedWorkerIds": [],
        "selectedAt": scan.timestamp,
    }
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' "
            "WHERE result_manifest_path = ?",
            (str(result),),
        )
        workbench_db.execute(
            "UPDATE deep_scan_runs SET coordinator_generation = ?, finalization_input_json = ?, "
            "workflow_version = 'deep-security-scan/v2' "
            "WHERE scan_id = ?",
            (1 if publication == "unfenced" else 3, json.dumps(selection), scan.scan_id),
        )
    # The accepted bytes survive replacement or deletion of the worker's output.
    result.unlink(missing_ok=True)
    staged = stage_publication(
        scan,
        generation=None
        if publication == "unfenced"
        else 2
        if publication == "stale-generation"
        else 3,
        result_path=result if publication == "mutable" else accepted,
        title="Selected accepted aggregate",
    )
    before = {path: path.read_bytes() for path in scan.scan_dir.rglob("*.json")}

    if publication == "selected":
        workbench_api["saved_results"].write_scan_draft(
            workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, staged
        )
        findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
        assert findings[0]["title"] == "Selected accepted aggregate"
    else:
        with pytest.raises(SystemExit, match="coordinator|publication|aggregate"):
            workbench_api["saved_results"].write_scan_draft(
                workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, staged
            )
        assert {path: path.read_bytes() for path in scan.scan_dir.rglob("*.json")} == before
    assert accepted.read_bytes() == contents
    current = json.loads(
        workbench_db.execute(
            "SELECT finalization_input_json FROM deep_scan_runs WHERE scan_id = ?",
            (scan.scan_id,),
        ).fetchone()[0]
    )
    if publication == "selected":
        digest = current.pop("publicationSha256")
        assert len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)
        current_scan = workbench_api["require_scan"](workbench_db, scan.scan_id)
        db = workbench_api["_WORKBENCH_DB_CONTEXT"]
        saved = workbench_api["saved_results"]
        prepared = saved._prepare_scan_finalization(
            scan.scan_dir,
            expected_coverage_mode=db.expected_coverage_mode(current_scan),
            completion_binding=db.workbench_completion_binding(current_scan, db.now()),
        )
        saved.require_selected_publication(db, workbench_db, current_scan, prepared)
    assert current == selection


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
    healthy = scan.add_worker()
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
        stopped = workbench_api["saved_results"].fail_scan(
            workbench_api["_WORKBENCH_DB_CONTEXT"],
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
