from __future__ import annotations

import copy
import json
import os
import sqlite3
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import assert_published_aggregate
from test_deep_scan_successful_publication import (
    publication_scan as publication_scan,
)
from workbench_test_support import (
    read_review_state,
    saved_draft,
    select_checkpoint,
    write_checkpoint,
)


@pytest.fixture
def saturated_scan(publication_scan, workbench_db):
    scan = publication_scan()
    completed_result = scan.add_worker()
    completed_result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": scan.findings,
                "coverage": scan.coverage,
            }
        )
    )
    reducer_result = scan.add_worker()
    reducer_result.write_bytes(completed_result.read_bytes())
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET completion_sequence = 1 WHERE id = ?",
            (completed_result.parent.name,),
        )
        workbench_db.execute(
            "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' WHERE id = ?",
            (reducer_result.parent.name,),
        )
        workbench_db.execute(
            "INSERT INTO deep_scan_dedup_inputs "
            "(scan_id, dedup_worker_id, discovery_worker_id, input_order) VALUES (?, ?, ?, 0)",
            (scan.scan_id, reducer_result.parent.name, completed_result.parent.name),
        )
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = 'running', phase = 'discovery', "
            "consecutive_no_new = stop_after_no_new, completion_sequence = 1, "
            "max_discovery_runs = 3, discovery_runs_dispatched = 1, "
            "manifest_path = NULL, terminal_reason = NULL, completed_at = NULL WHERE scan_id = ?",
            (scan.scan_id,),
        )
    scan.completed_worker_id = completed_result.parent.name
    scan.reducer_id = reducer_result.parent.name
    return scan


def finish(workbench_api, connection, scan, *, terminal_reason="saturated"):
    return workbench_api["deep_scan"].finish_deep_scan(
        connection,
        Namespace(
            scan_id=scan.scan_id,
            terminal_reason=terminal_reason,
            manifest_path=str(scan.scan_dir / "scan-manifest.json"),
            staged_manifest_path=None,
            omitted_worker_id=[],
        ),
    )["deepScan"]


@pytest.fixture
def deadline_scan(saturated_scan, workbench_db):
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET created_at = '2000-01-01T00:00:00+00:00' WHERE scan_id = ?",
            (saturated_scan.scan_id,),
        )
    return saturated_scan


def canceled_discovery_output(connection, scan, *, attempt=1):
    result = scan.add_worker(connection, status="canceled")
    worker_id = result.parent.name
    output = scan.scan_dir / "artifacts" / "deep_discovery" / "workers" / worker_id / "output"
    output.parent.mkdir(parents=True)
    result.parent.rename(output)
    with connection:
        connection.execute(
            "UPDATE deep_scan_workers SET artifact_dir = ?, prompt_path = ?, "
            "result_manifest_path = NULL, attempt = ? WHERE id = ?",
            (str(output), str(output.parent / "prompt.md"), attempt, worker_id),
        )
    return worker_id, output


@pytest.mark.parametrize("missing_writeup", [False, True], ids=["present", "missing"])
def test_deadline_preserves_optional_reduced_writeup_behavior(
    workbench_api, workbench_db, deadline_scan, missing_writeup
):
    scan = deadline_scan
    report_path = "findings/reduced/reduced.md"
    scan.findings[0]["writeup"] = {"reportPath": report_path}
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": scan.findings}))
    if not missing_writeup:
        report = scan.scan_dir / report_path
        report.parent.mkdir(parents=True)
        report.write_text("# Reduced finding\n")
    _, output = canceled_discovery_output(workbench_db, scan)
    write_checkpoint(
        output / "checkpoints",
        saved_draft(scan.scan_id, deferred=[{"reason": "Review the remaining upload paths."}]),
    )

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    completed = scan.complete()

    assert completed["progress"]["status"] == "complete"
    finding = json.loads((scan.scan_dir / "findings.json").read_text())["findings"][0]
    assert finding["title"] == scan.findings[0]["title"]
    assert ("writeup" not in finding) == missing_writeup
    assert any("Skipped missing writeup" in warning for warning in completed["warnings"]) == (
        missing_writeup
    )


def test_deadline_recovers_valid_findings_from_an_invalid_archived_retry(
    workbench_api, workbench_db, deadline_scan
):
    scan = deadline_scan
    worker_id, output = canceled_discovery_output(workbench_db, scan, attempt=2)
    archived = output.parent / "attempts" / "attempt-1"
    archived.mkdir(parents=True)
    valid = copy.deepcopy(scan.findings[0])
    valid["identity"]["anchor"] = "valid-archived-finding"
    valid["title"] = "Valid finding saved before retry"
    valid["provenance"] = {"source": "local_plugin"}
    invalid = copy.deepcopy(valid)
    invalid["identity"]["anchor"] = "invalid-archived-finding"
    invalid.pop("remediation")
    result = archived / "result.json"
    result.write_text(
        json.dumps(saved_draft(scan.scan_id, complete=True, findings=[valid, invalid]))
    )
    original = result.read_bytes()
    write_checkpoint(
        output / "checkpoints",
        saved_draft(scan.scan_id, deferred=[{"reason": "Retry review remains unfinished."}]),
    )

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    completed = scan.complete()

    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert {item["identity"]["anchor"] for item in findings} == {
        scan.findings[0]["identity"]["anchor"],
        valid["identity"]["anchor"],
    }
    recovered = next(item for item in findings if item["title"] == valid["title"])
    assert recovered["provenance"]["workerId"] == worker_id
    assert any("remediation" in warning for warning in completed["warnings"])
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]
    assert manifest["preservedSources"][result.relative_to(scan.scan_dir).as_posix()] == (
        workbench_api["saved_results"]._digest(json.loads(original))
    )
    assert result.read_bytes() == original


@pytest.mark.parametrize("invalid", ["finding", "unsafe-writeup"])
def test_deadline_does_not_recover_invalid_reduced_findings(
    workbench_api, workbench_db, deadline_scan, invalid
):
    from finalize_scan_contract import ContractError

    scan = deadline_scan
    if invalid == "finding":
        scan.findings[0].pop("remediation")
    else:
        scan.findings[0]["writeup"] = {"reportPath": "../invalid.md"}
    findings_path = scan.scan_dir / "findings.json"
    findings_path.write_text(json.dumps({"findings": scan.findings}))
    original = findings_path.read_bytes()
    _, output = canceled_discovery_output(workbench_db, scan)
    write_checkpoint(output / "checkpoints", saved_draft(scan.scan_id))

    with pytest.raises(ContractError, match="remediation|reportPath"):
        finish(workbench_api, workbench_db, scan, terminal_reason="capped")

    assert findings_path.read_bytes() == original
    assert (
        workbench_db.execute(
            "SELECT status FROM deep_scan_runs WHERE scan_id = ?", (scan.scan_id,)
        ).fetchone()[0]
        == "running"
    )


def test_deadline_preserves_worker_findings_with_optional_and_shared_identity(
    workbench_api, workbench_db, deadline_scan
):
    scan = deadline_scan
    _, output = canceled_discovery_output(workbench_db, scan)
    no_identity = copy.deepcopy(scan.findings[0])
    no_identity.pop("identity")
    no_identity["title"] = "Worker finding without authored identity"
    no_identity["provenance"] = {"source": "local_plugin"}
    first = copy.deepcopy(no_identity)
    first["title"] = "Shared semantic anchor at distinct locations"
    first["identity"] = {"anchor": "shared-worker-anchor"}
    first["locations"] = [{"path": "src/first.py", "startLine": 1}]
    second = copy.deepcopy(first)
    second["locations"] = [{"path": "src/second.py", "startLine": 1}]
    malformed = copy.deepcopy(first)
    malformed.pop("remediation")
    write_checkpoint(
        output / "checkpoints",
        saved_draft(scan.scan_id, findings=[no_identity, first, second, malformed]),
    )

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    completed = scan.complete()

    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert len(findings) == 4
    assert any(item["title"] == no_identity["title"] for item in findings)
    shared = [item for item in findings if item["identity"]["anchor"] == "shared-worker-anchor"]
    assert {item["locations"][0]["path"] for item in shared} == {"src/first.py", "src/second.py"}
    assert any("remediation" in warning for warning in completed["warnings"])


def test_deadline_resolves_worker_local_deferred_ids_before_scoping(
    workbench_api, workbench_db, deadline_scan
):
    scan = deadline_scan
    _, output = canceled_discovery_output(workbench_db, scan)
    write_checkpoint(
        output / "checkpoints",
        saved_draft(scan.scan_id, deferred=[{"id": "review", "reason": "Review pending."}]),
        mtime_ns=100,
    )
    current = saved_draft(scan.scan_id, complete=True)
    current["coverage"]["resolvedDeferred"] = [{"id": "review", "reason": "Review completed."}]
    latest = write_checkpoint(output / "checkpoints", current, mtime_ns=200)
    select_checkpoint(output, latest)

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    scan.complete()

    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert not any(item["reason"] == "Review pending." for item in coverage["deferred"])


def test_deadline_does_not_turn_invalid_worker_receipts_into_parent_artifacts(
    workbench_api, workbench_db, deadline_scan
):
    scan = deadline_scan
    _, output = canceled_discovery_output(workbench_db, scan)
    (output / "notes.txt").write_text("Not a worker receipt under artifacts/.\n")
    write_checkpoint(
        output / "checkpoints",
        saved_draft(
            scan.scan_id,
            surfaces=[
                {
                    "id": "entry",
                    "label": "Unverified review",
                    "disposition": "no_issue_found",
                    "receiptRefs": ["notes.txt", "../review.txt", "/artifacts/review.txt"],
                }
            ],
        ),
    )

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    completed = scan.complete()

    surface = read_review_state(workbench_db, scan.scan_dir)["surfaces"][0]
    assert surface["receiptRefs"] == []
    assert surface["disposition"] == "needs_follow_up"
    assert (
        len(
            [
                warning
                for warning in completed["warnings"]
                if "malformed coverage receipt" in warning
            ]
        )
        == 3
    )


@pytest.mark.parametrize("archived", [False, True], ids=["current", "archived"])
def test_deadline_preserves_worker_receipts_and_surface_links(
    workbench_api, workbench_db, deadline_scan, archived
):
    scan = deadline_scan
    canonical_receipt = scan.scan_dir / "artifacts" / "reduced.txt"
    canonical_receipt.parent.mkdir()
    canonical_receipt.write_text("Reduced review evidence.\n")
    canonical_surface = {
        "id": f"{scan.completed_worker_id}/entry",
        "workerId": scan.completed_worker_id,
        "label": "Reduced review",
        "disposition": "no_issue_found",
        "receiptRefs": ["artifacts/reduced.txt"],
    }
    scan.coverage["surfaces"] = [canonical_surface]
    (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))
    expected = {}
    for label in ("upload", "download"):
        worker_id, output = canceled_discovery_output(
            workbench_db, scan, attempt=2 if archived else 1
        )
        source = output.parent / "attempts" / "attempt-1" if archived else output
        receipt = source / "artifacts" / "review.txt"
        receipt.parent.mkdir(parents=True)
        receipt.write_text(f"Reviewed {label}.\n")
        if archived:
            current_receipt = output / "artifacts" / "review.txt"
            current_receipt.parent.mkdir(parents=True)
            current_receipt.write_text("Different current-attempt evidence.\n")
        checkpoint = write_checkpoint(
            source / "checkpoints",
            saved_draft(
                scan.scan_id,
                surfaces=[
                    {
                        "id": "entry",
                        "label": label,
                        "disposition": "no_issue_found",
                        "receiptRefs": ["artifacts/review.txt"],
                    }
                ],
                deferred=[{"id": "follow-up", "reason": label, "surfaceIds": ["entry"]}],
            ),
        )
        expected[label] = (worker_id, receipt, checkpoint, checkpoint.read_bytes())

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    scan.complete()

    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert len(coverage["surfaces"]) == 3
    assert canonical_surface in coverage["surfaces"]
    sources = json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"][
        "preservedSources"
    ]
    for label, (worker_id, receipt, checkpoint, original) in expected.items():
        surface = next(item for item in coverage["surfaces"] if item["label"] == label)
        deferred = next(item for item in coverage["deferred"] if item["reason"] == label)
        assert surface["id"] == f"{worker_id}/entry"
        assert deferred["id"] == f"{worker_id}/follow-up"
        assert deferred["surfaceIds"] == [surface["id"]]
        assert surface["workerId"] == deferred["workerId"] == worker_id
        assert surface["disposition"] == "no_issue_found"
        assert surface["receiptRefs"] == [receipt.relative_to(scan.scan_dir).as_posix()]
        assert (scan.scan_dir / surface["receiptRefs"][0]).read_text() == f"Reviewed {label}.\n"
        assert sources[checkpoint.relative_to(scan.scan_dir).as_posix()] == workbench_api[
            "saved_results"
        ]._digest(json.loads(original))
        assert checkpoint.read_bytes() == original


def test_saturated_finish_cancels_unfinished_discovery_without_using_its_drafts(
    workbench_api, workbench_db, saturated_scan
):
    scan = saturated_scan
    unfinished = []
    for status in ("queued", "running"):
        result = scan.add_worker(status=status)
        result.write_text("{unfinished worker draft")
        unfinished.append(result)

    finished = finish(workbench_api, workbench_db, scan)

    assert finished["status"] == "succeeded"
    assert finished["terminalReason"] == "saturated"
    workers = {worker["id"]: worker for worker in finished["workers"]}
    assert workers[scan.completed_worker_id]["status"] == "succeeded"
    assert workers[scan.reducer_id]["status"] == "succeeded"
    for result in unfinished:
        worker = workers[result.parent.name]
        assert worker["status"] == "canceled"
        assert worker["completedAt"] is not None
        assert worker["completionSequence"] is None
        assert worker["mergeState"] == "none"
        assert result.read_text() == "{unfinished worker draft"

    scan.complete()
    assert_published_aggregate(scan)


def test_saturated_finish_retains_failed_discovery_diagnostic(
    workbench_api, workbench_db, saturated_scan
):
    scan = saturated_scan
    result = scan.add_worker(status="failed")
    error = "Worker stopped while persisting its result."
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET error_message = ? WHERE id = ?",
            (error, result.parent.name),
        )

    finished = finish(workbench_api, workbench_db, scan)

    assert finished["status"] == "succeeded"
    failed_worker = next(
        worker for worker in finished["workers"] if worker["id"] == result.parent.name
    )
    assert failed_worker["status"] == "failed"
    assert failed_worker["error"] == error
    scan.complete()
    assert_published_aggregate(scan)


@pytest.mark.parametrize("stop", ["deadline", "run-limit", "saturated"])
def test_unfinished_checkpoints_after_a_completed_reduction(
    workbench_api, workbench_db, saturated_scan, stop
):
    scan = saturated_scan
    result = scan.add_worker(status="canceled")
    recovered = copy.deepcopy(scan.findings[0])
    recovered["identity"]["anchor"] = "unfinished-upload-review"
    recovered["title"] = "Separate upload handler bypasses containment"
    recovered["provenance"] = {"source": "local_plugin"}
    duplicate = copy.deepcopy(scan.findings[0])
    duplicate["severity"]["level"] = "critical"
    duplicate["remediation"] = "Unreduced remediation from an unfinished review."
    pending = {
        "id": "pending-upload",
        "reason": "The remaining upload paths need review.",
        "paths": ["subdir/extract.py"],
        "surfaceIds": ["upload"],
    }
    checkpoint = write_checkpoint(
        result.parent / "checkpoints",
        saved_draft(
            scan.scan_id,
            findings=[recovered, duplicate],
            deferred=[pending],
            surfaces=[
                {
                    "id": "upload",
                    "label": "Upload handler",
                    "disposition": "needs_follow_up",
                    "receiptRefs": [],
                }
            ],
        ),
    )
    source_bytes = checkpoint.read_bytes()
    # Earlier parent, discovery, and reducer drafts must not undo reduction.
    discarded = copy.deepcopy(recovered)
    discarded["identity"]["anchor"] = "discarded-during-reduction"
    for directory in (
        scan.scan_dir,
        scan.scan_dir / "workers" / scan.completed_worker_id,
        scan.scan_dir / "workers" / scan.reducer_id,
    ):
        discarded_checkpoint = write_checkpoint(
            directory / "checkpoints",
            saved_draft(scan.scan_id, findings=[discarded]),
        )
        if directory == scan.scan_dir:
            head = select_checkpoint(directory, discarded_checkpoint)
            observed = (
                max(
                    (directory / name).stat().st_mtime_ns
                    for name in ("scan-manifest.json", "findings.json", "coverage.json")
                )
                + 1_000_000_000
            )
            for path in (discarded_checkpoint, head):
                os.utime(path, ns=(observed, observed))
    with workbench_db:
        if stop == "deadline":
            workbench_db.execute(
                "UPDATE deep_scan_runs SET created_at = '2000-01-01T00:00:00+00:00' "
                "WHERE scan_id = ?",
                (scan.scan_id,),
            )
        elif stop == "run-limit":
            workbench_db.execute(
                "UPDATE deep_scan_runs SET discovery_runs_dispatched = max_discovery_runs "
                "WHERE scan_id = ?",
                (scan.scan_id,),
            )

    reason = "saturated" if stop == "saturated" else "capped"
    finished = finish(workbench_api, workbench_db, scan, terminal_reason=reason)

    assert finished["status"] == "succeeded"
    worker = next(item for item in finished["workers"] if item["id"] == result.parent.name)
    assert worker["status"] == "canceled"
    assert worker["completionSequence"] is None
    row = workbench_db.execute(
        "SELECT status, seal_manifest_digest FROM scans WHERE id = ?", (scan.scan_id,)
    ).fetchone()
    assert tuple(row) == ("running", None)
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())
    assert "sealedAt" not in manifest["scan"]
    completed = scan.complete()
    assert completed["progress"]["status"] == "complete"
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    expected_anchors = {scan.findings[0]["identity"]["anchor"]}
    if stop == "deadline":
        expected_anchors.add(recovered["identity"]["anchor"])
        retained = next(item for item in findings if item["title"] == recovered["title"])
        assert retained["provenance"]["workerId"] == result.parent.name
        assert (
            checkpoint.relative_to(scan.scan_dir).as_posix() in manifest["scan"]["preservedSources"]
        )
    assert {item["identity"]["anchor"] for item in findings} == expected_anchors
    canonical = next(item for item in findings if item["title"] == scan.findings[0]["title"])
    for field in ("severity", "confidence", "remediation"):
        assert canonical[field] == scan.findings[0][field]
    assert (
        canonical["provenance"]["sourceFindings"]
        == scan.findings[0]["provenance"]["sourceFindings"]
    )
    if stop == "deadline":
        assert any(
            item["remediation"] == duplicate["remediation"]
            for item in canonical["provenance"]["previousFindings"]
        )
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert any(item["reason"] == pending["reason"] for item in coverage["deferred"]) == (
        stop == "deadline"
    )
    assert any(item["disposition"] == "needs_follow_up" for item in coverage["surfaces"]) == (
        stop == "deadline"
    )
    assert checkpoint.read_bytes() == source_bytes
    names = ("scan-manifest.json", "findings.json", "report.md")
    sealed = {name: (scan.scan_dir / name).read_bytes() for name in names}
    finish(workbench_api, workbench_db, scan, terminal_reason=reason)
    scan.complete()
    assert {name: (scan.scan_dir / name).read_bytes() for name in names} == sealed


def test_deadline_after_all_reviews_complete_keeps_reduced_coverage(
    workbench_api, workbench_db, saturated_scan
):
    scan = saturated_scan
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET created_at = '2000-01-01T00:00:00+00:00' WHERE scan_id = ?",
            (scan.scan_id,),
        )

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    scan.complete()

    assert_published_aggregate(scan)


@pytest.mark.parametrize(
    ("terminal_reason", "kind"),
    [("saturated", "setup"), ("saturated", "dedup"), ("capped", "discovery")],
    ids=["saturated-setup", "saturated-reducer", "capped-discovery"],
)
def test_finish_preserves_other_worker_failure_checks(
    workbench_api, workbench_db, saturated_scan, terminal_reason, kind
):
    scan = saturated_scan
    result = scan.add_worker(status="failed")
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET kind = ? WHERE id = ?", (kind, result.parent.name)
        )
        if terminal_reason == "capped":
            workbench_db.execute(
                "UPDATE deep_scan_runs SET discovery_runs_dispatched = max_discovery_runs "
                "WHERE scan_id = ?",
                (scan.scan_id,),
            )

    with pytest.raises(SystemExit, match="after a worker has failed"):
        finish(workbench_api, workbench_db, scan, terminal_reason=terminal_reason)

    run = workbench_db.execute(
        "SELECT status, terminal_reason FROM deep_scan_runs WHERE scan_id = ?", (scan.scan_id,)
    ).fetchone()
    assert tuple(run) == ("running", None)


@pytest.mark.parametrize("existing_head", [False, True])
@pytest.mark.parametrize("with_reduction", [False, True], ids=["zero-accepted", "reduced"])
def test_rejected_deadline_publication_does_not_leave_parent_observations(
    workbench_api, workbench_db, publication_scan, request, existing_head, with_reduction
):
    scan = request.getfixturevalue("saturated_scan") if with_reduction else publication_scan()
    canonical_names = ("scan-manifest.json", "findings.json", "coverage.json")
    for name in canonical_names:
        os.utime(scan.scan_dir / name, ns=(1_000_000_000, 1_000_000_000))
    pending = {"id": "authorization-review", "reason": "Review the remaining authorization path."}
    if with_reduction:
        result = scan.add_worker(status="canceled")
        write_checkpoint(
            result.parent / "checkpoints",
            saved_draft(scan.scan_id, deferred=[pending]),
        )
    if existing_head:
        checkpoint = write_checkpoint(
            scan.scan_dir / "checkpoints",
            saved_draft(scan.scan_id, findings=scan.findings, deferred=[pending]),
        )
        head = select_checkpoint(scan.scan_dir, checkpoint)
        for path in (checkpoint, head):
            os.utime(path, ns=(2_000_000_000, 2_000_000_000))
    saved = workbench_api["saved_results"]

    def observations():
        return {
            relative: (
                (scan.scan_dir / relative).read_bytes(),
                (scan.scan_dir / relative).stat().st_mtime_ns,
            )
            for relative, _ in saved._saved_result_paths(scan.scan_dir, [])
            if (scan.scan_dir / relative).is_file()
        }

    before = observations()
    artifacts = {
        name: ((scan.scan_dir / name).read_bytes(), (scan.scan_dir / name).stat().st_mtime_ns)
        for name in canonical_names
    }
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = 'running', phase = 'discovery', "
            "created_at = '2000-01-01T00:00:00+00:00', manifest_path = NULL, "
            "terminal_reason = NULL, completed_at = NULL WHERE scan_id = ?",
            (scan.scan_id,),
        )
        workbench_db.execute(
            "CREATE TRIGGER reject_deadline_commit BEFORE UPDATE OF status ON deep_scan_runs "
            "WHEN NEW.status = 'succeeded' BEGIN SELECT RAISE(ABORT, 'deadline commit failed'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="deadline commit failed"):
        finish(workbench_api, workbench_db, scan, terminal_reason="capped")

    assert observations() == before
    assert {
        name: ((scan.scan_dir / name).read_bytes(), (scan.scan_dir / name).stat().st_mtime_ns)
        for name in artifacts
    } == artifacts
    assert (
        workbench_db.execute(
            "SELECT status FROM deep_scan_runs WHERE scan_id = ?", (scan.scan_id,)
        ).fetchone()[0]
        == "running"
    )
    with workbench_db:
        workbench_db.execute("DROP TRIGGER reject_deadline_commit")
    assert (
        finish(workbench_api, workbench_db, scan, terminal_reason="capped")["status"] == "succeeded"
    )
    if existing_head:
        coverage = json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"][
            "reviewState"
        ]
        assert any(item["reason"] == pending["reason"] for item in coverage["deferred"])


def test_zero_accepted_deadline_preserves_worker_checkpoint_links_and_receipts(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    workers = {}
    originals = {}
    for name in ("first", "second"):
        result = scan.add_worker(status="canceled")
        worker_id = result.parent.name
        output = scan.scan_dir / "artifacts" / "deep_discovery" / "workers" / worker_id / "output"
        output.parent.mkdir(parents=True)
        result.parent.rename(output)
        result = output / result.name
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET artifact_dir = ?, result_manifest_path = ? "
                "WHERE id = ?",
                (str(output), str(result), worker_id),
            )
        receipt = result.parent / "artifacts" / "review.md"
        receipt.parent.mkdir()
        receipt.write_text(f"Synthetic {name} source review.\n")
        checkpoint = write_checkpoint(
            result.parent / "checkpoints",
            saved_draft(
                scan.scan_id,
                complete=False,
                surfaces=[
                    {
                        "id": "api",
                        "label": name,
                        "disposition": "no_issue_found",
                        "receiptRefs": ["artifacts/review.md"],
                    }
                ],
                deferred=[{"id": "review", "reason": "Review remains.", "surfaceIds": ["api"]}],
            ),
        )
        head = select_checkpoint(result.parent, checkpoint)
        workers[worker_id] = receipt
        originals.update({path: path.read_bytes() for path in (receipt, checkpoint, head)})
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = 'running', phase = 'discovery', "
            "workers = 2, max_discovery_runs = 3, discovery_runs_dispatched = 2, "
            "created_at = '2000-01-01T00:00:00+00:00', manifest_path = NULL, "
            "terminal_reason = NULL, completed_at = NULL WHERE scan_id = ?",
            (scan.scan_id,),
        )

    finished = finish(workbench_api, workbench_db, scan, terminal_reason="capped")

    assert finished["status"] == "succeeded"
    assert finished["completionSequence"] == 0
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert {row["id"] for row in coverage["surfaces"]} == {
        f"{worker_id}/api" for worker_id in workers
    }
    for worker_id, receipt in workers.items():
        surface = next(row for row in coverage["surfaces"] if row["workerId"] == worker_id)
        task = next(row for row in coverage["deferred"] if row.get("workerId") == worker_id)
        assert surface["disposition"] == "no_issue_found"
        assert surface["receiptRefs"] == [receipt.relative_to(scan.scan_dir).as_posix()]
        assert task["id"] == f"{worker_id}/review"
        assert task["surfaceIds"] == [surface["id"]]
    assert all(path.read_bytes() == contents for path, contents in originals.items())
