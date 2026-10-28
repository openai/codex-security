from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import traceback

import pytest
from deep_deadline_crash import COMMIT_EXIT, finish_until_commit
from test_deep_scan_stop_conditions import (
    canceled_discovery_output,
    complete,
    finish,
)
from test_deep_scan_stop_conditions import (
    deadline_scan as deadline_scan,
)
from test_deep_scan_stop_conditions import (
    publication_scan as publication_scan,
)
from test_deep_scan_stop_conditions import (
    saturated_scan as saturated_scan,
)
from workbench_test_support import read_review_state, saved_draft, write_checkpoint


def worker_finding(scan, anchor):
    finding = copy.deepcopy(scan.findings[0])
    finding["identity"] = {"anchor": anchor}
    finding["title"] = anchor
    finding["provenance"] = {"source": "local_plugin"}
    return finding


@pytest.mark.parametrize(
    ("task_state", "task_id", "marker_count"),
    [
        ("resolvedDeferred", "scan-deadline", 0),
        ("resolvedDeferred", "prior-review", 1),
        ("deferred", "scan-deadline", 0),
    ],
)
def test_deadline_completion_preserves_existing_tasks_and_recovered_findings(
    workbench_api, workbench_db, deadline_scan, task_state, task_id, marker_count
):
    scan = deadline_scan
    task = {"id": task_id, "reason": "Existing review outcome."}
    scan.coverage[task_state] = [task]
    (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))
    worker_id, output = canceled_discovery_output(workbench_db, scan)
    recovered = worker_finding(scan, "saved-before-deadline")
    checkpoint = write_checkpoint(
        output / "checkpoints",
        saved_draft(
            scan.scan_id,
            findings=[recovered],
            deferred=[{"id": "unfinished-review", "reason": "Review remains unfinished."}],
        ),
    )
    original_checkpoint = checkpoint.read_bytes()

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    completed = complete(workbench_api, workbench_db, scan)

    assert completed["progress"]["status"] == "complete"
    assert (
        workbench_db.execute("SELECT status FROM scans WHERE id = ?", (scan.scan_id,)).fetchone()[0]
        == "complete"
    )
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert task in coverage[task_state]
    if task_state == "resolvedDeferred":
        assert coverage[task_state] == [task]
    assert any(
        row.get("workerId") == worker_id and row["reason"] == "Review remains unfinished."
        for row in coverage["deferred"]
    )
    assert (
        sum(row.get("id") == "scan-deadline" and row != task for row in coverage["deferred"])
        == marker_count
    )
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert {row["title"] for row in findings} == {scan.findings[0]["title"], recovered["title"]}
    assert (
        next(row for row in findings if row["title"] == recovered["title"])["provenance"][
            "workerId"
        ]
        == worker_id
    )
    assert checkpoint.read_bytes() == original_checkpoint


def interrupt_finish_before_commit(workbench_api, database, scan):
    child = os.fork()
    if child == 0:
        try:
            finish_until_commit(workbench_api["deep_scan"], database, scan.scan_id, scan.scan_dir)
        except BaseException:
            traceback.print_exc()
        os._exit(1)
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == COMMIT_EXIT


@pytest.mark.parametrize("missing_field", ["remediation", "codeEvidence", "validation"])
def test_discarded_worker_finding_leaves_its_review_pending(
    workbench_api, workbench_db, deadline_scan, missing_field
):
    scan = deadline_scan
    canonical = {
        "id": "accepted",
        "label": "Accepted review",
        "disposition": "reported",
        "receiptRefs": [],
    }
    scan.coverage["surfaces"] = [canonical]
    (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))
    worker_id, output = canceled_discovery_output(workbench_db, scan)
    invalid = worker_finding(scan, "incomplete-worker-finding")
    invalid.pop(missing_field)
    checkpoint = write_checkpoint(
        output / "checkpoints",
        saved_draft(
            scan.scan_id,
            findings=[invalid],
            surfaces=[
                {
                    "id": "entry",
                    "label": "Worker review",
                    "disposition": "reported",
                    "receiptRefs": [],
                }
            ],
        ),
    )
    original = checkpoint.read_bytes()

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    completed = complete(workbench_api, workbench_db, scan)

    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert canonical in coverage["surfaces"]
    surface = next(row for row in coverage["surfaces"] if row.get("workerId") == worker_id)
    assert surface["disposition"] == "needs_follow_up"
    assert any(
        row.get("workerId") == worker_id and missing_field in row["reason"]
        for row in coverage["deferred"]
    )
    assert completed["progress"]["status"] == "complete"
    assert len(json.loads((scan.scan_dir / "findings.json").read_text())["findings"]) == 1
    assert checkpoint.read_bytes() == original


@pytest.mark.parametrize("association", ["explicit", "anonymous", "shared", "embedded"])
def test_discarded_worker_evidence_preserves_other_surface_dispositions(
    workbench_api, workbench_db, deadline_scan, association
):
    scan = deadline_scan
    worker_id, output = canceled_discovery_output(workbench_db, scan)
    sparse = worker_finding(scan, "incomplete")
    sparse.pop("codeEvidence")
    candidate_id = "complete" if association == "shared" else "sparse"
    link = {} if association == "anonymous" else {"candidateId": candidate_id}
    sparse["provenance"].update(link)
    retained = worker_finding(scan, "retained")
    retained["provenance"]["candidateId"] = "complete"
    surfaces = [
        {"id": "one", "label": "Incomplete finding", "disposition": "reported", **link},
        {
            "id": "two",
            "label": "Complete finding",
            "disposition": "reported",
            "candidateId": "complete",
        },
        {
            "id": "three",
            "label": "Independent review",
            "disposition": "no_issue_found",
            "candidateId": "independent",
        },
    ]
    if association in {"shared", "embedded"}:
        surfaces[0]["finding"] = sparse
        surfaces[1]["finding"] = retained
    if association == "embedded":
        for surface in surfaces[:2]:
            surface["id"] = surface.pop("candidateId")
    checkpoint = write_checkpoint(
        output / "checkpoints",
        saved_draft(scan.scan_id, findings=[retained, sparse], surfaces=surfaces),
    )
    original = checkpoint.read_bytes()

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    assert complete(workbench_api, workbench_db, scan)["progress"]["status"] == "complete"

    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert sorted(
        (row["label"], row["disposition"])
        for row in coverage["surfaces"]
        if row.get("workerId") == worker_id
    ) == [
        ("Complete finding", "reported"),
        ("Incomplete finding", "needs_follow_up"),
        ("Independent review", "no_issue_found"),
    ]
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert {row["title"] for row in findings} == {scan.findings[0]["title"], retained["title"]}
    task = next(row for row in coverage["deferred"] if row.get("workerId") == worker_id)
    pending = next(row for row in coverage["surfaces"] if row["disposition"] == "needs_follow_up")
    assert task["surfaceIds"] == [pending["id"]]
    assert task["paths"] == [sparse["locations"][0]["path"]]
    assert f"{checkpoint.relative_to(scan.scan_dir)} finding 2" in task["reason"]
    assert sparse["title"] in task["reason"]
    assert json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]["sealedAt"]
    assert checkpoint.read_bytes() == original


def test_unlinked_sparse_checkpoint_leaves_earlier_worker_surface_reported(
    workbench_api, workbench_db, deadline_scan
):
    scan = deadline_scan
    worker_id, output = canceled_discovery_output(workbench_db, scan)
    retained = worker_finding(scan, "retained")
    surface = {"id": "first", "label": "First review", "disposition": "reported"}
    earlier = write_checkpoint(
        output / "checkpoints", saved_draft(scan.scan_id, findings=[retained], surfaces=[surface])
    )
    sparse = worker_finding(scan, "unrelated")
    sparse.pop("validation")
    later = write_checkpoint(
        output / "checkpoints",
        saved_draft(scan.scan_id, findings=[{"title": "Invalid row"}, sparse]),
    )
    original = [path.read_bytes() for path in (earlier, later)]

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    assert complete(workbench_api, workbench_db, scan)["progress"]["status"] == "complete"
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert (
        next(row for row in coverage["surfaces"] if row.get("workerId") == worker_id)["disposition"]
        == "reported"
    )
    task = next(
        row
        for row in coverage["deferred"]
        if row.get("workerId") == worker_id and "unrelated" in row["reason"]
    )
    assert "surfaceIds" not in task
    assert f"{later.relative_to(scan.scan_dir)} finding 2" in task["reason"]
    assert original == [path.read_bytes() for path in (earlier, later)]


@pytest.mark.parametrize("archived", [False, True])
def test_deferred_worker_candidate_cannot_reopen_another_owners_task(
    workbench_api, workbench_db, deadline_scan, archived
):
    scan = deadline_scan
    local_id = "input"
    accepted_owner = scan.completed_worker_id
    selected = copy.deepcopy(scan.findings)
    selected[0]["provenance"].update(workerId=accepted_owner, candidateId=local_id)
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": selected}))
    accepted = {
        "id": "accepted",
        "label": "Accepted",
        "disposition": "reported",
        "receiptRefs": [],
        "provenance": {"workerId": accepted_owner, "attempt": 1, "candidateId": local_id},
    }
    closure = {"id": local_id, "reason": "The parent completed this review."}
    scan.coverage.update(surfaces=[accepted], resolvedDeferred=[closure])
    (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))
    owner, output = canceled_discovery_output(workbench_db, scan, attempt=2 if archived else 1)
    if archived:
        output = output.parent / "attempts" / "attempt-1"
    sparse = worker_finding(scan, "unfinished")
    sparse.pop("validation")
    sparse["provenance"].update(workerId=accepted_owner, candidateId=local_id)
    surface = {
        "id": "unfinished",
        "label": "Unfinished",
        "disposition": "reported",
        "candidateId": local_id,
        "provenance": {"workerId": accepted_owner},
    }
    checkpoint = write_checkpoint(
        output / "checkpoints", saved_draft(scan.scan_id, findings=[sparse], surfaces=[surface])
    )
    original = checkpoint.read_bytes()

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    assert complete(workbench_api, workbench_db, scan)["progress"]["status"] == "complete"

    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert coverage["resolvedDeferred"] == [closure]
    assert accepted in coverage["surfaces"]
    (retained,) = json.loads((scan.scan_dir / "findings.json").read_bytes())["findings"]
    assert retained["identity"] == selected[0]["identity"]
    assert retained["provenance"]["workerId"] == accepted_owner
    assert retained["validation"] == selected[0]["validation"]
    unfinished = next(row for row in coverage["surfaces"] if row.get("workerId") == owner)
    assert unfinished["disposition"] == "needs_follow_up"
    (task,) = [row for row in coverage["deferred"] if row.get("workerId") == owner]
    suffix = hashlib.sha256(local_id.encode()).hexdigest()
    assert task["candidateId"] == f"{owner}-attempt-1-candidate-{suffix}"
    assert task["provenance"]["attempt"] == 1
    assert task["provenance"]["candidateId"] == local_id
    assert checkpoint.read_bytes() == original


def write_worker_revisions(scan, output, earlier, latest):
    previous = write_checkpoint(
        output / "checkpoints", saved_draft(scan.scan_id, findings=[earlier])
    )
    current = write_checkpoint(output / "checkpoints", saved_draft(scan.scan_id, findings=[latest]))
    os.utime(previous, ns=(100, 100))
    os.utime(current, ns=(200, 200))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": current.name}))
    return {path: path.read_bytes() for path in (previous, current, head)}


def test_complete_worker_revision_keeps_its_sparse_checkpoint_identity(
    workbench_api, workbench_db, deadline_scan
):
    scan = deadline_scan
    worker_id, output = canceled_discovery_output(workbench_db, scan)
    earlier = worker_finding(scan, "authored-anchor")
    earlier["ruleId"] = "checkpoint-revision"
    earlier["provenance"]["candidateId"] = "worker-candidate"
    latest = copy.deepcopy(earlier)
    latest.pop("identity")
    latest["summary"] = "The later revision supplies validation."
    earlier.pop("validation")
    originals = write_worker_revisions(scan, output, earlier, latest)

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    assert complete(workbench_api, workbench_db, scan)["progress"]["status"] == "complete"

    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    (finding,) = [row for row in findings if row["ruleId"] == earlier["ruleId"]]
    assert finding["identity"] == earlier["identity"]
    assert finding["summary"] == latest["summary"]
    assert finding["validation"] == latest["validation"]
    (history,) = finding["provenance"]["previousFindings"]
    assert history["identity"] == earlier["identity"]
    assert history["summary"] == earlier["summary"]
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert not any(row.get("workerId") == worker_id for row in coverage["deferred"])
    assert {path: path.read_bytes() for path in originals} == originals


@pytest.mark.parametrize(
    "revision",
    [
        {},
        {"summary": "The updated finding describes a different exposure."},
        {"extensions": {"observedRuntimeInput": {"mode": 1}}},
        {"validation": {}},
        {"provenance": {"source": "independent_scanner", "candidateId": "worker-candidate"}},
    ],
    ids=[
        "omitted-proof",
        "changed-claim",
        "number-for-boolean",
        "explicit-invalid-proof",
        "different-producer",
    ],
)
def test_deadline_reuses_omitted_proof_only_for_unchanged_worker_findings(
    workbench_api, workbench_db, deadline_scan, revision
):
    scan = deadline_scan
    worker_id, output = canceled_discovery_output(workbench_db, scan)
    earlier = worker_finding(scan, "checkpoint-proof")
    earlier["ruleId"] = "checkpoint-revision"
    earlier["provenance"]["candidateId"] = "worker-candidate"
    earlier["extensions"] = {"observedRuntimeInput": {"mode": True}}
    latest = copy.deepcopy(earlier)
    latest.pop("identity")
    latest.pop("validation")
    latest.update(revision)
    originals = write_worker_revisions(scan, output, earlier, latest)

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    assert complete(workbench_api, workbench_db, scan)["progress"]["status"] == "complete"

    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    retained = [row for row in findings if row["ruleId"] == earlier["ruleId"]]
    coverage = read_review_state(workbench_db, scan.scan_dir)
    deferred = [row for row in coverage["deferred"] if row.get("workerId") == worker_id]
    if revision:
        assert not retained
        assert len(deferred) == 1
    else:
        (finding,) = retained
        assert finding["identity"] == earlier["identity"]
        assert finding["validation"] == earlier["validation"]
        assert not deferred
    assert {path: path.read_bytes() for path in originals} == originals


@pytest.mark.parametrize("renewed", [False, True], ids=["withdrawn", "renewed"])
def test_deadline_uses_the_last_authored_validation(
    workbench_api, workbench_db, deadline_scan, renewed
):
    scan = deadline_scan
    _, output = canceled_discovery_output(workbench_db, scan)
    earlier = worker_finding(scan, "earlier-proof")
    earlier["ruleId"] = "checkpoint-revision"
    for key in ("findingId", "occurrenceId", "fingerprints"):
        earlier.pop(key, None)
    invalid = earlier | {"validation": None}
    history = [earlier, invalid]
    if renewed:
        valid = earlier | {"validation": {**earlier["validation"], "summary": "Later validation."}}
        history.append(valid)
    latest = copy.deepcopy(earlier)
    latest.pop("validation")
    latest["provenance"]["previousFindings"] = history
    originals = write_worker_revisions(scan, output, earlier, latest)

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    assert complete(workbench_api, workbench_db, scan)["progress"]["status"] == "complete"

    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    retained = [row for row in findings if row["ruleId"] == earlier["ruleId"]]
    assert [row["validation"]["summary"] for row in retained] == (
        ["Later validation."] if renewed else []
    )
    assert {path: path.read_bytes() for path in originals} == originals


@pytest.mark.parametrize(
    "invalid_terminal", [False, True], ids=["valid-terminal", "invalid-terminal"]
)
def test_terminal_worker_authority_requires_valid_findings(
    workbench_api, workbench_db, deadline_scan, invalid_terminal
):
    scan = deadline_scan
    _, output = canceled_discovery_output(workbench_db, scan)
    previous = worker_finding(scan, "earlier-valid-finding")
    checkpoint = write_checkpoint(
        output / "checkpoints",
        saved_draft(
            scan.scan_id,
            findings=[previous],
            deferred=[{"id": "review", "reason": "Review pending."}],
        ),
    )
    os.utime(checkpoint, ns=(100, 100))
    sibling = worker_finding(scan, "valid-terminal-sibling")
    terminal_findings = [sibling]
    if invalid_terminal:
        invalid = copy.deepcopy(previous)
        invalid.pop("remediation")
        terminal_findings.append(invalid)
    result = output / "result.json"
    result.write_text(
        json.dumps(
            saved_draft(
                scan.scan_id,
                complete=True,
                findings=terminal_findings,
                closures=[{"id": "review", "reason": "Review completed."}],
            )
        )
    )
    os.utime(result, ns=(200, 200))
    original = {path: path.read_bytes() for path in (checkpoint, result)}

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    complete(workbench_api, workbench_db, scan)

    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert any(row["title"] == previous["title"] for row in findings) == invalid_terminal
    assert any(row["title"] == sibling["title"] for row in findings)
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert not any(row["reason"] == "Review pending." for row in coverage["deferred"])
    assert {path: path.read_bytes() for path in original} == original


def test_malformed_worker_finding_preserves_a_valid_sibling_outcome(
    workbench_api, workbench_db, deadline_scan
):
    scan = deadline_scan
    worker_id, output = canceled_discovery_output(workbench_db, scan)
    earlier = worker_finding(scan, "rejected-candidate")
    earlier["provenance"]["candidateId"] = "candidate"
    checkpoint = write_checkpoint(
        output / "checkpoints", saved_draft(scan.scan_id, findings=[earlier])
    )
    os.utime(checkpoint, ns=(100, 100))
    invalid = worker_finding(scan, "malformed-sibling")
    invalid.pop("remediation")
    outcome = {
        "id": "review",
        "label": "Candidate reviewed",
        "candidateId": "candidate",
        "disposition": "rejected",
        "receiptRefs": [],
    }
    result = output / "result.json"
    result.write_text(
        json.dumps(saved_draft(scan.scan_id, complete=True, findings=[invalid], surfaces=[outcome]))
    )
    os.utime(result, ns=(200, 200))

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    complete(workbench_api, workbench_db, scan)

    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert all(row["title"] != earlier["title"] for row in findings)
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert (
        next(row for row in coverage["surfaces"] if row.get("workerId") == worker_id)["disposition"]
        == "rejected"
    )
    assert any("remediation" in row["reason"] for row in coverage["deferred"])


@pytest.mark.parametrize("invalid", ["surfaces", "missing-receipt"])
def test_deadline_keeps_canonical_coverage_validation_strict(
    workbench_api, workbench_db, deadline_scan, invalid
):
    from finalize_scan_contract import ContractError

    scan = deadline_scan
    scan.coverage["surfaces"] = (
        "invalid"
        if invalid == "surfaces"
        else [
            {
                "id": "accepted",
                "label": "Accepted review",
                "disposition": "no_issue_found",
                "receiptRefs": ["artifacts/missing.txt"],
            }
        ]
    )
    coverage_file = scan.scan_dir / "coverage.json"
    coverage_file.write_text(json.dumps(scan.coverage))
    original = coverage_file.read_bytes()
    _, output = canceled_discovery_output(workbench_db, scan)
    write_checkpoint(output / "checkpoints", saved_draft(scan.scan_id))

    with pytest.raises(ContractError, match="surfaces|receiptRefs"):
        finish(workbench_api, workbench_db, scan, terminal_reason="capped")

    assert coverage_file.read_bytes() == original
    assert (
        workbench_db.execute(
            "SELECT status FROM deep_scan_runs WHERE scan_id = ?", (scan.scan_id,)
        ).fetchone()[0]
        == "running"
    )


@pytest.mark.parametrize("worker_writeup_exists", [False, True], ids=["missing", "present"])
def test_worker_writeups_remain_bound_to_their_source_directory(
    workbench_api, workbench_db, deadline_scan, worker_writeup_exists
):
    scan = deadline_scan
    report_path = "findings/review/review.md"
    scan.findings[0]["writeup"] = {"reportPath": report_path}
    parent_writeup = scan.scan_dir / report_path
    parent_writeup.parent.mkdir(parents=True)
    parent_writeup.write_text("# Accepted parent writeup\n")
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": scan.findings}))
    originals = {parent_writeup: parent_writeup.read_bytes()}
    sources = []
    for archived in (False, True):
        _, output = canceled_discovery_output(workbench_db, scan, attempt=2 if archived else 1)
        source = output.parent / "attempts" / "attempt-1" if archived else output
        sources.append(source.relative_to(scan.scan_dir).as_posix())
        finding = worker_finding(scan, "archived-worker" if archived else "current-worker")
        if worker_writeup_exists:
            writeup = source / report_path
            writeup.parent.mkdir(parents=True)
            writeup.write_text(f"# Separate worker writeup: {finding['title']}\n")
            originals[writeup] = writeup.read_bytes()
        checkpoint = write_checkpoint(
            source / "checkpoints", saved_draft(scan.scan_id, findings=[finding])
        )
        originals[checkpoint] = checkpoint.read_bytes()

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    completed = complete(workbench_api, workbench_db, scan)

    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert len(findings) == 3
    assert next(row for row in findings if row["title"] == scan.findings[0]["title"])[
        "writeup"
    ] == {"reportPath": report_path}
    assert all(
        "writeup" not in row for row in findings if row["title"] != scan.findings[0]["title"]
    )
    writeup_warnings = [warning for warning in completed["warnings"] if "writeup" in warning]
    assert len(writeup_warnings) == 2
    expected = (
        "Retained worker writeup at" if worker_writeup_exists else "Skipped malformed writeup"
    )
    assert all(expected in warning for warning in writeup_warnings)
    assert all(any(source in warning for warning in writeup_warnings) for source in sources)
    report = (scan.scan_dir / "report.md").read_text()
    assert "archived-worker" in report and "current-worker" in report
    assert {path: path.read_bytes() for path in originals} == originals


@pytest.mark.skipif(
    not hasattr(os, "fork"), reason="Crash boundary uses a forked workbench process."
)
@pytest.mark.parametrize(
    ("colliding_ids", "parent_closure", "reviewed", "worker_like_id"),
    [
        (False, False, False, False),
        (True, False, False, False),
        (False, True, False, False),
        (True, True, False, False),
        (False, True, True, False),
        (False, True, True, True),
    ],
    ids=[
        "pending",
        "legacy-collision",
        "parent-closure",
        "parent-closure-with-collision",
        "reviewed-surface",
        "reviewed-surface-with-worker-like-id",
    ],
)
def test_deadline_recovery_is_idempotent_after_crash_before_commit(
    workbench_api,
    workbench_db,
    deadline_scan,
    tmp_path,
    colliding_ids,
    parent_closure,
    reviewed,
    worker_like_id,
):
    scan = deadline_scan
    if parent_closure:
        scan.coverage["resolvedDeferred"] = [
            {"id": "prior-review", "reason": "Earlier review completed."}
        ]
        (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))
    database = tmp_path / "crash-recovery.db"
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    workbench_db.backup(connection)
    worker_id, output = canceled_discovery_output(connection, scan)
    surface_id = f"{worker_id}/entry" if worker_like_id else "entry"
    surfaces = [
        {
            "id": surface_id,
            "label": "Worker review",
            "disposition": "no_issue_found" if reviewed else "needs_follow_up",
            "receiptRefs": [],
        }
    ]
    if colliding_ids:
        surfaces.append({**surfaces[0], "label": "Separate worker review"})
    write_checkpoint(
        output / "checkpoints",
        saved_draft(
            scan.scan_id,
            surfaces=surfaces,
            findings=[]
            if reviewed
            else [worker_finding(scan, "saved-before-crash"), copy.deepcopy(scan.findings[0])],
            deferred=[]
            if reviewed
            else [{"id": "review", "reason": "Review pending.", "surfaceIds": [surface_id]}],
        ),
    )
    connection.close()
    interrupt_finish_before_commit(workbench_api, database, scan)
    before = read_review_state(workbench_db, scan.scan_dir)
    findings_before = json.loads((scan.scan_dir / "findings.json").read_text())
    assert len([row for row in before["surfaces"] if row.get("workerId") == worker_id]) == len(
        surfaces
    )
    if reviewed:
        assert before["surfaces"][0]["id"] == f"{worker_id}/{surface_id}"
    assert len([row for row in before["deferred"] if row["id"] == "scan-deadline"]) == 1
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        assert (
            connection.execute(
                "SELECT status FROM deep_scan_runs WHERE scan_id = ?", (scan.scan_id,)
            ).fetchone()[0]
            == "running"
        )
        finish(workbench_api, connection, scan, terminal_reason="capped")
        complete(workbench_api, connection, scan)

    after = read_review_state(workbench_db, scan.scan_dir)
    findings_after = json.loads((scan.scan_dir / "findings.json").read_text())
    for document in (findings_before, findings_after):
        for finding in document["findings"]:
            # Existing recovery can materialize an empty optional history list.
            if finding["provenance"].get("previousFindings") == []:
                finding["provenance"].pop("previousFindings")
    assert findings_after == findings_before
    assert after == before


@pytest.mark.skipif(
    not hasattr(os, "fork"), reason="Crash boundary uses a forked workbench process."
)
@pytest.mark.parametrize("revision", ["unchanged", "corrected", "authored-followup"])
def test_deadline_followup_survives_publication_retries(
    workbench_api, workbench_db, deadline_scan, tmp_path, revision
):
    scan = deadline_scan
    worker, output = canceled_discovery_output(workbench_db, scan)
    finding = worker_finding(scan, "incomplete-worker-review")
    finding["provenance"]["candidateId"] = "input"
    validation = finding.pop("validation")
    surface = {
        "id": "entry",
        "label": "Worker review",
        "candidateId": "input",
        "disposition": "reported",
        "receiptRefs": [],
    }
    checkpoint = write_checkpoint(
        output / "checkpoints", saved_draft(scan.scan_id, findings=[finding], surfaces=[surface])
    )
    original = checkpoint.read_bytes()
    database = tmp_path / "replay.db"
    with sqlite3.connect(database) as connection:
        workbench_db.backup(connection)

    publications = []
    for _ in range(2):
        interrupt_finish_before_commit(workbench_api, database, scan)
        publications.append(read_review_state(workbench_db, scan.scan_dir))
    assert publications[0] == publications[1]
    if revision == "corrected":
        finding["validation"] = validation
        latest = write_checkpoint(
            output / "checkpoints",
            saved_draft(scan.scan_id, findings=[finding], surfaces=[surface]),
        )
        (output / "checkpoint-head.json").write_text(json.dumps({"checkpoint": latest.name}))
    elif revision == "authored-followup":
        write_checkpoint(
            output / "checkpoints",
            saved_draft(scan.scan_id, surfaces=[{**surface, "disposition": "needs_follow_up"}]),
        )
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        finish(workbench_api, connection, scan, terminal_reason="capped")
        assert complete(workbench_api, connection, scan)["progress"]["status"] == "complete"
    coverage = read_review_state(workbench_db, scan.scan_dir)
    surfaces = [row for row in coverage["surfaces"] if row.get("workerId") == worker]
    assert surfaces[0]["id"] == f"{worker}/entry"
    if revision == "corrected":
        (task,) = [row for row in publications[0]["deferred"] if row.get("workerId") == worker]
        findings = json.loads((scan.scan_dir / "findings.json").read_bytes())["findings"]
        (completed,) = [row for row in findings if row["provenance"].get("workerId") == worker]
        assert task["id"] == f"{worker}/discarded-{completed['findingId']}"
        assert completed["validation"] == validation
        assert not any(row.get("workerId") == worker for row in coverage["deferred"])
        assert [row["disposition"] for row in surfaces] == ["reported"]
    elif revision == "authored-followup":
        assert [row["disposition"] for row in surfaces] == ["needs_follow_up", "needs_follow_up"]
        (task,) = [row for row in coverage["deferred"] if row.get("workerId") == worker]
        assert task["surfaceIds"] == [row["id"] for row in surfaces]
    else:
        assert coverage == publications[0]
        assert [row["disposition"] for row in surfaces] == ["needs_follow_up"]
    assert checkpoint.read_bytes() == original


@pytest.mark.skipif(
    not hasattr(os, "fork"), reason="Crash boundary uses a forked workbench process."
)
@pytest.mark.parametrize("earlier_checkpoint_first", [False, True])
@pytest.mark.parametrize("colliding_ids", [False, True])
def test_deadline_rejection_history_is_stable_across_repeated_crashes(
    workbench_api, workbench_db, deadline_scan, tmp_path, earlier_checkpoint_first, colliding_ids
):
    scan = deadline_scan
    worker_id, output = canceled_discovery_output(workbench_db, scan)
    finding = worker_finding(scan, "reviewed-candidate")
    finding["provenance"]["candidateId"] = "candidate"
    # Check both hash filename orders without adding invalid or unrelated checkpoints.
    for attempt in range(1000):
        finding["title"] = f"Candidate review {attempt}"
        earlier = saved_draft(scan.scan_id, findings=[finding])
        outcomes = [
            {
                "id": "entry",
                "candidateId": "candidate",
                "finding": copy.deepcopy(finding),
                "label": "Candidate reviewed",
                "disposition": "rejected",
                "receiptRefs": [],
            }
        ]
        if colliding_ids:
            outcomes.append({**copy.deepcopy(outcomes[0]), "label": "Separate observation"})
        terminal = saved_draft(scan.scan_id, complete=True, surfaces=outcomes)
        earlier_hash = hashlib.sha256(json.dumps(earlier).encode()).hexdigest()
        terminal_hash = hashlib.sha256(json.dumps(terminal).encode()).hexdigest()
        if (earlier_hash < terminal_hash) == earlier_checkpoint_first:
            break
    else:
        pytest.fail("Could not select checkpoint filename order")
    old_checkpoint = write_checkpoint(output / "checkpoints", earlier)
    checkpoint = write_checkpoint(output / "checkpoints", terminal)
    assert (old_checkpoint.name < checkpoint.name) == earlier_checkpoint_first
    os.utime(old_checkpoint, ns=(100, 100))
    os.utime(checkpoint, ns=(200, 200))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    (output / "result.json").unlink(missing_ok=True)
    originals = {path: path.read_bytes() for path in (old_checkpoint, checkpoint, head)}
    database = tmp_path / "repeated-crash.db"
    with sqlite3.connect(database) as connection:
        workbench_db.backup(connection)

    publications = []
    for _ in range(3):
        interrupt_finish_before_commit(workbench_api, database, scan)
        publications.append(read_review_state(workbench_db, scan.scan_dir))
        with sqlite3.connect(database) as connection:
            assert (
                connection.execute(
                    "SELECT status FROM deep_scan_runs WHERE scan_id = ?", (scan.scan_id,)
                ).fetchone()[0]
                == "running"
            )
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        finish(workbench_api, connection, scan, terminal_reason="capped")
        complete(workbench_api, connection, scan)
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert all(publication == coverage for publication in publications)
    surfaces = [row for row in coverage["surfaces"] if row.get("workerId") == worker_id]
    assert {row["label"] for row in surfaces} == {row["label"] for row in outcomes}
    assert len(surfaces) == len({row["id"] for row in surfaces}) == len(outcomes)
    assert all(len(row["previousFindings"]) == 1 for row in surfaces)
    assert all(row["previousFindings"][0]["title"] == finding["title"] for row in surfaces)
    assert all(row["disposition"] == "rejected" for row in surfaces)
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert len(findings) == 1 and findings[0]["title"] == scan.findings[0]["title"]
    assert {path: path.read_bytes() for path in originals} == originals
