from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import traceback

import pytest
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
from workbench_test_support import saved_draft, write_checkpoint


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
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
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
        connection = sqlite3.connect(database)
        connection.row_factory = sqlite3.Row

        class CrashBeforeCommit:
            def __getattr__(self, name):
                return getattr(connection, name)

            def commit(self):
                os._exit(0)

        try:
            finish(workbench_api, CrashBeforeCommit(), scan, terminal_reason="capped")
        except BaseException:
            traceback.print_exc()
        os._exit(1)
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 0


def test_discarded_worker_finding_leaves_its_review_pending(
    workbench_api, workbench_db, deadline_scan
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
    invalid.pop("remediation")
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

    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert canonical in coverage["surfaces"]
    surface = next(row for row in coverage["surfaces"] if row.get("workerId") == worker_id)
    assert surface["disposition"] == "needs_follow_up"
    assert any(
        row.get("workerId") == worker_id and "remediation" in row["reason"]
        for row in coverage["deferred"]
    )
    assert completed["progress"]["status"] == "complete"
    assert len(json.loads((scan.scan_dir / "findings.json").read_text())["findings"]) == 1
    assert checkpoint.read_bytes() == original


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
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
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
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
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
    before = json.loads((scan.scan_dir / "coverage.json").read_text())
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

    after = json.loads((scan.scan_dir / "coverage.json").read_text())
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
        publications.append(json.loads((scan.scan_dir / "coverage.json").read_text()))
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
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
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
