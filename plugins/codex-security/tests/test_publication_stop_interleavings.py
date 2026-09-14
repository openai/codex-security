from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from argparse import Namespace
from pathlib import Path

import pytest
from test_accepted_publication_references import accept_reducer
from test_checkpoint_publication_authority import save_disposition
from test_deep_scan_publication_authority import stage_publication
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan


def saved_selection(connection, scan, accepted, omitted=None, *, reason="saturated"):
    selection = {
        "version": 1,
        "resultPath": accepted.relative_to(scan.scan_dir).as_posix(),
        "resultSha256": accepted.stem,
        "terminalReason": reason,
        "omittedWorkerIds": [omitted.parent.name] if omitted is not None else [],
        "selectedAt": scan.timestamp,
    }
    with connection:
        connection.execute(
            "UPDATE deep_scan_runs SET workflow_version = 'deep-security-scan/v2', "
            "finalization_input_json = ?, terminal_reason = ?, phase = 'terminal' "
            "WHERE scan_id = ?",
            (json.dumps(selection), reason, scan.scan_id),
        )
    return selection


def stop_scan(api, connection, scan, cause):
    if cause == "cancel":
        return api["cancel_scan"](connection, Namespace(scan_id=scan.scan_id, thread_id=None))
    return api["fail_scan"](
        connection,
        Namespace(
            scan_id=scan.scan_id,
            claim_token=None,
            cost_json=None,
            message="Scan stopped after reaching the configured cost limit.",
        ),
    )


def published_bytes(scan):
    return {
        path.relative_to(scan.scan_dir).as_posix(): path.read_bytes()
        for path in scan.scan_dir.rglob("*")
        if path.is_file() and "drafts" not in path.relative_to(scan.scan_dir).parts
    }


_CRASH_STOPPED_PUBLICATION = """
import os, runpy, sqlite3, sys
from argparse import Namespace

api = runpy.run_path(sys.argv[1], run_name="stopped_publication_crash_test")
scan_id, cause, boundary = sys.argv[3:]

class CrashConnection(sqlite3.Connection):
    def __exit__(self, *args):
        sealing = self.execute(
            "SELECT seal_manifest_digest FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()[0] is not None
        if sealing and boundary == "sqlite-before":
            os._exit(72)
        result = super().__exit__(*args)
        if sealing and boundary == "sqlite-after":
            os._exit(73)
        return result

connection = sqlite3.connect(sys.argv[2], factory=CrashConnection)
connection.row_factory = sqlite3.Row
connection.execute("PRAGMA foreign_keys = ON")
import finalize_scan_contract as contract
original_write = contract.write_scan_local_bytes
def crash_after_write(root, relative, contents, **kwargs):
    original_write(root, relative, contents, **kwargs)
    if relative == boundary:
        os._exit(71)
contract.write_scan_local_bytes = crash_after_write
if cause == "cancel":
    api["cancel_scan"](connection, Namespace(scan_id=scan_id, thread_id=None))
else:
    api["fail_scan"](connection, Namespace(
        scan_id=scan_id, claim_token=None, cost_json=None,
        message="Scan stopped after reaching the configured cost limit."
    ))
raise AssertionError("stop never reached the requested publication boundary")
"""

_CRASH_SELECTION_RECOVERY = """
import os, runpy, sqlite3, sys
from argparse import Namespace

api = runpy.run_path(sys.argv[1], run_name="selection_recovery_crash_test")
deep = api["deep_scan"]
deep.configure(deep.DeepScanDependencies(**{
    name: api["preserve_stopped_results_after_transition"
              if name == "preserve_stopped_results" else name]
    for name in deep.DeepScanDependencies.__dataclass_fields__
}))

class CrashConnection(sqlite3.Connection):
    def commit(self):
        if sys.argv[4] == "before":
            os._exit(72)
        super().commit()
        os._exit(73)

connection = sqlite3.connect(sys.argv[2], factory=CrashConnection)
connection.row_factory = sqlite3.Row
connection.execute("PRAGMA foreign_keys = ON")
deep.claim_deep_scan_coordinator(connection, Namespace(
    scan_id=sys.argv[3], thread_id="fixture-owner",
    claim_token=None, coordinator_generation=None,
))
raise AssertionError("recovery never reached the requested commit boundary")
"""


@pytest.mark.parametrize("cause", ["cancel", "cost"])
@pytest.mark.parametrize("cut", ["before-selection", "selected", "published", "sealed"])
def test_stop_and_publication_keep_the_winning_terminal_outcome(
    workbench_api, workbench_db, publication_scan, tmp_path, cause, cut
):
    scan = publication_scan()
    _, accepted, coverage = accept_reducer(workbench_db, scan)
    omitted = add_worker(workbench_db, scan)
    rejected = save_disposition(scan, omitted.parent, "reported")
    omitted.write_text(json.dumps(rejected))
    save_disposition(scan, omitted.parent, "rejected")
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET merge_state = 'buffered' WHERE id = ?",
            (omitted.parent.name,),
        )
        if cut in {"before-selection", "selected"}:
            workbench_db.execute(
                "UPDATE deep_scan_runs SET status = 'running', phase = 'reducing', "
                "terminal_reason = NULL, completed_at = NULL WHERE scan_id = ?",
                (scan.scan_id,),
            )
    selection = (
        None
        if cut == "before-selection"
        else saved_selection(workbench_db, scan, accepted, omitted)
    )
    staged = stage_publication(
        scan, generation=3, result_path=accepted, title="Selected accepted aggregate"
    )
    # The stop path must recover the accepted bytes and the rejection disposition.
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    evidence = {accepted: accepted.read_bytes(), omitted: omitted.read_bytes()}
    database_path = tmp_path / "stop-publication.sqlite3"
    with sqlite3.connect(database_path) as connection:
        workbench_db.backup(connection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        if cut in {"published", "sealed"}:
            workbench_api["write_scan_draft"](connection, staged)
        complete_args = Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
        if cut == "sealed":
            workbench_api["complete_scan"](connection, complete_args)
        before_stop = published_bytes(scan)
        if cut == "sealed":
            with pytest.raises(SystemExit, match="running|completed"):
                stop_scan(workbench_api, connection, scan, cause)
            assert published_bytes(scan) == before_stop
        else:
            stop_scan(workbench_api, connection, scan, cause)

    # Reconnect after the winning commit, then deliver the old publisher response.
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        row = dict(connection.execute("SELECT * FROM scans").fetchone())
        run = dict(connection.execute("SELECT * FROM deep_scan_runs").fetchone())
        assert row["status"] == ("complete" if cut == "sealed" else "failed")
        assert bool(row["canceled_at"]) == (cause == "cancel" and cut != "sealed")
        if cause == "cost" and cut != "sealed":
            assert row["failure_message"] == (
                "Scan stopped after reaching the configured cost limit."
            )
        assert json.loads(run["finalization_input_json"] or "null") == selection
        if selection is not None:
            assert run["terminal_reason"] == selection["terminalReason"]
        if cut != "sealed" and cause == "cancel":
            assert run["status"] == "canceled"
        if cut in {"published", "sealed"}:
            assert run["terminal_reason"] == "saturated"
        frozen = published_bytes(scan)
        with pytest.raises(SystemExit, match="stopped"):
            workbench_api["write_scan_draft"](connection, staged)
        if cut == "sealed":
            workbench_api["complete_scan"](connection, complete_args)
        else:
            with pytest.raises(SystemExit):
                workbench_api["complete_scan"](connection, complete_args)
            workbench_api["preserve_scan_results"](
                connection,
                Namespace(
                    scan_id=scan.scan_id,
                    claim_token=None,
                    thread_id=None,
                    coordinator_generation=None,
                ),
            )
        assert published_bytes(scan) == frozen
        assert dict(connection.execute("SELECT * FROM scans").fetchone()) == row
        assert dict(connection.execute("SELECT * FROM deep_scan_runs").fetchone()) == run
        assert all(path.read_bytes() == contents for path, contents in evidence.items())
        findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
        assert len(findings) == 1
        assert all(
            finding.get("extensions", {}).get("candidateId") != "candidate-disposition"
            for finding in findings
        )
        if cut != "sealed":
            published_coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
            assert coverage["deferred"][0] in published_coverage["deferred"]
            assert published_coverage["completeness"] == "partial"


@pytest.mark.parametrize("cause", ["cancel", "cost"])
@pytest.mark.parametrize(
    "boundary",
    ["findings.json", "coverage.json", "scan-manifest.json", "sqlite-before", "sqlite-after"],
)
def test_stopped_publication_process_loss_keeps_frozen_rejection_and_original_selection(
    workbench_api, workbench_db, publication_scan, tmp_path, cause, boundary
):
    scan = publication_scan()
    _, accepted, _ = accept_reducer(workbench_db, scan)
    omitted = add_worker(workbench_db, scan)
    reported = save_disposition(scan, omitted.parent, "reported")
    omitted.write_text(json.dumps(reported))
    save_disposition(scan, omitted.parent, "rejected")
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET merge_state = 'buffered' WHERE id = ?",
            (omitted.parent.name,),
        )
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = 'running', phase = 'reducing', "
            "terminal_reason = NULL, completed_at = NULL WHERE scan_id = ?",
            (scan.scan_id,),
        )
    selection = saved_selection(workbench_db, scan, accepted, omitted)
    staged = stage_publication(
        scan, generation=3, result_path=accepted, title="Obsolete selected publication"
    )
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    evidence = {accepted: accepted.read_bytes(), omitted: omitted.read_bytes()}
    database_path = tmp_path / "stopped-crash.sqlite3"
    with sqlite3.connect(database_path) as connection:
        workbench_db.backup(connection)
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            _CRASH_STOPPED_PUBLICATION,
            str(Path(__file__).resolve().parents[1] / "scripts" / "workbench_db.py"),
            str(database_path),
            scan.scan_id,
            cause,
            boundary,
        ],
        capture_output=True,
        text=True,
    )
    assert child.returncode == {"sqlite-before": 72, "sqlite-after": 73}.get(boundary, 71), (
        child.stdout,
        child.stderr,
    )
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        row = connection.execute("SELECT * FROM scans").fetchone()
        assert row["status"] == "failed"
        assert bool(row["canceled_at"]) == (cause == "cancel")
        assert bool(row["seal_manifest_digest"]) == (boundary == "sqlite-after")
        frozen_sources = row["retained_source_digests_json"]
        frozen_heads = row["retained_checkpoint_heads_json"]
        assert frozen_sources and frozen_heads
        run = dict(connection.execute("SELECT * FROM deep_scan_runs").fetchone())
        workers = [dict(row) for row in connection.execute("SELECT * FROM deep_scan_workers")]
        assert json.loads(run["finalization_input_json"]) == selection
        assert run["terminal_reason"] == selection["terminalReason"]
        assert run["status"] == ("canceled" if cause == "cancel" else "failed")
        # The replacement process sees a different live head, but replays the
        # already committed stopped selection instead of restoring the candidate.
        save_disposition(scan, omitted.parent, "reported")
        interrupted = published_bytes(scan)
        with pytest.raises(SystemExit, match="stopped"):
            workbench_api["write_scan_draft"](connection, staged)
        assert published_bytes(scan) == interrupted
        args = Namespace(
            scan_id=scan.scan_id,
            claim_token=None,
            thread_id=None,
            coordinator_generation=None,
        )
        workbench_api["preserve_scan_results"](connection, args)
        row = connection.execute("SELECT * FROM scans").fetchone()
        assert row["status"] == "failed"
        assert bool(row["canceled_at"]) == (cause == "cancel")
        assert row["retained_source_digests_json"] == frozen_sources
        assert row["retained_checkpoint_heads_json"] == frozen_heads
        assert row["seal_manifest_digest"]
        assert dict(connection.execute("SELECT * FROM deep_scan_runs").fetchone()) == run
        assert [
            dict(row) for row in connection.execute("SELECT * FROM deep_scan_workers")
        ] == workers
        findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
        assert len(findings) == 1
        assert findings[0].get("extensions", {}).get("candidateId") != "candidate-disposition"
        assert all(path.read_bytes() == contents for path, contents in evidence.items())
        sealed = published_bytes(scan)
        workbench_api["preserve_scan_results"](connection, args)
        assert published_bytes(scan) == sealed
        assert connection.execute("SELECT COUNT(*) FROM finding_occurrences").fetchone()[0] == 1


@pytest.mark.parametrize("cut", ["before", "after"])
def test_interrupted_selection_recovery_fences_observers_and_keeps_original_deadline(
    workbench_api, workbench_db, publication_scan, tmp_path, cut
):
    scan = publication_scan()
    _, accepted, _ = accept_reducer(workbench_db, scan)
    omitted = add_worker(workbench_db, scan)
    selection = saved_selection(workbench_db, scan, accepted, omitted)
    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET deep_scan_owner_thread_id = 'fixture-owner' WHERE id = ?",
            (scan.scan_id,),
        )
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = 'running', "
            "completed_at = NULL, max_time_hours = 1, "
            "created_at = '2000-01-01T00:00:00Z', updated_at = '2000-01-01T00:00:00Z' "
            "WHERE scan_id = ?",
            (scan.scan_id,),
        )
        workbench_db.execute(
            "UPDATE deep_scan_workers SET merge_state = 'buffered' WHERE id = ?",
            (omitted.parent.name,),
        )
    database_path = tmp_path / "recovery.sqlite3"
    with sqlite3.connect(database_path) as connection:
        workbench_db.backup(connection)
        original = "\n".join(connection.iterdump())
    before = published_bytes(scan)
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            _CRASH_SELECTION_RECOVERY,
            str(Path(__file__).resolve().parents[1] / "scripts" / "workbench_db.py"),
            str(database_path),
            scan.scan_id,
            cut,
        ],
        capture_output=True,
        text=True,
    )
    assert child.returncode == (72 if cut == "before" else 73), (child.stdout, child.stderr)
    deep = workbench_api["deep_scan"]
    args = Namespace(
        scan_id=scan.scan_id,
        thread_id="fixture-owner",
        claim_token=None,
        coordinator_generation=None,
    )
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        if cut == "before":
            assert "\n".join(connection.iterdump()) == original
        run = connection.execute("SELECT * FROM deep_scan_runs").fetchone()
        assert run["coordinator_generation"] == (3 if cut == "before" else 4)
        workers = [dict(row) for row in connection.execute("SELECT * FROM deep_scan_workers")]
        attempts = [dict(row) for row in connection.execute("SELECT * FROM deep_scan_attempts")]
        replayed = deep.claim_deep_scan_coordinator(connection, args)
        assert replayed["coordinatorDisposition"] == ("adopted" if cut == "before" else "observing")
        assert replayed["deepScan"]["coordinatorGeneration"] == 4
        assert replayed["deepScan"]["finalizationInput"] == selection
        assert replayed["deepScan"]["createdAt"] == "2000-01-01T00:00:00Z"
        assert replayed["deepScan"]["config"]["maxTimeHours"] == 1
        assert replayed["deepScan"]["phase"] == "terminal"
        assert replayed["deepScan"]["terminalReason"] == selection["terminalReason"]
        assert deep.deep_scan_deadline_reached(
            connection.execute("SELECT * FROM deep_scan_runs").fetchone()
        )
        stable = "\n".join(connection.iterdump())
        stale_claim = Namespace(**{**vars(args), "coordinator_generation": 3})
        with pytest.raises(SystemExit, match="generation"):
            deep.claim_deep_scan_coordinator(connection, stale_claim)
        assert "\n".join(connection.iterdump()) == stable
        stale = stage_publication(scan, generation=3, result_path=accepted, title="Old coordinator")
        with pytest.raises(SystemExit, match="generation"):
            workbench_api["write_scan_draft"](connection, stale)
        assert published_bytes(scan) == before
        assert [
            dict(row) for row in connection.execute("SELECT * FROM deep_scan_workers")
        ] == workers
        assert [
            dict(row) for row in connection.execute("SELECT * FROM deep_scan_attempts")
        ] == attempts
        current = stage_publication(
            scan, generation=4, result_path=accepted, title="Recovered selected aggregate"
        )
        workbench_api["write_scan_draft"](connection, current)
        assert accepted.read_bytes() == before[accepted.relative_to(scan.scan_dir).as_posix()]
        assert "\n".join(connection.iterdump()) == stable
