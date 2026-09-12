from __future__ import annotations

import io
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
from test_publication_stop_interleavings import published_bytes, stop_scan

_CRASH_SELECTION = """
import io, json, os, runpy, sqlite3, sys
from argparse import Namespace

api = runpy.run_path(sys.argv[1], run_name="selection_commit_crash_test")
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
sys.stdin = io.StringIO(json.dumps({"resultPath": sys.argv[5]}))
deep.finish_deep_scan(connection, Namespace(**json.loads(sys.argv[3])), select_finalization=True)
raise AssertionError("selection never reached its commit boundary")
"""


@pytest.mark.parametrize("reason", ["saturated", "capped"])
@pytest.mark.parametrize("cut", ["before", "after"])
@pytest.mark.parametrize("cause", ["cancel", "cost"])
@pytest.mark.parametrize("stop_before_replay", [False, True])
def test_selection_commit_loss_replays_accepted_identity_before_stopping(
    workbench_api,
    workbench_db,
    publication_scan,
    tmp_path,
    monkeypatch,
    reason,
    cut,
    cause,
    stop_before_replay,
):
    scan = publication_scan()
    result, accepted, _ = accept_reducer(workbench_db, scan)
    omissions = []
    if reason == "saturated":
        omitted = add_worker(workbench_db, scan)
        omitted.write_text(json.dumps(save_disposition(scan, omitted.parent, "reported")))
        save_disposition(scan, omitted.parent, "rejected")
        omissions.append(omitted.parent.name)
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET merge_state = 'buffered' WHERE id = ?",
                (omitted.parent.name,),
            )
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET workflow_version = 'deep-security-scan/v2', "
            "status = 'running', phase = 'reducing', terminal_reason = NULL, completed_at = NULL, "
            "consecutive_no_new = stop_after_no_new, discovery_runs_dispatched = max_discovery_runs "
            "WHERE scan_id = ?",
            (scan.scan_id,),
        )
    args = Namespace(
        scan_id=scan.scan_id,
        coordinator_generation=3,
        terminal_reason=reason,
        manifest_path=str(scan.scan_dir / "scan-manifest.json"),
        staged_manifest_path=None,
        omitted_worker_id=omissions,
    )
    database = tmp_path / "selection.sqlite3"
    with sqlite3.connect(database) as connection:
        workbench_db.backup(connection)
    before = published_bytes(scan)
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            _CRASH_SELECTION,
            str(Path(__file__).resolve().parents[1] / "scripts" / "workbench_db.py"),
            str(database),
            json.dumps(vars(args)),
            cut,
            str(result),
        ],
        capture_output=True,
        text=True,
    )
    assert child.returncode == (72 if cut == "before" else 73), (child.stdout, child.stderr)
    assert published_bytes(scan) == before
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        run = connection.execute("SELECT * FROM deep_scan_runs").fetchone()
        selected = json.loads(run["finalization_input_json"]) if cut == "after" else None
        if cut == "before":
            assert run["finalization_input_json"] is None
            assert run["terminal_reason"] is None
        # The request names the deleted output. Selection resolves its committed
        # accepted attempt rather than reading that replaceable file again.
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"resultPath": str(result)})))
        if stop_before_replay:
            stop_scan(workbench_api, connection, scan, cause)
            stopped = published_bytes(scan)
            stopped_database = "\n".join(connection.iterdump())
            with pytest.raises(SystemExit, match="running|stopped|failed|canceled"):
                workbench_api["deep_scan"].finish_deep_scan(
                    connection, args, select_finalization=True
                )
            assert "\n".join(connection.iterdump()) == stopped_database
            assert published_bytes(scan) == stopped
            run = connection.execute("SELECT * FROM deep_scan_runs").fetchone()
            assert run["status"] == ("canceled" if cause == "cancel" else "failed")
            assert run["terminal_reason"] == (reason if cut == "after" else None)
            assert (
                json.loads(run["finalization_input_json"]) if cut == "after" else None
            ) == selected
            assert accepted.read_bytes() == before[accepted.relative_to(scan.scan_dir).as_posix()]
            return
        replayed = workbench_api["deep_scan"].finish_deep_scan(
            connection, args, select_finalization=True
        )["deepScan"]
        selection = replayed["finalizationInput"]
        if selected is not None:
            assert selection == selected
        assert selection["resultPath"] == accepted.relative_to(scan.scan_dir).as_posix()
        assert selection["resultSha256"] == accepted.stem
        assert selection["terminalReason"] == reason
        assert selection["omittedWorkerIds"] == omissions
        assert replayed["terminalReason"] == reason
        assert replayed["status"] == "running"
        assert published_bytes(scan) == before
        stale = stage_publication(scan, generation=2, result_path=accepted, title="Stale aggregate")
        with pytest.raises(SystemExit, match="generation"):
            workbench_api["write_scan_draft"](connection, stale)
        assert published_bytes(scan) == before
        stop_scan(workbench_api, connection, scan, cause)
        stopped = published_bytes(scan)
        late = stage_publication(scan, generation=3, result_path=accepted, title="Late aggregate")
        with pytest.raises(SystemExit, match="stopped"):
            workbench_api["write_scan_draft"](connection, late)
        assert published_bytes(scan) == stopped
        run = connection.execute("SELECT * FROM deep_scan_runs").fetchone()
        assert run["status"] == ("canceled" if cause == "cancel" else "failed")
        assert run["terminal_reason"] == reason
        assert json.loads(run["finalization_input_json"]) == selection
        assert accepted.read_bytes() == before[selection["resultPath"]]
        findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
        assert len(findings) == 1
        assert findings[0].get("extensions", {}).get("candidateId") != "candidate-disposition"
