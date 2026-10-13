from __future__ import annotations

import json
import sqlite3
from argparse import Namespace

import pytest
from test_accepted_publication_references import accept_reducer
from test_deep_scan_publication_authority import stage_publication
from test_deep_scan_successful_publication import publication_scan as publication_scan
from test_publication_stop_interleavings import published_bytes, saved_selection
from test_workbench_db import BUDGET_COST


@pytest.mark.parametrize("selected", [False, True], ids=["legacy-v1", "selected-v2"])
@pytest.mark.parametrize("reason", ["saturated", "capped"])
@pytest.mark.parametrize("cancel_first", [False, True], ids=["budget-first", "cancel-first"])
def test_budget_completion_and_cancel_keep_the_committed_outcome(
    workbench_api, workbench_db, publication_scan, tmp_path, selected, reason, cancel_first
):
    scan = publication_scan()
    _, accepted, coverage = accept_reducer(workbench_db, scan)
    selection = saved_selection(workbench_db, scan, accepted, reason=reason) if selected else None
    scan.coverage = coverage
    with workbench_db:
        recipe = json.loads(workbench_db.execute("SELECT recipe_json FROM scans").fetchone()[0])
        recipe["maxCostUsd"] = 0.005
        workbench_db.execute("UPDATE scans SET recipe_json = ?", (json.dumps(recipe),))
        workbench_db.execute("UPDATE deep_scan_runs SET terminal_reason = ?", (reason,))
    staged = stage_publication(
        scan, generation=3, result_path=accepted, title="Selected accepted aggregate"
    )
    database_path = tmp_path / "budget-publication.sqlite3"
    with sqlite3.connect(database_path) as connection:
        workbench_db.backup(connection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        workbench_api["saved_results"].write_scan_draft(
            workbench_api["_WORKBENCH_DB_CONTEXT"], connection, staged
        )
        accepted_bytes = accepted.read_bytes()
        warning = "Scan stopped after reaching its configured cost limit."
        budget_args = Namespace(
            scan_id=scan.scan_id, cost_json=json.dumps(BUDGET_COST), message=warning
        )
        cancel_args = Namespace(scan_id=scan.scan_id, thread_id=None)
        if cancel_first:
            workbench_api["saved_results"].cancel_scan(
                workbench_api["_WORKBENCH_DB_CONTEXT"], connection, cancel_args
            )
            frozen = published_bytes(scan)
            with pytest.raises(SystemExit, match="running"):
                workbench_api["complete_budget_exhausted_scan"](connection, budget_args)
        else:
            workbench_api["complete_budget_exhausted_scan"](connection, budget_args)
            frozen = published_bytes(scan)
            with pytest.raises(SystemExit, match="running"):
                workbench_api["saved_results"].cancel_scan(
                    workbench_api["_WORKBENCH_DB_CONTEXT"], connection, cancel_args
                )
        assert published_bytes(scan) == frozen

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM scans").fetchone()
        run = connection.execute("SELECT * FROM deep_scan_runs").fetchone()
        assert row["status"] == ("failed" if cancel_first else "complete")
        assert bool(row["canceled_at"]) == cancel_first
        assert run["terminal_reason"] == reason
        assert json.loads(run["finalization_input_json"] or "null") == selection
        assert accepted.read_bytes() == accepted_bytes
        coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
        assert coverage["completeness"] == "partial"
        assert any(item["id"] == "accepted-follow-up" for item in coverage["deferred"])
        if not cancel_first:
            assert any(item["id"] == "scan-cost-limit" for item in coverage["deferred"])
            assert warning in json.loads(row["completion_warnings_json"])
        findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
        assert len(findings) == 1
        with pytest.raises(SystemExit, match="stopped"):
            workbench_api["saved_results"].write_scan_draft(
                workbench_api["_WORKBENCH_DB_CONTEXT"], connection, staged
            )
        assert published_bytes(scan) == frozen


@pytest.mark.parametrize("cut", ["findings.json", "coverage.json", "scan-manifest.json", "commit"])
@pytest.mark.parametrize("tamper", [None, "saved-projection", "accepted-result"])
def test_selected_budget_publication_can_retry_an_interrupted_write(
    workbench_api, workbench_db, publication_scan, tmp_path, monkeypatch, cut, tamper
):
    scan = publication_scan()
    _, accepted, _ = accept_reducer(workbench_db, scan)
    saved_selection(workbench_db, scan, accepted)
    with workbench_db:
        recipe = json.loads(workbench_db.execute("SELECT recipe_json FROM scans").fetchone()[0])
        recipe["maxCostUsd"] = 0.005
        workbench_db.execute("UPDATE scans SET recipe_json = ?", (json.dumps(recipe),))
    staged = stage_publication(scan, generation=3, result_path=accepted, title="Accepted aggregate")
    interrupt = False

    class InterruptedConnection(sqlite3.Connection):
        def __exit__(self, kind, error, traceback):
            if interrupt and cut == "commit" and kind is None:
                self.rollback()
                raise sqlite3.OperationalError("Synthetic budget publication commit failure")
            return super().__exit__(kind, error, traceback)

    with sqlite3.connect(
        tmp_path / "interrupted-budget.sqlite3", factory=InterruptedConnection
    ) as connection:
        workbench_db.backup(connection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        saved = workbench_api["saved_results"]
        context = workbench_api["_WORKBENCH_DB_CONTEXT"]
        saved.write_scan_draft(context, connection, staged)
        row = connection.execute("SELECT * FROM scans").fetchone()
        documents = tuple(
            json.loads((scan.scan_dir / name).read_text())
            for name in ("scan-manifest.json", "findings.json", "coverage.json")
        )
        saved.record_selected_publication(context, connection, row, documents)
        accepted_bytes = accepted.read_bytes()
        write = saved.write_scan_local_bytes

        def interrupted_write(directory, name, contents):
            result = write(directory, name, contents)
            if interrupt and name == cut:
                raise OSError("Synthetic interrupted canonical budget write")
            return result

        monkeypatch.setattr(saved, "write_scan_local_bytes", interrupted_write)
        args = Namespace(
            scan_id=scan.scan_id, cost_json=json.dumps(BUDGET_COST), message="Synthetic cost limit"
        )
        interrupt = True
        with pytest.raises((SystemExit, sqlite3.OperationalError), match="Synthetic"):
            workbench_api["complete_budget_exhausted_scan"](connection, args)
        interrupt = False
        if tamper is not None:
            if tamper == "saved-projection":
                selection = json.loads(
                    connection.execute(
                        "SELECT finalization_input_json FROM deep_scan_runs"
                    ).fetchone()[0]
                )
                snapshot = scan.scan_dir / "drafts" / f"{selection['publicationSha256']}.json"
                payload = json.loads(snapshot.read_text())
                payload["coverage"]["deferred"].append(
                    {"id": "changed-projection", "reason": "Changed saved coverage"}
                )
                snapshot.write_text(json.dumps(payload))
            else:
                accepted.write_bytes(accepted_bytes + b"\n")
            if tamper == "saved-projection" and cut == "findings.json":
                # Findings are unchanged in this publication; the intact
                # canonical projection does not need the saved recovery copy.
                workbench_api["complete_budget_exhausted_scan"](connection, args)
                assert connection.execute("SELECT status FROM scans").fetchone()[0] == "complete"
                return
            interrupted_bytes = published_bytes(scan)
            with pytest.raises(SystemExit):
                workbench_api["complete_budget_exhausted_scan"](connection, args)
            assert published_bytes(scan) == interrupted_bytes
            assert connection.execute("SELECT status FROM scans").fetchone()[0] == "running"
            return
        workbench_api["complete_budget_exhausted_scan"](connection, args)
        assert connection.execute("SELECT status FROM scans").fetchone()[0] == "complete"
        assert accepted.read_bytes() == accepted_bytes
        assert any(
            item["id"] == "scan-cost-limit"
            for item in json.loads((scan.scan_dir / "coverage.json").read_text())["deferred"]
        )
