from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
from argparse import Namespace
from pathlib import Path

import pytest
from test_accepted_publication_references import accept_reducer
from test_deep_scan_publication_authority import stage_publication
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan
from test_publication_stop_interleavings import published_bytes, saved_selection
from test_workbench_db import BUDGET_COST


def accept_unmerged(connection, scan):
    result = add_worker(connection, scan)
    worker_id = result.parent.name
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": scan.findings,
                "coverage": {
                    **scan.coverage,
                    "completeness": "partial",
                    "deferred": [
                        {
                            "id": "shared-gap",
                            "reason": "Independent unresolved review.",
                            "paths": ["subdir/extract.py"],
                        }
                    ],
                },
            }
        )
    )
    digest = hashlib.sha256(result.read_bytes()).hexdigest()
    accepted = result.parent / "accepted" / f"{digest}.json"
    accepted.parent.mkdir()
    accepted.write_bytes(result.read_bytes())
    with connection:
        connection.execute(
            "UPDATE deep_scan_workers SET merge_state = 'buffered' WHERE id = ?", (worker_id,)
        )
        connection.execute(
            "INSERT INTO deep_scan_attempts (scan_id, worker_id, attempt, status, started_at, "
            "completed_at, accepted_result_path, accepted_result_sha256) VALUES (?, ?, 1, 'succeeded', ?, ?, ?, ?)",
            (scan.scan_id, worker_id, scan.timestamp, scan.timestamp, str(accepted), digest),
        )
    return accepted


@pytest.mark.parametrize("defect", ["changed-bytes", "incomplete-result"])
def test_cost_before_selection_does_not_replace_invalid_accepted_evidence(
    workbench_api, workbench_db, publication_scan, defect
):
    scan = publication_scan()
    _, accepted, _ = accept_reducer(workbench_db, scan)
    document = json.loads(accepted.read_bytes())
    document["complete"] = False
    accepted.write_text(json.dumps(document))
    with workbench_db:
        recipe = json.loads(workbench_db.execute("SELECT recipe_json FROM scans").fetchone()[0])
        recipe["maxCostUsd"] = 0.005
        workbench_db.execute("UPDATE scans SET recipe_json = ?", (json.dumps(recipe),))
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = 'running', phase = 'discovery', "
            "workflow_version = 'deep-security-scan/v2', finalization_input_json = NULL"
        )
        if defect == "incomplete-result":
            workbench_db.execute(
                "UPDATE deep_scan_attempts SET accepted_result_sha256 = ?",
                (hashlib.sha256(accepted.read_bytes()).hexdigest(),),
            )
    before = published_bytes(scan)
    with pytest.raises(SystemExit):
        workbench_api["complete_budget_exhausted_scan"](
            workbench_db,
            Namespace(scan_id=scan.scan_id, cost_json=json.dumps(BUDGET_COST), message=None),
        )
    assert published_bytes(scan) == before
    assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "running"
    assert (
        workbench_db.execute("SELECT finalization_input_json FROM deep_scan_runs").fetchone()[0]
        is None
    )


@pytest.mark.parametrize("accepted_kind", ["none", "unmerged", "reducer"])
@pytest.mark.parametrize("cancel_first", [False, True])
@pytest.mark.parametrize("lower_bound", [False, True])
def test_cost_before_selection_retains_only_merged_findings(
    workbench_api, workbench_db, publication_scan, accepted_kind, cancel_first, lower_bound
):
    scan = publication_scan()
    accepted = None
    if accepted_kind == "reducer":
        _, accepted, _ = accept_reducer(workbench_db, scan)
    elif accepted_kind == "unmerged":
        accepted = accept_unmerged(workbench_db, scan)
    active = add_worker(workbench_db, scan, status="running")
    active_id = active.parent.name
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET completed_at = NULL WHERE id = ?", (active_id,)
        )
        workbench_db.execute(
            "INSERT INTO deep_scan_attempts (scan_id, worker_id, attempt, status, started_at) "
            "VALUES (?, ?, 1, 'running', ?)",
            (scan.scan_id, active_id, scan.timestamp),
        )
    counters = tuple(
        workbench_db.execute(
            "SELECT discovery_runs_dispatched, consecutive_no_new, completion_sequence FROM deep_scan_runs"
        ).fetchone()
    )
    original = accepted.read_bytes() if accepted is not None else None
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        (scan.scan_dir / name).unlink()
    with workbench_db:
        recipe = json.loads(workbench_db.execute("SELECT recipe_json FROM scans").fetchone()[0])
        recipe["maxCostUsd"] = 0.005
        workbench_db.execute("UPDATE scans SET recipe_json = ?", (json.dumps(recipe),))
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = 'running', phase = 'discovery', "
            "workflow_version = 'deep-security-scan/v2', manifest_path = NULL, "
            "terminal_reason = NULL, completed_at = NULL, max_discovery_runs = 100"
        )
    args = Namespace(
        scan_id=scan.scan_id,
        cost_json=json.dumps({"lowerBound": BUDGET_COST} if lower_bound else BUDGET_COST),
        message="Scan reached its original cost limit.",
    )
    if cancel_first:
        workbench_api["cancel_scan"](workbench_db, Namespace(scan_id=scan.scan_id, thread_id=None))
        before = published_bytes(scan)
        with pytest.raises(SystemExit, match="running"):
            workbench_api["complete_budget_exhausted_scan"](workbench_db, args)
        assert published_bytes(scan) == before
    else:
        workbench_api["complete_budget_exhausted_scan"](workbench_db, args)
        row = workbench_db.execute("SELECT * FROM scans").fetchone()
        run = workbench_db.execute("SELECT * FROM deep_scan_runs").fetchone()
        assert row["status"] == "complete"
        stored = json.loads(row["cost_json"])
        if lower_bound:
            assert "cost" not in stored and "estimatedUsd" not in stored
            assert stored["usage"]["coverage"] == "unavailable"
        else:
            assert stored == BUDGET_COST
        assert run["terminal_reason"] == "capped"
        assert run["error_message"] == args.message
        assert args.message in json.loads(row["completion_warnings_json"])
        findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
        assert len(findings) == (1 if accepted_kind == "reducer" else 0)
        coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
        assert coverage["completeness"] == "partial"
        assert any(item["id"] == "scan-cost-limit" for item in coverage["deferred"])
        if accepted_kind == "reducer":
            selection = json.loads(run["finalization_input_json"])
            assert selection["resultSha256"] == hashlib.sha256(original).hexdigest()
            assert any(item["id"] == "accepted-follow-up" for item in coverage["deferred"])
        assert (
            tuple(
                workbench_db.execute(
                    "SELECT discovery_runs_dispatched, consecutive_no_new, completion_sequence FROM deep_scan_runs"
                ).fetchone()
            )
            == counters
        )
        interrupted = workbench_db.execute(
            "SELECT * FROM deep_scan_attempts WHERE worker_id = ?", (active_id,)
        ).fetchone()
        assert interrupted["status"] == "canceled"
        assert interrupted["end_reason"] == "scan_stopped"
        if accepted_kind == "unmerged":
            assert any(
                item.get("provenance", {}).get("sourceId") == "shared-gap"
                for item in coverage["deferred"]
            )
        before = published_bytes(scan)
        workbench_api["complete_scan"](
            workbench_db, Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
        )
        assert published_bytes(scan) == before
    if accepted is not None:
        assert accepted.read_bytes() == original


@pytest.mark.parametrize(
    "bound", [None, {**BUDGET_COST, "estimatedUsd": -1}, {**BUDGET_COST, "estimatedUsd": 0.005}]
)
def test_lower_bound_budget_rejects_invalid_or_unexceeded_cost(
    workbench_api, workbench_db, publication_scan, bound
):
    scan = publication_scan()
    with workbench_db:
        recipe = json.loads(workbench_db.execute("SELECT recipe_json FROM scans").fetchone()[0])
        recipe["maxCostUsd"] = 0.005
        workbench_db.execute("UPDATE scans SET recipe_json = ?", (json.dumps(recipe),))
    before = published_bytes(scan)
    with pytest.raises(SystemExit):
        workbench_api["complete_budget_exhausted_scan"](
            workbench_db,
            Namespace(
                scan_id=scan.scan_id, cost_json=json.dumps({"lowerBound": bound}), message=None
            ),
        )
    assert published_bytes(scan) == before
    assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "running"


def test_lower_bound_is_not_an_ordinary_completion_cost(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    before = published_bytes(scan)
    with pytest.raises(SystemExit):
        workbench_api["complete_scan"](
            workbench_db,
            Namespace(
                scan_id=scan.scan_id,
                claim_token=None,
                cost_json=json.dumps({"lowerBound": BUDGET_COST}),
            ),
        )
    assert published_bytes(scan) == before
    assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "running"


@pytest.mark.parametrize("reason", ["saturated", "capped"])
def test_budget_keeps_selection_committed_before_transaction_and_unmerged_obligations(
    workbench_api, workbench_db, publication_scan, reason
):
    scan = publication_scan()
    _, accepted, original_coverage = accept_reducer(workbench_db, scan)
    unmerged = [accept_unmerged(workbench_db, scan) for _ in range(2)]
    originals = {path: path.read_bytes() for path in [accepted, *unmerged]}
    with workbench_db:
        recipe = json.loads(workbench_db.execute("SELECT recipe_json FROM scans").fetchone()[0])
        recipe["maxCostUsd"] = 0.005
        workbench_db.execute("UPDATE scans SET recipe_json = ?", (json.dumps(recipe),))
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = 'running', workflow_version = 'deep-security-scan/v2'"
        )
    # The selected publication may commit before cost recovery reaches its
    # transaction. Budget completion must use that exact input and cause.
    committed = saved_selection(workbench_db, scan, accepted, reason=reason)
    workbench_api["complete_budget_exhausted_scan"](
        workbench_db,
        Namespace(
            scan_id=scan.scan_id, cost_json=json.dumps(BUDGET_COST), message="Original cost stop."
        ),
    )
    run = workbench_db.execute("SELECT * FROM deep_scan_runs").fetchone()
    assert json.loads(run["finalization_input_json"]) == committed
    assert run["terminal_reason"] == reason
    assert all(path.read_bytes() == contents for path, contents in originals.items())
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert len(findings) == 1
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert original_coverage["deferred"][0] in coverage["deferred"]
    gaps = [
        item
        for item in coverage["deferred"]
        if item.get("provenance", {}).get("sourceId") == "shared-gap"
    ]
    assert len(gaps) == 2
    assert len({item["id"] for item in gaps}) == 2
    assert {item["provenance"]["workerId"] for item in gaps} == {
        path.parent.parent.name for path in unmerged
    }
    assert all(item["provenance"]["attempt"] == 1 for item in gaps)


def test_budget_accepts_complete_reducer_without_optional_complete_flag(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    _, accepted, _ = accept_reducer(workbench_db, scan)
    document = json.loads(accepted.read_bytes())
    del document["complete"]
    accepted.write_text(json.dumps(document))
    digest = hashlib.sha256(accepted.read_bytes()).hexdigest()
    with workbench_db:
        recipe = json.loads(workbench_db.execute("SELECT recipe_json FROM scans").fetchone()[0])
        recipe["maxCostUsd"] = 0.005
        workbench_db.execute("UPDATE scans SET recipe_json = ?", (json.dumps(recipe),))
        workbench_db.execute("UPDATE deep_scan_attempts SET accepted_result_sha256 = ?", (digest,))
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = 'running', workflow_version = 'deep-security-scan/v2'"
        )
    workbench_api["complete_budget_exhausted_scan"](
        workbench_db,
        Namespace(
            scan_id=scan.scan_id, cost_json=json.dumps(BUDGET_COST), message="Original cost stop."
        ),
    )
    assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "complete"
    assert hashlib.sha256(accepted.read_bytes()).hexdigest() == digest
    assert len(json.loads((scan.scan_dir / "findings.json").read_text())["findings"]) == 1


def test_budget_preserves_accepted_scope_and_unmerged_scope_limits(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    _, accepted, _ = accept_reducer(workbench_db, scan)
    unmerged = accept_unmerged(workbench_db, scan)
    scope = {
        "summary": "Synthetic upload boundaries.",
        "artifactsReviewed": ["subdir/extract.py"],
        "runtimeStatus": "Synthetic runtime unavailable.",
        "validationMode": "Static validation of the accepted findings.",
        "context": "External deployment behavior remains unresolved.",
        "limitations": ["The accepted review did not execute the deployment integration."],
    }
    unmerged_limit = "A separate unmerged review could not inspect the deployment credentials."
    for path, value in [(accepted, scope), (unmerged, {"limitations": [unmerged_limit]})]:
        document = json.loads(path.read_bytes())
        document["scope"] = value
        path.write_text(json.dumps(document))
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_attempts SET accepted_result_sha256 = ? WHERE accepted_result_path = ?",
                (hashlib.sha256(path.read_bytes()).hexdigest(), str(path)),
            )
    originals = {p: p.read_bytes() for p in [accepted, unmerged]}
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        (scan.scan_dir / name).unlink()
    with workbench_db:
        recipe = json.loads(workbench_db.execute("SELECT recipe_json FROM scans").fetchone()[0])
        recipe["maxCostUsd"] = 0.005
        workbench_db.execute("UPDATE scans SET recipe_json = ?", (json.dumps(recipe),))
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = 'running', workflow_version = 'deep-security-scan/v2'"
        )
    warning = "Scan stopped at its original cost limit before further validation."
    workbench_api["complete_budget_exhausted_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, cost_json=json.dumps(BUDGET_COST), message=warning),
    )
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())
    saved_scope = manifest["scan"]["scope"]
    for key, value in scope.items():
        if key == "limitations":
            assert all(item in saved_scope[key] for item in value)
        else:
            assert saved_scope[key] == value
    assert warning in saved_scope["limitations"]
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    assert any(
        item["reason"] == unmerged_limit
        and item["provenance"]["workerId"] == unmerged.parent.parent.name
        for item in coverage["deferred"]
    )
    assert all(p.read_bytes() == contents for p, contents in originals.items())
    assert len(json.loads((scan.scan_dir / "findings.json").read_text())["findings"]) == 1


@pytest.mark.parametrize("has_reducer", [False, True])
def test_budget_replay_after_draft_commit_keeps_unmerged_coverage_once(
    workbench_api, workbench_db, publication_scan, tmp_path, monkeypatch, has_reducer
):
    scan = publication_scan()
    if has_reducer:
        accept_reducer(workbench_db, scan)
    unmerged = accept_unmerged(workbench_db, scan)
    original = unmerged.read_bytes()
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        (scan.scan_dir / name).unlink()
    with workbench_db:
        recipe = json.loads(workbench_db.execute("SELECT recipe_json FROM scans").fetchone()[0])
        recipe["maxCostUsd"] = 0.005
        workbench_db.execute("UPDATE scans SET recipe_json = ?", (json.dumps(recipe),))
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = 'running', workflow_version = 'deep-security-scan/v2'"
        )
    budget = workbench_api["complete_budget_exhausted_scan"]
    original_complete = budget.__globals__["complete_scan_locked"]

    def fail_before_seal(*args, **kwargs):
        raise RuntimeError("Synthetic process loss after budget draft commit.")

    monkeypatch.setitem(budget.__globals__, "complete_scan_locked", fail_before_seal)
    args = Namespace(
        scan_id=scan.scan_id,
        cost_json=json.dumps(BUDGET_COST),
        message="Original cost interruption.",
    )
    path = tmp_path / "budget-gap.sqlite3"
    with sqlite3.connect(path) as connection:
        workbench_db.backup(connection)
        connection.row_factory = sqlite3.Row
        with pytest.raises(RuntimeError, match="after budget draft commit"):
            budget(connection, args)
        run = connection.execute("SELECT * FROM deep_scan_runs").fetchone()
        assert run["status"] == "succeeded"
        selection = run["finalization_input_json"]
        assert connection.execute("SELECT status FROM scans").fetchone()[0] == "running"
    before = json.loads((scan.scan_dir / "coverage.json").read_text())
    monkeypatch.setitem(budget.__globals__, "complete_scan_locked", original_complete)
    with sqlite3.connect(path) as connection:
        connection.row_factory = sqlite3.Row
        budget(connection, args)
        assert connection.execute("SELECT status FROM scans").fetchone()[0] == "complete"
        assert (
            connection.execute("SELECT finalization_input_json FROM deep_scan_runs").fetchone()[0]
            == selection
        )
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    for key in ("surfaces", "explicitExclusions", "deferred", "reviews"):
        assert coverage.get(key, []) == before.get(key, [])
    assert len({row["id"] for row in coverage["deferred"]}) == len(coverage["deferred"])
    assert unmerged.read_bytes() == original


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
        workbench_api["write_scan_draft"](connection, staged)
        accepted_bytes = accepted.read_bytes()
        warning = "Scan stopped after reaching its configured cost limit."
        budget_args = Namespace(
            scan_id=scan.scan_id, cost_json=json.dumps(BUDGET_COST), message=warning
        )
        cancel_args = Namespace(scan_id=scan.scan_id, thread_id=None)
        if cancel_first:
            workbench_api["cancel_scan"](connection, cancel_args)
            frozen = published_bytes(scan)
            with pytest.raises(SystemExit, match="running"):
                workbench_api["complete_budget_exhausted_scan"](connection, budget_args)
        else:
            workbench_api["complete_budget_exhausted_scan"](connection, budget_args)
            frozen = published_bytes(scan)
            with pytest.raises(SystemExit, match="running"):
                workbench_api["cancel_scan"](connection, cancel_args)
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
            workbench_api["write_scan_draft"](connection, staged)
        assert published_bytes(scan) == frozen


@pytest.mark.parametrize(
    "cut", ["after-findings", "after-coverage", "after-draft-commit", "after-seal"]
)
@pytest.mark.parametrize("has_reducer", [False, True])
def test_budget_process_death_replays_exact_evidence(
    workbench_api, workbench_db, publication_scan, tmp_path, cut, has_reducer
):
    scan = publication_scan()
    thread_id = "a23e657b-c14c-4da7-bd20-baa9e7579390"
    workbench_api["set_scan_thread"](
        workbench_db, Namespace(scan_id=scan.scan_id, thread_id=thread_id)
    )
    accepted = None
    if has_reducer:
        _, accepted, _ = accept_reducer(workbench_db, scan)
    unmerged = accept_unmerged(workbench_db, scan)
    originals = {str(p): p.read_bytes() for p in [unmerged, *([accepted] if accepted else [])]}
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        (scan.scan_dir / name).unlink()
    with workbench_db:
        recipe = json.loads(workbench_db.execute("SELECT recipe_json FROM scans").fetchone()[0])
        recipe["maxCostUsd"] = 0.005
        workbench_db.execute("UPDATE scans SET recipe_json = ?", (json.dumps(recipe),))
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status='running', workflow_version='deep-security-scan/v2'"
        )
    database = tmp_path / "budget-process-cut.sqlite3"
    with sqlite3.connect(database) as db:
        workbench_db.backup(db)
    budget = workbench_api["complete_budget_exhausted_scan"]
    args = Namespace(
        scan_id=scan.scan_id,
        cost_json=json.dumps(BUDGET_COST),
        message="Original synthetic cost stop.",
    )
    marker = tmp_path / "crash-marker.json"
    child_source = """
from argparse import Namespace
from pathlib import Path
import json
import os
import runpy
import sqlite3
import sys

script, database, scan_id, cost_json, warning, cut, marker = sys.argv[1:]
api = runpy.run_path(str(script), run_name='fault_review_budget_child')
budget = api['complete_budget_exhausted_scan']
deep = budget.__globals__['deep_scan']
deep.configure(deep.DeepScanDependencies(**{
    name: api['preserve_stopped_results_after_transition' if name == 'preserve_stopped_results' else name]
    for name in deep.DeepScanDependencies.__dataclass_fields__
}))


def terminate(stage):
    Path(marker).write_text(json.dumps({'stage': stage, 'pid': os.getpid()}))
    os._exit(86)


if cut == 'after-draft-commit':
    budget.__globals__['complete_scan_locked'] = lambda *a, **kw: terminate(cut)
elif cut == 'after-seal':
    original = budget.__globals__['_write_prepared_scan_finalization']

    def seal_then_die(prepared):
        original(prepared)
        terminate(cut)

    budget.__globals__['_write_prepared_scan_finalization'] = seal_then_die
else:
    saved = budget.__globals__['saved_results']
    original = saved.write_scan_local_bytes

    def write_then_die(scan_dir, name, contents):
        result = original(scan_dir, name, contents)
        if name == ('findings.json' if cut == 'after-findings' else 'coverage.json'):
            terminate(cut)
        return result

    saved.write_scan_local_bytes = write_then_die

with sqlite3.connect(database) as connection:
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA foreign_keys=ON')
    budget(connection, Namespace(scan_id=scan_id, cost_json=cost_json, message=warning))
os._exit(87)
"""
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            child_source,
            workbench_api["__file__"],
            str(database),
            scan.scan_id,
            args.cost_json,
            args.message,
            cut,
            str(marker),
        ],
        capture_output=True,
        text=True,
    )
    assert child.returncode == 86, (child.returncode, child.stdout, child.stderr)
    assert json.loads(marker.read_text())["stage"] == cut
    before = {
        name: (scan.scan_dir / name).exists()
        for name in ("findings.json", "coverage.json", "scan-manifest.json")
    }
    sealed_bytes = published_bytes(scan) if cut == "after-seal" else None
    if sealed_bytes is not None:
        assert json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]["sealedAt"]
    with sqlite3.connect(database) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        run = dict(db.execute("SELECT * FROM deep_scan_runs").fetchone())
        snapshot = {
            "cut": cut,
            "hasReducer": has_reducer,
            "database": str(database),
            "scanDir": str(scan.scan_dir),
            "beforeFiles": before,
            "beforeStatus": run["status"],
            "beforeSelection": run["finalization_input_json"],
        }
        saved_scan = workbench_api["require_scan"](db, scan.scan_id)
        resumed = workbench_api["scan_history"].cli_scan_resume(
            db,
            saved_scan,
            workbench_api["require_workspace"](db, saved_scan["workspace_id"]),
            **{
                name: workbench_api[source]
                for name, source in {
                    "parse_scan_recipe": "parse_scan_recipe",
                    "scan_contract": "scan_contract",
                    "require_scan_directory": "require_canonical_scan_directory",
                    "artifact_path": "artifact_path",
                    "read_json_object": "read_json_object",
                    "workbench_completion_binding": "workbench_completion_binding",
                }.items()
            },
        )
        assert resumed["scanId"] == scan.scan_id
        assert resumed["threadId"] == thread_id
        try:
            budget(db, args)
        except BaseException as error:
            snapshot["replayError"] = str(error)
            (tmp_path / "crash-result.json").write_text(json.dumps(snapshot, indent=2))
            raise
        snapshot["afterStatus"] = db.execute("SELECT status FROM scans").fetchone()[0]
        snapshot["afterSelection"] = db.execute(
            "SELECT finalization_input_json FROM deep_scan_runs"
        ).fetchone()[0]
        (tmp_path / "crash-result.json").write_text(json.dumps(snapshot, indent=2))
        assert snapshot["afterStatus"] == "complete"
        if sealed_bytes is not None:
            assert published_bytes(scan) == sealed_bytes
        if run["finalization_input_json"] is not None:
            assert snapshot["afterSelection"] == run["finalization_input_json"]
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert len(findings) == int(has_reducer)
    assert coverage["completeness"] == "partial"
    assert len({x["id"] for x in coverage["deferred"]}) == len(coverage["deferred"])
    assert all(Path(path).read_bytes() == data for path, data in originals.items())


@pytest.mark.parametrize("files", ["findings", "coverage", "manifest", "findings-and-coverage"])
def test_budget_rejects_unrelated_incomplete_drafts(
    workbench_api, workbench_db, publication_scan, files
):
    scan = publication_scan()
    accept_unmerged(workbench_db, scan)
    keep = {
        "findings": {"findings.json"},
        "coverage": {"coverage.json"},
        "manifest": {"scan-manifest.json"},
        "findings-and-coverage": {"findings.json", "coverage.json"},
    }[files]
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        if name not in keep:
            (scan.scan_dir / name).unlink()
    before = {name: (scan.scan_dir / name).read_bytes() for name in keep}
    with workbench_db:
        recipe = json.loads(workbench_db.execute("SELECT recipe_json FROM scans").fetchone()[0])
        recipe["maxCostUsd"] = 0.005
        workbench_db.execute("UPDATE scans SET recipe_json = ?", (json.dumps(recipe),))
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = 'running', workflow_version = 'deep-security-scan/v2'"
        )
    with pytest.raises(SystemExit, match="incomplete canonical scan draft"):
        workbench_api["complete_budget_exhausted_scan"](
            workbench_db,
            Namespace(
                scan_id=scan.scan_id,
                cost_json=json.dumps(BUDGET_COST),
                message="Original cost stop.",
            ),
        )
    assert {name: (scan.scan_dir / name).read_bytes() for name in keep} == before
    assert all(
        not (scan.scan_dir / name).exists()
        for name in ("scan-manifest.json", "findings.json", "coverage.json")
        if name not in keep
    )
    assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "running"


@pytest.mark.parametrize(
    "state",
    ["changed-findings", "wrong-scan", "running-discovery", "canceled", "other-owner", "complete"],
)
def test_budget_sealed_replay_keeps_integrity_and_ownership_guards(
    workbench_api, workbench_db, publication_scan, monkeypatch, state
):
    scan = publication_scan()
    accept_reducer(workbench_db, scan)
    with workbench_db:
        recipe = json.loads(workbench_db.execute("SELECT recipe_json FROM scans").fetchone()[0])
        recipe["maxCostUsd"] = 0.005
        workbench_db.execute("UPDATE scans SET recipe_json = ?", (json.dumps(recipe),))
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = 'running', workflow_version = 'deep-security-scan/v2'"
        )
    budget = workbench_api["complete_budget_exhausted_scan"]
    complete = budget.__globals__["complete_scan_locked"]
    args = Namespace(
        scan_id=scan.scan_id, cost_json=json.dumps(BUDGET_COST), message="Original cost stop."
    )
    with monkeypatch.context() as patch:
        patch.setitem(
            budget.__globals__,
            "complete_scan_locked",
            lambda *a: complete(*a, prepare_only=True),
        )
        budget(workbench_db, args)
    manifest = scan.scan_dir / "scan-manifest.json"
    assert json.loads(manifest.read_text())["scan"]["sealedAt"]
    if state in {"changed-findings", "wrong-scan"}:
        path = scan.scan_dir / (
            "findings.json" if state == "changed-findings" else "scan-manifest.json"
        )
        document = json.loads(path.read_text())
        if state == "changed-findings":
            document["findings"] = []
        else:
            document["scan"]["id"] = "69078890-d24c-4416-a6fa-c286825bef88"
        path.write_text(json.dumps(document))
    elif state == "running-discovery":
        with workbench_db:
            workbench_db.execute("UPDATE deep_scan_runs SET status = 'running'")
    elif state == "canceled":
        workbench_api["cancel_scan"](workbench_db, Namespace(scan_id=scan.scan_id, thread_id=None))
    elif state == "other-owner":
        with workbench_db:
            workbench_db.execute(
                "UPDATE scans SET handoff_claim_token = 'a3292ae4-9b47-430f-8ed6-73ff73db575c'"
            )
    else:
        complete(workbench_db, scan.scan_id, None, args.cost_json)
    before_files = published_bytes(scan)
    before_scan = dict(workbench_db.execute("SELECT * FROM scans").fetchone())
    before_run = dict(workbench_db.execute("SELECT * FROM deep_scan_runs").fetchone())
    with pytest.raises(SystemExit):
        budget(workbench_db, args)
    assert published_bytes(scan) == before_files
    assert dict(workbench_db.execute("SELECT * FROM scans").fetchone()) == before_scan
    assert dict(workbench_db.execute("SELECT * FROM deep_scan_runs").fetchone()) == before_run


@pytest.mark.parametrize(
    "state", ["parent-canceled", "stopping", "failed", "canceled", "unselected"]
)
def test_budget_resume_keeps_explicit_stop_and_unselected_guards(
    workbench_api, workbench_db, publication_scan, state
):
    scan = publication_scan()
    workbench_api["set_scan_thread"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, thread_id="a23e657b-c14c-4da7-bd20-baa9e7579390"),
    )
    with workbench_db:
        if state == "parent-canceled":
            workbench_db.execute("UPDATE scans SET canceled_at = ?", (scan.timestamp,))
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = ?, cancel_requested = 1, finalization_input_json = NULL",
            (
                "running"
                if state == "stopping"
                else state
                if state in {"failed", "canceled"}
                else "succeeded",
            ),
        )
    saved_scan = workbench_api["require_scan"](workbench_db, scan.scan_id)
    with pytest.raises(SystemExit, match="cannot resume"):
        workbench_api["scan_history"].cli_scan_resume(
            workbench_db,
            saved_scan,
            workbench_api["require_workspace"](workbench_db, saved_scan["workspace_id"]),
            **{
                name: workbench_api[source]
                for name, source in {
                    "parse_scan_recipe": "parse_scan_recipe",
                    "scan_contract": "scan_contract",
                    "require_scan_directory": "require_canonical_scan_directory",
                    "artifact_path": "artifact_path",
                    "read_json_object": "read_json_object",
                    "workbench_completion_binding": "workbench_completion_binding",
                }.items()
            },
        )
