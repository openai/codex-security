from __future__ import annotations

import json
import os
import sqlite3
from argparse import Namespace
from pathlib import Path

import pytest
from test_accepted_publication_references import accept_reducer
from test_deep_scan_publication_authority import stage_publication
from test_deep_scan_successful_publication import publication_scan as publication_scan
from test_publication_stop_interleavings import published_bytes, saved_selection
from test_workbench_db import BUDGET_COST


def publish_selected(api, connection, scan):
    _, accepted, coverage = accept_reducer(connection, scan)
    scan.coverage = coverage
    selection = saved_selection(connection, scan, accepted)
    staged = stage_publication(
        scan, generation=3, result_path=accepted, title=scan.findings[0]["title"]
    )
    api["saved_results"].write_scan_draft(api["_WORKBENCH_DB_CONTEXT"], connection, staged)
    recorded = json.loads(
        connection.execute("SELECT finalization_input_json FROM deep_scan_runs").fetchone()[0]
    )
    assert {key: recorded[key] for key in selection} == selection
    assert len(recorded["publicationSha256"]) == 64
    return accepted, recorded


def test_publication_uses_the_staged_draft_checked_for_selection(
    workbench_api, workbench_db, publication_scan, monkeypatch
):
    scan = publication_scan()
    _, accepted, coverage = accept_reducer(workbench_db, scan)
    scan.coverage = coverage
    saved_selection(workbench_db, scan, accepted)
    staged = stage_publication(
        scan, generation=3, result_path=accepted, title=scan.findings[0]["title"]
    )
    saved = workbench_api["saved_results"]
    require_publication = saved._require_current_deep_publication

    def replace_after_selection_check(*args):
        require_publication(*args)
        staged_path = Path(staged.draft_path)
        replacement = json.loads(staged_path.read_bytes())
        replacement["findings"]["findings"][0]["title"] = "Substituted staged finding"
        replacement_path = staged_path.with_suffix(".replacement")
        replacement_path.write_text(json.dumps(replacement))
        replacement_path.replace(staged_path)

    monkeypatch.setattr(saved, "_require_current_deep_publication", replace_after_selection_check)
    saved.write_scan_draft(workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, staged)
    workbench_api["complete_scan"](
        workbench_db, Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
    )
    published = json.loads((scan.scan_dir / "findings.json").read_bytes())
    assert published["findings"][0]["title"] == scan.findings[0]["title"]


def substitute(scan, accepted, defect):
    if defect == "accepted-result":
        path = accepted
        document = json.loads(path.read_bytes())
        document["findings"][0]["title"] = "Substituted accepted finding"
    else:
        path = scan.scan_dir / ("findings.json" if defect == "findings" else "coverage.json")
        document = json.loads(path.read_bytes())
        if defect == "findings":
            document["findings"][0]["title"] = "Substituted valid canonical finding"
        else:
            document["deferred"][0]["reason"] = "Substituted valid unresolved review"
    path.write_text(json.dumps(document))


@pytest.mark.parametrize("defect", [None, "findings", "coverage", "accepted-result"])
@pytest.mark.parametrize("persisted", [False, True], ids=["writer", "persisted-reader"])
def test_sdk_completion_keeps_selected_publication_binding(
    workbench_api, workbench_db, publication_scan, defect, persisted, request
):
    scan = publication_scan()
    accepted, recorded = publish_selected(workbench_api, workbench_db, scan)
    if persisted:
        # A resumed reader opens another connection to the persisted selected binding.
        recovered = sqlite3.connect(":memory:")
        recovered.row_factory = sqlite3.Row
        recovered.execute("PRAGMA foreign_keys = ON")
        workbench_db.backup(recovered)
        request.addfinalizer(recovered.close)
        workbench_db = recovered
    if defect is not None:
        substitute(scan, accepted, defect)
    before = published_bytes(scan)
    args = Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)

    def complete():
        workbench_api["complete_scan"](workbench_db, args, prepare_only=True)
        return workbench_api["complete_scan"](workbench_db, args)

    if defect is not None:
        with pytest.raises(SystemExit, match="selected.*publication|changed|accepted"):
            complete()
        assert published_bytes(scan) == before
        assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "running"
    else:
        complete()
        assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "complete"
        assert (
            json.loads((scan.scan_dir / "findings.json").read_text())["findings"][0]["title"]
            == scan.findings[0]["title"]
        )
        # Completion time and seal fields do not invalidate the selected projection.
        frozen = published_bytes(scan)
        complete()
        assert published_bytes(scan) == frozen
    assert (
        json.loads(
            workbench_db.execute("SELECT finalization_input_json FROM deep_scan_runs").fetchone()[0]
        )
        == recorded
    )


@pytest.mark.parametrize("defect", [None, "findings", "accepted-result"])
@pytest.mark.parametrize("lower_bound", [False, True])
def test_budget_completion_validates_then_binds_intentional_projection(
    workbench_api, workbench_db, publication_scan, defect, lower_bound
):
    scan = publication_scan()
    accepted, recorded = publish_selected(workbench_api, workbench_db, scan)
    with workbench_db:
        recipe = json.loads(workbench_db.execute("SELECT recipe_json FROM scans").fetchone()[0])
        recipe["maxCostUsd"] = 0.005
        workbench_db.execute("UPDATE scans SET recipe_json = ?", (json.dumps(recipe),))
    if defect is not None:
        substitute(scan, accepted, defect)
    before = published_bytes(scan)
    args = Namespace(
        scan_id=scan.scan_id,
        cost_json=json.dumps({"lowerBound": BUDGET_COST} if lower_bound else BUDGET_COST),
        message="Synthetic scan reached its configured cost limit.",
    )
    if defect is not None:
        with pytest.raises(SystemExit, match="selected.*publication|changed|accepted"):
            workbench_api["complete_budget_exhausted_scan"](workbench_db, args)
        assert published_bytes(scan) == before
        assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "running"
        assert (
            json.loads(
                workbench_db.execute(
                    "SELECT finalization_input_json FROM deep_scan_runs"
                ).fetchone()[0]
            )
            == recorded
        )
    else:
        workbench_api["complete_budget_exhausted_scan"](workbench_db, args)
        rebound = json.loads(
            workbench_db.execute("SELECT finalization_input_json FROM deep_scan_runs").fetchone()[0]
        )
        assert {key: rebound[key] for key in recorded if key != "publicationSha256"} == {
            key: value for key, value in recorded.items() if key != "publicationSha256"
        }
        assert rebound["publicationSha256"] != recorded["publicationSha256"]
        assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "complete"
        coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
        assert coverage["completeness"] == "partial"
        assert any(item["id"] == "scan-cost-limit" for item in coverage["deferred"])


@pytest.mark.parametrize("parent_newer_by_ns", [0, 1_000_000_000], ids=["tied", "newer"])
def test_stopped_recovery_keeps_accepted_reviews_with_later_parent_coverage(
    workbench_api, workbench_db, publication_scan, parent_newer_by_ns
):
    scan = publication_scan()
    _, accepted, coverage = accept_reducer(workbench_db, scan)
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    parent_coverage = scan.scan_dir / "coverage.json"
    timestamp = accepted.stat().st_mtime_ns + parent_newer_by_ns
    os.utime(parent_coverage, ns=(timestamp, timestamp))
    assert parent_coverage.stat().st_mtime_ns >= accepted.stat().st_mtime_ns
    contents = accepted.read_bytes()

    stopped = workbench_api["saved_results"].fail_scan(
        workbench_api["_WORKBENCH_DB_CONTEXT"],
        workbench_db,
        Namespace(
            scan_id=scan.scan_id,
            claim_token=None,
            cost_json=None,
            message="Synthetic stopped review.",
        ),
    )["scan"]

    assert stopped["findingCount"] == 1
    published = json.loads(parent_coverage.read_text())
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
