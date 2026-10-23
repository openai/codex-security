from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
from argparse import Namespace

import pytest
from test_accepted_publication_references import accept_reducer
from test_deep_scan_successful_publication import publication_scan as publication_scan
from test_publication_stop_interleavings import published_bytes
from test_workbench_db import BUDGET_COST
from workbench_test_support import run_workbench


def prepare_budget_publication(connection, scan):
    _, accepted, _ = accept_reducer(connection, scan)
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        (scan.scan_dir / name).unlink()
    with connection:
        recipe = json.loads(connection.execute("SELECT recipe_json FROM scans").fetchone()[0])
        recipe["maxCostUsd"] = 0.005
        connection.execute("UPDATE scans SET recipe_json = ?", (json.dumps(recipe),))
        connection.execute(
            "UPDATE deep_scan_runs SET status = 'running', phase = 'discovery', "
            "workflow_version = 'deep-security-scan/v2', manifest_path = NULL, "
            "terminal_reason = NULL, completed_at = NULL"
        )
    return accepted, Namespace(
        scan_id=scan.scan_id, cost_json=json.dumps(BUDGET_COST), message=None
    )


@pytest.mark.parametrize("identity_kind", ["omitted", "candidate", "authored", "anchor-only"])
def test_budget_publication_identifies_accepted_semantic_findings(
    workbench_api, workbench_db, publication_scan, identity_kind
):
    scan = publication_scan()
    finding = scan.findings[0]
    finding["title"] = "Archive extraction crosses output boundary"
    finding.pop("identity", None)
    finding.pop("extensions", None)
    expected = {"anchor": "archive-extraction-crosses-output-boundary"}
    if identity_kind == "candidate":
        finding["extensions"] = {"candidateId": "archive-candidate"}
        expected = {"anchor": "archive-candidate"}
    elif identity_kind == "authored":
        finding["identity"] = {"anchor": "authored-anchor", "instance": "first-route"}
        expected = finding["identity"].copy()
    elif identity_kind == "anchor-only":
        finding["identity"] = expected = {"anchor": "authored-anchor"}
    accepted, args = prepare_budget_publication(workbench_db, scan)
    original = accepted.read_bytes()
    workbench_api["complete_budget_exhausted_scan"](workbench_db, args)
    published = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert len(published) == 1
    assert published[0]["identity"] == expected
    assert published[0]["codeEvidence"] == finding["codeEvidence"]
    assert published[0]["remediation"] == finding["remediation"]
    assert accepted.read_bytes() == original
    selection = json.loads(
        workbench_db.execute("SELECT finalization_input_json FROM deep_scan_runs").fetchone()[0]
    )
    assert selection["resultSha256"] == hashlib.sha256(original).hexdigest()
    assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "complete"


def add_sibling_repairs(scan, count=2):
    first = scan.findings[0]
    first["title"] = "Shared repair"
    first.pop("identity", None)
    first.pop("extensions", None)
    scan.findings.extend(copy.deepcopy(first) for _ in range(count - 1))
    for index, finding in enumerate(scan.findings, 1):
        finding["locations"] = [{"path": "subdir/extract.py", "startLine": index}]
        finding["provenance"]["sourceFindingIds"] = [f"review-{index}:candidate-{index}"]
        finding["provenance"]["sourceFindings"][0]["id"] = f"review-{index}:candidate-{index}"
        finding["codeEvidence"][0].update(
            startLine=index, endLine=index, code=f"repair_point_{index}()"
        )
        finding["remediation"] = f"Apply distinct repair {index} at this location."
        finding["remediationTests"] = [f"Check distinct repair {index}."]


@pytest.mark.parametrize(
    "case",
    [
        "generated",
        "candidate",
        "authored-first",
        "authored-last",
        "reserved-instance",
        "authored-siblings",
        "different-rules",
        "different-titles",
    ],
)
def test_budget_publication_keeps_generated_sibling_repairs(
    workbench_api, workbench_db, publication_scan, case
):
    scan = publication_scan()
    add_sibling_repairs(scan, 4 if case == "reserved-instance" else 2)
    if case == "candidate":
        for finding in scan.findings:
            finding["extensions"] = {"candidateId": "shared-candidate"}
    elif case in {"authored-first", "authored-last"}:
        scan.findings[0 if case == "authored-first" else 1]["identity"] = {
            "anchor": "shared-repair"
        }
    elif case == "reserved-instance":
        scan.findings[2]["identity"] = {"anchor": "shared-repair"}
        scan.findings[3]["identity"] = {"anchor": "shared-repair", "instance": "saved-2"}
    elif case == "authored-siblings":
        for index, finding in enumerate(scan.findings):
            finding["identity"] = {"anchor": "shared-repair", "instance": f"route-{index}"}
    elif case == "different-rules":
        scan.findings[1]["ruleId"] = "distinct-rule"
    elif case == "different-titles":
        scan.findings[1]["title"] = "Distinct repair"
    originals = copy.deepcopy(scan.findings)
    accepted, args = prepare_budget_publication(workbench_db, scan)
    original = accepted.read_bytes()

    workbench_api["complete_budget_exhausted_scan"](workbench_db, args)

    published = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert len(published) == len(scan.findings)
    assert len({finding["occurrenceId"] for finding in published}) == len(scan.findings)
    for expected, actual in zip(scan.findings, published, strict=True):
        for key in expected.keys() - {"findingId", "occurrenceId", "fingerprints"}:
            assert actual[key] == expected[key]
        if "identity" not in expected:
            anchor = (
                "shared-candidate"
                if case == "candidate"
                else expected["title"].lower().replace(" ", "-")
            )
            assert actual["identity"]["anchor"] == anchor
        assert expected["remediation"] in (scan.scan_dir / "report.md").read_text()
        if case in {"different-rules", "different-titles"}:
            assert "instance" not in actual["identity"]
    selection = workbench_db.execute(
        "SELECT finalization_input_json FROM deep_scan_runs"
    ).fetchone()[0]
    assert json.loads(selection)["resultSha256"] == hashlib.sha256(original).hexdigest()
    before = published_bytes(scan)
    workbench_api["complete_scan"](
        workbench_db, Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
    )
    assert published_bytes(scan) == before
    assert (
        workbench_db.execute("SELECT finalization_input_json FROM deep_scan_runs").fetchone()[0]
        == selection
    )
    assert accepted.read_bytes() == original
    assert scan.findings == originals
    assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "complete"


@pytest.mark.parametrize("identity", [{}, {"instance": "first-route"}, None])
def test_budget_publication_does_not_repair_authored_invalid_identity(
    workbench_api, workbench_db, publication_scan, identity
):
    scan = publication_scan()
    scan.findings[0]["identity"] = identity
    accepted, args = prepare_budget_publication(workbench_db, scan)
    original = accepted.read_bytes()
    with pytest.raises(SystemExit, match="identity"):
        workbench_api["complete_budget_exhausted_scan"](workbench_db, args)
    assert accepted.read_bytes() == original
    assert scan.findings[0]["identity"] == identity
    assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] != "complete"


def test_budget_publication_rejects_duplicate_authored_identities(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    add_sibling_repairs(scan)
    for finding in scan.findings:
        finding["identity"] = {"anchor": "shared-repair", "instance": "authored-route"}
    accepted, args = prepare_budget_publication(workbench_db, scan)
    original = accepted.read_bytes()
    with pytest.raises(SystemExit, match="duplicate occurrence identity"):
        workbench_api["complete_budget_exhausted_scan"](workbench_db, args)
    assert accepted.read_bytes() == original


@pytest.mark.parametrize("boundary", ["before-selection-commit", "after-selection-commit"])
def test_budget_sibling_selection_replays_in_a_fresh_process(
    workbench_api, workbench_db, publication_scan, tmp_path, monkeypatch, boundary
):
    scan = publication_scan()
    add_sibling_repairs(scan)
    accepted, args = prepare_budget_publication(workbench_db, scan)
    original = accepted.read_bytes()
    budget = workbench_api["complete_budget_exhausted_scan"]
    drafts = []

    def interrupt(*args, **kwargs):
        drafts.append(json.loads((scan.scan_dir / "findings.json").read_text())["findings"])
        raise RuntimeError("Synthetic publication interruption.")

    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        workbench_db.backup(connection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        with monkeypatch.context() as patch:
            if boundary == "before-selection-commit":
                patch.setattr(workbench_api["deep_scan"], "cancel_active_workers", interrupt)
            else:
                patch.setitem(budget.__globals__, "complete_scan_locked", interrupt)
            with pytest.raises(RuntimeError, match="Synthetic publication interruption"):
                budget(connection, args)
        selection = connection.execute(
            "SELECT finalization_input_json FROM deep_scan_runs"
        ).fetchone()[0]
        if boundary == "before-selection-commit":
            assert selection is None
            assert not (scan.scan_dir / "findings.json").exists()
        else:
            assert json.loads(selection)["resultSha256"] == hashlib.sha256(original).hexdigest()
    run_workbench(
        state,
        "complete-budget-exhausted-scan",
        "--scan-id",
        scan.scan_id,
        "--cost-json",
        args.cost_json,
    )
    published = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert [finding["identity"] for finding in published] == [
        finding["identity"] for finding in drafts[0]
    ]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        replayed_selection = connection.execute(
            "SELECT finalization_input_json FROM deep_scan_runs"
        ).fetchone()[0]
        if selection is not None:
            assert replayed_selection == selection
        assert (
            json.loads(replayed_selection)["resultSha256"] == hashlib.sha256(original).hexdigest()
        )
        assert connection.execute("SELECT status FROM scans").fetchone()[0] == "complete"
    before = published_bytes(scan)
    run_workbench(state, "complete-scan", "--scan-id", scan.scan_id)
    assert published_bytes(scan) == before
    assert accepted.read_bytes() == original
