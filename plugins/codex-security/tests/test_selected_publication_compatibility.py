"""Preserve selected Deep Scan publications across main contract normalization."""

from __future__ import annotations

import copy
import hashlib
import json
from argparse import Namespace
from functools import partial

import pytest
from test_accepted_publication_references import accept_reducer
from test_deep_scan_publication_authority import stage_publication
from test_deep_scan_successful_publication import publication_scan as publication_scan
from test_publication_stop_interleavings import saved_selection
from test_workbench_db import BUDGET_COST


def selected_result(connection, scan):
    result = scan.scan_dir / "accepted.json"
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": scan.findings,
                "sourceCoverage": scan.coverage,
            }
        )
    )
    selection = {
        "version": 1,
        "resultPath": result.name,
        "resultSha256": hashlib.sha256(result.read_bytes()).hexdigest(),
        "terminalReason": "saturated",
        "omittedWorkerIds": [],
        "selectedAt": scan.timestamp,
    }
    with connection:
        connection.execute(
            "UPDATE deep_scan_runs SET workflow_version = 'deep-security-scan/v2', "
            "coordinator_generation = 2, finalization_input_json = ? WHERE scan_id = ?",
            (json.dumps(selection), scan.scan_id),
        )
    return result


def selected_publication(api, connection, scan, *, legacy_completeness=None):
    if legacy_completeness is not None:
        scan.coverage["completeness"] = legacy_completeness
        coverage_path = scan.scan_dir / "coverage.json"
        coverage = json.loads(coverage_path.read_bytes())
        coverage["completeness"] = legacy_completeness
        coverage_path.write_text(json.dumps(coverage))
    result = selected_result(connection, scan)
    row = api["require_scan"](connection, scan.scan_id)
    prepared = api["_prepare_scan_finalization"](
        scan.scan_dir,
        expected_coverage_mode=api["expected_coverage_mode"](row),
        completion_binding=api["workbench_completion_binding"](row, api["now"]()),
        accepted_findings=api["saved_results"].has_verified_selected_result(
            api["_WORKBENCH_DB_CONTEXT"], connection, row
        ),
    )
    manifest = copy.deepcopy(prepared[2])
    coverage = copy.deepcopy(prepared[4])
    if legacy_completeness is not None:
        coverage["completeness"] = legacy_completeness
        coverage_bytes = (json.dumps(coverage, indent=2, sort_keys=True) + "\n").encode()
        for artifact in manifest["scan"]["artifacts"]:
            if artifact["path"] == "coverage.json":
                artifact["sha256"] = hashlib.sha256(coverage_bytes).hexdigest()
    for key in ("completedAt", "sealedAt"):
        manifest["scan"].pop(key, None)
    encoded = json.dumps(
        [manifest, prepared[3], coverage], sort_keys=True, separators=(",", ":")
    ).encode()
    selection = json.loads(
        connection.execute("SELECT finalization_input_json FROM deep_scan_runs").fetchone()[0]
    )
    selection["publicationSha256"] = hashlib.sha256(encoded).hexdigest()
    with connection:
        connection.execute(
            "UPDATE deep_scan_runs SET finalization_input_json = ? WHERE scan_id = ?",
            (json.dumps(selection), scan.scan_id),
        )
    return result


def legacy_finding(scan):
    finding = scan.findings[0]
    finding.pop("rootCause", None)
    finding["root_cause"] = {
        "summary": "Previously accepted root cause.",
        "evidence_refs": ["legacy-source"],
    }
    finding["code_evidence"] = [{"id": "legacy-source", "code": "return synthetic_input;"}]
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": scan.findings}))
    return {key: copy.deepcopy(finding[key]) for key in ("root_cause", "code_evidence")}


def assert_legacy_finding_published(scan, expected):
    finding = json.loads((scan.scan_dir / "findings.json").read_text())["findings"][0]
    assert {key: finding[key] for key in expected} == expected
    report = (scan.scan_dir / "report.md").read_text()
    assert "Previously accepted root cause." in report
    assert "return synthetic_input;" in report


def assert_completed_preparation(api, connection, scan, *, accepted):
    files = {path: path.read_bytes() for path in scan.scan_dir.rglob("*") if path.is_file()}
    state = "\n".join(connection.iterdump())
    completion = Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
    prepared = api["complete_scan"](connection, completion, prepare_only=True)
    assert prepared["acceptedFindings"] is accepted
    completed = api["complete_scan"](connection, completion)
    assert "acceptedFindings" not in completed
    assert {path: path.read_bytes() for path in scan.scan_dir.rglob("*") if path.is_file()} == files
    assert "\n".join(connection.iterdump()) == state


@pytest.mark.parametrize("workflow", ["deep-scan-mcp/v1", "deep-security-scan/v1"])
@pytest.mark.parametrize("capped", [False, True])
def test_legacy_v1_accepted_findings_publish_and_resume_completion(
    workbench_api, workbench_db, publication_scan, monkeypatch, workflow, capped
):
    scan = publication_scan()
    expected = legacy_finding(scan)
    _, accepted, _ = accept_reducer(workbench_db, scan)
    accepted_bytes = accepted.read_bytes()
    with workbench_db:
        workbench_db.execute("UPDATE deep_scan_runs SET workflow_version = ?", (workflow,))
        if capped:
            recipe = json.loads(workbench_db.execute("SELECT recipe_json FROM scans").fetchone()[0])
            recipe["maxCostUsd"] = 0.005
            workbench_db.execute("UPDATE scans SET recipe_json = ?", (json.dumps(recipe),))
    staged = stage_publication(
        scan, generation=3, result_path=accepted, title=scan.findings[0]["title"]
    )
    workbench_api["saved_results"].write_scan_draft(
        workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, staged
    )

    def interrupted(*args, **kwargs):
        raise RuntimeError("Interrupted legacy completion")

    if capped:
        complete = workbench_api["complete_budget_exhausted_scan"]
        args = Namespace(scan_id=scan.scan_id, cost_json=json.dumps(BUDGET_COST), message=None)
        cut = "complete_scan_locked"
    else:
        complete = workbench_api["complete_scan"]
        args = Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
        cut = "_write_prepared_scan_finalization"
    with monkeypatch.context() as patch:
        patch.setitem(complete.__globals__, cut, interrupted)
        with pytest.raises(RuntimeError, match="Interrupted legacy completion"):
            complete(workbench_db, args)
    assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "running"
    prepared = workbench_api["complete_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None),
        prepare_only=True,
    )
    assert prepared["acceptedFindings"] is True
    complete(workbench_db, args)
    assert_legacy_finding_published(scan, expected)
    assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "complete"
    assert (
        workbench_db.execute("SELECT finalization_input_json FROM deep_scan_runs").fetchone()[0]
        is None
    )
    sealed = {path: path.read_bytes() for path in scan.scan_dir.rglob("*") if path.is_file()}
    assert_completed_preparation(workbench_api, workbench_db, scan, accepted=True)
    assert {path: path.read_bytes() for path in sealed} == sealed
    assert accepted.read_bytes() == accepted_bytes


@pytest.mark.parametrize(
    "workflow", ["deep-scan-mcp/v1", "deep-security-scan/v1", "deep-security-scan/v2"]
)
@pytest.mark.parametrize("damage", ["accepted-source", "sealed-findings"])
def test_completed_preparation_rejects_changed_accepted_or_sealed_artifacts(
    workbench_api, workbench_db, publication_scan, workflow, damage
):
    scan = publication_scan()
    legacy_finding(scan)
    if workflow.endswith("/v2"):
        accepted = selected_publication(workbench_api, workbench_db, scan)
    else:
        _, accepted, _ = accept_reducer(workbench_db, scan)
        with workbench_db:
            workbench_db.execute("UPDATE deep_scan_runs SET workflow_version = ?", (workflow,))
        staged = stage_publication(
            scan, generation=3, result_path=accepted, title=scan.findings[0]["title"]
        )
        workbench_api["saved_results"].write_scan_draft(
            workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, staged
        )
    completion = Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
    workbench_api["complete_scan"](workbench_db, completion)
    if damage == "accepted-source":
        accepted.write_bytes(accepted.read_bytes() + b"\n")
        expected_error = "changed after acceptance"
    else:
        findings = scan.scan_dir / "findings.json"
        findings.write_bytes(findings.read_bytes() + b"\n")
        expected_error = "sealed artifact changed"
    files = {path: path.read_bytes() for path in scan.scan_dir.rglob("*") if path.is_file()}
    state = "\n".join(workbench_db.iterdump())
    with pytest.raises(SystemExit, match=expected_error):
        workbench_api["complete_scan"](workbench_db, completion, prepare_only=True)
    assert {path: path.read_bytes() for path in scan.scan_dir.rglob("*") if path.is_file()} == files
    assert "\n".join(workbench_db.iterdump()) == state


def test_legacy_v1_authority_uses_reducer_sequence_instead_of_completion_order(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    expected = legacy_finding(scan)
    older_result, older_accepted, _ = accept_reducer(workbench_db, scan)
    latest_result, latest_accepted, _ = accept_reducer(workbench_db, scan)
    with workbench_db:
        for sequence, result in enumerate((older_result, latest_result), start=1):
            workbench_db.execute(
                "UPDATE deep_scan_workers SET prompt_path = ?, completed_at = ? WHERE id = ?",
                (
                    str(scan.scan_dir / f"dedup-{sequence:04d}" / "prompt.md"),
                    f"2026-01-0{3 - sequence}",
                    result.parent.name,
                ),
            )
    older_accepted.unlink()
    staged = stage_publication(
        scan, generation=3, result_path=latest_accepted, title=scan.findings[0]["title"]
    )
    workbench_api["saved_results"].write_scan_draft(
        workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, staged
    )
    workbench_api["complete_scan"](
        workbench_db, Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
    )
    assert_legacy_finding_published(scan, expected)


@pytest.mark.parametrize(
    "damage",
    [
        "source-before-publication",
        "source-before-completion",
        "unaccepted",
        "no-digest",
        "descriptor",
    ],
)
def test_legacy_v1_compatibility_requires_the_matching_accepted_source(
    workbench_api, workbench_db, publication_scan, damage
):
    scan = publication_scan()
    legacy_finding(scan)
    result, accepted, _ = accept_reducer(workbench_db, scan)
    selected = accepted
    expected_error = "changed after acceptance"
    if damage == "unaccepted":
        result.write_bytes(accepted.read_bytes())
        with workbench_db:
            workbench_db.execute("DELETE FROM deep_scan_attempts")
        selected = result
        expected_error = "invalid findings"
    elif damage == "no-digest":
        with workbench_db:
            workbench_db.execute("UPDATE deep_scan_attempts SET accepted_result_sha256 = NULL")
        expected_error = "invalid findings"
    elif damage == "descriptor":
        selected = result
        expected_error = "aggregate"
    staged = stage_publication(
        scan, generation=3, result_path=selected, title=scan.findings[0]["title"]
    )
    saved = workbench_api["saved_results"]
    completing = damage in {"source-before-completion", "unaccepted", "no-digest"}
    if completing:
        saved.write_scan_draft(workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, staged)
    if damage.startswith("source-"):
        accepted.write_bytes(accepted.read_bytes() + b"\n")
    files = {path: path.read_bytes() for path in scan.scan_dir.rglob("*") if path.is_file()}
    state = "\n".join(workbench_db.iterdump())
    operation = (
        partial(
            workbench_api["complete_scan"],
            workbench_db,
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None),
        )
        if completing
        else partial(
            saved.write_scan_draft, workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, staged
        )
    )
    with pytest.raises((SystemExit, workbench_api["ContractError"]), match=expected_error):
        operation()
    assert "\n".join(workbench_db.iterdump()) == state
    assert {path: path.read_bytes() for path in scan.scan_dir.rglob("*") if path.is_file()} == files


def test_selected_legacy_findings_publish_before_the_first_publication_receipt(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    expected = legacy_finding(scan)
    accepted = selected_result(workbench_db, scan)
    accepted_bytes = accepted.read_bytes()
    staged = stage_publication(
        scan, generation=2, result_path=accepted, title=scan.findings[0]["title"]
    )
    saved = workbench_api["saved_results"]
    saved.write_scan_draft(workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, staged)
    receipt = workbench_db.execute("SELECT finalization_input_json FROM deep_scan_runs").fetchone()[
        0
    ]
    assert len(json.loads(receipt)["publicationSha256"]) == 64
    workbench_api["complete_scan"](
        workbench_db, Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
    )
    assert_legacy_finding_published(scan, expected)
    workbench_api["validate_completed_scan_artifacts"](
        workbench_api["_WORKBENCH_DB_CONTEXT"],
        workbench_api["require_scan"](workbench_db, scan.scan_id),
    )
    assert accepted.read_bytes() == accepted_bytes
    assert (
        workbench_db.execute("SELECT finalization_input_json FROM deep_scan_runs").fetchone()[0]
        == receipt
    )


@pytest.mark.parametrize("cut", ["before", "after"])
def test_selected_historical_findings_resume_across_interrupted_sealing(
    workbench_api, workbench_db, publication_scan, monkeypatch, cut
):
    scan = publication_scan()
    expected = legacy_finding(scan)
    accepted = selected_publication(
        workbench_api, workbench_db, scan, legacy_completeness="partial"
    )
    accepted_bytes = accepted.read_bytes()
    receipt = workbench_db.execute("SELECT finalization_input_json FROM deep_scan_runs").fetchone()[
        0
    ]
    namespace = workbench_api["complete_scan_locked"].__globals__
    write = namespace["_write_prepared_scan_finalization"]

    def interrupted_write(*args, **kwargs):
        if cut == "after":
            write(*args, **kwargs)
        raise RuntimeError("Interrupted historical publication")

    completion = Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
    with monkeypatch.context() as patch:
        patch.setitem(namespace, "_write_prepared_scan_finalization", interrupted_write)
        with pytest.raises(RuntimeError, match="Interrupted historical publication"):
            workbench_api["complete_scan"](workbench_db, completion)
    assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "running"
    prepared = workbench_api["complete_scan"](workbench_db, completion, prepare_only=True)
    assert prepared["acceptedFindings"] is True
    workbench_api["complete_scan"](workbench_db, completion)
    assert_legacy_finding_published(scan, expected)
    sealed = {p: p.read_bytes() for p in scan.scan_dir.rglob("*") if p.is_file()}
    assert_completed_preparation(workbench_api, workbench_db, scan, accepted=True)
    assert {p: p.read_bytes() for p in sealed} == sealed
    assert accepted.read_bytes() == accepted_bytes
    assert (
        workbench_db.execute("SELECT finalization_input_json FROM deep_scan_runs").fetchone()[0]
        == receipt
    )


@pytest.mark.parametrize("damage", ["canonical-finding", "staged-finding", "accepted-source"])
def test_selected_legacy_finding_compatibility_retains_publication_integrity(
    workbench_api, workbench_db, publication_scan, damage
):
    scan = publication_scan()
    legacy_finding(scan)
    accepted = selected_publication(
        workbench_api, workbench_db, scan, legacy_completeness="partial"
    )
    if damage == "accepted-source":
        accepted.write_bytes(accepted.read_bytes() + b"\n")
    elif damage == "canonical-finding":
        path = scan.scan_dir / "findings.json"
        document = json.loads(path.read_text())
        document["findings"][0]["root_cause"]["summary"] = "Substituted accepted explanation."
        path.write_text(json.dumps(document))
    else:
        scan.findings[0]["code_evidence"][0]["code"] = "return substituted_input;"
        staged = stage_publication(
            scan, generation=2, result_path=accepted, title=scan.findings[0]["title"]
        )
    before = {p: p.read_bytes() for p in scan.scan_dir.rglob("*") if p.is_file()}
    state = "\n".join(workbench_db.iterdump())
    if damage == "staged-finding":
        with pytest.raises(workbench_api["ContractError"], match="publication"):
            workbench_api["saved_results"].write_scan_draft(
                workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, staged
            )
    else:
        with pytest.raises(SystemExit, match="publication|changed after acceptance"):
            workbench_api["complete_scan"](
                workbench_db, Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
            )
    assert {p: p.read_bytes() for p in before} == before
    assert "\n".join(workbench_db.iterdump()) == state


@pytest.mark.parametrize("mode", ["standard", "deep"])
def test_new_producers_still_reject_legacy_finding_fields(
    workbench_api, workbench_db, publication_scan, mode
):
    scan = publication_scan(mode=mode)
    findings_path = scan.scan_dir / "findings.json"
    original_findings = findings_path.read_bytes()
    legacy_finding(scan)
    with pytest.raises(SystemExit, match="invalid findings.*unexpected schema property"):
        workbench_api["complete_scan"](
            workbench_db, Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
        )
    assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "running"
    findings_path.write_bytes(original_findings)
    prepared = workbench_api["complete_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None),
        prepare_only=True,
    )
    assert prepared["acceptedFindings"] is False
    workbench_api["complete_scan"](
        workbench_db, Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
    )
    assert_completed_preparation(workbench_api, workbench_db, scan, accepted=False)


def test_zero_result_selection_does_not_admit_legacy_findings(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    legacy_finding(scan)
    selected_result(workbench_db, scan)
    selection = json.loads(
        workbench_db.execute("SELECT finalization_input_json FROM deep_scan_runs").fetchone()[0]
    )
    selection["resultPath"] = None
    selection["resultSha256"] = None
    selection["terminalReason"] = "capped"
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET finalization_input_json = ?, terminal_reason = 'capped'",
            (json.dumps(selection),),
        )
    with pytest.raises(SystemExit, match="invalid findings.*unexpected schema property"):
        workbench_api["complete_scan"](
            workbench_db, Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
        )
    assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "running"


@pytest.mark.parametrize("preselected", [False, True])
def test_budget_replays_legacy_accepted_findings_after_publication_commit(
    workbench_api, workbench_db, publication_scan, monkeypatch, preselected
):
    scan = publication_scan()
    expected = legacy_finding(scan)
    _, accepted, _ = accept_reducer(workbench_db, scan)
    accepted_bytes = accepted.read_bytes()
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        (scan.scan_dir / name).unlink()
    with workbench_db:
        recipe = json.loads(workbench_db.execute("SELECT recipe_json FROM scans").fetchone()[0])
        recipe["maxCostUsd"] = 0.005
        workbench_db.execute("UPDATE scans SET recipe_json = ?", (json.dumps(recipe),))
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = 'running', workflow_version = 'deep-security-scan/v2'"
        )
    if preselected:
        saved_selection(workbench_db, scan, accepted, reason="capped")
    budget = workbench_api["complete_budget_exhausted_scan"]

    def interrupted_completion(*args, **kwargs):
        raise RuntimeError("Interrupted after accepted budget publication")

    args = Namespace(scan_id=scan.scan_id, cost_json=json.dumps(BUDGET_COST), message=None)
    with monkeypatch.context() as patch:
        patch.setitem(budget.__globals__, "complete_scan_locked", interrupted_completion)
        with pytest.raises(RuntimeError, match="Interrupted after accepted budget publication"):
            budget(workbench_db, args)
    receipt = workbench_db.execute("SELECT finalization_input_json FROM deep_scan_runs").fetchone()[
        0
    ]
    assert "publicationSha256" in json.loads(receipt)
    budget(workbench_db, args)
    assert_legacy_finding_published(scan, expected)
    assert accepted.read_bytes() == accepted_bytes
    assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "complete"
    assert (
        workbench_db.execute("SELECT finalization_input_json FROM deep_scan_runs").fetchone()[0]
        == receipt
    )


@pytest.mark.parametrize("legacy_completeness", ["complete", "partial", "unknown"])
@pytest.mark.parametrize("cut", ["before", "after"])
def test_selected_replays_historical_publication_across_normalization(
    workbench_api, workbench_db, publication_scan, monkeypatch, legacy_completeness, cut
):
    scan = publication_scan()
    selected_publication(workbench_api, workbench_db, scan, legacy_completeness=legacy_completeness)
    selection = workbench_db.execute(
        "SELECT finalization_input_json FROM deep_scan_runs"
    ).fetchone()[0]
    namespace = workbench_api["complete_scan_locked"].__globals__
    write = namespace["_write_prepared_scan_finalization"]

    def interrupted_write(*args, **kwargs):
        if cut == "after":
            write(*args, **kwargs)
        raise RuntimeError("Interrupted parent completion")

    args = Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
    with monkeypatch.context() as patch:
        patch.setitem(namespace, "_write_prepared_scan_finalization", interrupted_write)
        with pytest.raises(RuntimeError, match="Interrupted parent completion"):
            workbench_api["complete_scan"](workbench_db, args)
    assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "running"
    if cut == "after":
        assert "completeness" not in json.loads((scan.scan_dir / "coverage.json").read_bytes())
    workbench_api["complete_scan"](workbench_db, args)
    assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "complete"
    assert (
        workbench_db.execute("SELECT finalization_input_json FROM deep_scan_runs").fetchone()[0]
        == selection
    )
    sealed = {p: p.read_bytes() for p in scan.scan_dir.rglob("*.json")}
    workbench_api["complete_scan"](workbench_db, args)
    assert {p: p.read_bytes() for p in sealed} == sealed


@pytest.mark.parametrize("damage", [None, "findings", "coverage", "selected"])
@pytest.mark.parametrize("legacy_completeness", [None, "complete", "partial", "unknown"])
def test_selected_completion_validates_saved_publication(
    workbench_api, workbench_db, publication_scan, damage, legacy_completeness
):
    scan = publication_scan()
    selected = selected_publication(
        workbench_api, workbench_db, scan, legacy_completeness=legacy_completeness
    )
    if damage == "selected":
        selected.write_bytes(selected.read_bytes() + b"\n")
    elif damage is not None:
        path = scan.scan_dir / f"{damage}.json"
        document = json.loads(path.read_bytes())
        if damage == "findings":
            document["findings"][0]["remediation"] = "Substituted repair."
        else:
            document["completeness"] = "partial"
            document["deferred"] = [
                {"id": "changed-coverage", "reason": "Substituted unresolved review."}
            ]
        path.write_text(json.dumps(document))
    before = {p: p.read_bytes() for p in scan.scan_dir.rglob("*.json")}
    state = "\n".join(workbench_db.iterdump())
    args = Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
    if damage is None:
        workbench_api["complete_scan"](workbench_db, args)
        sealed = {p: p.read_bytes() for p in scan.scan_dir.rglob("*.json")}
        workbench_api["complete_scan"](workbench_db, args)
        assert {p: p.read_bytes() for p in sealed} == sealed
    else:
        with pytest.raises(SystemExit, match="publication|changed after acceptance"):
            workbench_api["complete_scan"](workbench_db, args)
        assert "\n".join(workbench_db.iterdump()) == state
        assert {p: p.read_bytes() for p in before} == before


def test_selected_historical_publication_still_binds_receipt_bytes(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    receipt = scan.scan_dir / "artifacts" / "review.json"
    receipt.parent.mkdir()
    receipt.write_text('{"review": "original"}\n')
    scan.coverage["surfaces"] = [
        {
            "id": "saved-review",
            "label": "Synthetic saved review",
            "disposition": "no_issue_found",
            "receiptRefs": ["artifacts/review.json"],
        }
    ]
    (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))
    selected_publication(workbench_api, workbench_db, scan, legacy_completeness="complete")
    receipt.write_text('{"review": "substituted"}\n')
    state = "\n".join(workbench_db.iterdump())
    files = {p: p.read_bytes() for p in scan.scan_dir.rglob("*.json")}
    with pytest.raises(SystemExit, match="publication"):
        workbench_api["complete_scan"](
            workbench_db, Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
        )
    assert "\n".join(workbench_db.iterdump()) == state
    assert {p: p.read_bytes() for p in files} == files


@pytest.mark.parametrize("damage", [None, "draft", "selected"])
@pytest.mark.parametrize("legacy_completeness", [None, "partial"])
def test_selected_republication_checks_identity_before_writing_checkpoints(
    workbench_api, workbench_db, publication_scan, damage, legacy_completeness
):
    scan = publication_scan()
    result = selected_publication(
        workbench_api, workbench_db, scan, legacy_completeness=legacy_completeness
    )
    staged = stage_publication(
        scan,
        generation=2,
        result_path=result,
        title="Substituted aggregate" if damage == "draft" else scan.findings[0]["title"],
    )
    if damage == "selected":
        result.write_bytes(result.read_bytes() + b"\n")
    before = {p: p.read_bytes() for p in scan.scan_dir.rglob("*.json")}
    state = "\n".join(workbench_db.iterdump())
    if damage is None:
        result = workbench_api["saved_results"].write_scan_draft(
            workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, staged
        )
        assert result["status"] == "draft_written"
        workbench_api["complete_scan"](
            workbench_db, Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
        )
        return
    with pytest.raises(
        workbench_api["ContractError"], match="publication|changed after acceptance"
    ):
        workbench_api["saved_results"].write_scan_draft(
            workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, staged
        )
    assert {p: p.read_bytes() for p in scan.scan_dir.rglob("*.json")} == before
    assert "\n".join(workbench_db.iterdump()) == state


def test_selected_zero_discovery_deadline_preserves_the_published_draft(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    scan.findings = []
    scan.coverage["deferred"] = [
        {
            "id": "deadline",
            "reason": "The configured discovery time limit elapsed before source review completed.",
        }
    ]
    selection = {
        "version": 1,
        "resultPath": None,
        "terminalReason": "capped",
        "omittedWorkerIds": [],
        "selectedAt": scan.timestamp,
    }
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET workflow_version = 'deep-security-scan/v2', "
            "coordinator_generation = 2, status = 'running', phase = 'terminal', "
            "terminal_reason = 'capped', completed_at = NULL, "
            "created_at = '2000-01-01T00:00:00Z', max_time_hours = 1, "
            "finalization_input_json = ? WHERE scan_id = ?",
            (json.dumps(selection), scan.scan_id),
        )
    draft_dir = scan.scan_dir / "drafts"
    draft_dir.mkdir()
    draft_path = draft_dir / "00000000-0000-4000-8000-000000000001.json"
    draft_path.write_text(
        json.dumps(
            {
                "manifest": json.loads((scan.scan_dir / "scan-manifest.json").read_text()),
                "findings": {"findings": []},
                "coverage": scan.coverage,
                "deepScanPublication": {"coordinatorGeneration": 2, "resultPath": None},
            }
        )
    )
    workbench_api["saved_results"].write_scan_draft(
        workbench_api["_WORKBENCH_DB_CONTEXT"],
        workbench_db,
        Namespace(
            scan_id=scan.scan_id,
            claim_token=None,
            draft_path=str(draft_path),
            checkpoint_path=None,
            expected_draft_digest=None,
        ),
    )
    selection_json = workbench_db.execute(
        "SELECT finalization_input_json FROM deep_scan_runs"
    ).fetchone()[0]
    assert "publicationSha256" in json.loads(selection_json)
    before = {path: path.read_bytes() for path in scan.scan_dir.rglob("*.json")}
    finish = Namespace(
        scan_id=scan.scan_id,
        terminal_reason="capped",
        omitted_worker_id=[],
        manifest_path=str(scan.scan_dir / "scan-manifest.json"),
        staged_manifest_path=None,
        coordinator_generation=2,
    )
    deep = workbench_api["deep_scan"]
    deep.finish_deep_scan(workbench_db, finish)
    assert workbench_db.execute("SELECT status FROM deep_scan_runs").fetchone()[0] == "succeeded"
    assert {path: path.read_bytes() for path in scan.scan_dir.rglob("*.json")} == before
    completion = Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
    prepared = workbench_api["complete_scan"](workbench_db, completion, prepare_only=True)
    assert prepared["acceptedFindings"] is False
    workbench_api["complete_scan"](workbench_db, completion)
    assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "complete"
    sealed = {path: path.read_bytes() for path in scan.scan_dir.rglob("*.json")}
    assert_completed_preparation(workbench_api, workbench_db, scan, accepted=False)
    deep.finish_deep_scan(workbench_db, finish)
    workbench_api["complete_scan"](workbench_db, completion)
    assert {path: path.read_bytes() for path in scan.scan_dir.rglob("*.json")} == sealed
    assert (
        workbench_db.execute("SELECT finalization_input_json FROM deep_scan_runs").fetchone()[0]
        == selection_json
    )
