"""A reader preserves publication identity recorded by a newer writer."""

from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
import uuid
from argparse import Namespace
from pathlib import Path

import pytest
from test_deep_scan_publication_authority import stage_publication
from test_deep_scan_stop_conditions import canceled_discovery_output
from test_deep_scan_stop_conditions import deadline_scan as deadline_scan
from test_deep_scan_stop_conditions import saturated_scan as saturated_scan
from test_deep_scan_successful_publication import complete
from test_deep_scan_successful_publication import publication_scan as publication_scan
from test_workbench_standard_deep_results import committed_standard_reducer, deep_scan_fixture
from workbench_test_support import (
    finish_deep_scan,
    run_workbench,
    saved_coverage,
    upsert_deep_worker,
    worker_paths,
    write_completed_contract,
)


def publication_digest(manifest, findings, coverage):
    manifest = copy.deepcopy(manifest)
    for key in ("completedAt", "sealedAt"):
        manifest["scan"].pop(key, None)
    encoded = json.dumps([manifest, findings, coverage], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def selected_publication(api, connection, scan, *, reason="saturated", digest_bound=True):
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
    row = api["require_scan"](connection, scan.scan_id)
    prepared = api["_prepare_scan_finalization"](
        scan.scan_dir,
        expected_coverage_mode=api["expected_coverage_mode"](row),
        completion_binding=api["workbench_completion_binding"](row, api["now"]()),
    )
    selection = {
        "version": 1,
        "resultPath": result.name,
        "resultSha256": hashlib.sha256(result.read_bytes()).hexdigest(),
        "terminalReason": reason,
        "omittedWorkerIds": [],
        "selectedAt": scan.timestamp,
    }
    if digest_bound:
        selection["publicationSha256"] = publication_digest(
            prepared.manifest, prepared.findings, prepared.coverage
        )
    with connection:
        connection.execute(
            "UPDATE deep_scan_runs SET workflow_version = 'deep-security-scan/v2', "
            "coordinator_generation = 2, finalization_input_json = ? WHERE scan_id = ?",
            (json.dumps(selection), scan.scan_id),
        )
    return result


@pytest.mark.parametrize("digest_bound", [False, True], ids=["earlier-selection", "published"])
def test_capped_deadline_replays_selected_publication(
    workbench_api, workbench_db, deadline_scan, digest_bound
):
    scan = deadline_scan
    canceled_discovery_output(workbench_db, scan)
    accepted = selected_publication(
        workbench_api, workbench_db, scan, reason="capped", digest_bound=digest_bound
    )
    original = accepted.read_bytes()
    coverage_path = scan.scan_dir / "coverage.json"
    prior_coverage = coverage_path.read_bytes()
    workbench_api["deep_scan"].finish_deep_scan(
        workbench_db,
        Namespace(
            scan_id=scan.scan_id,
            terminal_reason="capped",
            manifest_path=str(scan.scan_dir / "scan-manifest.json"),
            staged_manifest_path=None,
            omitted_worker_id=[],
            coordinator_generation=2,
        ),
    )
    coverage = json.loads(coverage_path.read_bytes())
    assert (coverage_path.read_bytes() == prior_coverage) is digest_bound
    assert any(row["id"] == "scan-deadline" for row in coverage["deferred"]) is not digest_bound
    complete(workbench_api, workbench_db, scan, prepare_only=True)
    assert complete(workbench_api, workbench_db, scan)["progress"]["status"] == "complete"
    assert accepted.read_bytes() == original


@pytest.mark.parametrize("damage", [None, "findings", "coverage", "selected"])
def test_reader_completion_validates_saved_publication(
    workbench_api, workbench_db, publication_scan, damage
):
    scan = publication_scan()
    selected = selected_publication(workbench_api, workbench_db, scan)
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


@pytest.mark.parametrize("change", [None, "producer", "host"])
def test_prepared_selection_replays_its_sealed_warnings(
    workbench_api, workbench_db, publication_scan, change
):
    scan = publication_scan()
    manifest_path = scan.scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    producer = "Review was limited to local routes."
    manifest["scan"]["warnings"] = [producer]
    manifest_path.write_text(json.dumps(manifest))
    selected_publication(workbench_api, workbench_db, scan)

    target = Path(workbench_api["require_scan"](workbench_db, scan.scan_id)["target_path"])
    (target / "subdir" / "extract.py").write_text("# Changed after selection.\n")
    args = Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
    complete = workbench_api["complete_scan"]
    (host_warning,) = complete(workbench_db, args, prepare_only=True)["targetWarnings"]
    sealed = manifest_path.read_bytes()
    manifest = json.loads(sealed)
    assert manifest["scan"]["warnings"] == [producer, host_warning]

    if change is not None:
        manifest["scan"]["warnings"] = (
            ["Substituted limitation.", host_warning] if change == "producer" else [producer]
        )
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        with pytest.raises(SystemExit, match="selected Deep Scan publication changed"):
            complete(workbench_db, args)
    else:
        for _ in range(2):
            assert complete(workbench_db, args)["scan"]["progress"]["status"] == "complete"
            assert manifest_path.read_bytes() == sealed


@pytest.mark.parametrize("damage", ["draft", "selected"])
def test_reader_republication_checks_identity_before_writing_checkpoints(
    workbench_api, workbench_db, publication_scan, damage
):
    scan = publication_scan()
    result = selected_publication(workbench_api, workbench_db, scan)
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
    with pytest.raises(
        workbench_api["ContractError"], match="publication|changed after acceptance"
    ):
        workbench_api["saved_results"].write_scan_draft(
            workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, staged
        )
    assert {p: p.read_bytes() for p in scan.scan_dir.rglob("*.json")} == before
    assert "\n".join(workbench_db.iterdump()) == state


@pytest.mark.parametrize(
    "damage",
    [
        None,
        "findings",
        "coverage",
        "selected",
        "target",
        "displayName",
        "id",
        "includePaths",
        "excludePaths",
        "null-digest",
        "bad-digest",
        "claim",
        "protocol",
    ],
)
@pytest.mark.parametrize("omitted_scope", [False, True])
def test_reader_budget_validates_publication_before_changing_the_projection(
    workbench_api, workbench_db, publication_scan, damage, omitted_scope
):
    from test_workbench_db import BUDGET_COST, BUDGET_WARNING

    scan = publication_scan()
    scan.coverage["completeness"] = "partial"
    scan.coverage["deferred"] = [{"id": "remaining", "reason": "A review remains unresolved."}]
    (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))
    if omitted_scope:
        path = scan.scan_dir / "scan-manifest.json"
        manifest = json.loads(path.read_bytes())
        manifest["scan"]["scope"].pop("includePaths")
        manifest["scan"]["scope"].pop("excludePaths")
        path.write_text(json.dumps(manifest))
    selected = selected_publication(workbench_api, workbench_db, scan)
    recipe = json.loads(workbench_api["require_scan"](workbench_db, scan.scan_id)["recipe_json"])
    recipe["maxCostUsd"] = 0.005
    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET recipe_json = ? WHERE id = ?", (json.dumps(recipe), scan.scan_id)
        )
    if damage == "selected":
        selected.write_bytes(selected.read_bytes() + b"\n")
    elif damage in {
        "findings",
        "coverage",
        "target",
        "displayName",
        "id",
        "includePaths",
        "excludePaths",
    }:
        name = damage if damage in {"findings", "coverage"} else "scan-manifest"
        path = scan.scan_dir / f"{name}.json"
        document = json.loads(path.read_bytes())
        if damage == "findings":
            document["findings"][0]["remediation"] = "Substituted repair."
        elif damage == "coverage":
            document["deferred"][0]["reason"] = "Substituted unresolved review."
        elif damage in {"includePaths", "excludePaths"}:
            document["scan"]["scope"][damage] = ["another-path"]
        elif damage == "id":
            document["scan"]["id"] = "95a98220-0653-47cb-b6b8-b5f125a5b4e7"
        else:
            document["scan"]["target"]["targetId" if damage == "target" else damage] = (
                "another-target"
            )
        path.write_text(json.dumps(document))
    elif damage in {"null-digest", "bad-digest"}:
        selection = json.loads(
            workbench_db.execute("SELECT finalization_input_json FROM deep_scan_runs").fetchone()[0]
        )
        selection["publicationSha256"] = None if damage == "null-digest" else "0" * 64
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_runs SET finalization_input_json = ?", (json.dumps(selection),)
            )
    elif damage == "claim":
        with workbench_db:
            workbench_db.execute(
                "UPDATE scans SET handoff_claim_token = '407e80b8-a8a0-412a-8ec7-d4954afba06a'"
            )
    elif damage == "protocol":
        with workbench_db:
            workbench_db.execute("UPDATE deep_scan_runs SET workflow_version = 'future/v9'")

    def snapshot():
        return list(workbench_db.iterdump()), {
            p.relative_to(scan.scan_dir): p.read_bytes()
            for p in scan.scan_dir.rglob("*")
            if p.is_file()
        }

    before = snapshot()
    run_before = dict(workbench_db.execute("SELECT * FROM deep_scan_runs").fetchone())
    args = Namespace(
        scan_id=scan.scan_id, cost_json=json.dumps(BUDGET_COST), message=BUDGET_WARNING
    )
    if damage is not None:
        with pytest.raises(SystemExit):
            workbench_api["complete_budget_exhausted_scan"](workbench_db, args)
        assert snapshot() == before
        return

    result = workbench_api["complete_budget_exhausted_scan"](workbench_db, args)["scan"]
    assert result["progress"]["status"] == "complete"
    run_after = dict(workbench_db.execute("SELECT * FROM deep_scan_runs").fetchone())
    selection_before = json.loads(run_before.pop("finalization_input_json"))
    selection_after = json.loads(run_after.pop("finalization_input_json"))
    assert run_after == run_before
    after_publication_sha256 = selection_after.pop("publicationSha256")
    before_publication_sha256 = selection_before.pop("publicationSha256")
    assert after_publication_sha256 != before_publication_sha256
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_bytes())
    findings = json.loads((scan.scan_dir / "findings.json").read_bytes())
    coverage = json.loads((scan.scan_dir / "coverage.json").read_bytes())
    assert selection_after.pop("sealedPublicationSha256") == publication_digest(
        manifest, findings, coverage
    )
    assert manifest["scan"].pop("warnings") == [BUDGET_WARNING]
    assert publication_digest(manifest, findings, coverage) == after_publication_sha256
    assert selection_after == selection_before
    assert "completeness" not in coverage
    assert scan.coverage["deferred"][0] in coverage["deferred"]
    assert any(item["id"] == "scan-cost-limit" for item in coverage["deferred"])
    assert [f["remediation"] for f in result["findings"]] == [
        f["remediation"] for f in scan.findings
    ]
    sealed = snapshot()
    workbench_api["complete_scan"](
        workbench_db, Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
    )
    assert snapshot() == sealed
    with pytest.raises(SystemExit, match="Only a running CLI Deep Scan"):
        workbench_api["complete_budget_exhausted_scan"](workbench_db, args)
    assert snapshot() == sealed


@pytest.mark.parametrize(
    "explicit_complete,terminal", [(False, True), (True, True), (False, False)]
)
def test_legacy_reducer_replay_fences_partial_drafts_after_output_failure(
    tmp_path: Path,
    workbench_api,
    monkeypatch: pytest.MonkeyPatch,
    explicit_complete: bool,
    terminal: bool,
) -> None:
    state, home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    environment = {"CODEX_HOME": str(home)}
    worker = str(uuid.uuid4())
    prompt, artifacts, result = worker_paths(scan_dir, "accepted-worker")
    upsert_deep_worker(
        state,
        scan_id,
        worker,
        "discovery",
        "running",
        str(prompt),
        str(artifacts),
        "--attempt",
        "1",
        environment=environment,
    )
    payload = {
        "scanId": scan_id,
        "findings": [],
        "coverage": saved_coverage(
            deferred=[{"id": "review", "reason": "Another surface remains."}]
        ),
        "threatModel": {"format": "markdown", "content": "# Synthetic model\n"},
    }
    if explicit_complete:
        payload["complete"] = True
    result.write_text(json.dumps(payload))
    upsert_deep_worker(
        state,
        scan_id,
        worker,
        "discovery",
        "succeeded",
        str(prompt),
        str(artifacts),
        "--attempt",
        "1",
        "--result-manifest-path",
        str(result),
        environment=environment,
    )
    committed_standard_reducer(state, home, scan_dir, scan_id, worker, result)
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(
        contract, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    documents = {
        key: json.loads((contract / name).read_text())
        for key, name in [
            ("manifest", "scan-manifest.json"),
            ("findings", "findings.json"),
            ("coverage", "coverage.json"),
        ]
    }
    documents["manifest"]["scan"].update(complete=True, threatModel=payload["threatModel"])
    documents["findings"]["findings"] = []
    documents["coverage"].update(payload["coverage"])
    staged = scan_dir / "drafts" / f"{uuid.uuid4()}.json"
    staged.parent.mkdir(exist_ok=True)
    staged.write_text(json.dumps(documents))
    run_workbench(
        state,
        "write-scan-draft",
        "--scan-id",
        scan_id,
        "--draft-path",
        str(staged),
        environment=environment,
    )
    if terminal:
        finish_deep_scan(
            state, scan_id, "capped", str(scan_dir / "scan-manifest.json"), environment=environment
        )
        complete = workbench_api["complete_scan_locked"]
        original = complete.__globals__["_write_prepared_scan_finalization"]
        report = scan_dir / "report.md"
        original_report = report.read_bytes() if report.exists() else None

        def replace_output_with_directory(prepared, **kwargs):
            if report.exists():
                report.unlink()
            report.mkdir()
            return original(prepared, **kwargs)

        monkeypatch.setenv("CODEX_HOME", str(home))
        with monkeypatch.context() as patch:
            patch.setitem(
                complete.__globals__,
                "_write_prepared_scan_finalization",
                replace_output_with_directory,
            )
            with sqlite3.connect(state / "workbench.sqlite3") as connection:
                connection.row_factory = sqlite3.Row
                with pytest.raises(SystemExit, match="report.md: expected a regular"):
                    complete(connection, scan_id, None, None)
                assert (
                    connection.execute(
                        "SELECT status FROM scans WHERE id = ?", (scan_id,)
                    ).fetchone()[0]
                    == "running"
                )
        report.rmdir()
        if original_report is not None:
            report.write_bytes(original_report)
    before = {
        name: (scan_dir / name).read_bytes()
        for name in ["scan-manifest.json", "findings.json", "coverage.json", "checkpoint-head.json"]
    }
    partial = copy.deepcopy(documents)
    partial["manifest"]["scan"]["complete"] = False
    late = scan_dir / "drafts" / f"{uuid.uuid4()}.json"
    late.write_text(json.dumps(partial))
    outcome = run_workbench(
        state,
        "write-scan-draft",
        "--scan-id",
        scan_id,
        "--draft-path",
        str(late),
        environment=environment,
        check=False,
    )
    assert (outcome["returncode"] != 0) is terminal
    if terminal:
        assert "Deep Scan is terminal" in outcome["stderr"]
        assert all((scan_dir / name).read_bytes() == contents for name, contents in before.items())
        completed = run_workbench(
            state, "complete-scan", "--scan-id", scan_id, environment=environment
        )["scan"]
        assert completed["progress"]["status"] == "complete"
