from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from test_workbench_deep_continuation import completed_deep_fixture
from test_workbench_scan_checkpoints import save, semantic
from workbench_test_support import run_workbench, write_checkpoint, write_completed_contract


@pytest.mark.parametrize("stopped", [False, True])
def test_rotation_retains_unaccepted_worker_evidence_without_review_credit(
    tmp_path: Path, stopped: bool
) -> None:
    state, root, scan_id, child, child_id, workers = completed_deep_fixture(tmp_path)
    worker_id = workers[3]
    output = root / "artifacts/deep_discovery/workers/discovery-0004/output"
    for head in root.glob("artifacts/deep_discovery/*/*/output/checkpoint-head.json"):
        head.unlink()
        (head.parent / "checkpoints" / "old.json").unlink()
        completed = semantic(scan_id, [])
        completed["complete"] = True
        (head.parent / "result.json").write_text(json.dumps(completed))
    accepted = semantic(scan_id, ["clean.ts"])
    accepted["coverage"]["deferred"] = []
    save(state, scan_id, write_checkpoint(output / "checkpoints", accepted))
    accepted_head = (output / "checkpoint-head.json").read_bytes()

    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, scan_id, tmp_path / "repository", relative_path="pending.ts")
    finding = json.loads((contract / "findings.json").read_text())["findings"][0]
    finding.pop("writeup", None)
    finding["title"] = "Candidate saved before worker acceptance"
    raw = semantic(scan_id, ["clean.ts", "pending.ts"])
    raw["findings"] = [finding]
    raw["complete"] = True
    raw["coverage"].update(completeness="complete", deferred=[])
    # The MCP writer persists this snapshot before publishing a new head.
    raw_path = write_checkpoint(output / "checkpoints", raw)
    assert (output / "checkpoint-head.json").read_bytes() == accepted_head
    original = {p.relative_to(output): p.read_bytes() for p in output.rglob("*") if p.is_file()}
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET deep_scan_owner_thread_id = 'fixture-owner', handoff_status = 'delivered' WHERE id = ?",
            (scan_id,),
        )
        connection.execute(
            "UPDATE deep_scan_runs SET status = 'running', phase = 'discovery', coordinator_generation = 2, updated_at = '2026-01-01T02:00:00Z' WHERE scan_id = ?",
            (scan_id,),
        )
        connection.execute(
            "UPDATE deep_scan_workers SET status = 'running', attempt = 2, result_manifest_path = NULL, completion_sequence = NULL, completed_at = NULL, error_message = NULL WHERE id = ?",
            (worker_id,),
        )
        receipts = connection.execute(
            "SELECT sequence, acceptance_id, snapshot_json FROM scan_checkpoints WHERE scan_id = ? ORDER BY sequence",
            (scan_id,),
        ).fetchall()
    previous_output = output
    for generation in (3, 4):
        previous_bytes = {
            p.relative_to(previous_output): p.read_bytes()
            for p in previous_output.rglob("*")
            if p.is_file()
        }
        adopted = run_workbench(
            state,
            "claim-deep-scan-coordinator",
            "--scan-id",
            scan_id,
            "--thread-id",
            "fixture-owner",
        )
        assert adopted["coordinatorDisposition"] == "adopted"
        assert adopted["deepScan"]["coordinatorGeneration"] == generation
        replacement = next(row for row in adopted["deepScan"]["workers"] if row["id"] == worker_id)
        replacement_output = Path(replacement["artifactDir"])
        assert replacement_output != previous_output
        assert previous_bytes == {
            p.relative_to(previous_output): p.read_bytes()
            for p in previous_output.rglob("*")
            if p.is_file()
        }
        assert (replacement_output / "checkpoint-head.json").read_bytes() == accepted_head
        assert (
            replacement_output / "checkpoints" / raw_path.name
        ).read_bytes() == raw_path.read_bytes()
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            assert (
                connection.execute(
                    "SELECT sequence, acceptance_id, snapshot_json FROM scan_checkpoints WHERE scan_id = ? ORDER BY sequence",
                    (scan_id,),
                ).fetchall()
                == receipts
            )
            assert connection.execute(
                "SELECT custom_validation_checkpoint_acceptance_id FROM scans WHERE id = ?",
                (scan_id,),
            ).fetchone() == (None,)
            connection.execute(
                "UPDATE deep_scan_runs SET updated_at = '2026-01-01T02:00:00Z' WHERE scan_id = ?",
                (scan_id,),
            )
        previous_output = replacement_output
    checkpoint = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id)["checkpoint"]
    assert checkpoint["reviewedFiles"] == ["clean.ts"]
    assert checkpoint["remainingFiles"] == ["pending.ts"]
    assert all(source["findings"] == [] for source in checkpoint["sources"])

    current = semantic(scan_id, ["clean.ts"])
    current["coverage"]["deferred"][0]["candidateId"] = "replacement-validation"
    save(state, scan_id, write_checkpoint(replacement_output / "checkpoints", current))
    (replacement_output / "result.json").write_text(json.dumps(current))
    assert (
        replacement_output / "checkpoints" / raw_path.name
    ).read_bytes() == raw_path.read_bytes()

    late = json.loads(json.dumps(raw))
    late["findings"][0]["title"] = "Evidence written by the fenced old worker"
    late_path = write_checkpoint(output / "checkpoints", late)
    assert "registered scan worker" in save(state, scan_id, late_path, check=False)["stderr"]
    if stopped:
        run_workbench(
            state, "fail-scan", "--scan-id", scan_id, "--message", "Stopped after adoption"
        )
        assert any(
            item["title"] == finding["title"]
            for item in json.loads((root / "findings.json").read_text())["findings"]
        )
    parent_bytes = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    resumed = run_workbench(
        state, "continue-scan-checkpoint", "--scan-id", child_id, "--parent-scan-id", scan_id
    )
    findings = json.loads((child / "findings.json").read_text())["findings"]
    assert any(item["title"] == finding["title"] for item in findings)
    assert all(item["title"] != late["findings"][0]["title"] for item in findings)
    assert resumed["checkpoint"]["reviewedFiles"] == ["clean.ts"]
    assert resumed["checkpoint"]["remainingFiles"] == ["pending.ts"]
    assert resumed["completionReady"] is False
    assert raw_path.read_bytes() == original[raw_path.relative_to(output)]
    assert parent_bytes == {
        p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()
    }
