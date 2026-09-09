from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path

import pytest
from test_workbench_deep_continuation import completed_deep_fixture
from test_workbench_scan_checkpoints import save, semantic
from workbench_test_support import run_workbench, write_checkpoint, write_completed_contract


def continued_candidate(tmp_path: Path, *, other_pending: bool = False):
    state, parent, parent_id, child, child_id, workers = completed_deep_fixture(tmp_path)
    repository = tmp_path / "repository"
    for result in parent.glob("artifacts/deep_discovery/*/*/output/result.json"):
        value = semantic(parent_id, [])
        value["complete"] = True
        value["coverage"].update(completeness="complete", deferred=[])
        result.write_text(json.dumps(value))
    for head in parent.glob("artifacts/deep_discovery/*/*/output/checkpoint-head.json"):
        head.unlink()
        (head.parent / "checkpoints" / "old.json").unlink()
    empty = semantic(parent_id, [])
    empty["coverage"]["deferred"] = []
    save(state, parent_id, write_checkpoint(parent / "checkpoints", empty))
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, parent_id, repository, relative_path="clean.ts")
    finding = json.loads((contract / "findings.json").read_text())["findings"][0]
    finding["extensions"] = {"candidateId": "candidate-1"}
    pending = semantic(parent_id, ["clean.ts"])
    pending["findings"] = [finding]
    output = parent / "artifacts/deep_discovery/workers/discovery-0004/output"
    save(state, parent_id, write_checkpoint(output / "checkpoints", pending))
    if other_pending:
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE deep_scan_workers SET status = 'failed', merge_state = 'none', completion_sequence = NULL WHERE id = ?",
                (workers[2],),
            )
        other_output = output.parent.parent / "discovery-0003" / "output"
        save(
            state,
            parent_id,
            write_checkpoint(other_output / "checkpoints", semantic(parent_id, ["pending.ts"])),
        )
    run_workbench(
        state, "continue-scan-checkpoint", "--scan-id", child_id, "--parent-scan-id", parent_id
    )
    worker_id = str(uuid.uuid5(uuid.UUID(child_id), workers[3]))
    finding = json.loads((child / "findings.json").read_text())["findings"][0]
    return state, repository, parent, parent_id, child, child_id, worker_id, finding


def decision(scan_id: str, worker_id: str, finding: dict, outcome: str):
    value = semantic(scan_id, ["clean.ts", "pending.ts"])
    value["findings"] = [finding] if outcome in {"reported", "pending"} else []
    if outcome == "pending":
        value["coverage"]["deferred"][0]["provenance"] = {"workerId": worker_id}
        return value
    value["coverage"].update(completeness="complete", deferred=[])
    if outcome in {"rejected", "not_applicable"}:
        value["coverage"]["explicitExclusions" if outcome == "not_applicable" else "surfaces"] = [
            {
                "id": "saved-validation",
                "label": "Saved candidate validation",
                "candidateId": "candidate-1",
                "disposition": outcome,
                **({"pattern": "clean.ts"} if outcome == "not_applicable" else {}),
                "reason": "The existing control prevents the candidate.",
                "receiptRefs": [],
                "provenance": {"workerId": worker_id},
            }
        ]
    return value


@pytest.mark.parametrize(
    ("previous_outcome", "outcome", "previous_owner", "owner"),
    [
        ("pending", "reported", "worker", "root"),
        ("pending", "rejected", "root", "worker"),
        ("pending", "not_applicable", "worker", "worker"),
        ("reported", "pending", "worker", "root"),
        ("rejected", "pending", "root", "worker"),
        ("not_applicable", "pending", "root", "root"),
        ("reported", "rejected", "root", "worker"),
        ("rejected", "reported", "worker", "root"),
        ("not_applicable", "reported", "worker", "worker"),
    ],
)
def test_next_continuation_keeps_latest_validation_decision(
    tmp_path: Path, previous_outcome: str, outcome: str, previous_owner: str, owner: str
):
    state, repository, _, _, child, child_id, worker_id, finding = continued_candidate(
        tmp_path, other_pending=True
    )
    output = child / "artifacts/deep_discovery/workers/discovery-0004/output"
    save(
        state,
        child_id,
        write_checkpoint(
            (output if previous_owner == "worker" else child) / "checkpoints",
            decision(child_id, worker_id, finding, previous_outcome),
        ),
    )
    resolved = decision(child_id, worker_id, finding, outcome)
    save(
        state,
        child_id,
        write_checkpoint((output if owner == "worker" else child) / "checkpoints", resolved),
    )
    recipe = run_workbench(state, "get-scan-recipe", "--scan-id", child_id)["recipe"]
    grandchild = tmp_path / "grandchild"
    grandchild.mkdir(mode=0o700)
    grandchild_id = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(grandchild),
        "--recipe-json",
        json.dumps(recipe),
        "--parent-scan-id",
        child_id,
    )["scanId"]
    run_workbench(
        state, "continue-scan-checkpoint", "--scan-id", grandchild_id, "--parent-scan-id", child_id
    )
    coverage = json.loads((grandchild / "coverage.json").read_text())
    findings = json.loads((grandchild / "findings.json").read_text())["findings"]
    continued_worker_id = str(uuid.uuid5(uuid.UUID(grandchild_id), worker_id))
    deferred = coverage["deferred"]
    pending_owners = {item["provenance"]["workerId"] for item in deferred}
    assert len(pending_owners) == (2 if outcome == "pending" else 1)
    assert (continued_worker_id in pending_owners) == (outcome == "pending")
    assert all(item["candidateId"] == "candidate-1" for item in deferred)
    assert any(item["provenance"]["workerId"] != continued_worker_id for item in deferred)
    assert len(findings) == (1 if outcome in {"reported", "pending"} else 0)
    if findings:
        assert findings[0]["codeEvidence"] == finding["codeEvidence"]
    dispositions = {
        item["disposition"]
        for field in ("surfaces", "explicitExclusions")
        for item in coverage[field]
        if item.get("candidateId") == "candidate-1"
        and item.get("provenance", {}).get("workerId") == continued_worker_id
    }
    assert dispositions == ({outcome} if outcome in {"rejected", "not_applicable"} else set())
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT status, completion_sequence FROM deep_scan_workers WHERE id = ?",
            (continued_worker_id,),
        ).fetchone() == ("queued", None)
        worker_path = Path(
            connection.execute(
                "SELECT artifact_dir FROM deep_scan_workers WHERE id = ?",
                (str(uuid.uuid5(uuid.UUID(grandchild_id), worker_id)),),
            ).fetchone()[0]
        )
    head = json.loads((worker_path / "checkpoint-head.json").read_text())
    worker_checkpoint = json.loads((worker_path / "checkpoints" / head["checkpoint"]).read_text())
    pending = worker_checkpoint["coverage"]["deferred"]
    assert bool(pending) == (outcome == "pending")
    if pending:
        assert pending[0]["candidate"] == resolved["coverage"]["deferred"][0]["candidate"]
        assert worker_checkpoint["findings"][0]["codeEvidence"] == finding["codeEvidence"]
    assert worker_checkpoint["coverage"]["reviewedFiles"] == (
        ["clean.ts", "pending.ts"] if "worker" in {owner, previous_owner} else ["clean.ts"]
    )
    assert worker_checkpoint["complete"] is False


@pytest.mark.parametrize(
    ("worker_outcome", "root_pending"),
    [("rejected", False), ("reported", True), ("not_applicable", True)],
)
def test_finalization_keeps_current_root_or_completed_worker_decision(
    tmp_path: Path, worker_outcome: str, root_pending: bool
):
    state, repository, _, _, child, child_id, worker_id, finding = continued_candidate(tmp_path)
    output = child / "artifacts/deep_discovery/workers/discovery-0004/output"
    resolved = decision(child_id, worker_id, finding, worker_outcome)
    resolved["complete"] = True
    save(state, child_id, write_checkpoint(output / "checkpoints", resolved))
    result = output / "result.json"
    result.write_text(json.dumps(resolved))
    arguments = (
        "--scan-id",
        child_id,
        "--worker-id",
        worker_id,
        "--kind",
        "discovery",
        "--prompt-path",
        str(output.parent / "prompt.md"),
        "--artifact-dir",
        str(output),
        "--attempt",
        "1",
    )
    run_workbench(state, "upsert-deep-scan-worker", *arguments, "--status", "running")
    run_workbench(
        state,
        "upsert-deep-scan-worker",
        *arguments,
        "--status",
        "succeeded",
        "--result-manifest-path",
        str(result),
    )
    write_completed_contract(child, child_id, repository, relative_path="clean.ts")
    findings = json.loads((child / "findings.json").read_text())
    findings["findings"] = [finding] if root_pending else []
    (child / "findings.json").write_text(json.dumps(findings))
    coverage = json.loads((child / "coverage.json").read_text())
    coverage.update(completeness="complete", surfaces=[], explicitExclusions=[], deferred=[])
    if root_pending:
        coverage.update(decision(child_id, worker_id, finding, "pending")["coverage"])
        coverage["deferred"][0]["id"] = "saved-pending"
    (child / "coverage.json").write_text(json.dumps(coverage))
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET status = 'succeeded', phase = 'terminal', manifest_path = ? WHERE scan_id = ?",
            (str(child / "scan-manifest.json"), child_id),
        )
    run_workbench(state, "prepare-scan-completion", "--scan-id", child_id)
    findings = json.loads((child / "findings.json").read_text())["findings"]
    coverage = json.loads((child / "coverage.json").read_text())
    if root_pending:
        assert findings[0]["codeEvidence"] == finding["codeEvidence"]
        assert coverage["completeness"] == "partial"
        assert {item["candidateId"] for item in coverage["deferred"]} == {"candidate-1"}
        assert not any(
            item.get("disposition") in {"reported", "rejected", "not_applicable"}
            for field in ("surfaces", "explicitExclusions")
            for item in coverage[field]
        )
    else:
        assert findings == []
        assert coverage["completeness"] == "complete"
        assert coverage["deferred"] == []
        assert any(item.get("disposition") == "rejected" for item in coverage["surfaces"])


def test_archived_deep_checkpoint_rebases_worker_paths_and_can_continue(tmp_path: Path):
    state, repository, parent, parent_id, _, _, _, _ = continued_candidate(tmp_path)
    original = {
        path.relative_to(parent): path.read_bytes() for path in parent.rglob("*") if path.is_file()
    }
    archive = parent.with_name(parent.name + ".previous-test")
    parent.rename(archive)
    parent.mkdir(mode=0o700)
    recipe = run_workbench(state, "get-scan-recipe", "--scan-id", parent_id)["recipe"]
    run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(parent),
        "--recipe-json",
        json.dumps(recipe),
        "--archive-existing",
        "--archived-scan-dir",
        str(archive),
    )
    resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", parent_id)
    assert resumed["checkpoint"] is not None
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        for paths in connection.execute(
            "SELECT prompt_path, artifact_dir, result_manifest_path FROM deep_scan_workers WHERE scan_id = ?",
            (parent_id,),
        ):
            assert all(Path(value).is_relative_to(archive) for value in paths if value is not None)
    child = tmp_path / "archived-child"
    child.mkdir(mode=0o700)
    child_id = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(child),
        "--recipe-json",
        json.dumps(recipe),
        "--parent-scan-id",
        parent_id,
    )["scanId"]
    continued = run_workbench(
        state, "continue-scan-checkpoint", "--scan-id", child_id, "--parent-scan-id", parent_id
    )
    assert continued["restoredWorkers"] == 5
    assert json.loads((child / "findings.json").read_text())["findings"]
    assert original == {
        path.relative_to(archive): path.read_bytes()
        for path in archive.rglob("*")
        if path.is_file()
    }
