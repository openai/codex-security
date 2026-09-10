from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path

import pytest
from test_workbench_continuation_decisions import continued_candidate, decision
from test_workbench_scan_checkpoints import save, scan_fixture, semantic
from test_workbench_unsealed_continuation import continue_scan, scan_bytes
from workbench_test_support import write_checkpoint, write_completed_contract


@pytest.mark.parametrize("outcome", ["reported", "rejected", "not_applicable", "pending"])
def test_continuation_resolves_retained_fallback_id_with_accepted_decision(
    tmp_path: Path, outcome: str
) -> None:
    state, repository, parent, parent_id = scan_fixture(tmp_path)
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, parent_id, repository, relative_path="clean.ts")
    finding = json.loads((contract / "findings.json").read_text())["findings"][0]
    finding["extensions"] = {"candidateId": "candidate-1"}
    raw = semantic(parent_id, ["clean.ts", "pending.ts"])
    raw["findings"] = [finding]
    raw["coverage"]["deferred"] = (
        [] if outcome == "pending" else [{"id": "candidate-1", "reason": "Validation pending"}]
    )
    # The process saved this evidence without publishing or accepting its head.
    write_checkpoint(parent / "checkpoints", raw)
    reviewed = ["clean.ts"] if outcome == "rejected" else ["clean.ts", "pending.ts"]
    accepted = semantic(parent_id, reviewed)
    accepted["complete"] = outcome != "pending"
    accepted["coverage"].update(
        completeness="partial" if outcome == "pending" else "complete", deferred=[]
    )
    if outcome in {"reported", "pending"}:
        accepted["findings"] = [finding]
    if outcome == "pending":
        accepted["coverage"]["deferred"] = [{"id": "candidate-1", "reason": "Validation pending"}]
    elif outcome != "reported":
        accepted["coverage"][
            "explicitExclusions" if outcome == "not_applicable" else "surfaces"
        ] = [
            {
                "id": "candidate-1",
                "label": "Candidate validation",
                "disposition": outcome,
                "reason": "The source control prevents this candidate.",
                "receiptRefs": [],
                **({"pattern": "clean.ts"} if outcome == "not_applicable" else {}),
            }
        ]
    save(state, parent_id, write_checkpoint(parent / "checkpoints", accepted))
    original = scan_bytes(parent)
    child = tmp_path / "child"
    _, result = continue_scan(state, repository, parent_id, child)
    coverage = json.loads((child / "coverage.json").read_text())
    findings = json.loads((child / "findings.json").read_text())["findings"]
    assert bool(coverage["deferred"]) == (outcome == "pending")
    assert len(findings) == (1 if outcome in {"reported", "pending"} else 0)
    assert result["completionReady"] == (outcome in {"reported", "not_applicable"})
    assert result["checkpoint"]["reviewedFiles"] == reviewed
    assert result["checkpoint"]["remainingFiles"] == (
        ["pending.ts"] if outcome == "rejected" else []
    )
    if outcome == "rejected":
        rejected = next(row for row in coverage["surfaces"] if row["disposition"] == "rejected")
        assert rejected["previousFindings"][0]["codeEvidence"] == finding["codeEvidence"]
    assert scan_bytes(parent) == original


def test_fallback_ids_remain_owned_when_continuation_renames_coverage_rows(tmp_path: Path) -> None:
    state, repository, _, _, child, child_id, _, _ = continued_candidate(
        tmp_path, other_pending=True
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        workers = connection.execute(
            "SELECT id, artifact_dir FROM deep_scan_workers WHERE scan_id = ? AND status = 'queued'",
            (child_id,),
        ).fetchall()
    assert len(workers) == 2
    for worker_id, directory in workers:
        output = Path(directory)
        head = json.loads((output / "checkpoint-head.json").read_text())
        pending = json.loads((output / "checkpoints" / head["checkpoint"]).read_text())
        pending["coverage"]["deferred"] = [
            {
                "id": "candidate-1",
                "reason": "Validation pending",
                "provenance": {"workerId": worker_id},
            }
        ]
        save(state, child_id, write_checkpoint(output / "checkpoints", pending))
    grandchild = tmp_path / "grandchild"
    grandchild_id, _ = continue_scan(state, repository, child_id, grandchild)
    pending = json.loads((grandchild / "coverage.json").read_text())["deferred"]
    assert len(pending) == 2
    assert len({row["id"] for row in pending}) == 2
    assert {row.get("candidateId", row["id"]) for row in pending} == {"candidate-1"}
    renamed = next(row for row in pending if row["id"] != "candidate-1")
    owner = renamed["provenance"]["workerId"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        output = Path(
            connection.execute(
                "SELECT artifact_dir FROM deep_scan_workers WHERE id = ?", (owner,)
            ).fetchone()[0]
        )
    raw = semantic(grandchild_id, [])
    raw["coverage"]["deferred"] = [
        {
            "id": "candidate-1",
            "reason": "Retained before model exit",
            "provenance": {"workerId": owner},
        }
    ]
    write_checkpoint(output / "checkpoints", raw)
    resolved = decision(grandchild_id, owner, {}, "rejected")
    row = resolved["coverage"]["surfaces"][0]
    row["id"] = row.pop("candidateId")
    save(state, grandchild_id, write_checkpoint(grandchild / "checkpoints", resolved))
    original = scan_bytes(grandchild)
    final = tmp_path / "final"
    final_id, _ = continue_scan(state, repository, grandchild_id, final)
    coverage = json.loads((final / "coverage.json").read_text())
    resolved_owner = str(uuid.uuid5(uuid.UUID(final_id), owner))
    assert len(coverage["deferred"]) == 1
    assert coverage["deferred"][0]["provenance"]["workerId"] != resolved_owner
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        status, sequence, directory = connection.execute(
            "SELECT status, completion_sequence, artifact_dir FROM deep_scan_workers WHERE id = ?",
            (resolved_owner,),
        ).fetchone()
    assert (status, sequence) == ("queued", None)
    output = Path(directory)
    head = json.loads((output / "checkpoint-head.json").read_text())
    checkpoint = json.loads((output / "checkpoints" / head["checkpoint"]).read_text())
    assert checkpoint["coverage"]["deferred"] == []
    assert any(row["disposition"] == "rejected" for row in checkpoint["coverage"]["surfaces"])
    assert scan_bytes(grandchild) == original
