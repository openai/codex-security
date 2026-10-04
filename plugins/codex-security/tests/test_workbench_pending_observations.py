from __future__ import annotations

import copy
import hashlib
import json
import os
import uuid
from pathlib import Path

import pytest
from test_workbench_checkpoint_heads import saved, select
from workbench_test_support import (
    register,
    run_workbench,
    saved_binding,
    saved_draft,
    write_checkpoint,
    write_completed_contract,
)


@pytest.mark.parametrize("history_written", [False, True])
def test_pending_recovery_uses_publication_time_after_earlier_staging(
    tmp_path: Path, history_written: bool
) -> None:
    scan_id = "pending-observation"
    pending = {"id": "review", "reason": "New evidence reopened the review."}
    reopened = saved_draft(scan_id, deferred=[pending])
    closed = saved_draft(
        scan_id,
        complete=True,
        closures=[{"id": "review", "reason": "Earlier review completed."}],
    )
    accepted = write_checkpoint(tmp_path / "checkpoints", closed)
    os.utime(accepted, ns=(200, 200))
    select(tmp_path, accepted, 200)
    (tmp_path / "checkpoints/pending").mkdir()
    stage = tmp_path / "drafts" / f"{uuid.uuid4()}.checkpoint.json"
    stage.parent.mkdir()
    contents = json.dumps(reopened).encode()
    stage.write_bytes(contents)
    os.utime(stage, ns=(100, 100))
    name = hashlib.sha256(contents).hexdigest() + ".json"
    marker = tmp_path / "checkpoints/pending" / name
    marker.write_text(stage.relative_to(tmp_path).as_posix())
    os.utime(marker, ns=(300, 300))
    if history_written:
        history = tmp_path / "checkpoints" / name
        history.write_bytes(contents)
        os.utime(history, ns=(300, 300))
    documents = saved.merge_saved_results(
        tmp_path, scan_id, saved_binding(), [], stopped=True, reason="interrupted"
    )
    assert pending in documents[2]["deferred"]
    assert not documents[2].get("resolvedDeferred")


@pytest.mark.parametrize("disposition", ["rejected", "not_applicable", "reported"])
@pytest.mark.parametrize("implicit_complete", [False, True])
def test_conflicted_terminal_decision_is_not_admitted_to_pending_history(
    tmp_path: Path, disposition: str, implicit_complete: bool
) -> None:
    target, state, scan_dir = tmp_path / "target", tmp_path / "state", tmp_path / "scan"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    scan = register(state, target, scan_dir)
    write_completed_contract(scan_dir, scan["scanId"], target, relative_path="app.py")
    documents = {
        key: json.loads((scan_dir / name).read_text())
        for key, name in (
            ("manifest", "scan-manifest.json"),
            ("findings", "findings.json"),
            ("coverage", "coverage.json"),
        )
    }
    documents["findings"]["findings"][0]["provenance"]["candidateId"] = "accepted-candidate"
    finding = copy.deepcopy(documents["findings"]["findings"][0])
    if disposition == "reported":
        documents["findings"]["findings"] = []
        documents["coverage"]["surfaces"] = [
            {
                "id": "accepted-candidate",
                "candidateId": "accepted-candidate",
                "label": "Accepted rejection",
                "disposition": "rejected",
                "finding": copy.deepcopy(finding),
            }
        ]
    stages = scan_dir / "drafts"
    stages.mkdir()
    draft = stages / f"{uuid.uuid4()}.json"
    draft.write_text(json.dumps(documents))
    run_workbench(
        state, "write-scan-draft", "--scan-id", scan["scanId"], "--draft-path", str(draft)
    )
    accepted_head = (scan_dir / "artifacts/scan-draft.json").read_bytes()
    (scan_dir / "checkpoints/pending").mkdir(parents=True, exist_ok=True)
    decision = {
        "id": "accepted-candidate",
        "candidateId": "accepted-candidate",
        "label": "Candidate review",
        "disposition": disposition,
    }
    incoming = copy.deepcopy(documents)
    incoming["findings"]["findings"] = [finding] if disposition == "reported" else []
    incoming["coverage"]["surfaces"] = [] if disposition == "reported" else [decision]
    draft.write_text(json.dumps(incoming))
    checkpoint = stages / f"{uuid.uuid4()}.checkpoint.json"
    checkpoint.write_text(
        json.dumps(
            saved_draft(
                scan["scanId"],
                complete=True,
                surfaces=[] if disposition == "reported" else [decision],
                findings=[finding] if disposition == "reported" else [],
            )
        )
    )
    if implicit_complete:
        payload = json.loads(checkpoint.read_text())
        payload.pop("complete")
        checkpoint.write_text(json.dumps(payload))
    checkpoint_bytes = checkpoint.read_bytes()
    name = hashlib.sha256(checkpoint_bytes).hexdigest() + ".json"
    arguments = [
        "write-scan-draft",
        "--scan-id",
        scan["scanId"],
        "--draft-path",
        str(draft),
        "--checkpoint-path",
        str(checkpoint),
    ]
    conflict = run_workbench(state, *arguments, "--expected-draft-digest", "0" * 64, check=False)
    assert "scan_draft_conflict" in conflict["stderr"]
    assert (scan_dir / "artifacts/scan-draft.json").read_bytes() == accepted_head
    assert checkpoint.read_bytes() == checkpoint_bytes
    recovered = saved.merge_saved_results(
        scan_dir, scan["scanId"], saved_binding(), [], stopped=True, reason="interrupted"
    )
    if disposition == "reported":
        assert recovered[1]["findings"] == []
        assert any(row.get("disposition") == "rejected" for row in recovered[2]["surfaces"])
    else:
        assert recovered[1]["findings"]
    assert not (scan_dir / "checkpoints/pending" / name).exists()
    assert not (scan_dir / "checkpoints" / name).exists()
    draft.write_text(json.dumps(incoming))
    run_workbench(state, *arguments)
    assert bool(json.loads((scan_dir / "findings.json").read_text())["findings"]) == (
        disposition == "reported"
    )
    assert (scan_dir / "checkpoints" / name).read_bytes() == checkpoint_bytes
    assert not checkpoint.exists()


@pytest.mark.parametrize("action", ["fail-scan", "cancel-scan"])
def test_stopping_after_acknowledged_progress_retains_completed_tasks(
    tmp_path: Path, action: str
) -> None:
    target, state, scan_dir = tmp_path / "target", tmp_path / "state", tmp_path / "scan"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    scan = register(state, target, scan_dir)
    write_completed_contract(scan_dir, scan["scanId"], target, relative_path="app.py")
    documents = {
        key: json.loads((scan_dir / name).read_text())
        for key, name in (
            ("manifest", "scan-manifest.json"),
            ("findings", "findings.json"),
            ("coverage", "coverage.json"),
        )
    }
    closure = {"id": "review", "reason": "Review completed."}
    remaining = {"id": "other", "reason": "Other work remains."}
    documents["coverage"].update(
        completeness="partial", deferred=[remaining], resolvedDeferred=[closure]
    )
    stages = scan_dir / "drafts"
    stages.mkdir()
    for index, complete in enumerate((True, False, False)):
        documents["manifest"]["scan"]["complete"] = complete
        documents["coverage"]["openQuestions"] = [f"Progress update {index}"]
        stage = stages / f"{uuid.uuid4()}.json"
        stage.write_text(json.dumps(documents))
        run_workbench(
            state, "write-scan-draft", "--scan-id", scan["scanId"], "--draft-path", str(stage)
        )
    assert not list((scan_dir / "checkpoints/pending").glob("*.json"))
    run_workbench(
        state,
        action,
        "--scan-id",
        scan["scanId"],
        *(("--message", "Synthetic interruption") if action == "fail-scan" else ()),
    )
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert coverage["resolvedDeferred"] == [closure]
    assert remaining in coverage["deferred"]


@pytest.mark.parametrize("coverage_mode", ["repository", "diff"])
def test_committed_progress_retains_closures(tmp_path: Path, coverage_mode: str) -> None:
    scan_id = "accepted-progress"
    closure = {"id": "review", "reason": "Review completed."}
    remaining = {"id": "other", "reason": "Other work remains."}
    progress = saved_draft(scan_id, deferred=[remaining], closures=[closure])
    checkpoint = write_checkpoint(tmp_path / "checkpoints", progress)
    select(tmp_path, checkpoint, 200)
    (tmp_path / "checkpoints/pending").mkdir()
    documents = saved.merge_saved_results(
        tmp_path, scan_id, saved_binding(coverage_mode), [], stopped=True, reason="interrupted"
    )
    assert documents[2]["resolvedDeferred"] == [closure]
    assert remaining in documents[2]["deferred"]


@pytest.mark.parametrize("terminal", [False, True])
def test_pending_progress_preserves_accepted_assessment_and_new_evidence(
    tmp_path: Path, terminal: bool
) -> None:
    scan_id = "accepted-assessment"
    target = tmp_path / "repository"
    target.mkdir()
    write_completed_contract(tmp_path, scan_id, target, relative_path="app.py")
    accepted = json.loads((tmp_path / "findings.json").read_text())["findings"][0]
    accepted["provenance"]["candidateId"] = "accepted-candidate"
    accepted["severity"]["level"] = "low"
    accepted["remediation"] = "Accepted repair."
    task = {"id": "independent-review", "reason": "Review remains."}
    current = saved_draft(scan_id, findings=[accepted], deferred=[task], complete=terminal)
    selected = write_checkpoint(tmp_path / "checkpoints", current)
    select(tmp_path, selected, 100)
    incoming = copy.deepcopy(accepted)
    incoming["severity"]["level"] = "high"
    incoming["remediation"] = "Pending review repair."
    novel = copy.deepcopy(incoming)
    novel["ruleId"] = "fixture.independent"
    novel["identity"]["anchor"] = "independent-review"
    novel["provenance"]["candidateId"] = "new-candidate"
    checkpoint = write_checkpoint(
        tmp_path / "checkpoints", saved_draft(scan_id, findings=[incoming, novel], deferred=[task])
    )
    pending = tmp_path / "checkpoints/pending"
    pending.mkdir()
    (pending / checkpoint.name).write_bytes(checkpoint.read_bytes())
    os.utime(checkpoint, ns=(200, 200))
    binding = saved_binding()
    binding["target"]["targetId"] = "synthetic-target"
    first = saved.merge_saved_results(
        tmp_path, scan_id, binding, [], stopped=True, reason="interrupted"
    )
    assert len(first[1]["findings"]) == 2
    retained = next(
        f
        for f in first[1]["findings"]
        if f["provenance"].get("candidateId") == "accepted-candidate"
    )
    assert retained["severity"]["level"] == ("low" if terminal else "high")
    assert task in first[2]["deferred"]
    assert any(f["provenance"].get("candidateId") == "new-candidate" for f in first[1]["findings"])
    assert retained["provenance"]["previousFindings"]
