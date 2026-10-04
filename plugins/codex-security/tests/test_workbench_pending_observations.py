from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import uuid
from pathlib import Path

import pytest
from test_workbench_checkpoint_heads import saved, select
from test_workbench_saved_source_order import call_workbench
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
    (tmp_path / "checkpoints/pending" / accepted.name).unlink()
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
@pytest.mark.parametrize("indexed_history", [False, True])
@pytest.mark.parametrize("implicit_complete", [False, True])
def test_conflicted_terminal_decision_is_not_admitted_to_pending_history(
    tmp_path: Path, disposition: str, indexed_history: bool, implicit_complete: bool
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
    accepted_head = (scan_dir / "checkpoint-head.json").read_bytes()
    if indexed_history:
        (scan_dir / "checkpoints/pending").mkdir(exist_ok=True)
    else:
        (scan_dir / "checkpoints/pending").rmdir()
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
    assert (scan_dir / "checkpoint-head.json").read_bytes() == accepted_head
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
    run_workbench(state, *arguments)
    assert bool(json.loads((scan_dir / "findings.json").read_text())["findings"]) == (
        disposition == "reported"
    )
    assert (scan_dir / "checkpoints" / name).read_bytes() == checkpoint_bytes
    assert not checkpoint.exists()


@pytest.mark.parametrize("layout", ["canonical", "head", "tied", "unaccepted"])
@pytest.mark.parametrize("coverage_mode", ["repository", "diff"])
def test_indexed_recovery_retains_closures_in_accepted_progress(
    tmp_path: Path, layout: str, coverage_mode: str
) -> None:
    from test_workbench_standard_deep_results import write_saved_parent

    scan_id = "accepted-progress"
    closure = {"id": "review", "reason": "Review completed."}
    remaining = {"id": "other", "reason": "Other work remains."}
    progress = saved_draft(scan_id, deferred=[remaining], closures=[closure])
    checkpoint = write_checkpoint(tmp_path / "checkpoints", progress)
    os.utime(checkpoint, ns=(200, 200))
    if layout != "unaccepted":
        (tmp_path / "checkpoints/pending" / checkpoint.name).unlink()
    if layout in {"head", "tied"}:
        select(tmp_path, checkpoint, 200)
    if layout in {"canonical", "tied"}:
        canonical = copy.deepcopy(progress)
        canonical["coverage"]["openQuestions"] = ["Separate saved observation"]
        write_saved_parent(tmp_path, canonical, 200)
    documents = saved.merge_saved_results(
        tmp_path,
        scan_id,
        saved_binding(coverage_mode),
        [],
        stopped=True,
        reason="interrupted",
    )
    assert documents[2].get("resolvedDeferred", []) == ([] if layout == "unaccepted" else [closure])
    assert remaining in documents[2]["deferred"]


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
    assert not list((scan_dir / "checkpoints/pending").iterdir())
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


@pytest.mark.parametrize(
    "terminal,frozen_retry,rejected_terminal",
    [
        (False, None, False),
        (False, None, True),
        (True, None, False),
        (True, "unreadable", False),
        (True, "new_terminal", False),
    ],
)
@pytest.mark.parametrize("action", ["fail-scan", "cancel-scan"])
def test_conflicted_progress_preserves_accepted_assessment_and_new_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    terminal: bool,
    frozen_retry: str | None,
    rejected_terminal: bool,
    action: str,
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
    documents["manifest"]["scan"]["complete"] = terminal
    accepted = documents["findings"]["findings"][0]
    accepted["provenance"]["candidateId"] = "accepted-candidate"
    accepted["severity"]["level"] = "low"
    accepted["remediation"] = "Accepted repair."
    task = {"id": "independent-review", "reason": "Review remains."}
    documents["coverage"].update(completeness="partial", deferred=[task])
    stages = scan_dir / "drafts"
    stages.mkdir()
    draft = stages / f"{uuid.uuid4()}.json"
    draft.write_text(json.dumps(documents))
    run_workbench(
        state, "write-scan-draft", "--scan-id", scan["scanId"], "--draft-path", str(draft)
    )
    terminal_path = (
        scan_dir
        / "checkpoints"
        / json.loads((scan_dir / "checkpoint-head.json").read_text())["checkpoint"]
    )
    terminal_bytes = terminal_path.read_bytes()
    if frozen_retry:
        documents["manifest"]["scan"]["complete"] = False
        draft.write_text(json.dumps(documents))
        run_workbench(
            state, "write-scan-draft", "--scan-id", scan["scanId"], "--draft-path", str(draft)
        )
    accepted_head = (scan_dir / "checkpoint-head.json").read_bytes()
    checkpoint_dir = scan_dir / "checkpoints"
    accepted_bytes = {p.name: p.read_bytes() for p in checkpoint_dir.glob("*.json")}
    if rejected_terminal:
        unaccepted = stages / f"{uuid.uuid4()}.checkpoint.json"
        unaccepted.write_text(
            json.dumps(saved_draft(scan["scanId"], complete=True, findings=[accepted]))
        )
        unaccepted_bytes = unaccepted.read_bytes()
        rejected = run_workbench(
            state,
            "write-scan-draft",
            "--scan-id",
            scan["scanId"],
            "--draft-path",
            str(draft),
            "--checkpoint-path",
            str(unaccepted),
            "--expected-draft-digest",
            "0" * 64,
            check=False,
        )
        assert "scan_draft_conflict" in rejected["stderr"]
        assert unaccepted.read_bytes() == unaccepted_bytes
        assert {p.name: p.read_bytes() for p in checkpoint_dir.glob("*.json")} == accepted_bytes
    incoming = copy.deepcopy(accepted)
    incoming["severity"]["level"] = "high"
    incoming["remediation"] = "Unaccepted progress repair."
    novel = copy.deepcopy(incoming)
    novel["ruleId"] = "fixture.new-review"
    novel["identity"]["anchor"] = "independent-new-review"
    novel["provenance"]["candidateId"] = "new-candidate"
    checkpoint = stages / f"{uuid.uuid4()}.checkpoint.json"
    checkpoint.write_text(
        json.dumps(saved_draft(scan["scanId"], findings=[incoming, novel], deferred=[task]))
    )
    checkpoint_bytes = checkpoint.read_bytes()
    name = hashlib.sha256(checkpoint_bytes).hexdigest() + ".json"
    conflict = run_workbench(
        state,
        "write-scan-draft",
        "--scan-id",
        scan["scanId"],
        "--draft-path",
        str(draft),
        "--checkpoint-path",
        str(checkpoint),
        "--expected-draft-digest",
        "0" * 64,
        check=False,
    )
    assert "scan_draft_conflict" in conflict["stderr"]
    assert (scan_dir / "checkpoint-head.json").read_bytes() == accepted_head
    stop_args = [
        action,
        "--scan-id",
        scan["scanId"],
        *(("--message", "Synthetic interruption") if action == "fail-scan" else ()),
    ]
    if frozen_retry:
        home = tmp_path / "home"
        home.mkdir()

        def fail_publication(prepared, **_kwargs):
            retained = next(
                f
                for f in prepared[3]["findings"]
                if f["provenance"].get("candidateId") == "accepted-candidate"
            )
            assert retained["severity"]["level"] == "low"
            raise OSError("Synthetic publication failure")

        with monkeypatch.context() as patch:
            patch.setattr(saved, "_write_prepared_scan_finalization", fail_publication)
            call_workbench(patch, state, home, *stop_args)
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            frozen = json.loads(
                connection.execute(
                    "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan["scanId"],)
                ).fetchone()[0]
            )
        assert terminal_path.relative_to(scan_dir).as_posix() not in frozen
        frozen_bytes = {relative: (scan_dir / relative).read_bytes() for relative in frozen}
        if frozen_retry == "unreadable":
            terminal_path.write_text("{unreadable historical checkpoint")
            run_workbench(state, "preserve-scan-results", "--scan-id", scan["scanId"])
            assert terminal_path.read_text() == "{unreadable historical checkpoint"
            terminal_path.write_bytes(terminal_bytes)
        elif action == "cancel-scan":
            refused = run_workbench(
                state, "recover-scan-results", "--scan-id", scan["scanId"], check=False
            )
            assert "Canceled scans cannot recover terminal results" in refused["stderr"]
            run_workbench(state, "preserve-scan-results", "--scan-id", scan["scanId"])
        else:
            replacement = copy.deepcopy(accepted)
            replacement["severity"]["level"] = "medium"
            replacement["remediation"] = "New terminal repair."
            replacement_draft = saved_draft(
                scan["scanId"], complete=True, findings=[replacement], deferred=[task]
            )
            replacement_draft["coverage"] = copy.deepcopy(documents["coverage"])
            selected = write_checkpoint(checkpoint_dir, replacement_draft)
            observed = (
                max(path.stat().st_mtime_ns for path in checkpoint_dir.glob("*.json")) + 1_000_000
            )
            select(scan_dir, selected, observed)
            run_workbench(state, "recover-scan-results", "--scan-id", scan["scanId"])
        assert {relative: (scan_dir / relative).read_bytes() for relative in frozen} == frozen_bytes
    else:
        run_workbench(state, *stop_args)
    findings = json.loads((scan_dir / "findings.json").read_text())["findings"]
    retained = next(
        f for f in findings if f["provenance"].get("candidateId") == "accepted-candidate"
    )
    replaced_terminal = frozen_retry == "new_terminal" and action == "fail-scan"
    assert retained["severity"]["level"] == (
        "medium" if replaced_terminal else "low" if terminal else "high"
    )
    assert retained["remediation"] == (
        "New terminal repair."
        if replaced_terminal
        else "Accepted repair."
        if terminal
        else "Unaccepted progress repair."
    )
    assert len(findings) == 2
    assert any(f["provenance"].get("candidateId") == "new-candidate" for f in findings)
    assert any(
        f["remediation"] == ("Unaccepted progress repair." if terminal else "Accepted repair.")
        for f in retained["provenance"]["previousFindings"]
    )
    assert task in json.loads((scan_dir / "coverage.json").read_text())["deferred"]
    assert (checkpoint_dir / name).read_bytes() == checkpoint_bytes
    assert checkpoint.read_bytes() == checkpoint_bytes
    for filename, contents in accepted_bytes.items():
        assert (checkpoint_dir / filename).read_bytes() == contents
    preserved = {
        name: (scan_dir / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json")
    }
    run_workbench(state, "preserve-scan-results", "--scan-id", scan["scanId"])
    assert {name: (scan_dir / name).read_bytes() for name in preserved} == preserved
