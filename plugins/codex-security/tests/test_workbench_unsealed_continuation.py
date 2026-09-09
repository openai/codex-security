from __future__ import annotations

import copy
import json
import sqlite3
from pathlib import Path

import pytest
from test_workbench_scan_checkpoints import save, scan_fixture, semantic
from workbench_test_support import run_workbench, write_checkpoint, write_completed_contract


def continue_scan(state: Path, repository: Path, parent: str, directory: Path):
    recipe = run_workbench(state, "get-scan-recipe", "--scan-id", parent)["recipe"]
    directory.mkdir(mode=0o700)
    child = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(directory),
        "--recipe-json",
        json.dumps(recipe),
        "--parent-scan-id",
        parent,
    )["scanId"]
    result = run_workbench(
        state, "continue-scan-checkpoint", "--scan-id", child, "--parent-scan-id", parent
    )
    return child, result


def scan_bytes(directory: Path):
    return {
        path.relative_to(directory): path.read_bytes()
        for path in directory.rglob("*")
        if path.is_file()
    }


@pytest.mark.parametrize("pending_validation", [False, True])
def test_complete_continuation_keeps_unsealed_canonical_finding_without_changing_parent(
    tmp_path: Path,
    pending_validation: bool,
) -> None:
    state, repository, parent, parent_id = scan_fixture(tmp_path)
    accepted = semantic(parent_id, ["clean.ts", "pending.ts"])
    accepted["complete"] = True
    accepted["coverage"].update(completeness="complete", deferred=[])
    save(state, parent_id, write_checkpoint(parent / "checkpoints", accepted))
    # Custom discovery can publish canonical documents after its last accepted
    # checkpoint. An interruption must not discard that saved evidence.
    write_completed_contract(parent, parent_id, repository, relative_path="clean.ts")
    if pending_validation:
        coverage = json.loads((parent / "coverage.json").read_text())
        coverage["deferred"] = [
            {
                "id": "fresh-validation",
                "candidateId": "fresh-candidate",
                "reason": "The newly discovered candidate still needs validation.",
            }
        ]
        (parent / "coverage.json").write_text(json.dumps(coverage))
    original = scan_bytes(parent)
    finding = json.loads((parent / "findings.json").read_text())["findings"][0]
    child_dir = tmp_path / "child"
    child, result = continue_scan(state, repository, parent_id, child_dir)
    assert result["checkpoint"]["reviewedFiles"] == ["clean.ts", "pending.ts"]
    assert result["checkpoint"]["remainingFiles"] == []
    assert result["completionReady"] is not pending_validation
    assert result["checkpoint"]["sources"][0]["customValidationComplete"] is False
    assert (
        json.loads((child_dir / "findings.json").read_text())["findings"][0]["codeEvidence"]
        == finding["codeEvidence"]
    )
    if pending_validation:
        deferred = json.loads((child_dir / "coverage.json").read_text())["deferred"]
        assert [item["candidateId"] for item in deferred] == ["fresh-candidate"]
    else:
        run_workbench(state, "prepare-scan-completion", "--scan-id", child)
        completed = run_workbench(state, "complete-scan", "--scan-id", child)["scan"]
        assert completed["progress"]["status"] == "complete"
        assert completed["findingCount"] == 1
    assert scan_bytes(parent) == original


@pytest.mark.parametrize("decision", ["pending", "reported", "rejected"])
def test_unsealed_canonical_evidence_does_not_override_accepted_decision(
    tmp_path: Path, decision: str
) -> None:
    state, repository, parent, parent_id = scan_fixture(tmp_path)
    write_completed_contract(parent, parent_id, repository, relative_path="clean.ts")
    canonical = json.loads((parent / "findings.json").read_text())
    raw = canonical["findings"][0]
    raw["extensions"] = {"candidateId": "candidate-1"}
    (parent / "findings.json").write_text(json.dumps(canonical))
    # The unaccepted canonical publication claims all files were reviewed.
    coverage = json.loads((parent / "coverage.json").read_text())
    coverage["reviewedFiles"] = ["clean.ts", "pending.ts"]
    (parent / "coverage.json").write_text(json.dumps(coverage))
    accepted = semantic(parent_id, ["clean.ts"])
    if decision == "reported":
        updated = copy.deepcopy(raw)
        updated["summary"] = "The accepted validation replaces the earlier discovery."
        updated["provenance"]["previousFindings"] = [copy.deepcopy(raw)]
        accepted["findings"] = [updated]
        accepted["coverage"]["deferred"] = []
    elif decision == "rejected":
        accepted["coverage"].update(
            deferred=[],
            surfaces=[
                {
                    "id": "validated-candidate",
                    "label": "Candidate validation",
                    "candidateId": "candidate-1",
                    "disposition": "rejected",
                    "reason": "The source control prevents the candidate.",
                    "receiptRefs": [],
                }
            ],
        )
    save(state, parent_id, write_checkpoint(parent / "checkpoints", accepted))
    original = scan_bytes(parent)
    child_dir = tmp_path / "child"
    _, result = continue_scan(state, repository, parent_id, child_dir)
    assert result["checkpoint"]["reviewedFiles"] == ["clean.ts"]
    assert result["checkpoint"]["remainingFiles"] == ["pending.ts"]
    assert result["completionReady"] is False
    findings = json.loads((child_dir / "findings.json").read_text())["findings"]
    coverage = json.loads((child_dir / "coverage.json").read_text())
    assert bool(coverage["deferred"]) == (decision == "pending")
    if decision == "rejected":
        assert findings == []
        rejected = next(
            item for item in coverage["surfaces"] if item.get("candidateId") == "candidate-1"
        )
        assert rejected["disposition"] == "rejected"
        assert rejected["previousFindings"][0]["codeEvidence"] == raw["codeEvidence"]
    else:
        assert len(findings) == 1
        assert findings[0]["codeEvidence"] == raw["codeEvidence"]
        if decision == "reported":
            assert findings[0]["summary"] == updated["summary"]
            assert any(
                item["summary"] == raw["summary"]
                for item in findings[0]["provenance"]["previousFindings"]
            )
    assert scan_bytes(parent) == original


@pytest.mark.parametrize("accepted_outcome", ["absent", "reported", "rejected"])
def test_raw_canonical_finding_cannot_inherit_unrelated_custom_validation(
    tmp_path: Path, accepted_outcome: str
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "clean.ts").write_text("export const count = 1;\n")
    state = tmp_path / "state"
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    parent_id = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(parent),
        "--recipe-json",
        json.dumps(
            {
                "repository": str(repository),
                "target": {"kind": "repository", "paths": []},
                "mode": "standard",
                "config": {},
                "validationMode": "custom",
            }
        ),
    )["scanId"]
    write_completed_contract(parent, parent_id, repository, relative_path="clean.ts")
    canonical = json.loads((parent / "findings.json").read_text())
    raw = canonical["findings"][0]
    raw["extensions"] = {"candidateId": "candidate-1"}
    (parent / "findings.json").write_text(json.dumps(canonical))
    accepted = semantic(parent_id, ["clean.ts"])
    accepted["complete"] = True
    accepted["coverage"].update(completeness="complete", deferred=[])
    if accepted_outcome == "reported":
        accepted["findings"] = [copy.deepcopy(raw)]
    elif accepted_outcome == "rejected":
        accepted["coverage"]["surfaces"] = [
            {
                "id": "validated-candidate",
                "label": "Candidate validation",
                "candidateId": "candidate-1",
                "disposition": "rejected",
                "reason": "The custom validator rejected this candidate.",
                "receiptRefs": [],
            }
        ]
    run_workbench(
        state,
        "record-scan-checkpoint",
        "--scan-id",
        parent_id,
        "--checkpoint-path",
        str(write_checkpoint(parent / "checkpoints", accepted)),
        "--custom-validation-complete",
    )
    original = scan_bytes(parent)
    child_dir = tmp_path / "child"
    child_id, result = continue_scan(state, repository, parent_id, child_dir)
    assert result["completionReady"] is True
    assert result["checkpoint"]["sources"][0]["customValidationComplete"] is (
        accepted_outcome != "absent"
    )
    findings = json.loads((child_dir / "findings.json").read_text())["findings"]
    assert len(findings) == (0 if accepted_outcome == "rejected" else 1)
    grandchild_dir = tmp_path / "grandchild"
    _, continued = continue_scan(state, repository, child_id, grandchild_dir)
    assert continued["checkpoint"]["sources"][0]["customValidationComplete"] is (
        accepted_outcome != "absent"
    )
    assert len(json.loads((grandchild_dir / "findings.json").read_text())["findings"]) == len(
        findings
    )
    assert scan_bytes(parent) == original


@pytest.mark.parametrize("evidence_first", [False, True])
def test_rejected_checkpoint_evidence_survives_either_source_order(
    tmp_path: Path, workbench_api, monkeypatch, evidence_first: bool
) -> None:
    import workbench_saved_results as saved_results

    state, repository, scan, scan_id = scan_fixture(tmp_path)
    write_completed_contract(scan, scan_id, repository, relative_path="clean.ts")
    finding = json.loads((scan / "findings.json").read_text())["findings"][0]
    finding["extensions"] = {"candidateId": "candidate-1"}
    raw = semantic(scan_id, [])
    raw["findings"] = [finding]
    raw["coverage"]["deferred"] = []
    raw_path = write_checkpoint(scan / "checkpoints", raw)
    accepted = semantic(scan_id, ["clean.ts"])
    accepted["coverage"].update(
        deferred=[],
        surfaces=[
            {
                "id": "validated-candidate",
                "label": "Candidate validation",
                "candidateId": "candidate-1",
                "disposition": "rejected",
                "reason": "The existing control prevents the candidate.",
                "receiptRefs": [],
            }
        ],
    )
    accepted_path = write_checkpoint(scan / "checkpoints", accepted)
    original_children = saved_results._children

    def ordered_children(directory, relative):
        children = original_children(directory, relative)
        if relative == "checkpoints":
            return sorted(children, key=lambda name: (name == raw_path.name) != evidence_first)
        return children

    monkeypatch.setattr(saved_results, "_children", ordered_children)
    originals = scan_bytes(scan)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        _, findings, coverage = saved_results.merge_saved_results(
            scan,
            scan_id,
            workbench_api["workbench_completion_binding"](row, workbench_api["now"]()),
            [],
            [],
            stopped=False,
            reason="Continue saved evidence",
            include_parent=False,
            preserve_sources={raw_path.relative_to(scan).as_posix()},
            current_checkpoint_paths=[accepted_path.relative_to(scan).as_posix()],
        )
    assert findings["findings"] == []
    assert coverage["deferred"] == []
    assert coverage["surfaces"][0]["disposition"] == "rejected"
    assert coverage["surfaces"][0]["previousFindings"][0]["codeEvidence"] == finding["codeEvidence"]
    assert scan_bytes(scan) == originals
