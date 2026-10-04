from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from test_workbench_recovery_edges import select_checkpoint
from workbench_test_support import (
    checkpoint,
    register,
    run_workbench,
    saved_draft,
    write_checkpoint,
    write_completed_contract,
)


def file_snapshot(directory: Path) -> dict[str, bytes]:
    return {
        path.relative_to(directory).as_posix(): path.read_bytes()
        for path in directory.rglob("*")
        if path.is_file()
    }


@pytest.mark.parametrize("change", ["unchanged", "move", "expand"])
def test_parent_recovers_child_location_correction(tmp_path: Path, change: str) -> None:
    target, state = tmp_path / "target", tmp_path / "state"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    parent = register(state, target, tmp_path / "parent", mode="deep")
    parent_dir = Path(parent["scanDir"])
    write_completed_contract(
        parent_dir,
        parent["scanId"],
        target,
        relative_path="app.py",
        identity_anchor="shared-child-anchor",
    )
    child_dir = parent_dir / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
    write_completed_contract(child_dir, child["scanId"], target, relative_path="app.py")
    child_findings = json.loads((child_dir / "findings.json").read_text())
    finding = child_findings["findings"][0]
    finding["title"] = "Synthetic corrected child finding"
    finding["identity"]["anchor"] = "shared-child-anchor"
    sibling = copy.deepcopy(finding)
    sibling["title"] = "Synthetic distinct child instance"
    sibling["identity"]["instance"] = "distinct-instance"
    sibling["locations"][0]["startLine"] = 30
    sibling["locations"][0]["endLine"] = 31
    child_findings["findings"].append(sibling)
    (child_dir / "findings.json").write_text(json.dumps(child_findings))
    run_workbench(state, "fail-scan", "--scan-id", child["scanId"], "--message", "Synthetic stop")
    before_child = json.loads((child_dir / "findings.json").read_text())["findings"]
    assert len(before_child) == 2
    other_dir = parent_dir / "artifacts/deep-scan/passes/pass-2"
    other = register(state, target, other_dir, parent=parent["scanId"], role="deep_pass")
    write_completed_contract(
        other_dir,
        other["scanId"],
        target,
        relative_path="app.py",
        identity_anchor="shared-child-anchor",
    )
    other_findings = json.loads((other_dir / "findings.json").read_text())
    other_findings["findings"][0]["title"] = "Synthetic separate child"
    (other_dir / "findings.json").write_text(json.dumps(other_findings))
    run_workbench(state, "complete-scan", "--scan-id", other["scanId"])
    other_before = file_snapshot(other_dir)
    checkpoint(state, parent)
    stopped = run_workbench(
        state, "fail-scan", "--scan-id", parent["scanId"], "--message", "Synthetic stop"
    )["scan"]
    assert stopped["findingCount"] == 4
    updated = copy.deepcopy(before_child)
    corrected = next(row for row in updated if row["title"] == "Synthetic corrected child finding")
    old = copy.deepcopy(corrected)
    if change == "move":
        corrected["locations"][0]["startLine"] += 3
        corrected["locations"][0]["endLine"] += 3
    elif change == "expand":
        corrected["locations"].append({"path": "app.py", "startLine": 20, "endLine": 21})
    if change != "unchanged":
        corrected["provenance"]["previousFindings"] = [old]
    draft = saved_draft(child["scanId"], complete=True, findings=updated)
    draft["coverage"] = json.loads((child_dir / "coverage.json").read_text())
    saved = write_checkpoint(child_dir / "checkpoints", draft)
    select_checkpoint(child_dir, saved)
    recovered_child = run_workbench(state, "recover-scan-results", "--scan-id", child["scanId"])[
        "scan"
    ]
    assert recovered_child["findingCount"] == 2
    after_child = json.loads((child_dir / "findings.json").read_text())["findings"]
    current = next(row for row in after_child if row["title"] == old["title"])
    assert current["findingId"] == old["findingId"]
    assert current["occurrenceId"] == old["occurrenceId"]
    assert current["identity"] == old["identity"]
    assert current["locations"] == corrected["locations"]
    assert (
        next(row for row in after_child if row["title"] == sibling["title"])["identity"]["instance"]
        == "distinct-instance"
    )
    child_before = file_snapshot(child_dir)
    parent_before = None
    for _ in range(2):
        recovered = run_workbench(state, "recover-scan-results", "--scan-id", parent["scanId"])[
            "scan"
        ]
        assert recovered["findingCount"] == 4
        assert recovered["resultsRecoveryNeeded"] is False
        findings = json.loads((parent_dir / "findings.json").read_text())["findings"]
        retained = [row for row in findings if row["title"] == old["title"]]
        assert len(retained) == 1
        assert retained[0]["locations"] == corrected["locations"]
        assert sum(row["title"] == sibling["title"] for row in findings) == 1
        assert sum(row["title"] == "Synthetic separate child" for row in findings) == 1
        assert sum(not row["provenance"].get("sourceFindings") for row in findings) == 1
        if change != "unchanged":
            assert any(
                previous["locations"] == old["locations"]
                for previous in retained[0]["provenance"]["previousFindings"]
            )
        assert file_snapshot(child_dir) == child_before
        assert file_snapshot(other_dir) == other_before
        if parent_before is not None:
            assert file_snapshot(parent_dir) == parent_before
        parent_before = file_snapshot(parent_dir)


@pytest.mark.parametrize("new_evidence", ["canonical", "pending", "selected"])
def test_parent_recovery_recognizes_retained_unfrozen_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, new_evidence: str
) -> None:
    import sqlite3

    from test_workbench_saved_source_order import call_workbench, saved

    target, state, home = tmp_path / "target", tmp_path / "state", tmp_path / "home"
    target.mkdir()
    home.mkdir()
    (target / "app.py").write_text("\n" * 50)
    parent = register(state, target, tmp_path / "parent", mode="deep")
    parent_dir = Path(parent["scanDir"])
    child_dir = parent_dir / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
    write_completed_contract(child_dir, child["scanId"], target, relative_path="app.py")
    checkpoint(state, parent)

    def interrupt_recovery(*args, **kwargs):
        raise OSError("Synthetic child recovery interruption before freezing sources.")

    with monkeypatch.context() as patch:
        patch.setattr(saved, "merge_saved_results", interrupt_recovery)
        call_workbench(
            patch,
            state,
            home,
            "fail-scan",
            "--scan-id",
            child["scanId"],
            "--message",
            "Synthetic interruption",
        )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT status, seal_manifest_digest, retained_source_digests_json FROM scans WHERE id = ?",
            (child["scanId"],),
        ).fetchone() == ("failed", None, None)
    stopped = run_workbench(
        state, "fail-scan", "--scan-id", parent["scanId"], "--message", "Synthetic interruption"
    )["scan"]
    assert stopped["findingCount"] == 1
    recovered = run_workbench(state, "recover-scan-results", "--scan-id", parent["scanId"])["scan"]
    assert recovered["findingCount"] == 1
    assert recovered["resultsRecoveryNeeded"] is False

    retained = file_snapshot(parent_dir)
    for _ in range(2):
        observed = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]
        assert observed["resultsRecoveryNeeded"] is False
        assert file_snapshot(parent_dir) == retained

    child_findings = json.loads((child_dir / "findings.json").read_text())
    added = copy.deepcopy(child_findings["findings"][0])
    added["identity"]["instance"] = "new-evidence"
    added["title"] = "Synthetic newly available finding"
    child_findings["findings"].append(added)
    if new_evidence == "canonical":
        (child_dir / "findings.json").write_text(json.dumps(child_findings))
        # The complete file-authored contract is newer than its retained head.
        for name in ("coverage.json", "scan-manifest.json"):
            path = child_dir / name
            path.write_bytes(path.read_bytes())
    else:
        draft = saved_draft(child["scanId"], complete=False, findings=child_findings["findings"])
        draft["coverage"] = json.loads((child_dir / "coverage.json").read_text())
        saved_path = write_checkpoint(child_dir / "checkpoints", draft)
        if new_evidence == "selected":
            select_checkpoint(child_dir, saved_path)
    changed = file_snapshot(parent_dir)
    for _ in range(2):
        observed = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]
        assert observed["resultsRecoveryNeeded"] is True
        assert file_snapshot(parent_dir) == changed
    recovered = run_workbench(state, "recover-scan-results", "--scan-id", parent["scanId"])["scan"]
    assert recovered["findingCount"] == 2
    assert recovered["resultsRecoveryNeeded"] is False
    retained = file_snapshot(parent_dir)
    for _ in range(2):
        observed = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]
        assert observed["resultsRecoveryNeeded"] is False
        assert file_snapshot(parent_dir) == retained
