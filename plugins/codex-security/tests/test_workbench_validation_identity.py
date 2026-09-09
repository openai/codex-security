from __future__ import annotations

import copy
import json
import sqlite3
from pathlib import Path

import pytest
from test_workbench_scan_checkpoints import save, scan_fixture
from workbench_test_support import write_checkpoint, write_completed_contract


@pytest.mark.parametrize(
    ("mode", "latest"),
    [
        ("standard", "rejected"),
        ("standard", "not_applicable"),
        ("standard", "reported"),
        ("standard", "needs_follow_up"),
        ("standard", "unaccepted_rejection"),
        ("deep", "rejected"),
    ],
)
def test_accepted_validation_uses_existing_identity_without_candidate_ids(
    tmp_path: Path, workbench_api, mode: str, latest: str
) -> None:
    from workbench_saved_results import merge_saved_results

    state, repository, scan_dir, scan_id = scan_fixture(tmp_path, mode=mode)
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, scan_id, repository, relative_path="clean.ts")
    original = json.loads((contract / "findings.json").read_text())["findings"][0]
    original.pop("extensions", None)
    original["provenance"].pop("candidateId", None)
    snapshot = {
        "scanId": scan_id,
        "complete": True,
        "findings": [original],
        "coverage": {
            "completeness": "complete",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [],
        },
    }
    save(state, scan_id, write_checkpoint(scan_dir / "checkpoints", snapshot))
    raw = copy.deepcopy(snapshot)
    raw["findings"][0]["summary"] = "Earlier unaccepted evidence for the same source."
    write_checkpoint(scan_dir / "checkpoints", raw)
    rejected = copy.deepcopy(snapshot)
    rejected["findings"] = []
    rejected["coverage"]["surfaces"] = [
        {
            "id": "custom-validation-candidate-1",
            "label": original["title"],
            "disposition": "rejected",
            "previousFindings": [copy.deepcopy(original)],
        }
    ]
    save(state, scan_id, write_checkpoint(scan_dir / "checkpoints", rejected))
    if latest != "rejected":
        current = copy.deepcopy(rejected)
        current["coverage"]["surfaces"][0]["disposition"] = (
            "reported" if latest == "unaccepted_rejection" else latest
        )
        if latest in {"reported", "unaccepted_rejection"}:
            finding = copy.deepcopy(original)
            finding["confidence"] = {"level": "low", "rationale": "Validated limited impact."}
            finding["provenance"]["previousFindings"] = [original, raw["findings"][0]]
            current["findings"] = [finding]
        if latest == "needs_follow_up":
            current["coverage"]["completeness"] = "partial"
            current["coverage"]["deferred"] = [
                {"reason": "New evidence requires review.", "previousFindings": [original]}
            ]
        save(state, scan_id, write_checkpoint(scan_dir / "checkpoints", current))
    if latest == "unaccepted_rejection":
        rejected["coverage"]["surfaces"][0]["notes"] = "Later unaccepted decision."
        write_checkpoint(scan_dir / "checkpoints", rejected)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        scan = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        accepted = connection.execute(
            "SELECT checkpoint_path FROM scan_checkpoints WHERE scan_id = ? ORDER BY sequence DESC",
            (scan_id,),
        ).fetchall()
        binding = workbench_api["workbench_completion_binding"](scan, workbench_api["now"]())
        documents = merge_saved_results(
            scan_dir,
            scan_id,
            {**binding, "status": "failed"},
            [],
            [],
            stopped=True,
            reason="Stopped after validation.",
            include_parent=False,
            current_checkpoint_paths=[row["checkpoint_path"] for row in accepted],
        )
    assert documents is not None
    _, findings, coverage = documents
    suppressed = latest in {"rejected", "not_applicable"} and mode != "deep"
    assert len(findings["findings"]) == (0 if suppressed else 1)
    if suppressed:
        history = coverage["surfaces"][0]["previousFindings"]
        assert original in history
        assert raw["findings"][0] in history
    if latest in {"reported", "needs_follow_up", "unaccepted_rejection"}:
        assert all(item["disposition"] != "rejected" for item in coverage["surfaces"])
    if latest in {"reported", "unaccepted_rejection"}:
        assert findings["findings"][0]["confidence"]["level"] == "low"
    if latest == "needs_follow_up":
        assert any(
            item.get("reason") == "New evidence requires review." for item in coverage["deferred"]
        )
