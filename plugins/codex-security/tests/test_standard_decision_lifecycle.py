import json
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from workbench_test_support import (
    empty_target_scan,
    read_draft_documents,
    read_review_state,
    scan_command,
    write_completed_contract,
)

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "standard_validation.py"


def decision_scan(tmp_path, count):
    state, target, scan_id, scan = empty_target_scan(tmp_path)
    write_completed_contract(scan, scan_id, target)
    draft = read_draft_documents(scan)
    coverage = draft.pop("coverage")
    draft["reviewState"] = {k: coverage[k] for k in ("surfaces", "deferred", "explicitExclusions")}
    manifest = draft["manifest"]["scan"]
    del manifest["coverageRef"]
    manifest["mode"] = "repository"
    manifest["reviewState"] = draft["reviewState"]
    (scan / "scan-manifest.json").write_text(json.dumps(draft["manifest"]))
    (scan / "coverage.json").unlink()
    queue = scan / "artifacts/01_context/standard-queue.json"
    returned = "artifacts/02_discovery/return.json"
    paths = ["src/extract.py"]
    queue.parent.mkdir(parents=True, exist_ok=True)
    queue.write_text(
        json.dumps(
            {"batches": [paths], "reviewed": paths, "returns": [{"file": returned, "count": count}]}
        )
    )
    (scan / returned).parent.mkdir(parents=True, exist_ok=True)
    (scan / returned).write_text(
        json.dumps(
            {
                "findings": [{"title": f"Claim {i}"} for i in range(1, count + 1)],
                "reviewed_files": paths,
                "resolved_questions": ["A caller checks the path."],
            }
        )
    )
    return state, scan_id, scan, draft


def stage_draft(scan, draft):
    stage = scan / "drafts" / f"{uuid.uuid4()}.json"
    stage.parent.mkdir(exist_ok=True)
    stage.write_text(json.dumps(draft))
    return str(stage)


def record(scan, *rows, check=True):
    return subprocess.run(
        [sys.executable, SCRIPT, "record", scan],
        input=json.dumps(rows),
        text=True,
        capture_output=True,
        check=check,
    )


@pytest.mark.parametrize(
    "reportable_target", [True, False], ids=["reportable-target", "duplicate-chain"]
)
def test_record_forward_duplicate_before_target_batch(tmp_path, reportable_target):
    state, scan_id, scan, draft = decision_scan(tmp_path, 3)
    duplicate = {"disposition": "duplicate", "duplicateOf": "standard-3.1", "reason": "Same write."}
    verified = {"disposition": "reportable", "reason": "Verified in src/extract.py:41."}
    record(
        scan,
        {"candidateId": "standard-1", "parts": [duplicate]},
        {"candidateId": "standard-2", "parts": [verified]},
    )
    saved = scan / "artifacts/04_validation/standard-decisions.json"
    assert json.loads(saved.read_text()) == {"standard-1": [duplicate], "standard-2": [verified]}

    target = verified if reportable_target else {**duplicate, "duplicateOf": "standard-2.1"}
    record(scan, {"candidateId": "standard-3", "parts": [target]})
    draft["findings"]["findings"][0]["provenance"].update(
        candidateId="standard-2.1", duplicateCandidateIds=["standard-3.1"]
    )
    stage = stage_draft(scan, draft)
    if not reportable_target:
        # Even naming the intermediate duplicate as a finding alias cannot authorize a chain.
        (scan / "findings.json").write_text(json.dumps(draft["findings"]))
        for command in [("write-scan-draft", "--draft-path", stage), ("complete-scan",)]:
            result = scan_command(state, command[0], scan_id, *command[1:], check=False)
            assert result["returncode"] != 0
            assert "Duplicate target standard-3.1 has no reportable decision." in result["stderr"]

        pending = json.loads(subprocess.check_output([sys.executable, SCRIPT, "pending", scan]))
        assert [(row["candidateId"], row["parts"]) for row in pending] == [
            ("standard-1", [duplicate])
        ]
        corrected = {"candidateId": "standard-1", "parts": [target]}
        record(scan, corrected)
        record(scan, corrected)
        assert json.loads(saved.read_text())["standard-1"] == [
            {**target, "previousDecisions": [duplicate]}
        ]
        changed = {"disposition": "rejected", "reason": "Different conclusion."}
        assert (
            record(scan, {"candidateId": "standard-3", "parts": [changed]}, check=False).returncode
            != 0
        )
    scan_command(state, "write-scan-draft", scan_id, "--draft-path", stage)
    assert scan_command(state, "complete-scan", scan_id)["scan"]["findingCount"] == 1


def test_resume_deferred_parts_under_their_original_claim_ids(tmp_path):
    state, scan_id, scan, draft = decision_scan(tmp_path, 1)
    deferred = [
        {"disposition": "deferred", "reason": "Need the write path."},
        {"disposition": "deferred", "reason": "Need the guard definition."},
    ]
    record(scan, {"candidateId": "standard-1", "parts": deferred})
    draft["manifest"]["scan"]["complete"] = False
    finding = draft["findings"]["findings"].pop()
    for index, part in enumerate(deferred, 1):
        claim = f"standard-1.{index}"
        draft["reviewState"]["deferred"].append(
            {"id": claim, "candidateId": claim, "reason": part["reason"]}
        )
    scan_command(state, "write-scan-draft", scan_id, "--draft-path", stage_draft(scan, draft))
    assert read_review_state(state, scan)["deferred"] == draft["reviewState"]["deferred"]

    original = json.loads(subprocess.check_output([sys.executable, SCRIPT, "pending", scan]))
    assert len(original) == 1
    assert original[0]["candidateId"] == "standard-1"
    assert original[0]["parts"] == deferred
    assert original[0]["candidate"] == {"title": "Claim 1"}
    assert original[0]["counterevidence"] == ["A caller checks the path."]

    reported = {"disposition": "reportable", "reason": "Confirmed the write at line 41."}
    rejected = {"disposition": "rejected", "reason": "The second path checks containment."}
    record(scan, {"candidateId": "standard-1", "parts": [reported, deferred[1]]})
    pending = json.loads(subprocess.check_output([sys.executable, SCRIPT, "pending", scan]))
    assert pending[0]["parts"] == [{**reported, "previousDecisions": [deferred[0]]}, deferred[1]]
    row = {"candidateId": "standard-1", "parts": [reported, rejected]}
    assert record(scan, {**row, "parts": [rejected, reported]}, check=False).returncode != 0
    record(scan, row)
    record(scan, row)
    saved = scan / "artifacts/04_validation/standard-decisions.json"
    assert json.loads(saved.read_text())["standard-1"] == [
        {**reported, "previousDecisions": [deferred[0]]},
        {**rejected, "previousDecisions": [deferred[1]]},
    ]
    assert json.loads(subprocess.check_output([sys.executable, SCRIPT, "pending", scan])) == []

    draft["manifest"]["scan"]["complete"] = True
    draft["reviewState"]["deferred"].clear()
    finding["provenance"]["candidateId"] = "standard-1.1"
    draft["findings"]["findings"].append(finding)
    draft["reviewState"]["surfaces"].append(
        {
            "id": "guarded-path",
            "candidateId": "standard-1.2",
            "label": "Guarded path",
            "disposition": "rejected",
            "notes": rejected["reason"],
            "receiptRefs": [],
        }
    )
    scan_command(state, "write-scan-draft", scan_id, "--draft-path", stage_draft(scan, draft))
    assert scan_command(state, "complete-scan", scan_id)["scan"]["findingCount"] == 1
    assert read_review_state(state, scan)["deferred"] == []


def test_settled_claim_cannot_remain_in_active_deferred_rows(tmp_path):
    state, scan_id, scan, draft = decision_scan(tmp_path, 1)
    parts = [
        {"disposition": "deferred", "reason": "The write path needs review."},
        {"disposition": "deferred", "reason": "The guard still needs verification."},
    ]
    record(scan, {"candidateId": "standard-1", "parts": parts})
    review = draft["reviewState"]
    first, second = [
        {"id": f"task-{i}", "candidateId": f"standard-1.{i}", "reason": part["reason"]}
        for i, part in enumerate(parts, 1)
    ]
    review["deferred"] = [first, second]
    review["resolvedDeferred"] = [{"id": "prior-task", "reason": "Source review complete."}]
    reported = {"disposition": "reportable", "reason": "The source confirms the write."}
    record(scan, {"candidateId": "standard-1", "parts": [reported, parts[1]]})
    draft["findings"]["findings"][0]["provenance"]["candidateId"] = "standard-1.1"
    draft["manifest"]["scan"]["complete"] = True
    (scan / "scan-manifest.json").write_text(json.dumps(draft["manifest"]))
    (scan / "findings.json").write_text(json.dumps(draft["findings"]))
    stage = stage_draft(scan, draft)
    for command in [("write-scan-draft", "--draft-path", stage), ("complete-scan",)]:
        result = scan_command(state, command[0], scan_id, *command[1:], check=False)
        assert result["returncode"] != 0
        assert "standard-1.1 is reportable and cannot remain deferred" in result["stderr"]

    review["deferred"] = [second]
    scan_command(state, "write-scan-draft", scan_id, "--draft-path", stage_draft(scan, draft))
    assert scan_command(state, "complete-scan", scan_id)["scan"]["findingCount"] == 1
    sealed = read_review_state(state, scan)
    assert sealed["deferred"] == [second]
    head = json.loads((scan / "checkpoint-head.json").read_text())
    checkpoint = json.loads((scan / "checkpoints" / head["checkpoint"]).read_text())
    assert checkpoint["reviewState"]["resolvedDeferred"] == review["resolvedDeferred"]
