"""Stopped Standard scans retain the acknowledged worker returns as unfinished work."""

import hashlib
import json
from pathlib import Path

import pytest
from workbench_test_support import (
    empty_target_scan,
    get_scan,
    read_review_state,
    scan_command,
    write_completed_contract,
)


def write_receipt(scan, *titles):
    payload = {
        "batch": 1,
        "reviewed_files": ["src/extract.py"],
        "findings": [{"title": title} for title in titles],
        "resolved_questions": ["A caller checks the input."],
    }
    digest = hashlib.sha256(json.dumps(payload, separators=(",", ":")).encode()).hexdigest()
    path = Path("artifacts/02_discovery/standard-returns") / f"{digest}.json"
    (scan / path).parent.mkdir(parents=True, exist_ok=True)
    (scan / path).write_text(json.dumps(payload))
    return {"file": path.as_posix(), "count": len(titles)}


@pytest.mark.parametrize("stop", ["fail-scan", "cancel-scan"])
def test_stopped_standard_receipts_are_frozen_at_transition(tmp_path, stop):
    state, target, scan_id, scan = empty_target_scan(tmp_path)
    if stop == "fail-scan":
        write_completed_contract(scan, scan_id, target)
        path = scan / "findings.json"
        findings = json.loads(path.read_text())
        findings["findings"][0]["provenance"]["candidateId"] = "standard-2.1"
        path.write_text(json.dumps(findings))
        path = scan / "coverage.json"
        coverage = json.loads(path.read_text())
        coverage["deferred"] = [
            {
                "id": "standard-3",
                "candidateId": "standard-3",
                "reason": "Later validation required.",
                "paths": ["src/caller.py"],
                "counterevidence": ["A synthetic guard."],
            },
            {
                "id": "standard-unreviewed-files",
                "reason": "Unfinished files.",
                "paths": ["src/extract.py", "unread.py"],
            },
        ]
        coverage["resolvedDeferred"] = [{"id": "standard-5", "reason": "Confirmed safe."}]
        path.write_text(json.dumps(coverage))
    missing = write_receipt(scan, "unavailable")
    (scan / missing["file"]).unlink()
    returned = write_receipt(
        scan, "checkpointed claim", "pending worker claim", "matching claim", "closed"
    )
    orphan = write_receipt(scan, "unacknowledged result")
    queue = {
        "batches": [["src/extract.py", "unread.py", "second-unread.py"]],
        "reviewed": ["src/extract.py"],
        "returns": [missing, returned],
    }
    queue_path = scan / "artifacts/01_context/standard-queue.json"
    queue_path.parent.mkdir(parents=True, exist_ok=True)
    queue_path.write_text(json.dumps(queue))
    decisions = scan / "artifacts/04_validation/standard-decisions.json"
    decisions.parent.mkdir(parents=True, exist_ok=True)
    decisions.write_text(
        json.dumps(
            {
                "standard-2": [{"disposition": "reportable", "reason": "Verified."}],
                "standard-4": [
                    {
                        "disposition": "duplicate",
                        "duplicateOf": "standard-2.1",
                        "reason": "Same claim.",
                    }
                ],
            }
        )
    )

    extra = ("--message", "Stopped during validation.") if stop == "fail-scan" else ()
    scan_command(state, stop, scan_id, *extra)
    saved = get_scan(state, scan_id)["scan"]
    assert saved["findingCount"] == int(stop == "fail-scan")
    assert any("Could not retain Standard return" in w for w in saved["warnings"])
    rows = read_review_state(state, scan)["deferred"]
    assert [row["id"] for row in rows].count("standard-3") == 1
    assert ("standard-2.1" in {row["id"] for row in rows}) == (stop == "cancel-scan")
    assert ("standard-4.1" in {row["id"] for row in rows}) == (stop == "cancel-scan")
    pending = next(row for row in rows if row["id"] == "standard-3")
    assert pending["workerCandidate"] == {"title": "pending worker claim"}
    assert pending["counterevidence"] == (
        (["A synthetic guard."] if stop == "fail-scan" else []) + ["A caller checks the input."]
    )
    assert pending["workerReturn"] == returned["file"]
    assert pending["paths"] == (
        (["src/caller.py"] if stop == "fail-scan" else []) + ["src/extract.py"]
    )
    unread = next(row for row in rows if row["id"] == "standard-unreviewed-files")
    assert unread["paths"] == ["unread.py", "second-unread.py"]
    if stop == "fail-scan":
        assert pending["reason"] == "Later validation required."
        assert unread["reason"] == "Unfinished files."
    assert ("standard-5" in {row["id"] for row in rows}) == (stop == "cancel-scan")
    assert "pending worker claim" not in (scan / "findings.json").read_text()

    report = (scan / "report.md").read_bytes()
    assert b"unacknowledged result" not in report
    # The writer finishes another acknowledgement after the stop, and the original
    # receipt is lost. A fresh workbench process must use only the frozen snapshot.
    queue["returns"].append(orphan)
    queue_path.write_text(json.dumps(queue))
    (scan / returned["file"]).unlink()
    scan_command(state, stop, scan_id, *extra)
    scan_command(state, "preserve-scan-results", scan_id)
    if stop == "fail-scan":
        scan_command(state, "recover-scan-results", scan_id)
    assert read_review_state(state, scan)["deferred"] == rows
    assert (scan / "report.md").read_bytes() == report


@pytest.mark.parametrize(
    ("queue", "exhausted"),
    [
        ({"batches": [["a.py"]], "reviewed": ["a.py"], "returns": []}, True),
        ({"returns": []}, False),
        ({"batches": [["a.py"]], "reviewed": ["a.py", "b.py"], "returns": []}, False),
        (None, False),
    ],
    ids=["exhausted", "missing-inventory", "inconsistent-inventory", "no-queue"],
)
def test_stopped_scan_clears_only_confirmed_exhausted_files(tmp_path, queue, exhausted):
    state, target, scan_id, scan = empty_target_scan(tmp_path)
    write_completed_contract(scan, scan_id, target)
    path = scan / "coverage.json"
    coverage = json.loads(path.read_text())
    unread = {
        "id": "standard-unreviewed-files",
        "reason": "Review remaining files.",
        "paths": ["a.py"],
    }
    caller = {"id": "caller-review", "reason": "Review another claim.", "paths": ["a.py"]}
    coverage["deferred"] = [unread, caller]
    path.write_text(json.dumps(coverage))
    queue_path = scan / "artifacts/01_context/standard-queue.json"
    queue_path.parent.mkdir(parents=True, exist_ok=True)
    if queue is not None:
        queue_path.write_text(json.dumps(queue))

    scan_command(state, "fail-scan", scan_id, "--message", "Synthetic interruption.")
    rows = read_review_state(state, scan)["deferred"]
    assert caller in rows
    assert [row for row in rows if row["id"] == unread["id"]] == ([] if exhausted else [unread])
    queue_path.write_text(json.dumps({"batches": [["b.py"]], "reviewed": [], "returns": []}))
    scan_command(state, "recover-scan-results", scan_id)
    assert read_review_state(state, scan)["deferred"] == rows
