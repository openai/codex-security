from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from workbench_test_support import (
    replay_saved_results,
    saved_binding,
    saved_discovery_worker,
    saved_draft,
    write_checkpoint,
)

SCAN_ID = "worker-closeout-scan"
CLOSURES = [
    {"id": "review-a", "reason": "Source review completed."},
    {"id": "review-b", "reason": "Source review completed."},
]


def observed(path: Path, seconds: int) -> None:
    os.utime(path, ns=(seconds * 1_000_000_000, seconds * 1_000_000_000))


def saved_worker(root: Path, worker_id: str, *, headed: bool = False):
    output = root / worker_id / "output"
    pending = saved_draft(
        SCAN_ID, deferred=[{"id": row["id"], "reason": "Review remains."} for row in CLOSURES]
    )
    observed(write_checkpoint(output / "checkpoints", pending), 10)
    complete = saved_draft(SCAN_ID, closures=CLOSURES, complete=True)
    checkpoint = write_checkpoint(output / "checkpoints", complete)
    observed(checkpoint, 20)
    result = output / "result.json"
    result.write_text(json.dumps(complete))
    observed(result, 20)
    if headed:
        head = output / "checkpoint-head.json"
        head.write_text(json.dumps({"checkpoint": checkpoint.name}))
        observed(head, 20)
    worker = saved_discovery_worker(output, worker_id, 2)
    worker.update(status="succeeded", result_manifest_path=str(result))
    return worker


def parent_copy(root: Path, closures: list[dict]) -> None:
    observed(
        write_checkpoint(
            root / "checkpoints", saved_draft(SCAN_ID, closures=closures, complete=True)
        ),
        40,
    )


def recover(root: Path, module, workers):
    binding = saved_binding("deep_repository", repository="synthetic")
    documents = module.merge_saved_results(
        root, SCAN_ID, binding, workers, [], stopped=True, reason="interrupted"
    )
    assert documents is not None
    replay = replay_saved_results(module, documents, root, SCAN_ID, binding, workers)
    assert replay is not None
    assert replay[2] == documents[2]
    return documents[2]


@pytest.mark.parametrize("headed", [False, True])
@pytest.mark.parametrize("published", [False, True])
def test_worker_closeouts_keep_distinct_ids_and_do_not_duplicate_parent_copies(
    tmp_path, workbench_api, headed, published
):
    workers = [
        saved_worker(tmp_path, worker_id, headed=headed) for worker_id in ("first", "second")
    ]
    expected = [
        {"id": f"{worker_id}-attempt-2-resolved-{closure['id']}", "reason": closure["reason"]}
        for worker_id in ("first", "second")
        for closure in CLOSURES
    ]
    if published:
        parent_copy(tmp_path, expected)
    originals = {path: path.read_bytes() for path in tmp_path.rglob("*.json")}
    coverage = recover(tmp_path, workbench_api["saved_results"], workers)
    assert sorted(coverage.get("resolvedDeferred", []), key=lambda row: row["id"]) == expected
    assert all(path.read_bytes() == contents for path, contents in originals.items())


@pytest.mark.parametrize("published", [False, True])
@pytest.mark.parametrize("reopened_at", [19, 20, 21], ids=["older", "tied", "newer"])
def test_worker_reopening_invalidates_its_copied_parent_closeout(
    tmp_path, workbench_api, published, reopened_at
):
    worker = saved_worker(tmp_path, "worker")
    output = Path(worker["artifact_dir"])
    expected = [
        {"id": f"worker-attempt-2-resolved-{closure['id']}", "reason": closure["reason"]}
        for closure in CLOSURES
    ]
    if published:
        parent_copy(tmp_path, expected)
    reopened = {"id": "review-a", "reason": "New evidence requires another review."}
    checkpoint = write_checkpoint(output / "checkpoints", saved_draft(SCAN_ID, deferred=[reopened]))
    observed(checkpoint, reopened_at)
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    observed(head, reopened_at)
    coverage = recover(tmp_path, workbench_api["saved_results"], [worker])
    assert sorted(coverage.get("resolvedDeferred", []), key=lambda row: row["id"]) == (
        expected if reopened_at < 20 else expected[1:]
    )
    pending = [row for row in coverage["deferred"] if row.get("reason") == reopened["reason"]]
    assert bool(pending) is (reopened_at >= 20)


def test_archived_worker_closeout_keeps_its_original_attempt(tmp_path, workbench_api):
    worker = saved_worker(tmp_path, "worker")
    output = Path(worker["artifact_dir"])
    archive = output.parent / "attempts" / "attempt-01"
    archive.parent.mkdir(parents=True)
    output.rename(archive)
    output.mkdir()
    result = output / "result.json"
    result.write_text(json.dumps(saved_draft(SCAN_ID, complete=True)))
    observed(result, 30)
    coverage = recover(tmp_path, workbench_api["saved_results"], [worker])
    assert sorted(coverage.get("resolvedDeferred", []), key=lambda row: row["id"]) == [
        {"id": f"worker-attempt-1-resolved-{closure['id']}", "reason": closure["reason"]}
        for closure in CLOSURES
    ]
