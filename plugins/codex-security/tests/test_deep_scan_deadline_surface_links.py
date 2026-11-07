"""Track source-to-surface links through deadline recovery, reused IDs, and repeated crashes."""

from __future__ import annotations

from workbench_test_support import (
    replay_saved_results,
    saved_binding,
    saved_discovery_worker,
    saved_draft,
    write_checkpoint,
)


def surface(label, identity="entry", disposition="needs_follow_up"):
    return {"id": identity, "label": label, "disposition": disposition, "receiptRefs": []}


def pending(identity, reason, surface_id="entry"):
    return {"id": identity, "reason": reason, "surfaceIds": [surface_id]}


def test_stopped_recovery_preserves_source_link_union(workbench_api, tmp_path):
    saved = workbench_api["saved_results"]
    scan_id = "surface-links"
    binding = saved_binding("deep_repository")
    output = tmp_path / "worker" / "output"
    archived = output.parent / "attempts" / "attempt-01"
    shared = pending("review", "Review retained observations.")
    originals = {}
    for source, label in ((archived, "download"), (output, "upload")):
        checkpoint = write_checkpoint(
            source / "checkpoints",
            saved_draft(scan_id, surfaces=[surface(label)], deferred=[shared]),
        )
        originals[checkpoint] = checkpoint.read_bytes()
    workers = [saved_discovery_worker(output, "worker", 2)]

    documents = saved.merge_saved_results(
        tmp_path, scan_id, binding, workers, [], stopped=True, reason="interrupted"
    )
    replay = replay_saved_results(saved, documents, tmp_path, scan_id, binding, workers)

    assert replay[2] == documents[2]
    coverage = documents[2]
    assert {row["label"] for row in coverage["surfaces"]} == {"download", "upload"}
    tasks = [row for row in coverage["deferred"] if row["reason"] == shared["reason"]]
    assert len(tasks) == 1
    assert tasks[0]["surfaceIds"] == [row["id"] for row in coverage["surfaces"]]
    assert {path: path.read_bytes() for path in originals} == originals
