"""Track deferred observations through ID collisions, worker revisions, and frozen source order."""

from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path

import pytest
from test_workbench_checkpoint_heads import select
from workbench_test_support import (
    saved_binding,
    saved_discovery_worker,
    saved_draft,
    write_checkpoint,
    write_result_draft,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import workbench_saved_results as saved


def save_worker(root: Path, module, worker_id: str, drafts: list[dict], result: dict):
    output = root / worker_id
    checkpoints = output / "checkpoints"
    checkpoints.mkdir(parents=True)
    for index, draft in enumerate(drafts, 1):
        path = checkpoints / f"{module._digest(draft)}.json"
        path.write_text(json.dumps(draft))
        os.utime(path, ns=(index * 100, index * 100))
    write_result_draft(output / "result.json", result, mtime_ns=1000)
    return saved_discovery_worker(output, worker_id, 1)


def recover(root: Path, module, workers, frozen=None, *, preserve_reduction=False):
    binding = {
        "status": "interrupted",
        "allowedTargetKinds": ["git_revision"],
        "target": {
            "kind": "git_revision",
            "targetId": "synthetic",
            "displayName": "test",
            "revision": "head",
        },
        "scope": {"includePaths": ["."], "excludePaths": []},
        "coverageMode": "deep_repository",
    }
    result = module.merge_saved_results(
        root,
        "identity-scan",
        binding,
        workers,
        [],
        stopped=not preserve_reduction,
        reason="interrupted",
        frozen_source_digests=frozen,
        preserve_canonical_parent=preserve_reduction,
        current_contract=preserve_reduction,
        scan_mode="deep" if preserve_reduction else None,
    )
    assert result is not None
    return result


@pytest.mark.parametrize("named_history", [False, True])
def test_accepted_rejection_preserves_independent_candidate_with_matching_context(
    tmp_path: Path, named_history: bool
) -> None:
    scan_id = "identity-scan"
    first = {
        "id": "first-review",
        "candidateId": "first",
        "reason": "Review caller.",
        "paths": ["api.py"],
        "candidate": {"title": "First caller"},
    }
    second = {
        "id": "second-review",
        "candidateId": "second",
        "reason": "Review caller.",
        "paths": ["api.py"],
        "candidate": {"title": "Independent caller"},
    }
    raw = copy.deepcopy(second)
    if not named_history:
        raw.pop("id")
    checkpoint = write_checkpoint(
        tmp_path / "checkpoints", saved_draft(scan_id, deferred=[first, raw])
    )
    os.utime(checkpoint, ns=(100, 100))
    accepted = saved_draft(
        scan_id,
        deferred=[second],
        surfaces=[
            {
                "id": "first-surface",
                "candidateId": "first",
                "label": "First caller",
                "disposition": "rejected",
                "candidate": first["candidate"],
            }
        ],
        complete=True,
    )
    selected = write_checkpoint(tmp_path / "checkpoints", accepted)
    select(tmp_path, selected, 200)
    binding = saved_binding(repository="synthetic")
    result = saved.merge_saved_results(
        tmp_path, scan_id, binding, [], stopped=True, reason="interrupted"
    )
    replay = saved.merge_saved_results(
        tmp_path,
        scan_id,
        binding,
        [],
        stopped=True,
        reason="interrupted",
        frozen_source_digests=result[0]["scan"]["preservedSources"],
    )
    for documents in (result, replay):
        assert [row for row in documents[2]["deferred"] if row["id"] != "scan-stopped"] == [second]


def test_unnamed_distinct_observations_keep_distinct_ids_in_frozen_recovery(tmp_path: Path) -> None:
    scan_id = "identity-scan"
    rows = [
        {"reason": "Review caller.", "paths": ["api.py"], "candidate": {"title": title}}
        for title in ("First caller", "Second caller")
    ]
    write_checkpoint(tmp_path / "checkpoints", saved_draft(scan_id, deferred=rows))
    binding = saved_binding(repository="synthetic")
    result = saved.merge_saved_results(
        tmp_path, scan_id, binding, [], stopped=True, reason="interrupted"
    )
    replay = saved.merge_saved_results(
        tmp_path,
        scan_id,
        binding,
        [],
        stopped=True,
        reason="interrupted",
        frozen_source_digests=result[0]["scan"]["preservedSources"],
    )
    assert result[2] == replay[2]
    retained = [row for row in result[2]["deferred"] if row["id"] != "scan-stopped"]
    assert len({row["id"] for row in retained}) == 2
    assert [row["candidate"] for row in retained] == [row["candidate"] for row in rows]
