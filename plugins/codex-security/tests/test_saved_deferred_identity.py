from __future__ import annotations

import copy
import os
import sys
from pathlib import Path

import pytest
from test_workbench_checkpoint_heads import select
from workbench_test_support import saved_binding, saved_draft, write_checkpoint

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import workbench_saved_results as saved


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
