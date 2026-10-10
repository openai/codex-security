from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from test_workbench_checkpoint_heads import select
from workbench_test_support import saved_binding, saved_draft, write_checkpoint

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import workbench_saved_results as saved


@pytest.mark.parametrize(
    "reason",
    [
        pytest.param("\ud800", id="high-surrogate"),
        pytest.param("\udfff", id="low-surrogate"),
        "\U0001f600",
        "\\ud800",
        "é",
        "A\U0001f600Z",
    ],
)
@pytest.mark.parametrize("closed", [False, True])
def test_unicode_review_identity_survives_committed_and_frozen_recovery(
    tmp_path: Path, reason: str, closed: bool
) -> None:
    scan_id = "identity-scan"
    identity = "unicode-review"
    pending = saved_draft(
        scan_id, deferred=[{"id": identity, "reason": reason, "paths": ["src/example.py"]}]
    )
    checkpoint = write_checkpoint(tmp_path / "checkpoints", pending)
    os.utime(checkpoint, ns=(100, 100))
    if closed:
        selected = write_checkpoint(
            tmp_path / "checkpoints",
            saved_draft(
                scan_id, closures=[{"id": identity, "reason": "Review completed."}], complete=True
            ),
        )
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
    assert result[2] == replay[2]
    assert any(row["id"] == identity for row in result[2]["deferred"]) is not closed
