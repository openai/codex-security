from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from test_workbench_standard_deep_results import (
    generic_review_recovery as generic_review_recovery,
)
from test_workbench_standard_deep_results import write_saved_parent
from workbench_test_support import write_checkpoint


@pytest.mark.parametrize("candidate_linked", [False, True])
def test_retained_work_keeps_complete_parent_projection_partial(
    tmp_path: Path, generic_review_recovery, candidate_linked: bool
) -> None:
    module, pending, terminal, binding = generic_review_recovery
    terminal["coverage"].pop("resolvedDeferred")
    if candidate_linked:
        pending["coverage"]["deferred"][0]["candidateId"] = "candidate-review"
    checkpoint = write_checkpoint(tmp_path / "checkpoints", pending)
    os.utime(checkpoint, ns=(100, 100))
    complete_checkpoint = write_checkpoint(tmp_path / "checkpoints", terminal)
    os.utime(complete_checkpoint, ns=(200, 200))
    write_saved_parent(tmp_path, terminal, 100)
    original = {path: path.read_bytes() for path in (checkpoint, complete_checkpoint)}

    documents = module.merge_saved_results(
        tmp_path,
        pending["scanId"],
        {**binding, "status": "in_progress"},
        [],
        [],
        stopped=False,
        reason="",
    )

    assert documents is not None
    coverage = documents[2]
    assert {row["id"] for row in coverage["deferred"]} == {"review"}
    assert coverage["completeness"] == "partial"
    assert documents[1]["findings"] == []
    assert all(path.read_bytes() == value for path, value in original.items())
    assert json.loads((tmp_path / "coverage.json").read_text())["completeness"] == "complete"
