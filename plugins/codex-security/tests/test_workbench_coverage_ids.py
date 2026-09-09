from __future__ import annotations

import copy
import json
import sqlite3
from pathlib import Path

import pytest
from test_workbench_scan_checkpoints import scan_fixture
from workbench_test_support import write_checkpoint, write_completed_contract


@pytest.mark.parametrize("ordering", ["historical", "reversed", "canonical", "canonical-reversed"])
def test_saved_coverage_ids_do_not_collide_with_previously_renamed_rows(
    tmp_path: Path, workbench_api, ordering: str
) -> None:
    from workbench_saved_results import merge_saved_results

    state, repository, scan, scan_id = scan_fixture(tmp_path)
    reported = {
        "id": "surface-0",
        "label": "Fixture 0",
        "disposition": "reported",
        "receiptRefs": [],
    }
    rejected = {
        **reported,
        "disposition": "rejected",
        "receiptRefs": [
            "artifacts/custom-validation/results.json",
            "artifacts/custom-validation/proof.txt",
            "artifacts/custom-validation/candidates.json",
        ],
    }
    # This is the ID produced by an earlier recovery of the rejected row above.
    renamed = {**rejected, "id": "surface-0-cabfb24a91d14992"}
    rows = [reported, rejected, renamed]
    canonical = ordering.startswith("canonical")
    canonical_rows = [reported, renamed]
    if ordering == "canonical-reversed":
        canonical_rows.reverse()
    if canonical:
        write_completed_contract(scan, scan_id, repository, relative_path="clean.ts")
        manifest = json.loads((scan / "scan-manifest.json").read_text())
        manifest["scan"].pop("sealedAt", None)
        manifest["scan"].pop("artifacts", None)
        (scan / "scan-manifest.json").write_text(json.dumps(manifest))
        (scan / "findings.json").write_text(json.dumps({"scanId": scan_id, "findings": []}))
        coverage = json.loads((scan / "coverage.json").read_text())
        coverage["surfaces"] = canonical_rows
        (scan / "coverage.json").write_text(json.dumps(coverage))
        rows = [rejected]
    elif ordering == "reversed":
        rows.reverse()
    snapshot = {
        "scanId": scan_id,
        "complete": True,
        "findings": [],
        "coverage": {
            "completeness": "complete",
            "surfaces": copy.deepcopy(rows),
            "explicitExclusions": [],
            "deferred": [],
            "reviewedFiles": [],
        },
    }
    path = write_checkpoint(scan / "checkpoints", snapshot)
    original = path.read_bytes()
    warnings = []
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        binding = workbench_api["workbench_completion_binding"](row, workbench_api["now"]())
        documents = merge_saved_results(
            scan,
            scan_id,
            binding,
            [],
            warnings,
            stopped=False,
            reason="",
            include_parent=canonical,
            preserve_sources={path.relative_to(scan).as_posix()},
        )
    assert documents is not None
    _, findings, coverage = documents
    surfaces = coverage["surfaces"]
    assert len(surfaces) == 3
    assert len({surface["id"] for surface in surfaces}) == 3
    assert sorted(surface["disposition"] for surface in surfaces) == [
        "rejected",
        "rejected",
        "reported",
    ]
    if canonical:
        assert surfaces[:2] == canonical_rows
    assert not coverage.get("reviewedFiles")
    assert findings["findings"] == []
    assert warnings == []
    assert path.read_bytes() == original
