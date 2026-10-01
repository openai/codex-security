from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    ("scenario", "expected_owners"),
    [
        ("exact", {"worker-one"}),
        ("generated-id", {"worker-one"}),
        ("different-payload", {None, "worker-one"}),
        ("two-workers", {"worker-one", "worker-two"}),
        ("ordinary-parent", {None, "worker-one"}),
    ],
)
def test_recovery_scopes_matching_legacy_parent_candidate_without_duplication(
    tmp_path: Path, scenario: str, expected_owners: set[str | None]
) -> None:
    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    from report_projection import unresolved_candidates
    from workbench_saved_results import _digest, merge_saved_results

    scan_id = "legacy-candidate-scan"
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    pending = {
        "id": "candidate-synthetic",
        "candidateId": "candidate-synthetic",
        "reason": "Synthetic pending review.",
        "paths": ["app.py"],
        "candidate": {"summary": "Synthetic route review."},
    }
    surface = {
        "id": "candidate-surface",
        "candidateId": pending["candidateId"],
        "label": "Synthetic route",
        "disposition": "needs_follow_up",
        "notes": pending["reason"],
        "receiptRefs": [],
    }
    coverage = {
        "documentType": "codex-security.coverage",
        "schemaVersion": "1.0",
        "scanId": scan_id,
        "mode": "deep_repository",
        "inventoryStrategy": "repository",
        "includePaths": ["."],
        "excludePaths": [],
        "completeness": "partial",
        "surfaces": [surface],
        "explicitExclusions": [],
        "deferred": [pending],
    }
    binding = {
        "status": "failed",
        "coverageMode": "deep_repository",
        "allowedTargetKinds": ["directory_snapshot"],
        "target": {"kind": "directory_snapshot", "displayName": "Synthetic fixture"},
        "scope": {"includePaths": ["."], "excludePaths": []},
    }
    parent_scan = {
        "id": scan_id,
        "complete": False,
        "status": "failed",
        "scope": binding["scope"],
        "target": binding["target"],
    }
    if scenario != "ordinary-parent":
        parent_scan.update(sealedAt="2026-01-01T00:00:00Z", preservedSources={})
    for filename, document in (
        ("scan-manifest.json", {"scan": parent_scan}),
        ("findings.json", {"scanId": scan_id, "findings": []}),
        ("coverage.json", coverage),
    ):
        (scan_dir / filename).write_text(json.dumps(document))
    original_parent = (scan_dir / "coverage.json").read_bytes()
    workers = []
    source_digests = {}
    for worker_id in ("worker-one", "worker-two") if scenario == "two-workers" else ("worker-one",):
        output = scan_dir / "artifacts/deep_discovery" / worker_id / "output"
        output.mkdir(parents=True)
        worker_coverage = copy.deepcopy(coverage)
        for field in ("surfaces", "deferred"):
            item = worker_coverage[field][0]
            if scenario == "generated-id":
                item.pop("id")
                if field == "surfaces":
                    item.pop("receiptRefs")
            if scenario == "different-payload":
                item["notes" if field == "surfaces" else "reason"] = "Different route needs review."
        draft = {"scanId": scan_id, "complete": False, "findings": [], "coverage": worker_coverage}
        result = output / "result.json"
        result.write_text(json.dumps(draft))
        source_digests[result.relative_to(scan_dir).as_posix()] = _digest(draft)
        workers.append(
            {
                "id": worker_id,
                "kind": "discovery",
                "status": "running",
                "completed_at": None,
                "artifact_dir": str(output),
                "result_manifest_path": None,
                "attempt": 1,
            }
        )
    warnings = []
    result = merge_saved_results(
        scan_dir,
        scan_id,
        binding,
        workers,
        warnings,
        stopped=True,
        reason="Synthetic interruption.",
        frozen_source_digests=source_digests,
        allow_frozen_legacy_parent=True,
    )
    assert result is not None
    assert warnings == []
    for iteration in range(2):
        pending_rows = unresolved_candidates(result[2])
        assert len(pending_rows) == len(expected_owners)
        assert {row.get("sourceWorkerId") for row in pending_rows} == expected_owners
        candidate_surfaces = [row for row in result[2]["surfaces"] if row.get("candidateId")]
        assert len(candidate_surfaces) == len(expected_owners)
        assert {row.get("sourceWorkerId") for row in candidate_surfaces} == expected_owners
        assert "legacyUnscopedParentCandidates" not in result[2]
        if iteration == 0:
            # Frozen replay excludes the live parent and must retain the legacy
            # source's role without consulting or modifying the original files.
            result = merge_saved_results(
                scan_dir,
                scan_id,
                binding,
                workers,
                warnings,
                stopped=True,
                reason="Synthetic interruption.",
                frozen_source_digests=result[0]["scan"]["preservedSources"],
            )
            assert result is not None
    assert (scan_dir / "coverage.json").read_bytes() == original_parent
