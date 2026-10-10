from __future__ import annotations

import copy
import json
import os
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


@pytest.mark.parametrize("checkpoint_time", [100, 200, 300])
@pytest.mark.parametrize("same_owner", [False, True])
def test_legacy_owned_parent_respects_pending_only_checkpoint_order(
    tmp_path: Path, checkpoint_time: int, same_owner: bool
) -> None:
    from workbench_test_support import (
        load_script,
        saved_discovery_worker,
        saved_draft,
        write_checkpoint,
        write_completed_contract,
    )

    module = load_script("workbench_saved_results")
    finalizer = load_script("finalize_scan_contract")
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("synthetic source\n")
    scan_id = "legacy-owned-candidate"
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    finding = findings["findings"][0]
    finding["provenance"].update(candidateId="candidate-review", workerId="worker-one")
    findings_path.write_text(json.dumps(findings))
    manifest, _, _ = finalizer.finalize_scan(scan_dir)
    parent_bytes = {
        name: (scan_dir / name).read_bytes()
        for name in ("findings.json", "coverage.json", "scan-manifest.json")
    }
    os.utime(scan_dir / "coverage.json", ns=(200, 200))
    owner = "worker-one" if same_owner else "worker-two"
    output = scan_dir / "artifacts/deep_discovery" / owner / "output"
    pending = {
        "id": "pending-review",
        "candidateId": "candidate-review",
        "reason": "The worker still needs independent validation.",
        "candidate": {"evidence": "Pending worker evidence remains available."},
    }
    checkpoint = write_checkpoint(output / "checkpoints", saved_draft(scan_id, deferred=[pending]))
    os.utime(checkpoint, ns=(checkpoint_time, checkpoint_time))
    original_checkpoint = checkpoint.read_bytes()
    binding = {
        "status": "failed",
        "coverageMode": "deep_repository",
        "allowedTargetKinds": ["directory_snapshot"],
        "target": manifest["scan"]["target"],
        "scope": manifest["scan"]["scope"],
    }
    warnings = []
    documents = module.merge_saved_results(
        scan_dir,
        scan_id,
        binding,
        [saved_discovery_worker(output, owner)],
        warnings,
        stopped=True,
        reason="Synthetic interruption.",
    )
    assert documents is not None
    assert warnings == []
    rows = [
        row for row in documents[2]["deferred"] if row.get("candidateId") == pending["candidateId"]
    ]
    expected = not same_owner or checkpoint_time >= 200
    assert bool(rows) is expected
    if expected:
        assert rows[0]["sourceWorkerId"] == owner
        assert rows[0]["candidate"] == pending["candidate"]
        assert rows[0]["reason"] == pending["reason"]
    assert len(documents[1]["findings"]) == 1
    assert documents[1]["findings"][0]["summary"] == finding["summary"]
    from candidate_identity import unresolved_candidates
    from report_projection import build_report_markdown

    candidates = unresolved_candidates(documents[2], documents[1]["findings"])
    assert candidates == rows
    markdown = build_report_markdown(*documents)
    assert (pending["reason"] in markdown) is expected
    assert checkpoint.read_bytes() == original_checkpoint
    assert {name: (scan_dir / name).read_bytes() for name in parent_bytes} == parent_bytes

    # A later accepted finding resolves the reopened candidate without erasing history.
    accepted_finding = json.loads(json.dumps(documents[1]["findings"][0]))
    terminal = write_checkpoint(
        output / "checkpoints", saved_draft(scan_id, findings=[accepted_finding], complete=True)
    )
    os.utime(terminal, ns=(400, 400))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": terminal.name}))
    os.utime(head, ns=(400, 400))
    accepted = module.merge_saved_results(
        scan_dir,
        scan_id,
        binding,
        [saved_discovery_worker(output, owner)],
        [],
        stopped=True,
        reason="Synthetic interruption.",
    )
    assert accepted is not None
    assert unresolved_candidates(accepted[2], accepted[1]["findings"]) == []
    assert all(
        row["provenance"].get("candidateReopened") is not True for row in accepted[1]["findings"]
    )
    assert checkpoint.read_bytes() == original_checkpoint
    assert {name: (scan_dir / name).read_bytes() for name in parent_bytes} == parent_bytes
