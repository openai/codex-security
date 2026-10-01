from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from workbench_test_support import write_checkpoint, write_completed_contract


def saved_parent(tmp_path: Path, scan_id: str) -> tuple[Path, dict, dict, dict]:
    target = tmp_path.resolve() / "target"
    target.mkdir()
    (target / "app.py").write_text("value = 1\n")
    scan_dir = tmp_path.resolve() / "scan"
    scan_dir.mkdir()
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    return (
        scan_dir,
        json.loads((scan_dir / "scan-manifest.json").read_text()),
        json.loads((scan_dir / "findings.json").read_text())["findings"][0],
        json.loads((scan_dir / "coverage.json").read_text()),
    )


@pytest.mark.parametrize("source", ["parent", "checkpoint", "worker"])
@pytest.mark.parametrize("owner_field", ["sourceWorkerId", "workerId"])
@pytest.mark.parametrize("metadata", [["worker-one", "worker-two"], {"workers": ["worker-one"]}])
def test_saved_findings_retain_nonstring_ownership_metadata(
    tmp_path: Path, workbench_api, source: str, owner_field: str, metadata: object
) -> None:
    workbench_saved_results = workbench_api["saved_results"]

    scan_id = "nonstring-owner-metadata"
    scan_dir, manifest, finding, coverage = saved_parent(tmp_path, scan_id)
    finding["provenance"].update(candidateId="candidate-one", **{owner_field: metadata})
    pending = {"candidateId": "candidate-one", "reason": "Validation remains pending."}
    if source == "worker":
        pending["sourceWorkerId"] = "worker-one"
    coverage.update(completeness="partial", deferred=[pending])
    (scan_dir / "coverage.json").write_text(json.dumps(coverage))
    (scan_dir / "findings.json").write_text(
        json.dumps({"scanId": scan_id, "findings": [finding] if source == "parent" else []})
    )
    draft = {
        "scanId": scan_id,
        "complete": False,
        "findings": [finding],
        "coverage": {"completeness": "complete", "surfaces": [], "deferred": []},
    }
    workers = []
    if source == "checkpoint":
        write_checkpoint(scan_dir / "checkpoints", draft)
    elif source == "worker":
        artifact_dir = scan_dir / "worker"
        artifact_dir.mkdir()
        result_path = artifact_dir / "result.json"
        result_path.write_text(json.dumps(draft))
        workers.append(
            {
                "id": "worker-one",
                "kind": "discovery",
                "status": "succeeded",
                "artifact_dir": str(artifact_dir),
                "result_manifest_path": str(result_path),
                "attempt": 1,
            }
        )
    binding = {
        "status": "failed",
        "allowedTargetKinds": ["directory_snapshot"],
        "target": manifest["scan"]["target"],
        "scope": manifest["scan"]["scope"],
        "coverageMode": "deep_repository",
    }
    original = copy.deepcopy(finding)
    warnings: list[str] = []

    result = workbench_saved_results.merge_saved_results(
        scan_dir, scan_id, binding, workers, warnings, stopped=True, reason="Stopped after review."
    )

    assert result is not None
    assert warnings == []
    retained = result[1]["findings"]
    assert len(retained) == 1
    if source == "worker" and owner_field == "sourceWorkerId":
        assert retained[0]["provenance"]["sourceWorkerId"] == "worker-one"
        assert original in retained[0]["provenance"]["previousFindings"]
        assert json.loads(result_path.read_text())["findings"][0] == original
    else:
        assert retained[0]["provenance"][owner_field] == metadata
    assert retained[0]["summary"] == original["summary"]
    candidates = [row for row in result[2]["deferred"] if row.get("candidateId")]
    assert len(candidates) == (1 if source == "checkpoint" else 0)
    if candidates:
        assert candidates[0]["candidateId"] == pending["candidateId"]
        assert candidates[0]["reason"] == pending["reason"]
        assert candidates[0].get("sourceWorkerId") is None


@pytest.mark.parametrize("field", ["surfaces", "explicitExclusions", "deferred"])
@pytest.mark.parametrize("metadata", [["worker-one"], {"worker": "worker-one"}])
def test_unsealed_coverage_retains_nonstring_owner_for_finalizer_recovery(
    tmp_path: Path, workbench_api, field: str, metadata: object
) -> None:
    workbench_saved_results = workbench_api["saved_results"]

    scan_dir = tmp_path.resolve() / "scan"
    scan_dir.mkdir()
    scan_id = "unsealed-coverage-owner"
    target = {"kind": "git_revision", "repository": "test", "revision": "head"}
    scope = {"includePaths": ["."], "excludePaths": []}
    (scan_dir / "scan-manifest.json").write_text(
        json.dumps({"scan": {"id": scan_id, "target": target, "scope": scope}})
    )
    (scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    row = {
        "id": "imported-decision",
        "candidateId": "candidate-one",
        "sourceWorkerId": metadata,
        "label": "Imported coverage decision",
        "disposition": "rejected",
        "reason": "Retained imported coverage evidence.",
        "receiptRefs": [],
    }
    coverage = {"completeness": "partial", "surfaces": [], "explicitExclusions": [], "deferred": []}
    coverage[field] = [row]
    pending = {"candidateId": "candidate-one", "reason": "Valid review still needs evidence."}
    if field != "deferred":
        coverage["deferred"] = [pending]
    (scan_dir / "coverage.json").write_text(json.dumps(coverage))
    binding = {
        "status": "failed",
        "allowedTargetKinds": ["git_revision"],
        "target": target,
        "scope": scope,
        "coverageMode": "repository",
    }

    result = workbench_saved_results.merge_saved_results(
        scan_dir, scan_id, binding, [], [], stopped=True, reason="Stopped after importing coverage."
    )

    assert result is not None
    assert any(item.get("sourceWorkerId") == metadata for item in result[2][field])
    if field != "deferred":
        assert pending in result[2]["deferred"]


def test_retained_source_finding_resolves_its_worker_candidate_without_current_result(
    tmp_path: Path, workbench_api
) -> None:
    scan_id = "retained-source-candidate"
    scan_dir, manifest, finding, _ = saved_parent(tmp_path, scan_id)
    source_finding = copy.deepcopy(finding)
    source_finding["provenance"]["candidateId"] = "candidate-source"
    finding["provenance"].update(
        candidateId="candidate-canonical",
        sourceFindings=[{"id": "worker-one:0", "finding": source_finding}],
    )
    (scan_dir / "findings.json").write_text(json.dumps({"findings": [finding]}))
    artifact_dir = scan_dir / "worker"
    artifact_dir.mkdir()
    checkpoint = write_checkpoint(
        artifact_dir / "checkpoints",
        {
            "scanId": scan_id,
            "complete": False,
            "findings": [],
            "coverage": {
                "completeness": "partial",
                "surfaces": [],
                "deferred": [
                    {"candidateId": "candidate-source", "reason": "Earlier saved review."}
                ],
            },
        },
    )
    original = checkpoint.read_bytes()
    workers = [
        {
            "id": "worker-one",
            "kind": "discovery",
            "status": "failed",
            "artifact_dir": str(artifact_dir),
            "result_manifest_path": None,
            "attempt": 1,
        }
    ]
    binding = {
        "status": "failed",
        "allowedTargetKinds": ["directory_snapshot"],
        "target": manifest["scan"]["target"],
        "scope": manifest["scan"]["scope"],
        "coverageMode": "deep_repository",
    }
    warnings = []

    result = workbench_api["saved_results"].merge_saved_results(
        scan_dir, scan_id, binding, workers, warnings, stopped=True, reason="Stopped after review."
    )

    assert result is not None
    assert warnings == []
    assert len(result[1]["findings"]) == 1
    assert not any(item.get("candidateId") for item in result[2]["deferred"])
    assert checkpoint.read_bytes() == original


def test_rejected_finding_history_stays_with_its_logical_worker(
    tmp_path: Path, workbench_api
) -> None:
    scan_id = "owned-terminal-history"
    scan_dir, manifest, finding, coverage = saved_parent(tmp_path, scan_id)
    finding["provenance"]["candidateId"] = "shared-candidate"
    other_decision = {
        "id": "other-worker-decision",
        "candidateId": "shared-candidate",
        "sourceWorkerId": "worker-b",
        "label": "Independent worker decision",
        "disposition": "rejected",
        "notes": "Worker B review concluded.",
        "receiptRefs": [],
    }
    coverage.update(surfaces=[other_decision], deferred=[])
    (scan_dir / "coverage.json").write_text(json.dumps(coverage))
    (scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    artifact_dir = scan_dir / "worker-a"
    artifact_dir.mkdir()
    old = {
        "scanId": scan_id,
        "complete": False,
        "findings": [finding],
        "coverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [],
        },
    }
    checkpoint = write_checkpoint(artifact_dir / "checkpoints", old)
    original = checkpoint.read_bytes()
    current = copy.deepcopy(old)
    current["findings"] = []
    current["coverage"]["surfaces"] = [
        {
            "candidateId": "shared-candidate",
            "label": "Worker A decision",
            "disposition": "rejected",
            "notes": "Worker A review concluded.",
        }
    ]
    result_path = artifact_dir / "result.json"
    result_path.write_text(json.dumps(current))
    workers = [
        {
            "id": "worker-a",
            "kind": "discovery",
            "status": "succeeded",
            "attempt": 1,
            "artifact_dir": str(artifact_dir),
            "result_manifest_path": str(result_path),
        }
    ]
    binding = {
        "status": "failed",
        "allowedTargetKinds": ["directory_snapshot"],
        "target": manifest["scan"]["target"],
        "scope": manifest["scan"]["scope"],
        "coverageMode": "deep_repository",
    }

    result = workbench_api["saved_results"].merge_saved_results(
        scan_dir, scan_id, binding, workers, [], stopped=True, reason="Stopped after review."
    )

    assert result is not None
    assert result[1]["findings"] == []
    surfaces = {item["sourceWorkerId"]: item for item in result[2]["surfaces"]}
    assert surfaces["worker-b"] == other_decision
    assert surfaces["worker-a"]["previousFindings"] == [finding]
    assert checkpoint.read_bytes() == original


def test_saved_surface_collision_updates_links_for_the_matching_owner(
    tmp_path: Path, workbench_api
) -> None:
    scan_id = "owned-surface-links"
    scan_dir, manifest, _, coverage = saved_parent(tmp_path, scan_id)
    manifest["scan"]["complete"] = False
    (scan_dir / "scan-manifest.json").write_text(json.dumps(manifest))
    surfaces = [
        {
            "id": "shared-surface-id",
            "candidateId": f"candidate-{owner}",
            "sourceWorkerId": owner,
            "label": f"Saved evidence for {owner}",
            "disposition": "needs_follow_up",
            "notes": "Independent review remains pending.",
            "receiptRefs": [f"artifacts/{owner}.txt"],
        }
        for owner in ("worker-a", "worker-b")
    ]
    deferred = [
        {
            "id": surface["candidateId"],
            "candidateId": surface["candidateId"],
            "sourceWorkerId": surface["sourceWorkerId"],
            "reason": "Saved evidence requires review.",
            "surfaceIds": [surface["id"]],
        }
        for surface in surfaces
    ]
    coverage.update(completeness="partial", surfaces=surfaces[:1], deferred=deferred[:1])
    coverage_path = scan_dir / "coverage.json"
    coverage_path.write_text(json.dumps(coverage))
    parent_bytes = coverage_path.read_bytes()
    (scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    checkpoint = write_checkpoint(
        scan_dir / "checkpoints",
        {
            "scanId": scan_id,
            "complete": False,
            "findings": [],
            "coverage": {**coverage, "surfaces": surfaces[1:], "deferred": deferred[1:]},
        },
    )
    checkpoint_bytes = checkpoint.read_bytes()
    binding = {
        "status": "failed",
        "allowedTargetKinds": ["directory_snapshot"],
        "target": manifest["scan"]["target"],
        "scope": manifest["scan"]["scope"],
        "coverageMode": "deep_repository",
    }

    result = workbench_api["saved_results"].merge_saved_results(
        scan_dir, scan_id, binding, [], [], stopped=True, reason="Stopped after review."
    )

    assert result is not None
    retained = {item["sourceWorkerId"]: item for item in result[2]["surfaces"]}
    assert retained["worker-a"] == surfaces[0]
    assert retained["worker-b"]["id"] != surfaces[1]["id"]
    assert retained["worker-b"] == {**surfaces[1], "id": retained["worker-b"]["id"]}
    pending = [item for item in result[2]["deferred"] if item.get("candidateId")]
    assert len(pending) == 2
    for item in pending:
        assert item["surfaceIds"] == [retained[item["sourceWorkerId"]]["id"]]
    assert coverage_path.read_bytes() == parent_bytes
    assert checkpoint.read_bytes() == checkpoint_bytes
