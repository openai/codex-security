from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest
from test_workbench_checkpoint_heads import select
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


@pytest.mark.parametrize(
    "source, observation",
    [
        ("parent", "newer"),
        ("checkpoint", "newer"),
        ("worker", "older"),
        ("worker", "tied"),
        ("worker", "newer"),
    ],
)
@pytest.mark.parametrize("owner_field", ["sourceWorkerId", "workerId"])
@pytest.mark.parametrize("metadata", [["worker-one", "worker-two"], {"workers": ["worker-one"]}])
def test_saved_findings_retain_nonstring_ownership_metadata(
    tmp_path: Path, workbench_api, source: str, observation: str, owner_field: str, metadata: object
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
    if source == "worker":
        parent_time = 1_700_000_000_000_000_000
        for name in ("scan-manifest.json", "findings.json", "coverage.json"):
            os.utime(scan_dir / name, ns=(parent_time, parent_time))
        worker_time = (
            parent_time + {"older": -1, "tied": 0, "newer": 1}[observation] * 1_000_000_000
        )
        os.utime(result_path, ns=(worker_time, worker_time))
        assert result_path.stat().st_mtime_ns == worker_time
        assert (scan_dir / "coverage.json").stat().st_mtime_ns == parent_time
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
    assert len(candidates) == (
        1 if source == "checkpoint" or (source == "worker" and observation != "newer") else 0
    )
    if candidates:
        assert candidates[0]["candidateId"] == pending["candidateId"]
        assert candidates[0]["reason"] == pending["reason"]
        assert candidates[0].get("sourceWorkerId") == ("worker-one" if source == "worker" else None)


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


@pytest.mark.parametrize("checkpoint_time", [100, 200, 300])
def test_retained_source_finding_respects_worker_checkpoint_order_without_current_result(
    tmp_path: Path, workbench_api, checkpoint_time: int
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
    os.utime(scan_dir / "coverage.json", ns=(200, 200))
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
    os.utime(checkpoint, ns=(checkpoint_time, checkpoint_time))
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
    assert any(item.get("candidateId") for item in result[2]["deferred"]) is (
        checkpoint_time >= 200
    )
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


@pytest.mark.parametrize("worker_observation", ["older", "tied", "newer"])
def test_saved_source_owner_finding_follows_parent_worker_observation_order(
    tmp_path: Path, workbench_api, worker_observation: str
) -> None:
    scan_id = "parent-worker-outcome-order"
    scan_dir, manifest, finding, coverage = saved_parent(tmp_path, scan_id)
    manifest["scan"]["sealedAt"] = "2026-01-01T00:00:00Z"
    (scan_dir / "scan-manifest.json").write_text(json.dumps(manifest))
    finding["provenance"].pop("workerId", None)
    finding["provenance"].update(candidateId="candidate-one", sourceWorkerId="worker-one")
    (scan_dir / "findings.json").write_text(json.dumps({"scanId": scan_id, "findings": [finding]}))
    coverage.update(completeness="complete", deferred=[])
    (scan_dir / "coverage.json").write_text(json.dumps(coverage))
    parent_time = 1_700_000_000_000_000_000
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        os.utime(scan_dir / name, ns=(parent_time, parent_time))
    output = scan_dir / "worker"
    output.mkdir()
    result_path = output / "result.json"
    result_path.write_text(
        json.dumps(
            {
                "scanId": scan_id,
                "complete": True,
                "findings": [],
                "coverage": {
                    "completeness": "complete",
                    "surfaces": [
                        {
                            "candidateId": "candidate-one",
                            "label": "Worker review",
                            "disposition": "rejected",
                            "notes": "Saved worker dismissal.",
                        }
                    ],
                    "deferred": [],
                },
            }
        )
    )
    worker_time = (
        parent_time + {"older": -1, "tied": 0, "newer": 1}[worker_observation] * 1_000_000_000
    )
    os.utime(result_path, ns=(worker_time, worker_time))
    checkpoint = write_checkpoint(output / "checkpoints", json.loads(result_path.read_text()))
    os.utime(checkpoint, ns=(worker_time, worker_time))
    select(output, checkpoint, worker_time)
    workers = [
        {
            "id": "worker-one",
            "kind": "discovery",
            "status": "succeeded",
            "artifact_dir": str(output),
            "result_manifest_path": str(result_path),
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
    warnings: list[str] = []
    result = workbench_api["saved_results"].merge_saved_results(
        scan_dir, scan_id, binding, workers, warnings, stopped=True, reason="Stopped after review."
    )
    assert result is not None
    assert warnings == []
    assert len(result[1]["findings"]) == (1 if worker_observation == "older" else 0)


@pytest.mark.parametrize(
    "unresolved", [1, [], [{"id": "pending-reducer", "reason": "Pending reducer evidence."}]]
)
def test_saved_malformed_reducer_candidates_preserve_valid_parent(
    tmp_path: Path, workbench_api, unresolved: object
) -> None:
    scan_id = "malformed-reducer-candidates"
    scan_dir, manifest, finding, _ = saved_parent(tmp_path, scan_id)
    output = scan_dir / "reducer"
    output.mkdir()
    result_path = output / "result.json"
    result_path.write_text(
        json.dumps(
            {
                "scanId": scan_id,
                "complete": False,
                "findings": [],
                "coverage": {"completeness": "complete", "surfaces": [], "deferred": []},
                "unresolvedCandidates": unresolved,
            }
        )
    )
    checkpoint = json.loads(result_path.read_text())
    checkpoint.pop("unresolvedCandidates")
    write_checkpoint(output / "checkpoints", checkpoint)
    warnings: list[str] = []
    binding = {
        "status": "failed",
        "allowedTargetKinds": ["directory_snapshot"],
        "target": manifest["scan"]["target"],
        "scope": manifest["scan"]["scope"],
        "coverageMode": "deep_repository",
    }
    result = workbench_api["saved_results"].merge_saved_results(
        scan_dir,
        scan_id,
        binding,
        [
            {
                "id": "reducer-one",
                "kind": "dedup",
                "status": "failed",
                "artifact_dir": str(output),
                "result_manifest_path": str(result_path),
                "attempt": 1,
            }
        ],
        warnings,
        stopped=True,
        reason="Stopped after review.",
    )
    assert result is not None
    assert finding in result[1]["findings"]
    assert bool(warnings) is (unresolved == 1)
    assert any(row.get("id") == "pending-reducer" for row in result[2]["deferred"]) is (
        isinstance(unresolved, list) and bool(unresolved)
    )


@pytest.mark.parametrize("owner_field", ["sourceWorkerId", "workerId"])
@pytest.mark.parametrize("reference_suffix", ["0", "opaque"])
@pytest.mark.parametrize("saved_owner", ["worker-one", "worker-two"])
@pytest.mark.parametrize("registered_candidate", [None, "different-candidate", "saved-candidate"])
def test_retained_finding_owner_is_not_rebound_from_source_reference(
    tmp_path: Path,
    workbench_api,
    owner_field: str,
    reference_suffix: str,
    saved_owner: str,
    registered_candidate: str | None,
) -> None:
    scan_id = "legacy-source-owner"
    scan_dir, manifest, finding, _ = saved_parent(tmp_path, scan_id)
    finding["provenance"].update(candidateId="saved-candidate", **{owner_field: saved_owner})
    original = copy.deepcopy(finding)
    finding["provenance"]["sourceFindings"] = [
        {"id": f"worker-one:{reference_suffix}", "finding": original}
    ]
    (scan_dir / "findings.json").write_text(json.dumps({"findings": [finding]}))
    worker = scan_dir / "worker"
    worker.mkdir()
    result_path = worker / "result.json"
    registered = copy.deepcopy(original)
    registered["provenance"]["candidateId"] = registered_candidate
    if registered_candidate == "different-candidate":
        registered["identity"] = {"anchor": "independent-registered-finding"}
        registered["summary"] = "Independent registered worker evidence."
    expected_owner = (
        "worker-one"
        if reference_suffix == "0" and registered_candidate == "saved-candidate"
        else saved_owner
    )
    result_path.write_text(
        json.dumps(
            {
                "scanId": scan_id,
                "complete": True,
                "findings": [registered] if registered_candidate else [],
                "coverage": {
                    "completeness": "complete",
                    "surfaces": [],
                    "explicitExclusions": [],
                    "deferred": [],
                },
            }
        )
    )
    originals = {path: path.read_bytes() for path in scan_dir.rglob("*.json")}
    workers = [
        {
            "id": "worker-one",
            "kind": "discovery",
            "status": "succeeded",
            "artifact_dir": str(worker),
            "result_manifest_path": str(result_path),
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
    module = workbench_api["saved_results"]
    first = module.merge_saved_results(
        scan_dir, scan_id, binding, workers, [], stopped=True, reason="Synthetic interruption."
    )
    assert first is not None
    replay = module.merge_saved_results(
        scan_dir,
        scan_id,
        binding,
        workers,
        [],
        stopped=True,
        reason="Synthetic interruption.",
        frozen_source_digests=first[0]["scan"]["preservedSources"],
    )
    for result in (first, replay):
        assert result is not None
        retained = [
            item
            for item in result[1]["findings"]
            if item["provenance"].get("sourceFindings") == finding["provenance"]["sourceFindings"]
        ]
        assert len(retained) == 1
        provenance = retained[0]["provenance"]
        assert (provenance.get("sourceWorkerId") or provenance.get("workerId")) == expected_owner
        if registered_candidate == "different-candidate":
            assert any(
                item["provenance"].get("candidateId") == registered_candidate
                for item in result[1]["findings"]
            )
        assert provenance["sourceFindings"] == finding["provenance"]["sourceFindings"]
    assert all(path.read_bytes() == value for path, value in originals.items())


@pytest.mark.parametrize("reference", ["opaque", "0", "other-owner"])
@pytest.mark.parametrize("owned", [False, True])
@pytest.mark.parametrize("worker_time", [100, 200, 300])
def test_parent_source_reference_preserves_independent_pending_candidate(
    tmp_path: Path, workbench_api, reference: str, owned: bool, worker_time: int
) -> None:
    scan_id = "parent-source-reference"
    scan_dir, manifest, finding, _ = saved_parent(tmp_path, scan_id)
    finding["provenance"]["candidateId"] = "shared-candidate"
    if owned:
        finding["provenance"]["sourceWorkerId"] = "worker-two"
    original = copy.deepcopy(finding)
    source_id = "worker-two:opaque" if reference == "other-owner" else f"worker-one:{reference}"
    finding["provenance"]["sourceFindings"] = [{"id": source_id, "finding": original}]
    (scan_dir / "findings.json").write_text(json.dumps({"findings": [finding]}))
    os.utime(scan_dir / "coverage.json", ns=(200, 200))
    output = scan_dir / "worker"
    output.mkdir()
    pending = {
        "id": "independent-gap",
        "candidateId": "shared-candidate",
        "reason": "Independent worker review remains pending.",
    }
    draft = {
        "scanId": scan_id,
        "complete": True,
        "findings": [],
        "coverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [pending],
        },
    }
    result_path = output / "result.json"
    result_path.write_text(json.dumps(draft))
    checkpoint = write_checkpoint(output / "checkpoints", draft)
    for file in (result_path, checkpoint):
        os.utime(file, ns=(worker_time, worker_time))
    originals = {file: file.read_bytes() for file in (result_path, checkpoint)}
    workers = [
        {
            "id": "worker-one",
            "kind": "discovery",
            "status": "succeeded",
            "artifact_dir": str(output),
            "result_manifest_path": str(result_path),
            "attempt": 1,
        }
    ]
    binding = {
        "status": "interrupted",
        "allowedTargetKinds": ["directory_snapshot"],
        "target": manifest["scan"]["target"],
        "scope": manifest["scan"]["scope"],
        "coverageMode": "deep_repository",
    }
    module = workbench_api["saved_results"]
    first = module.merge_saved_results(
        scan_dir, scan_id, binding, workers, [], stopped=True, reason="Synthetic interruption."
    )
    assert first is not None
    replay = module.merge_saved_results(
        scan_dir,
        scan_id,
        binding,
        workers,
        [],
        stopped=True,
        reason="Synthetic interruption.",
        frozen_source_digests=first[0]["scan"]["preservedSources"],
    )
    expected_pending = owned or reference != "0" or worker_time >= 200
    for result in (first, replay):
        assert result is not None
        deferred = [
            row for row in result[2]["deferred"] if row.get("candidateId") == pending["candidateId"]
        ]
        assert len(deferred) == int(expected_pending)
        if deferred:
            assert deferred[0]["sourceWorkerId"] == "worker-one"
            assert deferred[0]["reason"] == pending["reason"]
        assert len(result[1]["findings"]) == 1
        if owned:
            assert result[1]["findings"][0]["provenance"]["sourceWorkerId"] == "worker-two"
        assert (
            result[1]["findings"][0]["provenance"]["sourceFindings"]
            == finding["provenance"]["sourceFindings"]
        )
    assert all(file.read_bytes() == value for file, value in originals.items())


@pytest.mark.parametrize("marker, named_marker", [(True, 1), (False, 0), (True, True)])
def test_candidate_task_id_reuse_preserves_distinct_json_evidence(
    tmp_path: Path, workbench_api, marker: object, named_marker: object
) -> None:
    scan_id = "candidate-task-content"
    scan_dir, manifest, _, coverage = saved_parent(tmp_path, scan_id)
    coverage.update(completeness="partial", surfaces=[], explicitExclusions=[], deferred=[])
    (scan_dir / "coverage.json").write_text(json.dumps(coverage))
    (scan_dir / "findings.json").write_text(json.dumps({"scanId": scan_id, "findings": []}))
    row = {
        "candidateId": "candidate-one",
        "sourceWorkerId": "worker-one",
        "reason": "Candidate review remains.",
        "candidate": {"marker": marker},
    }
    named = {**row, "id": "candidate-task", "candidate": {"marker": named_marker}}
    worker = scan_dir / "worker"
    worker.mkdir()
    write_checkpoint(
        worker / "checkpoints",
        {
            "scanId": scan_id,
            "complete": False,
            "findings": [],
            "coverage": {
                "completeness": "partial",
                "surfaces": [],
                "explicitExclusions": [],
                "deferred": [row, named],
            },
        },
    )
    originals = {file: file.read_bytes() for file in scan_dir.rglob("*.json")}
    workers = [
        {
            "id": "worker-one",
            "kind": "discovery",
            "status": "failed",
            "artifact_dir": str(worker),
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
    module = workbench_api["saved_results"]
    warnings: list[str] = []
    first = module.merge_saved_results(
        scan_dir,
        scan_id,
        binding,
        workers,
        warnings,
        stopped=True,
        reason="Synthetic interruption.",
    )
    assert first is not None
    replay = module.merge_saved_results(
        scan_dir,
        scan_id,
        binding,
        workers,
        warnings,
        stopped=True,
        reason="Synthetic interruption.",
        frozen_source_digests=first[0]["scan"]["preservedSources"],
    )
    expected = {json.dumps(value) for value in (marker, named_marker)}
    for result in (first, replay):
        assert result is not None
        rows = [
            item for item in result[2]["deferred"] if item.get("candidateId") == "candidate-one"
        ]
        assert len(rows) == len(expected)
        assert {json.dumps(item["candidate"]["marker"]) for item in rows} == expected
    assert warnings == []
    assert all(file.read_bytes() == value for file, value in originals.items())
