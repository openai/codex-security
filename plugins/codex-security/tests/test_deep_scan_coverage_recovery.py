from __future__ import annotations

import copy
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from workbench_test_support import write_checkpoint, write_completed_contract


@pytest.fixture
def scan_dir(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    write_completed_contract(scan_dir, "synthetic-scan", target, coverage_mode="deep_repository")
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    manifest["scan"]["complete"] = True
    (scan_dir / "scan-manifest.json").write_text(json.dumps(manifest))
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    coverage.update(
        completeness="partial", openQuestions=[{"question": "Which deployment controls apply?"}]
    )
    (scan_dir / "coverage.json").write_text(json.dumps(coverage))
    return scan_dir


def recover_saved_scan(
    saved: ModuleType,
    scan_dir: Path,
    workers: list[dict[str, Any]],
    warnings: list[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    scan = json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]
    binding = {
        "scanId": scan["id"],
        "startedAt": scan["startedAt"],
        "completedAt": scan["completedAt"],
        "producer": scan["producer"],
        "allowedTargetKinds": [scan["target"]["kind"]],
        "target": scan["target"],
        "scope": scan["scope"],
        "coverageMode": "deep_repository",
        "status": "completed",
    }
    drafts = saved.merge_saved_results(
        scan_dir, scan["id"], binding, workers, warnings, stopped=False, reason=""
    )
    prepared = saved._prepare_scan_finalization(
        scan_dir,
        draft_documents=drafts,
        completion_binding=binding,
        completion_warnings=warnings,
    )
    _, findings, coverage = saved._write_prepared_scan_finalization(prepared)
    return findings, coverage


@pytest.mark.parametrize(
    "case",
    [
        pytest.param({"expected": "complete"}, id="reviewed"),
        pytest.param(
            {
                "warnings": ["Recovered finding 1: normalized semantic anchor."],
                "expected": "complete",
            },
            id="normalized",
        ),
        pytest.param(
            {
                "warnings": [
                    (
                        "Repository HEAD changed while the scan was running; "
                        "results were saved for the original revision."
                    )
                ],
                "expected": "complete",
            },
            id="target-changed",
        ),
        pytest.param(
            {"warnings": ["Recovered finding 1: discarded unverified evidence."]},
            id="unverified-evidence",
        ),
        pytest.param({"warnings": ["Saved checkpoint could not be read."]}, id="unknown-warning"),
        pytest.param({"coverage": {"surfaces": []}}, id="no-surfaces"),
        pytest.param(
            {"coverage": {"deferred": [{"id": "pending", "reason": "Review is incomplete."}]}},
            id="deferred",
        ),
        pytest.param({"disposition": "needs_follow_up"}, id="follow-up"),
        pytest.param({"receipt": "artifacts/missing-receipt.json"}, id="missing-receipt"),
        pytest.param({"coverage": {"explicitExclusions": [None]}}, id="invalid-exclusion"),
        pytest.param({"discarded": True}, id="discarded-finding"),
        pytest.param({"coverage": {"mode": "repository"}}, id="standard-scan"),
        pytest.param(
            {"coverage": {"completeness": "unknown"}, "expected": "unknown"},
            id="unknown-completeness",
        ),
    ],
)
def test_recovers_only_fully_reviewed_deep_coverage(scan_dir: Path, workbench_api, case) -> None:
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    coverage.update(case.get("coverage", {}))
    if "disposition" in case:
        coverage["surfaces"][0]["disposition"] = case["disposition"]
    if "receipt" in case:
        coverage["surfaces"][0]["receiptRefs"] = [case["receipt"]]
    (scan_dir / "coverage.json").write_text(json.dumps(coverage))
    if case.get("discarded"):
        findings = json.loads((scan_dir / "findings.json").read_text())
        findings["findings"].append(None)
        (scan_dir / "findings.json").write_text(json.dumps(findings))
    warnings = list(case.get("warnings", []))
    prepared = workbench_api["_prepare_scan_finalization"](scan_dir, completion_warnings=warnings)
    recovered = prepared[4]
    assert recovered["completeness"] == case.get("expected", "partial")
    assert recovered["openQuestions"] == [{"question": "Which deployment controls apply?"}]


@pytest.mark.parametrize(
    "case",
    [
        pytest.param({"expected": "complete"}, id="complete-worker"),
        pytest.param({"complete": True, "expected": "complete"}, id="explicit-complete"),
        *[
            pytest.param({"complete": marker}, id=f"worker-marker-{marker}")
            for marker in (False, None, 0, "false")
        ],
        *[
            pytest.param({"parent_complete": marker}, id=f"parent-marker-{marker}")
            for marker in (False, None, 0, "false")
        ],
        *[
            pytest.param({"worker": status}, id=f"worker-coverage-{status}")
            for status in ("unknown", "partial", None, "invalid", [])
        ],
        *[
            pytest.param({"malformed": field}, id=f"worker-{field}")
            for field in ("surfaces", "explicitExclusions", "deferred")
        ],
        pytest.param({"parent": "complete", "worker": "partial"}, id="complete-parent"),
        pytest.param({"parent": "unknown", "worker": "partial"}, id="unknown-parent-partial"),
        pytest.param({"parent": "unknown", "expected": "unknown"}, id="unknown-parent"),
        pytest.param({"missing": True}, id="missing-successful-worker"),
        pytest.param({"kind": "dedup", "missing": True}, id="missing-reducer"),
        pytest.param({"kind": "dedup", "expected": "complete"}, id="complete-reducer"),
        *[
            pytest.param({"kind": "dedup", "complete": marker}, id=f"reducer-marker-{marker}")
            for marker in (False, None, 0, "false")
        ],
        pytest.param({"kind": "dedup", "worker": "partial"}, id="partial-reducer"),
        pytest.param({"kind": "dedup", "malformed": "surfaces"}, id="malformed-reducer"),
        pytest.param(
            {"status": "failed", "missing": True, "expected": "complete"},
            id="missing-failed-worker",
        ),
        pytest.param(
            {"status": "canceled", "missing": True, "expected": "complete"},
            id="missing-canceled-worker",
        ),
    ],
)
def test_preserves_source_coverage_and_retry_warnings(scan_dir: Path, workbench_api, case) -> None:
    saved = workbench_api["saved_results"]
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    if "parent_complete" in case:
        manifest["scan"]["complete"] = case["parent_complete"]
    (scan_dir / "scan-manifest.json").write_text(json.dumps(manifest))
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    coverage["completeness"] = case.get("parent", "partial")
    (scan_dir / "coverage.json").write_text(json.dumps(coverage))

    output = scan_dir / "worker"
    output.mkdir()
    result = output / "result.json"
    worker = {
        "id": "synthetic-worker",
        "kind": case.get("kind", "discovery"),
        "status": case.get("status", "succeeded"),
        "artifact_dir": str(output),
        "result_manifest_path": str(result),
        "completed_at": "2026-08-29T00:00:00Z",
        "attempt": 1,
    }
    worker_coverage = {
        "completeness": case.get("worker", "complete"),
        "surfaces": [],
        "explicitExclusions": [],
        "deferred": [],
    }
    if "malformed" in case:
        worker_coverage[case["malformed"]] = "unverified review"
    draft = {"scanId": "synthetic-scan", "findings": [], "coverage": worker_coverage}
    if "complete" in case:
        draft["complete"] = case["complete"]
    if not case.get("missing"):
        result.write_text(json.dumps(draft))

    expected = case.get("expected", "partial")
    warnings: list[str] = []
    for _ in range(2):
        _, recovered = recover_saved_scan(saved, scan_dir, [worker], warnings)
        assert recovered["completeness"] == expected
        assert warnings.count(saved._UNVERIFIED_COVERAGE_WARNING) == (expected == "partial")


@pytest.mark.parametrize("owner", ["discovery", "parent"])
@pytest.mark.parametrize("marker", [None, 0, "false", False, True])
def test_unverified_replacement_preserves_checkpoint_findings(
    scan_dir: Path, workbench_api, owner: str, marker
) -> None:
    findings = json.loads((scan_dir / "findings.json").read_text())
    checkpoint = {
        "scanId": "synthetic-scan",
        "complete": False,
        "findings": findings["findings"],
        "coverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [],
        },
    }
    findings["findings"] = []
    (scan_dir / "findings.json").write_text(json.dumps(findings))
    workers = []
    output = scan_dir
    if owner == "discovery":
        output = scan_dir / "worker"
        output.mkdir()
        result = output / "result.json"
        current = copy.deepcopy(checkpoint)
        current.update(complete=marker, findings=[])
        current["coverage"]["completeness"] = "complete"
        result.write_text(json.dumps(current))
        workers.append(
            {
                "id": "synthetic-worker",
                "kind": "discovery",
                "status": "succeeded",
                "artifact_dir": str(output),
                "result_manifest_path": str(result),
                "completed_at": "2026-08-29T00:00:00Z",
                "attempt": 1,
            }
        )
    else:
        manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
        manifest["scan"]["complete"] = marker
        (scan_dir / "scan-manifest.json").write_text(json.dumps(manifest))
    write_checkpoint(output / "checkpoints", checkpoint)

    recovered, coverage = recover_saved_scan(workbench_api["saved_results"], scan_dir, workers, [])
    assert len(recovered["findings"]) == (0 if marker is True else 1)
    assert coverage["completeness"] == ("complete" if marker is True else "partial")


@pytest.mark.parametrize("severities", [("low", "high"), ("high", "low"), ("high", "high")])
def test_lossless_duplicates_do_not_prevent_complete_coverage(
    scan_dir: Path, workbench_api, severities
) -> None:
    findings = json.loads((scan_dir / "findings.json").read_text())
    baseline = findings["findings"][0]
    findings["findings"] = []
    for severity in severities:
        finding = copy.deepcopy(baseline)
        finding["severity"]["level"] = severity
        findings["findings"].append(finding)
    (scan_dir / "findings.json").write_text(json.dumps(findings))
    prepared = workbench_api["_prepare_scan_finalization"](scan_dir, completion_warnings=[])

    assert prepared[4]["completeness"] == "complete"
    assert len(prepared[3]["findings"]) == 1
    assert prepared[3]["findings"][0]["severity"]["level"] == "high"
