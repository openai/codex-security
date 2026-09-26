from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "patch-risk-assessment.schema.json"
VALIDATOR_PATH = (
    PLUGIN_ROOT / "skills" / "assess-patch-risk" / "scripts" / "validate_patch_risk_assessment.py"
)


def assessment() -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "patch": {
            "repository": "example/project",
            "sourceType": "pull_request_diff",
            "base": "a" * 40,
            "head": "b" * 40,
            "changedFiles": ["src/request.ts"],
            "sha256": "c" * 64,
        },
        "recommendation": "merge",
        "workflowLabel": "human_review_required",
        "impact": {"rating": "moderate", "rationale": "A bounded caller can fail."},
        "regressionLikelihood": {
            "rating": "low",
            "rationale": "The changed path and its caller are covered.",
        },
        "regressionProtection": {
            "rating": "strong",
            "rationale": "Focused and integration checks passed at the exact head.",
            "exactHeadChecksPassed": True,
        },
        "recoverability": {"rating": "easy", "rationale": "A revert is isolated."},
        "confidence": {"rating": "high", "rationale": "Runtime callers are known."},
        "applicability": {"status": "confirmed", "rationale": "The path is deployed."},
        "statusQuoRisk": {"rating": "moderate", "rationale": "The defect remains."},
        "autoMergeExclusions": [],
        "affectedRuntimeRoots": ["service.request"],
        "materialBoundaries": [
            {
                "id": "request-contract",
                "invariant": "Supported requests retain their existing response contract.",
                "runtimeRoot": "service.request",
                "counterexample": "A supported request takes the changed branch.",
                "legitimateControl": "A supported request takes the unchanged branch.",
                "result": "supported",
            }
        ],
        "validation": [
            {
                "name": "focused request tests",
                "status": "passed",
                "protects": "Changed behavior through the production caller.",
            }
        ],
        "unknowns": [],
        "evidencePlan": [],
    }


def validate(tmp_path: Path, payload: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    assessment_path = tmp_path / "assessment.json"
    assessment_path.write_text(json.dumps(payload), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(VALIDATOR_PATH), str(assessment_path)],
        cwd=PLUGIN_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_schema_is_valid_draft_2020_12() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)


def test_supported_human_review_merge_is_valid(tmp_path: Path) -> None:
    assert validate(tmp_path, assessment()).returncode == 0


def test_strict_low_risk_assessment_can_be_auto_merge_candidate(tmp_path: Path) -> None:
    payload = assessment()
    payload["workflowLabel"] = "auto_merge_candidate"
    payload["impact"]["rating"] = "low"

    assert validate(tmp_path, payload).returncode == 0


def test_auto_merge_rejects_non_low_impact(tmp_path: Path) -> None:
    payload = assessment()
    payload["workflowLabel"] = "auto_merge_candidate"

    assert validate(tmp_path, payload).returncode != 0


def test_auto_merge_rejects_materially_excluded_change(tmp_path: Path) -> None:
    payload = assessment()
    payload["workflowLabel"] = "auto_merge_candidate"
    payload["impact"]["rating"] = "low"
    payload["autoMergeExclusions"] = ["public_contract"]

    assert validate(tmp_path, payload).returncode != 0


def test_merge_rejects_decision_critical_unknown(tmp_path: Path) -> None:
    payload = assessment()
    payload["unknowns"] = [
        {"summary": "Deployment ownership is unresolved.", "decisionCritical": True}
    ]

    assert validate(tmp_path, payload).returncode != 0


def test_merge_rejects_unknown_applicability(tmp_path: Path) -> None:
    payload = assessment()
    payload["applicability"] = {
        "status": "unknown",
        "rationale": "The supported runtime owner is unresolved.",
    }

    result = validate(tmp_path, payload)

    assert result.returncode != 0
    assert "merge requires confirmed applicability" in result.stderr


def test_auto_merge_requires_affected_runtime_root(tmp_path: Path) -> None:
    payload = assessment()
    payload["workflowLabel"] = "auto_merge_candidate"
    payload["impact"]["rating"] = "low"
    payload["affectedRuntimeRoots"] = []

    result = validate(tmp_path, payload)

    assert result.returncode != 0
    assert "auto_merge_candidate gate failed: affectedRuntimeRoots" in result.stderr


def test_hold_requires_bounded_evidence_plan(tmp_path: Path) -> None:
    payload = assessment()
    payload["recommendation"] = "hold_for_evidence"
    payload["workflowLabel"] = "hold_for_evidence"
    payload["unknowns"] = [
        {"summary": "The rollout target is unavailable.", "decisionCritical": True}
    ]

    assert validate(tmp_path, payload).returncode != 0

    payload["evidencePlan"] = [
        {
            "question": "Does the changed configuration own the rollout target?",
            "action": "Inspect the checked-in deployment mapping.",
            "outcomes": {
                "supported": "merge",
                "contradicted": "no_op",
                "unavailable": "hold_for_evidence",
            },
        }
    ]
    assert validate(tmp_path, payload).returncode == 0


def test_no_op_requires_non_applicable_disposition(tmp_path: Path) -> None:
    payload = assessment()
    payload["recommendation"] = "no_op"
    payload["workflowLabel"] = "no_op"

    assert validate(tmp_path, payload).returncode != 0

    payload["applicability"] = {
        "status": "superseded",
        "rationale": "A narrower patch already landed.",
    }
    assert validate(tmp_path, payload).returncode == 0


def test_no_op_rejects_decision_critical_unknown(tmp_path: Path) -> None:
    payload = assessment()
    payload["recommendation"] = "no_op"
    payload["workflowLabel"] = "no_op"
    payload["applicability"] = {
        "status": "superseded",
        "rationale": "A sibling patch may cover the affected runtime.",
    }
    payload["unknowns"] = [
        {
            "summary": "Whether the sibling covers the runtime is unresolved.",
            "decisionCritical": True,
        }
    ]

    result = validate(tmp_path, payload)

    assert result.returncode != 0
    assert "no_op cannot retain a decision-critical unknown" in result.stderr


def test_raw_worktree_is_not_a_supported_patch_source(tmp_path: Path) -> None:
    payload = assessment()
    payload["patch"]["sourceType"] = "raw_worktree"

    assert validate(tmp_path, payload).returncode != 0


def test_non_merge_recommendation_requires_matching_workflow_label(tmp_path: Path) -> None:
    payload = assessment()
    payload["recommendation"] = "revise"
    payload["validation"][0]["status"] = "failed"

    assert validate(tmp_path, payload).returncode != 0

    payload["workflowLabel"] = "revise"
    assert validate(tmp_path, payload).returncode == 0


def test_validator_does_not_modify_input(tmp_path: Path) -> None:
    payload = assessment()
    original = copy.deepcopy(payload)

    result = validate(tmp_path, payload)

    assert result.returncode == 0
    assert payload == original
