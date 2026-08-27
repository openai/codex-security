#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "patch-risk-assessment.schema.json"
NON_APPLICABLE = {"no_live_effect", "wrong_owner", "duplicate", "superseded"}


def load_scan_contract_validator() -> ModuleType:
    script = PLUGIN_ROOT / "scripts" / "finalize_scan_contract.py"
    spec = importlib.util.spec_from_file_location("codex_security_scan_contract", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load scan contract validator: {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SCAN_CONTRACT = load_scan_contract_validator()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate a patch-risk assessment.")
    parser.add_argument("assessment", help="Assessment JSON path, or - for stdin.")
    return parser.parse_args()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def read_object(path: str) -> dict[str, Any]:
    try:
        text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
        value = json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read assessment: {error}") from error
    if not isinstance(value, dict):
        raise ValueError("assessment must be a JSON object")
    return value


def schema_errors(value: dict[str, Any]) -> list[str]:
    try:
        SCAN_CONTRACT.validate_against_schema(value, SCHEMA_PATH)
    except (OSError, ValueError, RecursionError) as error:
        return [str(error)]
    return []


def semantic_errors(value: dict[str, Any]) -> list[str]:
    recommendation = value["recommendation"]
    workflow_label = value["workflowLabel"]
    unknowns = value["unknowns"]
    evidence_plan = value["evidencePlan"]
    boundaries = value["materialBoundaries"]
    applicability_status = value["applicability"]["status"]
    affirmative_failure = (
        value["regressionLikelihood"]["rating"] == "critical"
        or any(item["result"] == "contradicted" for item in boundaries)
        or any(item["status"] == "failed" for item in value["validation"])
    )
    errors: list[str] = []

    if recommendation == "merge":
        if workflow_label not in {"auto_merge_candidate", "human_review_required"}:
            errors.append("merge requires an auto-merge or human-review workflow label")
        if value["applicability"]["status"] != "confirmed":
            errors.append("merge requires confirmed applicability")
        if any(item["decisionCritical"] for item in unknowns):
            errors.append("merge cannot retain a decision-critical unknown")
        if any(item["result"] != "supported" for item in boundaries):
            errors.append("merge requires every material boundary to be supported")
        if any(item["status"] == "failed" for item in value["validation"]):
            errors.append("merge cannot retain a failed validation")
        if evidence_plan:
            errors.append("merge cannot retain an evidence plan")
    elif workflow_label != recommendation:
        errors.append("non-merge workflow label must match the recommendation")

    if recommendation == "hold_for_evidence":
        if not any(item["decisionCritical"] for item in unknowns):
            errors.append("hold_for_evidence requires a decision-critical unknown")
        if not evidence_plan:
            errors.append("hold_for_evidence requires a bounded evidence plan")
        if affirmative_failure:
            errors.append("hold_for_evidence cannot defer an established defect")
    elif evidence_plan:
        errors.append("only hold_for_evidence may include an evidence plan")

    if recommendation == "no_op":
        if applicability_status not in NON_APPLICABLE:
            errors.append("no_op requires an established non-applicable disposition")
        if any(item["decisionCritical"] for item in unknowns):
            errors.append("no_op cannot retain a decision-critical unknown")
    elif applicability_status in NON_APPLICABLE:
        errors.append("an established non-applicable disposition requires no_op")

    if recommendation in {"revise", "block"}:
        if not affirmative_failure:
            errors.append(f"{recommendation} requires affirmative failure evidence")

    if workflow_label == "auto_merge_candidate":
        auto_merge_requirements = {
            "impact.rating": value["impact"]["rating"] == "low",
            "regressionLikelihood.rating": value["regressionLikelihood"]["rating"] == "low",
            "regressionProtection.rating": value["regressionProtection"]["rating"] == "strong",
            "regressionProtection.exactHeadChecksPassed": value["regressionProtection"][
                "exactHeadChecksPassed"
            ],
            "recoverability.rating": value["recoverability"]["rating"] == "easy",
            "confidence.rating": value["confidence"]["rating"] == "high",
            "applicability.status": value["applicability"]["status"] == "confirmed",
            "affectedRuntimeRoots": bool(value["affectedRuntimeRoots"]),
            "statusQuoRisk.rating": value["statusQuoRisk"]["rating"] != "unknown",
            "autoMergeExclusions": not value["autoMergeExclusions"],
            "unknowns": not unknowns,
            "validation": all(item["status"] == "passed" for item in value["validation"]),
        }
        for field, passed in auto_merge_requirements.items():
            if not passed:
                errors.append(f"auto_merge_candidate gate failed: {field}")

    return errors


def validate(value: dict[str, Any]) -> list[str]:
    errors = schema_errors(value)
    if errors:
        return errors
    return semantic_errors(value)


def main() -> int:
    args = parse_args()
    try:
        value = read_object(args.assessment)
        errors = validate(value)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
