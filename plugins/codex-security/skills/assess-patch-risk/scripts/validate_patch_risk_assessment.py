#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "patch-risk-assessment.schema.json"
NON_APPLICABLE = {"no_live_effect", "wrong_owner", "duplicate", "superseded"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate a patch-risk assessment.")
    parser.add_argument("assessment", help="Assessment JSON path, or - for stdin.")
    return parser.parse_args()


def read_object(path: str) -> dict[str, Any]:
    try:
        text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
        value = json.loads(text)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read assessment: {error}") from error
    if not isinstance(value, dict):
        raise ValueError("assessment must be a JSON object")
    return value


def schema_errors(value: dict[str, Any]) -> list[str]:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors: list[str] = []
    for error in sorted(validator.iter_errors(value), key=lambda item: list(item.absolute_path)):
        path = ".".join(str(part) for part in error.absolute_path) or "$"
        errors.append(f"{path}: {error.message}")
    return errors


def semantic_errors(value: dict[str, Any]) -> list[str]:
    recommendation = value["recommendation"]
    workflow_label = value["workflowLabel"]
    unknowns = value["unknowns"]
    evidence_plan = value["evidencePlan"]
    boundaries = value["materialBoundaries"]
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
        if evidence_plan:
            errors.append("merge cannot retain an evidence plan")
    elif workflow_label != recommendation:
        errors.append("non-merge workflow label must match the recommendation")

    if recommendation == "hold_for_evidence":
        if not any(item["decisionCritical"] for item in unknowns):
            errors.append("hold_for_evidence requires a decision-critical unknown")
        if not evidence_plan:
            errors.append("hold_for_evidence requires a bounded evidence plan")
    elif evidence_plan:
        errors.append("only hold_for_evidence may include an evidence plan")

    if recommendation == "no_op":
        if value["applicability"]["status"] not in NON_APPLICABLE:
            errors.append("no_op requires an established non-applicable disposition")
        if any(item["decisionCritical"] for item in unknowns):
            errors.append("no_op cannot retain a decision-critical unknown")

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
