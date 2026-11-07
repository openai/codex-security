"""Keep review bookkeeping separate from published scan results."""

from __future__ import annotations

import argparse
import copy
from typing import Any


def uses_legacy_review(scan: dict[str, Any]) -> bool:
    """Return whether the manifest points to separate coverage or predates inline review metadata."""
    return "coverageRef" in scan or ("reviewState" not in scan and "review" not in scan)


def review_summary(state: dict[str, Any]) -> dict[str, Any]:
    """Return the excluded path patterns in the compact form stored on the scan manifest."""
    return {
        "excludedPaths": [item["pattern"] for item in state.get("explicitExclusions", [])],
    }


def review_state(scan: dict[str, Any]) -> dict[str, Any]:
    """Build the recovery coverage record from inline manifest metadata.

    Copy the saved review state, deriving exclusions from the summary when needed,
    and attach the inventory strategy and scope for this scan.
    """
    summary = scan.get("review", {})
    state = copy.deepcopy(scan.get("reviewState", {}))
    mode = scan.get("mode", "repository")
    state.setdefault("surfaces", [])
    state.setdefault("deferred", [])
    state.setdefault(
        "explicitExclusions",
        [
            {"pattern": path, "reason": "Excluded from review"}
            for path in summary.get("excludedPaths", [])
        ],
    )
    state.update(
        documentType="codex-security.coverage",
        schemaVersion="1.0",
        scanId=scan.get("id"),
        mode=mode,
        inventoryStrategy="scoped_path"
        if mode == "scoped_path"
        else "diff"
        if mode in {"diff", "commit", "branch_diff", "working_tree"}
        else "repository",
        includePaths=copy.deepcopy(scan.get("scope", {}).get("includePaths", [])),
        excludePaths=copy.deepcopy(scan.get("scope", {}).get("excludePaths", [])),
    )
    return state


def checkpoint_review_state(state: dict[str, Any]) -> dict[str, Any]:
    """Copy the review data needed for recovery, omitting per-surface risk areas and report metadata."""
    return {
        "surfaces": [
            {key: copy.deepcopy(value) for key, value in item.items() if key != "riskArea"}
            for item in state.get("surfaces", [])
        ],
        "explicitExclusions": copy.deepcopy(state.get("explicitExclusions", [])),
        "deferred": copy.deepcopy(state.get("deferred", [])),
        **{
            key: copy.deepcopy(state[key])
            for key in ("resolvedDeferred", "openQuestions", "reviews")
            if key in state
        },
    }


def _normalize_unsealed_open_questions(coverage: dict[str, Any]) -> None:
    """Keep only schema-valid optional open-question rows without inventing content."""

    open_questions = coverage.get("openQuestions")
    if not isinstance(open_questions, list):
        coverage.pop("openQuestions", None)
        return

    normalized: list[Any] = []
    for item in open_questions:
        if isinstance(item, str):
            question = item.strip()
            if question:
                normalized.append({"question": question})
            continue
        if not isinstance(item, dict):
            continue

        question = item.get("question")
        if not isinstance(question, str) or not question.strip():
            continue
        row = dict(item)
        row["question"] = question.strip()
        follow_up = row.get("followUpPrompt")
        if not isinstance(follow_up, str) or not follow_up.strip():
            row.pop("followUpPrompt", None)
        normalized.append(row)
    coverage["openQuestions"] = normalized


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
