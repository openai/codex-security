"""Keep review bookkeeping separate from published scan results."""

from __future__ import annotations

import argparse
import copy
from typing import Any


def uses_legacy_review(scan: dict[str, Any]) -> bool:
    return "coverageRef" in scan or ("reviewState" not in scan and "review" not in scan)


def review_summary(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "excludedPaths": [item["pattern"] for item in state.get("explicitExclusions", [])],
    }


def review_state(scan: dict[str, Any]) -> dict[str, Any]:
    """Read new manifest metadata using the recovery code's existing representation."""
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
    """Retain unfinished work and candidate outcomes, without a coverage report."""
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


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
