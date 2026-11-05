"""Merge usage coverage across observations without losing known gaps."""

from __future__ import annotations

import json

import pytest
from workbench_test_support import usage_counts as _counts


@pytest.mark.parametrize(
    ("previous_input", "previous_output", "latest_roles"),
    [(21, 8, True), (37, 8, True), (20, 9, True), (21, 8, False)],
    ids=["equal-subtotal", "older-larger-subtotal", "different-token-fields", "no-latest-roles"],
)
def test_coverage_counts_and_roles_follow_the_latest_observation(
    workbench_api, previous_input: int, previous_output: int, latest_roles: bool
) -> None:
    merge = workbench_api["_WORKBENCH_DB_CONTEXT"].scan_usage.merge_scan_usage_fields
    previous = {
        "coverage": "complete",
        "coverageScope": ["thread:parent"],
        "source": "codex_runtime",
        "threadCount": 1,
        "observedAt": "2026-01-01T00:00:00Z",
        **_counts(previous_input, 0, previous_output),
        "byRole": {
            "parent": {"threadCount": 1, **_counts(previous_input, 0, previous_output)},
            "workers": {"threadCount": 0, **_counts(0, 0, 0)},
        },
    }
    observed = {
        "coverage": "complete",
        "coverageScope": ["thread:parent", "thread:worker"],
        "source": "codex_rollout" if latest_roles else "codex_runtime",
        "threadCount": 2,
        "observedAt": "2026-01-01T00:00:01Z",
        "cacheWriteInputTokensReported": False,
        **_counts(21, 0, 8),
    }
    if latest_roles:
        observed["byRole"] = {
            "parent": {
                "threadCount": 1,
                "cacheWriteInputTokensReported": False,
                **_counts(21, 0, 8),
            },
            "workers": {"threadCount": 1, **_counts(0, 0, 0)},
        }
    for observation in [previous, observed]:
        workbench_api["parse_scan_cost"](json.dumps({"usage": observation}))

    merged = merge({"usage": previous}, {"usage": observed})
    usage = merged["usage"]
    assert usage["threadCount"] == 2
    assert usage["coverage"] == "complete"
    assert usage["coverageScope"] == observed["coverageScope"]
    assert usage["observedAt"] == observed["observedAt"]
    for field, value in _counts(previous_input, 0, previous_output).items():
        assert usage[field] == value
    if latest_roles and (previous_input, previous_output) == (21, 8):
        assert usage["byRole"] == observed["byRole"]
    else:
        assert "byRole" not in usage
    assert json.loads(workbench_api["parse_scan_cost"](json.dumps(merged))) == merged
    assert merge({"usage": observed}, {"usage": previous}) == merged
    assert merge(merged, {"usage": previous}) == merged


@pytest.mark.parametrize(
    ("previous_threads", "previous_tokens", "new_threads", "new_tokens", "combined_tokens"),
    [
        (["parent", "validation"], 1_000, ["parent", "worker"], 1_200, 1_400),
        (["parent", "validation"], 1_000, ["parent"], 1_200, 1_400),
        (["parent", "validation", "worker"], 1_010, ["parent", "worker"], 910, 1_110),
        (["validation"], 200, ["parent"], 800, 1_000),
    ],
    ids=["incomparable", "narrower-larger", "narrower-smaller", "disjoint"],
)
def test_newer_scoped_subtotals_need_encompassing_complete_evidence(
    workbench_api,
    previous_threads: list[str],
    previous_tokens: int,
    new_threads: list[str],
    new_tokens: int,
    combined_tokens: int,
) -> None:
    merge = workbench_api["_WORKBENCH_DB_CONTEXT"].scan_usage.merge_scan_usage_fields
    previous = {
        "coverage": "complete",
        "coverageScope": [f"thread:{thread}" for thread in previous_threads],
        "source": "codex_runtime",
        "threadCount": len(previous_threads),
        "observedAt": "2026-01-01T00:00:00Z",
        **_counts(previous_tokens, 0, 0),
    }
    observed = {
        "coverage": "complete",
        "coverageScope": [f"thread:{thread}" for thread in new_threads],
        "source": "codex_rollout",
        "threadCount": len(new_threads),
        "observedAt": "2026-01-01T00:00:01Z",
        **_counts(new_tokens, 0, 0),
    }
    partial = merge({"usage": previous}, {"usage": observed})
    assert partial["usage"]["totalTokens"] == max(previous_tokens, new_tokens)
    assert partial["usage"]["coverage"] == "partial"
    assert partial["usage"]["warnings"] == ["usage_scope_incomplete"]
    assert partial["usage"]["coverageScope"] == sorted(
        set(previous["coverageScope"]) | set(observed["coverageScope"])
    )
    assert partial["usage"]["observedAt"] == observed["observedAt"]
    assert partial["usage"]["threadCount"] == len(new_threads)
    assert merge({"usage": observed}, {"usage": previous}) == partial
    assert merge(partial, {"usage": previous}) == partial

    complete = {
        **previous,
        "coverageScope": partial["usage"]["coverageScope"],
        "threadCount": len(partial["usage"]["coverageScope"]),
        "observedAt": "2026-01-01T00:00:02Z",
        **_counts(combined_tokens, 0, 0),
    }
    resolved = merge(partial, {"usage": complete})
    assert resolved["usage"] == complete
    assert merge(resolved, partial) == resolved
    assert merge(resolved, {"usage": observed}) == resolved


def test_legacy_partial_without_scope_does_not_claim_resolved_coverage(workbench_api) -> None:
    merge = workbench_api["_WORKBENCH_DB_CONTEXT"].scan_usage.merge_scan_usage_fields
    partial = {
        "coverage": "partial",
        "source": "codex_runtime",
        "threadCount": 1,
        "missingThreadCount": 1,
        **_counts(40, 0, 5),
    }
    complete = {
        "coverage": "complete",
        "coverageScope": ["thread:scan-parent"],
        "source": "codex_rollout",
        "threadCount": 1,
        **_counts(50, 0, 8),
    }
    merged = merge({"usage": partial}, {"usage": complete})["usage"]
    assert merged["coverage"] == "partial"
    assert merged["totalTokens"] == 58
    assert merged["missingThreadCount"] == 1
    assert "coverageScope" not in merged


def test_unscoped_complete_observation_keeps_known_gap_identity(workbench_api) -> None:
    merge = workbench_api["_WORKBENCH_DB_CONTEXT"].scan_usage.merge_scan_usage_fields
    partial = {
        "coverage": "partial",
        "coverageScope": ["thread:scan-parent", "thread:missing-worker"],
        "source": "codex_runtime",
        "threadCount": 1,
        "missingThreadCount": 1,
        **_counts(40, 0, 5),
    }
    legacy_complete = {
        "coverage": "complete",
        "source": "codex_runtime",
        "threadCount": 2,
        **_counts(50, 0, 8),
    }
    merged = merge({"usage": partial}, {"usage": legacy_complete})
    assert merged["usage"]["coverage"] == "partial"
    assert merged["usage"]["coverageScope"] == partial["coverageScope"]
    resolved = merge(
        merged,
        {"usage": {**legacy_complete, "coverageScope": partial["coverageScope"]}},
    )
    assert resolved["usage"]["coverage"] == "complete"
    assert not resolved["usage"].get("missingThreadCount")
