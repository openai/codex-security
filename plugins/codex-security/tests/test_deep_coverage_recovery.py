"""Coverage recovery through ordinary child scans and composed parent publication."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from test_workbench_recovery_edges import select_checkpoint
from test_workbench_stopped_worker_coverage import child_scan, composed_scan, stop_parent
from workbench_test_support import run_workbench, saved_draft, write_checkpoint


def coverage(directory: Path) -> dict:
    return json.loads((directory / "coverage.json").read_text())


def save_child(
    child: dict, directory: Path, *, surfaces=(), deferred=(), closures=(), complete=True
):
    draft = saved_draft(
        child["scanId"],
        complete=complete,
        surfaces=surfaces,
        deferred=deferred,
        closures=closures,
    )
    draft["coverage"]["inventoryStrategy"] = "repository"
    selected = write_checkpoint(directory / "checkpoints", draft)
    select_checkpoint(directory, selected)
    return selected


def receipt(directory: Path, name: str) -> str:
    path = directory / "artifacts" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"Synthetic evidence from {name}.\n")
    return path.relative_to(directory).as_posix()


def assert_replay(state: Path, parent: dict, originals: dict[Path, bytes]) -> None:
    directory = Path(parent["scanDir"])
    published = {
        name: (directory / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json", "report.md")
    }
    run_workbench(state, "preserve-scan-results", "--scan-id", parent["scanId"])
    assert all((directory / name).read_bytes() == contents for name, contents in published.items())
    assert all(path.read_bytes() == contents for path, contents in originals.items())


def original_evidence(directory: Path) -> dict[Path, bytes]:
    return {
        path: path.read_bytes()
        for pattern in ("checkpoints/*.json", "artifacts/*.md")
        for path in directory.glob(pattern)
    }


@pytest.mark.parametrize(
    "reference", ["artifacts/review.md", "artifacts/./review.md", "artifacts//review.md"]
)
@pytest.mark.parametrize("exclusion_id", [{}, {"id": None}, {"id": 7}, {"id": "external"}])
def test_child_projection_normalizes_receipts_and_preserves_extension_metadata(
    tmp_path, reference, exclusion_id
):
    state, target, parent, parent_dir = composed_scan(tmp_path)
    child, directory, selected = child_scan(
        state,
        target,
        parent,
        "first",
        surfaces=[
            {
                "id": "api",
                "label": "API",
                "disposition": "no_issue_found",
                "receiptRefs": [reference],
            }
        ],
        deferred=[
            {
                "id": "review",
                "reason": "Review another route.",
                "surfaceIds": ["api"],
                "receiptRefs": {"external": "opaque metadata"},
            }
        ],
    )
    draft = json.loads(selected.read_text())
    draft["coverage"]["explicitExclusions"] = [
        {
            **exclusion_id,
            "pattern": "vendor/**",
            "reason": "External code.",
            "receiptRefs": ["opaque/missing.md"],
            "surfaceIds": ["opaque-id"],
        }
    ]
    question = {
        "id": "configuration",
        "question": "Which deployments enable this handler?",
        "receiptRefs": ["opaque/question.md"],
        "surfaceIds": ["opaque-question"],
    }
    draft["coverage"]["openQuestions"] = [question]
    selected = write_checkpoint(directory / "checkpoints", draft)
    select_checkpoint(directory, selected)
    receipt(directory, "review.md")
    originals = original_evidence(directory)
    stopped = stop_parent(state, parent, [(child, directory, selected)])
    assert stopped["progress"]["status"] == "failed"
    result = coverage(parent_dir)
    surface = result["surfaces"][0]
    assert surface["receiptRefs"] == [
        (directory / "artifacts/review.md").relative_to(parent_dir).as_posix()
    ]
    task = next(row for row in result["deferred"] if row["id"] == f"{child['scanId']}/review")
    assert task["surfaceIds"] == [surface["id"]]
    assert task["receiptRefs"] == {"external": "opaque metadata"}
    exclusion = result["explicitExclusions"][0]
    assert {key: value for key, value in exclusion.items() if key != "id"} == {
        key: value
        for key, value in draft["coverage"]["explicitExclusions"][0].items()
        if key != "id"
    }
    assert result["openQuestions"] == [{**question, "id": f"{child['scanId']}/configuration"}]
    assert_replay(state, parent, originals)


@pytest.mark.parametrize("duplicate_ids", [False, True])
def test_distinct_child_tasks_keep_unique_identities_during_stopped_replay(tmp_path, duplicate_ids):
    state, target, parent, parent_dir = composed_scan(tmp_path)
    tasks = [
        {"reason": "Review authentication."},
        {"reason": "Review authorization."},
        {"reason": "Review routing."},
    ]
    if duplicate_ids:
        for row, identity in zip(tasks, ["review", "review", "review-2"], strict=True):
            row["id"] = identity
    child, directory, selected = child_scan(
        state, target, parent, "first", deferred=tasks if duplicate_ids else ()
    )
    if not duplicate_ids:
        for task in tasks:
            selected = save_child(child, directory, deferred=[task], complete=False)
    originals = original_evidence(directory)
    stop_parent(state, parent, [(child, directory, selected)])
    retained = [
        row
        for row in coverage(parent_dir)["deferred"]
        if row["id"].startswith(f"{child['scanId']}/")
        and row["id"] != f"{child['scanId']}/scan-stopped"
    ]
    assert {row["reason"] for row in retained} == {row["reason"] for row in tasks}
    assert len({row["id"] for row in retained}) == len(tasks)
    assert_replay(state, parent, originals)


@pytest.mark.parametrize("split_surfaces", [False, True])
def test_stopped_child_receipt_collisions_preserve_other_child_findings(tmp_path, split_surfaces):
    state, target, parent, parent_dir = composed_scan(tmp_path)
    accepted = child_scan(state, target, parent, "accepted", finding=True)
    rows = [
        {
            "id": "reader",
            "label": "Reader",
            "disposition": "no_issue_found",
            "receiptRefs": ["artifacts/review.md"],
        },
        {
            "id": "writer",
            "label": "Writer",
            "disposition": "no_issue_found",
            "receiptRefs": ["artifacts/Review.md"],
        },
    ]
    if not split_surfaces:
        rows[0]["receiptRefs"].extend(rows.pop()["receiptRefs"])
    child, directory, selected = child_scan(state, target, parent, "failed", surfaces=rows)
    receipt(directory, "review.md")
    receipt(directory, "Review.md")
    originals = original_evidence(directory) | original_evidence(accepted[1])
    stopped = stop_parent(state, parent, [accepted, (child, directory, selected)])
    assert stopped["progress"]["status"] == "failed"
    assert stopped["findingCount"] == 1
    failed_rows = [
        row for row in coverage(parent_dir)["surfaces"] if row["id"].startswith(child["scanId"])
    ]
    assert any(row["disposition"] == "needs_follow_up" for row in failed_rows)
    child_state = run_workbench(state, "get-scan", "--scan-id", child["scanId"])["scan"]
    assert any("duplicate artifact path" in warning for warning in child_state["warnings"])
    assert_replay(state, parent, originals)


@pytest.mark.parametrize(
    "missing,surviving_case_variant,reverse",
    [(False, False, False), (True, False, False), (True, True, False), (True, True, True)],
)
def test_terminal_child_closeout_replaces_invalid_historical_receipt(
    tmp_path, missing, surviving_case_variant, reverse
):
    state, target, parent, parent_dir = composed_scan(tmp_path)
    old_ref = "artifacts/missing.md" if missing else "artifacts/unsafe:name.md"
    surface = {
        "id": "api",
        "label": "Original review",
        "notes": "Original notes",
        "disposition": "needs_follow_up",
        "receiptRefs": [old_ref],
    }
    if surviving_case_variant:
        surface["receiptRefs"].append("artifacts/Missing.md")
    if reverse:
        surface["receiptRefs"].reverse()
    child, directory, _ = child_scan(
        state,
        target,
        parent,
        "first",
        surfaces=[surface],
        deferred=[{"id": "review", "reason": "Review remains.", "surfaceIds": ["api"]}],
    )
    if not missing:
        receipt(directory, "unsafe:name.md")
    if surviving_case_variant:
        receipt(directory, "Missing.md")
    replacement = receipt(directory, "replacement.md")
    selected = save_child(
        child,
        directory,
        surfaces=[
            {
                **surface,
                "label": "Accepted review",
                "notes": "Accepted notes",
                "disposition": "no_issue_found",
                "receiptRefs": [replacement],
            }
        ],
        closures=[{"id": "review", "reason": "Review completed."}],
    )
    originals = original_evidence(directory)
    stop_parent(state, parent, [(child, directory, selected)])
    result = coverage(parent_dir)
    retained = next(row for row in result["surfaces"] if row["id"] == f"{child['scanId']}/api")
    assert retained["label"] == "Accepted review"
    assert retained["notes"] == "Accepted notes"
    assert retained["disposition"] == "no_issue_found"
    expected = {(directory / replacement).relative_to(parent_dir).as_posix()}
    if surviving_case_variant:
        expected.add((directory / "artifacts/Missing.md").relative_to(parent_dir).as_posix())
    assert set(retained["receiptRefs"]) == expected
    assert not any(row["id"] == f"{child['scanId']}/review" for row in result["deferred"])
    assert_replay(state, parent, originals)


@pytest.mark.parametrize("reverse", [False, True])
def test_selected_child_receipt_spelling_precedes_historical_surface_receipts(tmp_path, reverse):
    state, target, parent, parent_dir = composed_scan(tmp_path)
    rows = [
        {
            "id": "reader",
            "label": "Reader",
            "disposition": "needs_follow_up",
            "receiptRefs": ["artifacts/review.md"],
        },
        {
            "id": "writer",
            "label": "Writer",
            "disposition": "needs_follow_up",
            "receiptRefs": ["artifacts/Review.md"],
        },
    ]
    if reverse:
        rows.reverse()
    child, directory, _ = child_scan(
        state,
        target,
        parent,
        "first",
        surfaces=rows,
        deferred=[
            {"id": "review", "reason": "Review remains.", "surfaceIds": ["reader", "writer"]}
        ],
    )
    for name in ("review.md", "Review.md", "replacement.md"):
        receipt(directory, name)
    current = copy.deepcopy(rows)
    for row in current:
        row["disposition"] = "no_issue_found"
        if row["id"] == "reader":
            row["receiptRefs"] = ["artifacts/replacement.md"]
    selected = save_child(
        child,
        directory,
        surfaces=current,
        closures=[{"id": "review", "reason": "Review completed."}],
    )
    originals = original_evidence(directory)
    stop_parent(state, parent, [(child, directory, selected)])
    rows = {row["label"]: row for row in coverage(parent_dir)["surfaces"]}
    for label, name in [("Reader", "replacement.md"), ("Writer", "Review.md")]:
        assert rows[label]["disposition"] == "no_issue_found"
        assert rows[label]["receiptRefs"] == [
            (directory / "artifacts" / name).relative_to(parent_dir).as_posix()
        ]
    assert_replay(state, parent, originals)


def test_parent_refresh_preserves_repaired_child_receipts(tmp_path):
    state, target, parent, parent_dir = composed_scan(tmp_path)
    surface = {
        "id": "api",
        "label": "API",
        "disposition": "no_issue_found",
        "receiptRefs": ["artifacts/review.md"],
    }
    child, directory, selected = child_scan(state, target, parent, "first", surfaces=[surface])
    receipt(directory, "review.md")
    stop_parent(state, parent, [(child, directory, selected)])
    replacement = receipt(directory, "Review.md")
    latest = save_child(child, directory, surfaces=[{**surface, "receiptRefs": [replacement]}])
    run_workbench(state, "recover-scan-results", "--scan-id", child["scanId"])
    expected = coverage(directory)["surfaces"][0]
    assert expected["disposition"] == "no_issue_found"
    assert expected["receiptRefs"] == [replacement]
    originals = original_evidence(directory)
    for _ in range(2):
        recovered = run_workbench(state, "recover-scan-results", "--scan-id", parent["scanId"])[
            "scan"
        ]
        assert recovered["resultsRecoveryNeeded"] is False
        retained = next(
            row for row in coverage(parent_dir)["surfaces"] if row["id"] == f"{child['scanId']}/api"
        )
        assert retained["disposition"] == "no_issue_found"
        assert retained["receiptRefs"] == [
            (directory / replacement).relative_to(parent_dir).as_posix()
        ]
        assert all(path.read_bytes() == content for path, content in originals.items())
    assert latest.read_bytes() == originals[latest]
