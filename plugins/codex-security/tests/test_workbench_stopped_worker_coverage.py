from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_workbench_recovery_edges import select_checkpoint
from workbench_test_support import (
    checkpoint,
    register,
    run_workbench,
    saved_draft,
    write_checkpoint,
    write_completed_contract,
)


def composed_scan(tmp_path: Path):
    state, target = tmp_path / "state", tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('synthetic')\n")
    parent = register(state, target, tmp_path / "parent", mode="deep")
    return state, target, parent, Path(parent["scanDir"])


def child_scan(state, target, parent, name, *, surfaces=(), deferred=(), finding=False):
    directory = Path(parent["scanDir"]) / "artifacts/deep-scan/passes" / name
    child = register(state, target, directory, parent=parent["scanId"], role="deep_pass")
    findings = []
    if finding:
        write_completed_contract(directory, child["scanId"], target, relative_path="app.py")
        findings = json.loads((directory / "findings.json").read_text())["findings"]
        for filename in ("scan-manifest.json", "findings.json", "coverage.json"):
            (directory / filename).unlink()
    draft = saved_draft(
        child["scanId"], complete=True, surfaces=surfaces, deferred=deferred, findings=findings
    )
    draft["coverage"]["inventoryStrategy"] = "repository"
    selected = write_checkpoint(directory / "checkpoints", draft)
    select_checkpoint(directory, selected)
    return child, directory, selected


def stop_parent(state, parent, children, termination="failed"):
    directory = Path(parent["scanDir"])
    checkpoint(
        state,
        parent,
        passes=[
            {"directory": str(path.relative_to(directory)), "scanId": child["scanId"]}
            for child, path, _ in children
        ],
    )
    run_workbench(
        state,
        "cancel-scan" if termination == "canceled" else "fail-scan",
        "--scan-id",
        parent["scanId"],
        *([] if termination == "canceled" else ["--message", "Synthetic interruption"]),
    )
    return run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]


@pytest.mark.parametrize("termination", ["failed", "canceled"])
@pytest.mark.parametrize("same_label", [False, True])
def test_stopped_composition_preserves_independent_coverage_and_receipts(
    tmp_path: Path, termination: str, same_label: bool
) -> None:
    state, target, parent, parent_dir = composed_scan(tmp_path)
    children = []
    originals = {}
    for name in ("first", "second"):
        child, directory, selected = child_scan(
            state,
            target,
            parent,
            name,
            finding=name == "first",
            surfaces=[
                {
                    "id": "api",
                    "label": "API" if same_label else name,
                    "disposition": "no_issue_found",
                    "receiptRefs": ["artifacts/review.md"],
                }
            ],
            deferred=[{"id": "review", "reason": f"Review {name} remains.", "surfaceIds": ["api"]}],
        )
        receipt = directory / "artifacts/review.md"
        receipt.write_text(f"Synthetic {name} review.\n")
        children.append((child, directory, selected))
        originals.update({path: path.read_bytes() for path in (selected, receipt)})
    stopped = stop_parent(state, parent, children, termination)
    assert stopped["progress"]["status"] == termination
    assert stopped["findingCount"] == 1
    assert not any("coverage receipt" in warning for warning in stopped["warnings"])
    coverage = json.loads((parent_dir / "coverage.json").read_text())
    assert "completeness" not in coverage
    assert {row["id"] for row in coverage["surfaces"]} == {
        f"{child['scanId']}/api" for child, _, _ in children
    }
    for child, directory, _ in children:
        surface = next(row for row in coverage["surfaces"] if row["id"] == f"{child['scanId']}/api")
        task = next(row for row in coverage["deferred"] if row["id"] == f"{child['scanId']}/review")
        assert task["surfaceIds"] == [surface["id"]]
        assert surface["disposition"] == "no_issue_found"
        assert surface["receiptRefs"] == [
            (directory / "artifacts/review.md").relative_to(parent_dir).as_posix()
        ]
    sealed = {
        name: (parent_dir / name).read_bytes()
        for name in ("scan-manifest.json", "coverage.json", "report.md")
    }
    run_workbench(state, "preserve-scan-results", "--scan-id", parent["scanId"])
    assert all((parent_dir / name).read_bytes() == contents for name, contents in sealed.items())
    assert all(path.read_bytes() == contents for path, contents in originals.items())


@pytest.mark.parametrize("reference", ["checkpoint.json", "artifacts/missing.md", "../outside.md"])
def test_stopped_child_recovers_invalid_receipts_before_projection(
    tmp_path: Path, reference: str
) -> None:
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
    )
    original = selected.read_bytes()
    stopped = stop_parent(state, parent, [(child, directory, selected)])
    assert stopped["progress"]["status"] == "failed"
    surface = json.loads((parent_dir / "coverage.json").read_text())["surfaces"][0]
    assert surface["id"] == f"{child['scanId']}/api"
    assert surface["disposition"] == "needs_follow_up"
    assert surface["receiptRefs"] == []
    child_state = run_workbench(state, "get-scan", "--scan-id", child["scanId"])["scan"]
    assert any("coverage receipt" in warning for warning in child_state["warnings"])
    assert selected.read_bytes() == original


@pytest.mark.parametrize("anonymous_first", [True, False])
def test_child_links_remain_bound_to_explicit_surface_through_generated_id_collisions(
    tmp_path: Path, anonymous_first: bool
) -> None:
    state, target, parent, parent_dir = composed_scan(tmp_path)
    anonymous = {"candidateId": "api", "label": "Anonymous", "disposition": "needs_follow_up"}
    explicit = {"id": "api", "label": "Explicit", "disposition": "needs_follow_up"}
    child, directory, selected = child_scan(
        state,
        target,
        parent,
        "first",
        surfaces=[anonymous, explicit] if anonymous_first else [explicit, anonymous],
        deferred=[{"id": "review", "reason": "Review remains.", "surfaceIds": ["api"]}],
    )
    stop_parent(state, parent, [(child, directory, selected)])
    coverage = json.loads((parent_dir / "coverage.json").read_text())
    surfaces = {row["label"]: row for row in coverage["surfaces"]}
    assert len(surfaces) == 2
    assert surfaces["Explicit"]["id"] != surfaces["Anonymous"]["id"]
    task = next(row for row in coverage["deferred"] if row["id"] == f"{child['scanId']}/review")
    assert task["surfaceIds"] == [surfaces["Explicit"]["id"]]
