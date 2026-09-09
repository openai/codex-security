from __future__ import annotations

import hashlib
import json
import os
import runpy
import sqlite3
import subprocess
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from workbench_test_support import (
    SCRIPT,
    create_saved_git_workspace,
    create_saved_workspace,
    initialize_git_repository,
    run_workbench,
    stable_target_id,
    start_delivered_scan,
    write_completed_contract,
)

HEAD_CHANGED_WARNING = (
    "Repository HEAD changed while the scan was running; "
    "results were saved for the original revision."
)
WORKTREE_CHANGED_WARNING = (
    "Working-tree contents changed while the scan was running; "
    "results were saved for the original snapshot."
)
DIRECTORY_CHANGED_WARNING = (
    "Directory contents changed while the scan was running; "
    "results were saved for the original snapshot."
)
TARGET_UNAVAILABLE_WARNING = (
    "The scan target became unavailable while the scan was running; "
    "results were saved for the original revision or snapshot."
)
GIT_UNAVAILABLE_WARNING = (
    "The scanned Git repository became unavailable while the scan was running; "
    "results were saved for the original revision."
)
BUDGET_COST = {
    "model": "gpt-5.6-sol",
    "inputTokens": 1250,
    "cachedInputTokens": 200,
    "cacheWriteInputTokens": 0,
    "outputTokens": 30,
    "estimatedUsd": 0.00625,
}
BUDGET_WARNING = "Scan stopped: estimated cost $0.00625 exceeded the $0.005 cost limit."

EXPECTED_TABLES = {
    "deep_scan_dedup_inputs",
    "deep_scan_runs",
    "deep_scan_workers",
    "finding_decisions",
    "finding_dedupe_group_members",
    "finding_dedupe_groups",
    "finding_embeddings",
    "finding_locations",
    "finding_occurrences",
    "finding_publications",
    "finding_remediation_attempts",
    "finding_repositories",
    "finding_triage",
    "finding_workflow_reviews",
    "finding_severity_assessments",
    "scan_severity_classifications",
    "finding_workflows",
    "findings",
    "scan_artifacts",
    "scan_comparison_matches",
    "scan_comparisons",
    "scan_progress",
    "scans",
    "schema_migrations",
    "security_targets",
    "setup_preferences",
    "triage_results",
    "workspaces",
}


def budget_scan_fixture(
    tmp_path: Path,
    *,
    candidates: list[dict[str, Any]] | None = None,
    mode: str = "deep",
    paths: list[str] | None = None,
    terminal: bool = True,
    terminal_reason: str = "saturated",
) -> tuple[Path, Path, Path, str, Path]:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("value = request.args['value']\n")
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    registered = run_workbench(
        state_dir,
        "register-cli-scan",
        "--scan-dir",
        str(scan_dir),
        "--repository",
        str(target),
        "--recipe-json",
        json.dumps(
            {
                "config": {},
                "mode": mode,
                "repository": str(target),
                "target": {
                    "kind": "paths" if paths else "repository",
                    "paths": paths or [],
                },
                "maxCostUsd": 0.005,
            }
        ),
    )
    scan_id = str(registered["scanId"])
    if mode != "deep":
        return state_dir, target, scan_dir, scan_id, scan_dir / "candidate_ledger.jsonl"
    run_workbench(
        state_dir,
        "begin-deep-scan",
        "--thread-id",
        "sdk-thread",
        "--scan-id",
        scan_id,
        environment={"CODEX_HOME": str(tmp_path / "codex-home")},
    )
    discovery = scan_dir / "artifacts" / "02_discovery"
    discovery.mkdir(parents=True, exist_ok=True)
    (discovery / "in_scope_files.txt").write_text("app.py\n")
    ledger = discovery / "candidate_ledger.jsonl"
    rows = (
        candidates
        if candidates is not None
        else [
            {
                "candidate_id": "candidate-1",
                "cwe_ids": ["CWE-89"],
                "locations": [{"path": "app.py", "start_line": 1, "end_line": 1, "role": "sink"}],
                "summary": "User input reaches a SQL statement",
                "evidence": "request.args['value'] reaches execute() without parameter binding",
            }
        ]
    )
    ledger.write_text("".join(f"{json.dumps(row)}\n" for row in rows))
    if terminal:
        manifest = scan_dir / "artifacts" / "deep_discovery" / "coordinator-manifest.json"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text('{"status":"succeeded"}\n')
        with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
            connection.execute(
                """
                UPDATE deep_scan_runs
                SET status = 'succeeded', phase = 'terminal', terminal_reason = ?,
                    manifest_path = ?, completed_at = updated_at
                WHERE scan_id = ?
                """,
                (terminal_reason, str(manifest), scan_id),
            )
    return state_dir, target, scan_dir, scan_id, ledger


def complete_budget_scan(state_dir: Path, scan_id: str, *, check: bool = True) -> dict[str, object]:
    return run_workbench(
        state_dir,
        "complete-budget-exhausted-scan",
        "--scan-id",
        scan_id,
        "--cost-json",
        json.dumps(BUDGET_COST),
        "--message",
        BUDGET_WARNING,
        check=check,
    )


def test_cost_limit_increases_are_saved_without_replacing_the_scan_recipe(
    tmp_path: Path,
) -> None:
    state_dir, _, _, scan_id, _ = budget_scan_fixture(tmp_path)
    original = run_workbench(state_dir, "get-scan-recipe", "--scan-id", scan_id)["recipe"]
    for limit in (0.0055, 0.006):
        run_workbench(
            state_dir,
            "set-scan-cost-limit",
            "--scan-id",
            scan_id,
            "--max-cost-usd",
            str(limit),
        )
    saved = run_workbench(state_dir, "get-scan-recipe", "--scan-id", scan_id)["recipe"]
    assert saved == {**original, "maxCostUsd": 0.006}
    assert complete_budget_scan(state_dir, scan_id)["scan"]["progress"]["status"] == "complete"
    stopped = run_workbench(
        state_dir,
        "set-scan-cost-limit",
        "--scan-id",
        scan_id,
        "--max-cost-usd",
        "1",
        check=False,
    )
    assert stopped["returncode"] != 0


@pytest.mark.parametrize("limit", ["0", "-1", "nan", "inf", "0.004", "0.005"])
def test_cost_limit_rejects_invalid_or_nonincreasing_totals(tmp_path: Path, limit: str) -> None:
    state_dir, _, _, scan_id, _ = budget_scan_fixture(tmp_path, mode="standard")
    result = run_workbench(
        state_dir,
        "set-scan-cost-limit",
        "--scan-id",
        scan_id,
        "--max-cost-usd",
        limit,
        check=False,
    )
    assert result["returncode"] != 0
    assert (
        run_workbench(state_dir, "get-scan-recipe", "--scan-id", scan_id)["recipe"]["maxCostUsd"]
        == 0.005
    )


def test_budget_exhaustion_preserves_unvalidated_discovery_as_deferred_work(
    tmp_path: Path,
) -> None:
    state_dir, target, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    original_ledger = ledger.read_bytes()

    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    assert completed["progress"]["status"] == "complete"
    assert completed["findings"] == []
    assert completed["cost"] == BUDGET_COST
    assert completed["warnings"] == [BUDGET_WARNING]
    assert ledger.read_bytes() == original_ledger
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["target"]["displayName"] == target.name
    assert manifest["scan"]["target"]["targetId"] == stable_target_id(target)
    assert manifest["scan"]["sealedAt"]
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert coverage["mode"] == "deep_repository"
    assert coverage["completeness"] == "partial"
    assert coverage["deferred"][0]["id"] == "candidate-1"
    assert coverage["deferred"][0]["paths"] == ["app.py"]
    assert "cost limit" in coverage["deferred"][0]["reason"]
    assert "User input reaches a SQL statement" in coverage["deferred"][0]["reason"]
    assert coverage["surfaces"][0]["disposition"] == "needs_follow_up"
    report = (scan_dir / "report.md").read_text()
    assert "No findings were validated before the scan reached its cost limit" in report
    assert "User input reaches a SQL statement" in report


def test_budget_exhaustion_preserves_authored_validated_findings(tmp_path: Path) -> None:
    state_dir, target, scan_dir, scan_id, _ = budget_scan_fixture(tmp_path)
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        relative_path="app.py",
        coverage_mode="deep_repository",
    )

    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    assert completed["progress"]["status"] == "complete"
    assert completed["findingCount"] == 1
    assert "Unsafe archive extraction" in completed["findings"][0]["title"]
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    assert coverage["deferred"][0]["id"] == "candidate-1"


@pytest.mark.parametrize(
    ("validation", "attack_path", "surface_disposition", "deferred"),
    [
        ("suppressed", None, "rejected", False),
        ("reportable", "ignore", "rejected", False),
        ("suppressed", "ignore", "rejected", False),
        ("not_applicable", None, "not_applicable", False),
        ("not_applicable", "ignore", "not_applicable", False),
        ("deferred", "ignore", "needs_follow_up", True),
        ("suppressed", "deferred", "needs_follow_up", True),
        ("not_applicable", "deferred", "needs_follow_up", True),
        ("reportable", None, "needs_follow_up", True),
        ("reportable", "reportable", "needs_follow_up", True),
        (None, None, "needs_follow_up", True),
    ],
)
def test_budget_exhaustion_preserves_existing_candidate_decisions(
    tmp_path: Path,
    validation: str | None,
    attack_path: str | None,
    surface_disposition: str,
    deferred: bool,
) -> None:
    state_dir, _, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    if validation is not None:
        candidate["validation"] = {"disposition": validation}
    if attack_path is not None:
        candidate["attack_path"] = {"decision": attack_path}
    ledger.write_text(f"{json.dumps(candidate)}\n")

    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    assert completed["progress"]["status"] == "complete"
    assert completed["findings"] == []
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    assert coverage["surfaces"][0]["disposition"] == surface_disposition
    assert any(row["id"] == "candidate-1" for row in coverage["deferred"]) is deferred
    if not deferred:
        assert coverage["deferred"][0]["id"] == "scan-cost-limit"


def test_budget_exhaustion_preserves_existing_terminal_surface(tmp_path: Path) -> None:
    state_dir, target, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {"disposition": "suppressed"}
    ledger.write_text(f"{json.dumps(candidate)}\n")
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        relative_path="app.py",
        coverage_mode="deep_repository",
    )
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["surfaces"].append(
        {
            "id": "candidate-candidate-1",
            "label": "Already dismissed candidate",
            "disposition": "rejected",
            "receiptRefs": [],
        }
    )
    coverage_path.write_text(json.dumps(coverage))

    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    assert completed["findingCount"] == 1
    preserved = json.loads(coverage_path.read_text())
    assert sum(row["id"] == "candidate-candidate-1" for row in preserved["surfaces"]) == 1
    assert preserved["surfaces"][1]["disposition"] == "rejected"
    assert not any(row["id"] == "candidate-1" for row in preserved["deferred"])


@pytest.mark.parametrize(
    ("reason", "marker_added"),
    [
        ("Upstream validation dependency was unavailable.", True),
        ("Validation was deferred because the scan reached its cost limit unexpectedly.", True),
        ("Validation was deferred because the scan reached its cost limit.", False),
        (
            "Validation was deferred because the scan reached its cost limit: existing proof gap.",
            False,
        ),
    ],
)
def test_budget_exhaustion_preserves_existing_deferred_work_with_one_trusted_marker(
    tmp_path: Path,
    reason: str,
    marker_added: bool,
) -> None:
    state_dir, target, scan_dir, scan_id, _ = budget_scan_fixture(tmp_path, candidates=[])
    write_completed_contract(scan_dir, scan_id, target, coverage_mode="deep_repository")
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    findings["findings"] = []
    findings_path.write_text(json.dumps(findings))
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    existing = {"id": "existing-proof-gap", "reason": reason, "paths": ["app.py"]}
    coverage["deferred"] = [existing]
    coverage_path.write_text(json.dumps(coverage))

    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    assert completed["progress"]["status"] == "complete"
    preserved = json.loads(coverage_path.read_text())
    assert preserved["deferred"][0] == existing
    assert len(preserved["deferred"]) == 1 + marker_added
    if marker_added:
        assert preserved["deferred"][1] == {
            "id": "scan-cost-limit",
            "reason": "Validation was deferred because the scan reached its cost limit.",
        }
    assert (
        "No findings were validated before the scan reached its cost limit"
        in (scan_dir / "report.md").read_text()
    )


def test_budget_exhaustion_preserves_capped_discovery(tmp_path: Path) -> None:
    state_dir, _, scan_dir, scan_id, _ = budget_scan_fixture(tmp_path, terminal_reason="capped")

    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    assert completed["progress"]["status"] == "complete"
    assert (
        json.loads((scan_dir / "coverage.json").read_text())["deferred"][0]["id"] == "candidate-1"
    )


def test_budget_exhaustion_with_no_candidates_is_honestly_partial(tmp_path: Path) -> None:
    state_dir, _, scan_dir, scan_id, _ = budget_scan_fixture(tmp_path, candidates=[])

    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    assert completed["progress"]["status"] == "complete"
    assert completed["findings"] == []
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    assert coverage["deferred"] == [
        {
            "id": "scan-cost-limit",
            "reason": "Validation was deferred because the scan reached its cost limit.",
        }
    ]


def test_budget_exhaustion_preserves_scoped_path_inventory(tmp_path: Path) -> None:
    state_dir, _, scan_dir, scan_id, _ = budget_scan_fixture(tmp_path, paths=["app.py"])

    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    assert completed["progress"]["status"] == "complete"
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert coverage["mode"] == "scoped_path"
    assert coverage["inventoryStrategy"] == "scoped_path"
    assert coverage["includePaths"] == ["app.py"]


def test_budget_exhaustion_rejects_scan_below_configured_limit(tmp_path: Path) -> None:
    state_dir, _, _, scan_id, _ = budget_scan_fixture(tmp_path)
    cost = {**BUDGET_COST, "estimatedUsd": 0.005}

    rejected = run_workbench(
        state_dir,
        "complete-budget-exhausted-scan",
        "--scan-id",
        scan_id,
        "--cost-json",
        json.dumps(cost),
        check=False,
    )

    assert rejected["returncode"] != 0
    assert "has not exceeded its configured cost limit" in str(rejected["stderr"])


def test_budget_exhaustion_rejects_incomplete_discovery(tmp_path: Path) -> None:
    state_dir, _, _, scan_id, _ = budget_scan_fixture(tmp_path, terminal=False)

    rejected = complete_budget_scan(state_dir, scan_id, check=False)

    assert rejected["returncode"] != 0
    assert "requires successfully completed Deep Scan discovery" in str(rejected["stderr"])
    assert (
        run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]["progress"]["status"]
        == "running"
    )


def test_budget_exhaustion_rejects_standard_scan(tmp_path: Path) -> None:
    state_dir, _, _, scan_id, _ = budget_scan_fixture(tmp_path, mode="standard")

    rejected = complete_budget_scan(state_dir, scan_id, check=False)

    assert rejected["returncode"] != 0
    assert "Only a running CLI Deep Scan" in str(rejected["stderr"])


def test_budget_exhaustion_rejects_invalid_candidate_ledger(tmp_path: Path) -> None:
    state_dir, _, _, scan_id, ledger = budget_scan_fixture(tmp_path)
    ledger.write_text('{"candidate_id":"candidate-1"}\n')

    rejected = complete_budget_scan(state_dir, scan_id, check=False)

    assert rejected["returncode"] != 0
    assert "contains an invalid candidate" in str(rejected["stderr"])


def test_budget_exhaustion_rejects_unsafe_candidate_path(tmp_path: Path) -> None:
    state_dir, _, _, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["locations"][0]["path"] = "../outside.py"
    ledger.write_text(f"{json.dumps(candidate)}\n")

    rejected = complete_budget_scan(state_dir, scan_id, check=False)

    assert rejected["returncode"] != 0
    assert "candidate location must be repository-relative" in str(rejected["stderr"])


def test_budget_exhaustion_rejects_candidate_outside_inventory(tmp_path: Path) -> None:
    state_dir, _, _, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["locations"][0]["path"] = "outside-scope.py"
    ledger.write_text(f"{json.dumps(candidate)}\n")

    rejected = complete_budget_scan(state_dir, scan_id, check=False)

    assert rejected["returncode"] != 0
    assert "must include a location in its in-scope inventory" in str(rejected["stderr"])


def test_budget_exhaustion_rejects_windows_drive_candidate_path(tmp_path: Path) -> None:
    state_dir, _, _, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["locations"][0]["path"] = "C:/outside.py"
    ledger.write_text(f"{json.dumps(candidate)}\n")

    rejected = complete_budget_scan(state_dir, scan_id, check=False)

    assert rejected["returncode"] != 0
    assert "candidate location must be repository-relative" in str(rejected["stderr"])


def test_budget_exhaustion_preserves_out_of_scope_supporting_evidence(tmp_path: Path) -> None:
    state_dir, _, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["locations"].append(
        {"path": "shared/control.py", "start_line": 9, "end_line": 9, "role": "root_control"}
    )
    ledger.write_text(f"{json.dumps(candidate)}\n")

    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    assert completed["progress"]["status"] == "complete"
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert coverage["deferred"][0]["paths"] == ["app.py", "shared/control.py"]


def test_budget_exhaustion_preserves_unicode_line_separator_inventory(tmp_path: Path) -> None:
    candidate = {
        "candidate_id": "candidate-1",
        "cwe_ids": ["CWE-89"],
        "locations": [{"path": "dir\u2028name.py", "start_line": 1, "end_line": 1, "role": "sink"}],
        "summary": "Candidate in a Unicode filename",
        "evidence": "The source contains an untrusted SQL expression.",
    }
    state_dir, target, scan_dir, scan_id, _ = budget_scan_fixture(tmp_path, candidates=[candidate])
    (target / "dir\u2028name.py").write_text("query = value\n")
    (scan_dir / "artifacts" / "02_discovery" / "in_scope_files.txt").write_text(
        "dir\u2028name.py\n"
    )

    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    assert completed["progress"]["status"] == "complete"
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert coverage["deferred"][0]["paths"] == ["dir\u2028name.py"]


def test_budget_exhaustion_rejects_symlink_candidate_ledger(tmp_path: Path) -> None:
    state_dir, _, _, scan_id, ledger = budget_scan_fixture(tmp_path)
    outside = tmp_path / "outside.jsonl"
    outside.write_text(ledger.read_text())
    ledger.unlink()
    ledger.symlink_to(outside)

    rejected = complete_budget_scan(state_dir, scan_id, check=False)

    assert rejected["returncode"] != 0
    assert "candidate ledger path" in str(rejected["stderr"]).casefold()


def test_workbench_reopens_workspace_only_from_owning_thread(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace = create_saved_workspace(state_dir, target, thread_id="thread-a")

    reopened = run_workbench(
        state_dir,
        "get-workspace",
        "--workspace-id",
        str(workspace["id"]),
        "--thread-id",
        "thread-a",
    )
    assert reopened["id"] == workspace["id"]

    rejected = run_workbench(
        state_dir,
        "get-workspace",
        "--workspace-id",
        str(workspace["id"]),
        "--thread-id",
        "thread-b",
        check=False,
    )
    assert rejected["returncode"] != 0
    assert "workspace not found in this thread" in str(rejected["stderr"])


def test_completion_normalizes_unsealed_deep_inventory_strategy_alias(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    workspace_id = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--thread-id",
        "thread-i",
        "--target-path",
        str(target),
    )
    run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "deep",
    )
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        workspace_id,
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    run_workbench(
        state_dir,
        "begin-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-i",
        environment={"CODEX_HOME": str(codex_home)},
    )
    manifest_path = scan_dir / "coordinator-manifest.json"
    manifest_path.write_text("{}\n")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            """
            UPDATE deep_scan_runs
            SET status = 'succeeded', phase = 'terminal',
                terminal_reason = 'capped', manifest_path = ?,
                completed_at = updated_at
            WHERE scan_id = ?
            """,
            (str(manifest_path), scan_id),
        )
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        inventory_strategy="deep_repository_repeated_discovery",
    )

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)

    assert completed["scan"]["progress"]["status"] == "complete"
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert coverage["mode"] == "deep_repository"
    assert coverage["inventoryStrategy"] == "repository"


def test_completion_warns_after_plain_directory_changes(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    source = target / "app.py"
    source.write_text("version = 1\n")
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        str(saved["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target, relative_path="app.py")
    original_digest = started["results"]["contract"]["target"]["requiredSnapshotDigest"]
    source.write_text("version = 2\n")

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)

    assert completed["scan"]["progress"]["status"] == "complete"
    assert completed["scan"]["warnings"] == [DIRECTORY_CHANGED_WARNING]
    assert completed["targetWarnings"] == [DIRECTORY_CHANGED_WARNING]
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["target"]["snapshotDigest"] == original_digest
    assert (
        run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]["warnings"]
        == completed["scan"]["warnings"]
    )


def test_completion_warns_when_scanned_directory_becomes_unavailable(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("version = 1\n")
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        str(saved["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target, relative_path="app.py")
    target.rename(tmp_path / "moved-target")

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)

    assert completed["scan"]["progress"]["status"] == "complete"
    assert completed["scan"]["warnings"] == [TARGET_UNAVAILABLE_WARNING]
    assert completed["targetWarnings"] == [TARGET_UNAVAILABLE_WARNING]
    assert completed["scan"]["findingCount"] == 1
    assert completed["scan"]["remediationAvailable"] is False
    assert (scan_dir / "report.md").is_file()


def test_scan_start_rejects_artifact_root_inside_target(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)

    failed = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        str(saved["id"]),
        "--scan-root",
        str(target / "scan-artifacts"),
        check=False,
    )

    assert failed["returncode"] != 0
    assert "scan artifact directory must be outside" in str(failed["stderr"])


def test_workbench_serializes_concurrent_scan_completion(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        str(saved["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda _: run_workbench(
                    state_dir,
                    "complete-scan",
                    "--scan-id",
                    scan_id,
                ),
                range(2),
            )
        )

    assert all(result["scan"]["progress"]["status"] == "complete" for result in results)
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert (
            connection.execute("SELECT seal_manifest_digest FROM scans WHERE id = ?", (scan_id,))
            .fetchone()[0]
            .startswith("sha256:")
        )
        assert connection.execute(
            "SELECT COUNT(*) FROM finding_occurrences WHERE scan_id = ?", (scan_id,)
        ).fetchone() == (1,)


def test_workbench_persists_scan_model_and_updates_it_from_progress(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        str(saved["id"]),
        "--model",
        "gpt-5.6-sol",
        "--reasoning-effort",
        "high",
    )
    scan = started["results"]
    scan_id = str(scan["scanId"])
    assert scan["model"] == "gpt-5.6-sol"
    assert scan["reasoningEffort"] == "high"

    listed = run_workbench(state_dir, "list-scans")["scans"]
    assert listed[0]["model"] == "gpt-5.6-sol"
    assert listed[0]["reasoningEffort"] == "high"

    updated = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        "discovery",
        "--model",
        "gpt-5.6-terra",
        "--reasoning-effort",
        "low",
    )["scan"]
    assert updated["model"] == "gpt-5.6-terra"
    assert updated["reasoningEffort"] == "low"

    preserved = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        "discovery",
    )["scan"]
    assert preserved["model"] == "gpt-5.6-terra"
    assert preserved["reasoningEffort"] == "low"


def test_workbench_persists_progress_and_indexes_completed_findings(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    workspace_id = str(saved["id"])
    assert saved["userContext"] == "Pay attention to uploaded archives."

    started = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        workspace_id,
        "--scan-root",
        str(tmp_path / "scans"),
    )
    results = started["results"]
    assert isinstance(results, dict)
    assert results["userContext"] == "Pay attention to uploaded archives."
    scan_id = str(results["scanId"])
    scan_dir = Path(str(results["scanDir"]))
    assert results["progress"]["phase"] == "preflight"
    assert results["handoffStatus"] == "pending"
    assert results["contract"]["target"]["targetId"] == stable_target_id(target)
    assert results["contract"]["scope"]["requiredIncludePaths"] == ["."]
    assert results["contract"]["scope"]["requiredExcludePaths"] == []
    assert not (scan_dir / "progress.json").exists()
    assert not (scan_dir / "events.jsonl").exists()

    claim_token = str(uuid.uuid4())
    claimed = run_workbench(
        state_dir, "claim-handoff-delivery", "--scan-id", scan_id, "--claim-token", claim_token
    )
    assert claimed["results"]["handoffClaimedAt"] is not None
    assert claimed["results"]["handoffClaimToken"] == claim_token
    released = run_workbench(
        state_dir, "release-handoff-delivery", "--scan-id", scan_id, "--claim-token", claim_token
    )
    assert released["results"]["handoffClaimedAt"] is None
    claimed_again = run_workbench(
        state_dir, "claim-handoff-delivery", "--scan-id", scan_id, "--claim-token", claim_token
    )
    assert claimed_again["results"]["handoffClaimedAt"] is not None
    delivered = run_workbench(
        state_dir, "mark-handoff-delivered", "--scan-id", scan_id, "--claim-token", claim_token
    )
    assert delivered["results"]["handoffStatus"] == "delivered"
    assert delivered["results"]["handoffClaimedAt"] is None

    updated = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        "validation",
        "--review-items-total",
        "31",
        "--review-items-completed",
        "22",
        "--reportable-findings-count",
        "1",
        "--claim-token",
        claim_token,
    )
    assert updated["scan"]["progress"]["coverage"] == {
        "closedRows": 22,
        "filesTotal": 0,
        "worklistRows": 31,
    }
    assert updated["scan"]["progress"]["candidates"] == {"reportable": 1}

    write_completed_contract(scan_dir, scan_id, target)
    completed = run_workbench(
        state_dir, "complete-scan", "--scan-id", scan_id, "--claim-token", claim_token
    )
    completed_scan = completed["scan"]
    assert completed_scan["progress"]["status"] == "complete"
    assert completed_scan["findingCount"] == 1
    assert completed_scan["severityCounts"] == {"high": 1}
    assert completed_scan["reportAvailable"] is True
    assert completed_scan["artifacts"]["findings"] == str(
        Path(str(completed_scan["scanDir"])) / "findings.json"
    )
    finding = completed_scan["findings"][0]
    assert finding["severity"] == {
        "level": "high",
        "rationale": "The reachable write can escape the extraction root.",
    }
    assert finding["validation"]["summary"] == (
        "A crafted entry wrote outside the extraction root."
    )
    assert finding["validation"]["assertions"] == [
        "The archive entry controls the destination path."
    ]
    assert finding["rootCause"]["summary"] == (
        "The archive destination is written before containment is enforced."
    )
    assert finding["rootCause"]["evidenceRefs"] == ["archive-write"]
    assert finding["codeEvidence"][0]["id"] == "archive-write"
    assert finding["codeEvidence"][0]["code"] == "destination.write_bytes(entry.read())"
    assert finding["validation"]["evidenceRefs"] == ["archive-write"]
    assert finding["evidenceExcerpt"] == "destination.write_bytes(entry.read())"
    assert finding["attackPath"]["dataFlow"] == (
        "archive entry -> destination path -> filesystem write"
    )
    assert finding["attackPath"]["impact"]["level"] == "high"
    assert finding["attackPath"]["evidenceRefs"] == ["archive-write"]
    assert finding["preventiveControls"] == ["Use a containment-checking extraction helper."]
    assert finding["remediationTests"] == ["Reject traversal entries during extraction."]
    assert finding["locations"][0]["absolutePath"] == str(target / "src" / "extract.py")

    reopened = run_workbench(state_dir, "get-workspace", "--workspace-id", workspace_id)
    assert reopened["results"]["findings"][0]["findingId"].startswith("csf_")
    assert reopened["results"]["findings"][0]["occurrenceId"].startswith("occ_")
    assert reopened["results"]["findings"][0]["attackPath"]["reachability"] == (
        "An archive uploader can supply the crafted entry."
    )
    assert reopened["results"]["findings"][0]["validation"]["limitations"] == [
        "The test used a temporary extraction directory."
    ]

    database = state_dir / "workbench.sqlite3"
    occurrence_id = reopened["results"]["findings"][0]["occurrenceId"]
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE finding_occurrences SET details_json = ? WHERE id = ?",
            (
                json.dumps(
                    {
                        "rootCause": {"code": "destination.write_bytes(entry.read())"},
                        "root_cause": {
                            "evidence_refs": ["archive-write"],
                            "summary": "Legacy containment details remain visible.",
                        },
                    }
                ),
                occurrence_id,
            ),
        )
    aliased = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)
    assert aliased["scan"]["findings"][0]["rootCause"] == {
        "code": "destination.write_bytes(entry.read())",
        "evidenceRefs": ["archive-write"],
        "summary": "Legacy containment details remain visible.",
    }

    run_workbench(
        state_dir,
        "set-finding-triage",
        "--occurrence-id",
        occurrence_id,
        "--status",
        "closed",
        "--close-reason",
        "already_fixed",
    )
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE finding_occurrences SET details_json = '{}' WHERE id = ?",
            (occurrence_id,),
        )
    backfilled = run_workbench(state_dir, "get-workspace", "--workspace-id", workspace_id)
    assert backfilled["results"]["findings"][0]["attackPath"]["impact"]["level"] == "high"
    assert backfilled["results"]["findings"][0]["triage"]["status"] == "closed"

    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            UPDATE finding_occurrences
            SET details_json = '{"attackPath":{"likelihood":NaN}}'
            WHERE id = ?
            """,
            (occurrence_id,),
        )
    poisoned = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)
    assert "attackPath" not in poisoned["scan"]["findings"][0]
    assert poisoned["scan"]["findings"][0]["title"] == finding["title"]

    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        assert tables == EXPECTED_TABLES
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone() == (41,)
        assert connection.execute("SELECT COUNT(*) FROM findings").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM finding_locations").fetchone() == (1,)


def test_completed_findings_are_summarized_and_sorted_by_severity(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        str(saved["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target)

    findings_path = scan_dir / "findings.json"
    document = json.loads(findings_path.read_text())
    high = document["findings"][0]
    low = {
        **high,
        "ruleId": "fixture.low",
        "identity": {"anchor": "low"},
        "title": "Low priority finding",
        "severity": {"level": "low"},
    }
    critical = {
        **high,
        "ruleId": "fixture.critical",
        "identity": {"anchor": "critical"},
        "title": "Critical priority finding",
        "severity": {"level": "critical"},
    }
    informational = {
        **high,
        "ruleId": "fixture.informational",
        "identity": {"anchor": "informational"},
        "title": "Informational finding",
        "severity": {"level": "informational"},
    }
    document["findings"] = [informational, low, high, critical]
    findings_path.write_text(json.dumps(document))

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    assert completed["severityCounts"] == {
        "critical": 1,
        "high": 1,
        "informational": 1,
        "low": 1,
    }
    assert [finding["title"] for finding in completed["findings"]] == [
        "Critical priority finding",
        "Unsafe archive extraction can escape the output directory",
        "Low priority finding",
        "Informational finding",
    ]


@pytest.mark.parametrize("line_ending", ["\n", "\r\n"], ids=["lf", "crlf"])
def test_completed_finding_triage_and_remediation_persist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, line_ending: str
) -> None:
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.autocrlf")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "true")
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    source = target / "source.txt"
    source.write_bytes(f"vulnerable{line_ending}".encode())
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        str(saved["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target, relative_path=source.name)
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    scan_dir = Path(str(completed["scanDir"]))
    occurrence_id = str(completed["findings"][0]["occurrenceId"])
    assert completed["findings"][0]["triage"] == {"status": "open"}
    assert completed["findings"][0]["remediationState"] == {"state": "idle"}

    closed = run_workbench(
        state_dir,
        "set-finding-triage",
        "--occurrence-id",
        occurrence_id,
        "--status",
        "closed",
        "--close-reason",
        "already_fixed",
        "--note",
        "Patched before this scan completed.",
    )["scan"]
    assert closed["findings"][0]["triage"] | {"updatedAt": None} == {
        "closeReason": "already_fixed",
        "note": "Patched before this scan completed.",
        "status": "closed",
        "updatedAt": None,
    }
    run_workbench(
        state_dir,
        "set-finding-triage",
        "--occurrence-id",
        occurrence_id,
        "--status",
        "closed",
        "--close-reason",
        "already_fixed",
        "--note",
        "Patched before this scan completed.",
    )

    request_id = str(uuid.uuid4())
    generation_token = str(uuid.uuid4())
    closed_request = run_workbench(
        state_dir,
        "request-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        generation_token,
        check=False,
    )
    assert "Reopen this finding" in str(closed_request["stderr"])
    run_workbench(
        state_dir,
        "set-finding-triage",
        "--occurrence-id",
        occurrence_id,
        "--status",
        "open",
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            """
            SELECT status, close_reason, note
            FROM finding_decisions
            WHERE occurrence_id = ?
            ORDER BY created_at, rowid
            """,
            (occurrence_id,),
        ).fetchall() == [
            ("closed", "already_fixed", "Patched before this scan completed."),
            ("open", None, None),
        ]
    requested = run_workbench(
        state_dir,
        "request-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        generation_token,
    )["scan"]
    assert requested["findings"][0]["remediationState"]["state"] == "requested"
    assert requested["findings"][0]["remediationState"]["pendingAction"] == "generate"
    assert requested["findings"][0]["remediationState"]["actionClaimToken"] == generation_token
    pending_close = run_workbench(
        state_dir,
        "set-finding-triage",
        "--occurrence-id",
        occurrence_id,
        "--status",
        "closed",
        "--close-reason",
        "already_fixed",
        check=False,
    )
    assert "pending remediation operation" in str(pending_close["stderr"])
    patch_path = scan_dir / "remediation.patch"
    patch_path.write_text(
        "diff --git a/source.txt b/source.txt\n"
        "--- a/source.txt\n"
        "+++ b/source.txt\n"
        "@@ -1 +1 @@\n"
        "-vulnerable\n"
        "+fixed\n",
        newline="\n",
    )
    generated = run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        generation_token,
        "--expected-version",
        "1",
        "--state",
        "generated",
        "--patch-path",
        patch_path.name,
        "--patch-digest",
        f"sha256:{hashlib.sha256(patch_path.read_bytes()).hexdigest()}",
        "--summary",
        "Contained archive extraction under the selected output directory.",
    )["scan"]
    assert generated["findings"][0]["remediationState"]["state"] == "generated"
    assert generated["findings"][0]["remediationState"]["pendingAction"] is None
    assert generated["findings"][0]["remediationState"]["patchPath"] == patch_path.name
    assert generated["findings"][0]["remediationState"]["patch"] == patch_path.read_bytes().decode()
    assert generated["findings"][0]["remediationState"]["patchStats"] == {
        "additions": 1,
        "deletions": 1,
        "fileCount": 1,
        "previewTruncated": False,
    }
    assert generated["findings"][0]["remediationState"]["summary"] == (
        "Contained archive extraction under the selected output directory."
    )
    apply_token = str(uuid.uuid4())
    apply_requested = run_workbench(
        state_dir,
        "request-finding-remediation-action",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--expected-version",
        "2",
        "--action",
        "apply",
        "--action-token",
        apply_token,
    )["scan"]
    assert apply_requested["findings"][0]["remediationState"]["pendingAction"] == "apply"
    assert apply_requested["findings"][0]["remediationState"]["actionClaimToken"] == apply_token
    assert apply_requested["findings"][0]["remediationState"]["version"] == 3
    apply_retried = run_workbench(
        state_dir,
        "request-finding-remediation-action",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--expected-version",
        "2",
        "--action",
        "apply",
        "--action-token",
        apply_token,
    )["scan"]
    assert apply_retried["findings"][0]["remediationState"]["version"] == 3
    wrong_apply = run_workbench(
        state_dir,
        "request-finding-remediation-action",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--expected-version",
        "2",
        "--action",
        "apply",
        "--action-token",
        generation_token,
        check=False,
    )
    assert "operation is already pending" in str(wrong_apply["stderr"])
    live_resend = run_workbench(
        state_dir,
        "claim-finding-remediation-resend",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        str(uuid.uuid4()),
        check=False,
    )
    assert "still owned by another panel" in str(live_resend["stderr"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            """
            UPDATE finding_remediation_attempts
            SET pending_action_claimed_at = ?
            WHERE request_id = ?
            """,
            ("2000-01-01T00:00:00Z", request_id),
        )
    resend_token = str(uuid.uuid4())
    stale_resend = run_workbench(
        state_dir,
        "claim-finding-remediation-resend",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        resend_token,
    )["scan"]
    assert stale_resend["findings"][0]["remediationState"]["actionClaimToken"] == resend_token
    wrong_release = run_workbench(
        state_dir,
        "release-finding-remediation-claim",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        str(uuid.uuid4()),
    )["scan"]
    assert wrong_release["findings"][0]["remediationState"]["actionClaimToken"] == resend_token
    released = run_workbench(
        state_dir,
        "release-finding-remediation-claim",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        resend_token,
    )["scan"]
    assert released["findings"][0]["remediationState"]["actionClaimToken"] is None
    unowned_apply = run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        resend_token,
        "--expected-version",
        "3",
        "--state",
        "applied",
        "--base-revision",
        "unversioned",
        check=False,
    )
    assert "does not have an owned pending host request" in str(unowned_apply["stderr"])
    retry_token = str(uuid.uuid4())
    reclaimed = run_workbench(
        state_dir,
        "claim-finding-remediation-resend",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        retry_token,
    )["scan"]
    assert reclaimed["findings"][0]["remediationState"]["actionClaimToken"] == retry_token
    delivered = run_workbench(
        state_dir,
        "mark-finding-remediation-delivered",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        retry_token,
    )["scan"]
    assert delivered["findings"][0]["remediationState"]["actionDeliveredAt"]
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            """
            UPDATE finding_remediation_attempts
            SET pending_action_claimed_at = ?, pending_action_delivered_at = ?
            WHERE request_id = ?
            """,
            ("2000-01-01T00:00:00Z", "2000-01-01T00:00:00Z", request_id),
        )
    recovery_token = str(uuid.uuid4())
    recovered_delivery = run_workbench(
        state_dir,
        "claim-finding-remediation-resend",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        recovery_token,
    )["scan"]
    assert (
        recovered_delivery["findings"][0]["remediationState"]["actionClaimToken"] == recovery_token
    )
    assert recovered_delivery["findings"][0]["remediationState"]["actionDeliveredAt"] is None
    run_workbench(
        state_dir,
        "mark-finding-remediation-delivered",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        recovery_token,
    )
    replacement_path = scan_dir / "replacement.patch"
    replacement_path.write_text("diff --git a/src/other.py b/src/other.py\n")
    replaced_patch = run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        recovery_token,
        "--expected-version",
        "3",
        "--state",
        "applied",
        "--base-revision",
        "unversioned",
        "--patch-path",
        replacement_path.name,
        "--patch-digest",
        f"sha256:{hashlib.sha256(replacement_path.read_bytes()).hexdigest()}",
        check=False,
    )
    assert "cannot replace its reviewed patch path" in str(replaced_patch["stderr"])
    unchanged_apply = run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        recovery_token,
        "--expected-version",
        "3",
        "--state",
        "applied",
        "--base-revision",
        "unversioned",
        check=False,
    )
    assert "checkout is unchanged" in str(unchanged_apply["stderr"])
    subprocess.run(
        ["git", "apply", "--no-index", str(patch_path)],
        cwd=target,
        check=True,
    )
    applied_source = source.read_bytes()
    unrelated = target / "unrelated.txt"
    unrelated.write_text("not part of the reviewed patch\n")
    extra_changes = run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        recovery_token,
        "--expected-version",
        "3",
        "--state",
        "applied",
        "--base-revision",
        "unversioned",
        check=False,
    )
    assert "changes outside the reviewed patch" in str(extra_changes["stderr"])
    unrelated.unlink()
    applied = run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        recovery_token,
        "--expected-version",
        "3",
        "--state",
        "applied",
        "--base-revision",
        "unversioned",
    )["scan"]
    assert applied["findings"][0]["remediationState"]["state"] == "applied"
    verify_token = str(uuid.uuid4())
    verify_requested = run_workbench(
        state_dir,
        "request-finding-remediation-action",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--expected-version",
        "4",
        "--action",
        "verify",
        "--action-token",
        verify_token,
    )["scan"]
    assert verify_requested["findings"][0]["remediationState"]["pendingAction"] == "verify"
    verifying = run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        verify_token,
        "--expected-version",
        "5",
        "--state",
        "verifying",
        "--base-revision",
        "unversioned",
    )["scan"]
    assert verifying["findings"][0]["remediationState"]["state"] == "verifying"
    assert verifying["findings"][0]["remediationState"]["pendingAction"] == "verify"
    assert verifying["findings"][0]["remediationState"]["actionClaimToken"] == verify_token
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            """
            UPDATE finding_remediation_attempts
            SET pending_action_claimed_at = ?
            WHERE request_id = ?
            """,
            ("2000-01-01T00:00:00Z", request_id),
        )
    recovery_token = str(uuid.uuid4())
    recovered = run_workbench(
        state_dir,
        "claim-finding-remediation-resend",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        recovery_token,
    )["scan"]
    assert recovered["findings"][0]["remediationState"]["actionClaimToken"] == recovery_token
    verifying_again = run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        recovery_token,
        "--expected-version",
        "6",
        "--state",
        "verifying",
        "--base-revision",
        "unversioned",
    )["scan"]
    assert verifying_again["findings"][0]["remediationState"]["pendingAction"] == "verify"
    verified = run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        recovery_token,
        "--expected-version",
        "7",
        "--state",
        "verified",
        "--base-revision",
        "unversioned",
        "--verification-summary",
        "Focused regression tests passed.",
    )["scan"]
    assert verified["findings"][0]["remediationState"]["state"] == "verified"

    source.write_text("drifted after verification\n")
    stale_close = run_workbench(
        state_dir,
        "set-finding-triage",
        "--occurrence-id",
        occurrence_id,
        "--status",
        "closed",
        "--close-reason",
        "already_fixed",
        check=False,
    )
    assert "Working-tree contents changed" in str(stale_close["stderr"])
    source.write_bytes(applied_source)
    run_workbench(
        state_dir,
        "set-finding-triage",
        "--occurrence-id",
        occurrence_id,
        "--status",
        "closed",
        "--close-reason",
        "already_fixed",
    )

    reopened = run_workbench(
        state_dir,
        "set-finding-triage",
        "--occurrence-id",
        occurrence_id,
        "--status",
        "open",
    )["scan"]
    assert reopened["findings"][0]["triage"]["status"] == "open"
    assert reopened["findings"][0]["triage"]["closeReason"] is None


def test_filesystem_identity_serialization_supports_windows_stat_values() -> None:
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_db")
    serialize_identity = namespace["serialize_filesystem_identity"]
    identity_matches = namespace["stored_filesystem_identity_matches"]
    windows_device_id = (1 << 64) - 1
    windows_inode_id = (1 << 128) - 1

    with sqlite3.connect(":memory:") as connection:
        connection.execute("CREATE TABLE scan (device INTEGER, inode INTEGER)")
        connection.execute(
            "INSERT INTO scan (device, inode) VALUES (?, ?)",
            (serialize_identity(windows_device_id), serialize_identity(windows_inode_id)),
        )
        stored_device, stored_inode, device_type, inode_type = connection.execute(
            "SELECT device, inode, typeof(device), typeof(inode) FROM scan"
        ).fetchone()

    assert device_type == inode_type == "text"
    assert identity_matches(stored_device, windows_device_id)
    assert identity_matches(stored_inode, windows_inode_id)
    assert identity_matches(42, 42)  # Scans created before this fix stored SQLite integers.
    assert serialize_identity(42) == 42
    assert not identity_matches(stored_device, windows_device_id - 1)


def test_completed_scan_disables_remediation_after_checkout_revision_changes(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    revision = initialize_git_repository(target)
    saved = create_saved_git_workspace(state_dir, target)
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        str(saved["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        relative_path="README.md",
        target_kind="git_revision",
        target_revision=revision,
    )
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    assert completed["remediationAvailable"] is True

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET target_device = target_device + 1 WHERE id = ?",
            (scan_id,),
        )
    remounted = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert remounted["remediationAvailable"] is True
    assert remounted["findings"][0]["locations"][0]["absolutePath"] == str(target / "README.md")

    (target / "README.md").write_text("new revision\n")
    subprocess.run(["git", "add", "README.md"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "Advance checkout"], cwd=target, check=True)
    refreshed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]

    assert refreshed["remediationAvailable"] is False
    assert "not at the revision that was scanned" in refreshed["remediationUnavailableReason"]


def assert_completed_scan_disables_remediation_after_checkout_path_is_replaced(
    tmp_path: Path, *, replacement_kind: str
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "source.txt").write_text("vulnerable\n")
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        str(saved["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target, relative_path="source.txt")
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    occurrence_id = str(completed["findings"][0]["occurrenceId"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        identity = connection.execute(
            "SELECT target_device, target_inode FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    assert identity is not None and all(value is not None for value in identity)

    original = tmp_path / "original-target"
    target.rename(original)
    if replacement_kind == "symlink":
        replacement = tmp_path / "replacement-target"
        replacement.mkdir()
        (replacement / "source.txt").write_text("vulnerable\n")
        target.symlink_to(replacement, target_is_directory=True)
    else:
        target.mkdir()
        (target / "source.txt").write_text("vulnerable\n")

    refreshed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert refreshed["remediationAvailable"] is False
    assert "checkout path was replaced" in refreshed["remediationUnavailableReason"]
    assert "absolutePath" not in refreshed["findings"][0]["locations"][0]
    rejected = run_workbench(
        state_dir,
        "request-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        str(uuid.uuid4()),
        "--action-token",
        str(uuid.uuid4()),
        check=False,
    )
    assert "checkout path was replaced" in str(rejected["stderr"])


def test_completed_scan_disables_remediation_after_checkout_directory_is_replaced(
    tmp_path: Path,
) -> None:
    assert_completed_scan_disables_remediation_after_checkout_path_is_replaced(
        tmp_path, replacement_kind="directory"
    )


def test_completed_scan_disables_remediation_after_checkout_symlink_is_replaced(
    tmp_path: Path,
) -> None:
    assert_completed_scan_disables_remediation_after_checkout_path_is_replaced(
        tmp_path, replacement_kind="symlink"
    )


def test_finding_management_rejects_invalid_state_transitions(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        str(saved["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target)
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    scan_dir = Path(str(completed["scanDir"]))
    occurrence_id = str(completed["findings"][0]["occurrenceId"])

    missing_reason = run_workbench(
        state_dir,
        "set-finding-triage",
        "--occurrence-id",
        occurrence_id,
        "--status",
        "closed",
        check=False,
    )
    assert "Choose why this finding is being closed." in str(missing_reason["stderr"])

    missing_wont_fix_rationale = run_workbench(
        state_dir,
        "set-finding-triage",
        "--occurrence-id",
        occurrence_id,
        "--status",
        "closed",
        "--close-reason",
        "wont_fix",
        check=False,
    )
    assert "Explain why this finding will not be fixed." in str(
        missing_wont_fix_rationale["stderr"]
    )

    invalid_transition = run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        str(uuid.uuid4()),
        "--action-token",
        str(uuid.uuid4()),
        "--expected-version",
        "1",
        "--state",
        "verified",
        check=False,
    )
    assert "remediation request not found" in str(invalid_transition["stderr"])

    request_id = str(uuid.uuid4())
    generation_token = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "request-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        generation_token,
    )
    overlapping_request = run_workbench(
        state_dir,
        "request-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        str(uuid.uuid4()),
        "--action-token",
        str(uuid.uuid4()),
        check=False,
    )
    assert "active remediation operation" in str(overlapping_request["stderr"])
    patch_path = scan_dir / "remediation.patch"
    patch_path.write_text("diff --git a/src/extract.py b/src/extract.py\n")
    digest_mismatch = run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        generation_token,
        "--expected-version",
        "1",
        "--state",
        "generated",
        "--patch-path",
        patch_path.name,
        "--patch-digest",
        f"sha256:{'0' * 64}",
        check=False,
    )
    assert "Patch digest does not match" in str(digest_mismatch["stderr"])

    patch_path.write_bytes(
        b"diff --git a/src/extract.py b/src/extract.py\n+" + b"x" * (2 * 1024 * 1024)
    )
    run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        generation_token,
        "--expected-version",
        "1",
        "--state",
        "generated",
        "--patch-path",
        patch_path.name,
        "--patch-digest",
        f"sha256:{hashlib.sha256(patch_path.read_bytes()).hexdigest()}",
    )
    generated = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    remediation = generated["findings"][0]["remediationState"]
    assert remediation["patch"].endswith("... patch preview truncated ...")
    assert remediation["patchStats"]["previewTruncated"] is True
    replayed_generation = run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        generation_token,
        "--expected-version",
        "2",
        "--state",
        "generated",
        check=False,
    )
    assert "does not have an owned pending host request" in str(replayed_generation["stderr"])
    patch_path.write_text("tampered after review\n")
    refreshed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert refreshed["findings"][0]["remediationState"]["patch"] is None
    tampered_apply = run_workbench(
        state_dir,
        "request-finding-remediation-action",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--expected-version",
        "2",
        "--action",
        "apply",
        "--action-token",
        str(uuid.uuid4()),
        check=False,
    )
    assert "Patch digest does not match" in str(tampered_apply["stderr"])
    stale_replay = run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        generation_token,
        "--expected-version",
        "1",
        "--state",
        "failed",
        check=False,
    )
    assert "changed. Refresh it" in str(stale_replay["stderr"])


def test_finding_remediation_rejects_apply_after_checkout_changes(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    target = repository / "nested-target"
    target.mkdir()
    (target / "README.md").write_text("fixture\n")
    subprocess.run(["git", "add", "nested-target/README.md"], cwd=repository, check=True)
    subprocess.run(
        ["git", "commit", "-m", "add nested target"],
        cwd=repository,
        check=True,
        capture_output=True,
    )
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repository, text=True
    ).strip()
    nested_repository = target / "untracked-repository"
    initialize_git_repository(nested_repository)
    workspace_id = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
    )
    run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "standard",
    )
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        workspace_id,
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        relative_path="README.md",
        target_kind="git_worktree",
        target_revision=revision,
        snapshot_digest=str(started["results"]["contract"]["target"]["requiredSnapshotDigest"]),
    )
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    scan_dir = Path(str(completed["scanDir"]))
    occurrence_id = str(completed["findings"][0]["occurrenceId"])
    request_id = str(uuid.uuid4())
    generation_token = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "request-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        generation_token,
    )
    patch_path = scan_dir / "remediation.patch"
    patch_path.write_text(
        "diff --git a/README.md b/README.md\n"
        "--- a/README.md\n"
        "+++ b/README.md\n"
        "@@ -1 +1 @@\n"
        "-fixture\n"
        "+fixed\n"
    )
    (target / "README.md").write_text("changed while generating\n")
    stale_generation = run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        generation_token,
        "--expected-version",
        "1",
        "--state",
        "generated",
        "--patch-path",
        patch_path.name,
        "--patch-digest",
        f"sha256:{hashlib.sha256(patch_path.read_bytes()).hexdigest()}",
        check=False,
    )
    assert "Working-tree contents changed" in str(stale_generation["stderr"])
    (target / "README.md").write_text("fixture\n")
    run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        generation_token,
        "--expected-version",
        "1",
        "--state",
        "generated",
        "--patch-path",
        patch_path.name,
        "--patch-digest",
        f"sha256:{hashlib.sha256(patch_path.read_bytes()).hexdigest()}",
    )
    (target / "README.md").write_text("changed after patch generation\n")
    stale_checkout = run_workbench(
        state_dir,
        "request-finding-remediation-action",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--expected-version",
        "2",
        "--action",
        "apply",
        "--action-token",
        str(uuid.uuid4()),
        check=False,
    )
    assert stale_checkout["returncode"] != 0
    assert "Working-tree contents changed" in str(stale_checkout["stderr"])
    (target / "README.md").write_text("fixture\n")
    apply_token = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "request-finding-remediation-action",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--expected-version",
        "2",
        "--action",
        "apply",
        "--action-token",
        apply_token,
    )
    subprocess.run(
        ["git", "apply", "--directory=nested-target", str(patch_path)],
        cwd=repository,
        check=True,
    )
    ignored = target / "ignored-cache"
    ignored.mkdir()
    with (repository / ".git" / "info" / "exclude").open("a") as exclude:
        exclude.write("ignored-cache/\n")
    ignored_entry = ignored / "runtime-entry"
    if hasattr(os, "mkfifo"):
        os.mkfifo(ignored_entry)
    else:
        ignored_entry.write_text("ignored runtime data\n")
    unrelated = target / "unrelated.txt"
    unrelated.write_text("not reviewed\n")
    extra_changes = run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        apply_token,
        "--expected-version",
        "3",
        "--state",
        "applied",
        "--base-revision",
        revision,
        check=False,
    )
    assert "changes outside the reviewed patch" in str(extra_changes["stderr"])
    unrelated.unlink()
    applied = run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        apply_token,
        "--expected-version",
        "3",
        "--state",
        "applied",
        "--base-revision",
        revision,
    )
    assert applied["scan"]["findings"][0]["remediationState"]["state"] == "applied"


def test_finding_remediation_rejects_delayed_update_after_superseding_patch(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        str(saved["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target)
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    scan_dir = Path(str(completed["scanDir"]))
    occurrence_id = str(completed["findings"][0]["occurrenceId"])
    first_request_id = str(uuid.uuid4())
    first_generation_token = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "request-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        first_request_id,
        "--action-token",
        first_generation_token,
    )
    patch_path = scan_dir / "remediation.patch"
    patch_path.write_text("diff --git a/src/extract.py b/src/extract.py\n")
    run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        first_request_id,
        "--action-token",
        first_generation_token,
        "--expected-version",
        "1",
        "--state",
        "generated",
        "--patch-path",
        patch_path.name,
        "--patch-digest",
        f"sha256:{hashlib.sha256(patch_path.read_bytes()).hexdigest()}",
    )
    run_workbench(
        state_dir,
        "request-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        str(uuid.uuid4()),
        "--action-token",
        str(uuid.uuid4()),
    )
    delayed = run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        first_request_id,
        "--action-token",
        first_generation_token,
        "--expected-version",
        "2",
        "--state",
        "applied",
        "--base-revision",
        "unversioned",
        check=False,
    )
    assert "changed. Refresh it" in str(delayed["stderr"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT state, version FROM finding_remediation_attempts WHERE request_id = ?",
            (first_request_id,),
        ).fetchone() == ("superseded", 3)


def test_finding_remediation_rejects_unversioned_directory_changes(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    source = target / "source.txt"
    source.write_text("original\n")
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        str(saved["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target, relative_path=source.name)
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    scan_dir = Path(str(completed["scanDir"]))
    occurrence_id = str(completed["findings"][0]["occurrenceId"])
    request_id = str(uuid.uuid4())
    generation_token = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "request-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        generation_token,
    )
    patch_path = scan_dir / "remediation.patch"
    patch_path.write_text("diff --git a/source.txt b/source.txt\n")
    source.write_text("changed while generating\n")
    stale_generation = run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        generation_token,
        "--expected-version",
        "1",
        "--state",
        "generated",
        "--patch-path",
        patch_path.name,
        "--patch-digest",
        f"sha256:{hashlib.sha256(patch_path.read_bytes()).hexdigest()}",
        check=False,
    )
    assert "Working-tree contents changed" in str(stale_generation["stderr"])
    source.write_text("original\n")
    run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        generation_token,
        "--expected-version",
        "1",
        "--state",
        "generated",
        "--patch-path",
        patch_path.name,
        "--patch-digest",
        f"sha256:{hashlib.sha256(patch_path.read_bytes()).hexdigest()}",
    )
    source.write_text("changed before apply\n")
    stale_apply = run_workbench(
        state_dir,
        "request-finding-remediation-action",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--expected-version",
        "2",
        "--action",
        "apply",
        "--action-token",
        str(uuid.uuid4()),
        check=False,
    )
    assert "Working-tree contents changed" in str(stale_apply["stderr"])


def test_workbench_defaults_scan_artifacts_to_persistent_state_dir(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = run_workbench(state_dir, "start-scan", "--workspace-id", str(saved["id"]))
    scan_dir = Path(str(started["results"]["scanDir"]))
    assert scan_dir.is_relative_to(state_dir / "scans")


def test_workbench_serializes_concurrent_scan_starts(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    workspace_id = str(saved["id"])
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda _: run_workbench(
                    state_dir,
                    "start-scan",
                    "--workspace-id",
                    workspace_id,
                    "--scan-root",
                    str(tmp_path / "scans"),
                ),
                range(2),
            )
        )
    assert results[0]["results"]["scanId"] == results[1]["results"]["scanId"]
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM scans WHERE status = 'running'"
        ).fetchone() == (1,)


def test_workbench_rejects_setup_changes_after_scan_starts(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    run_workbench(state_dir, "start-scan", "--workspace-id", str(saved["id"]))

    failed = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        str(saved["id"]),
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "standard",
        check=False,
    )

    assert failed["returncode"] != 0
    assert "already has a scan" in str(failed["stderr"])


def test_workbench_rejects_scoped_deep_scan(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace_id = str(uuid.uuid4())
    run_workbench(state_dir, "create-workspace", "--workspace-id", workspace_id)
    failed = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        "src",
        "--mode",
        "deep",
        check=False,
    )
    assert failed["returncode"] != 0
    assert "repository-wide" in str(failed["stderr"])


def test_workbench_rejects_diff_scan_for_non_git_target(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace_id = str(uuid.uuid4())
    run_workbench(state_dir, "create-workspace", "--workspace-id", workspace_id)
    failed = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "diff",
        check=False,
    )
    assert failed["returncode"] != 0
    assert "non-bare Git worktree" in str(failed["stderr"])


def test_workbench_derives_git_branch_revision_and_detached_head(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    revision = initialize_git_repository(target)
    workspace_id = str(uuid.uuid4())
    created = run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
    )
    assert created["targetMetadata"] == {
        "branch": "main",
        "commitSubject": "Initial commit",
        "detachedHead": False,
        "hasHead": True,
        "isGit": True,
        "isWorktree": True,
        "revision": revision,
        "reviewChangesSupported": True,
        "shortRevision": revision[:7],
    }

    saved = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "diff",
        "--target-summary",
        "Latest commit",
        "--diff-target-kind",
        "commit",
        "--diff-head-revision",
        revision,
    )
    assert saved["mode"] == "diff"
    assert saved["targetSummary"] == "Latest commit"
    assert saved["diffTarget"]["kind"] == "commit"
    assert saved["diffTarget"]["headRevision"] == revision

    relabeled = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "diff",
        "--target-summary",
        "",
        "--diff-target-kind",
        "commit",
        "--diff-head-revision",
        revision,
    )
    assert relabeled["targetSummary"] == f"Commit {revision[:7]}"

    subprocess.run(["git", "checkout", "-q", "--detach", "HEAD"], cwd=target, check=True)
    detached = run_workbench(state_dir, "get-workspace", "--workspace-id", workspace_id)
    assert detached["targetMetadata"]["branch"] is None
    assert detached["targetMetadata"]["detachedHead"] is True
    assert detached["targetMetadata"]["shortRevision"] == revision[:7]


def test_workbench_git_inspection_ignores_repository_environment(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target_revision = initialize_git_repository(target)
    nested_target = target / "nested"
    nested_target.mkdir()
    foreign = tmp_path / "foreign"
    initialize_git_repository(foreign)
    subprocess.run(["git", "branch", "-M", "foreign"], cwd=foreign, check=True)

    inspected = run_workbench(
        state_dir,
        "inspect-target",
        "--target-path",
        str(nested_target),
        environment={
            "GIT_CEILING_DIRECTORIES": str(target),
            "GIT_DIR": str(foreign / ".git"),
            "GIT_WORK_TREE": str(foreign),
        },
    )

    assert inspected["targetMetadata"]["branch"] == "main"
    assert inspected["targetMetadata"]["revision"] == target_revision


def test_workbench_rejects_nested_git_target_for_review_changes(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    revision = initialize_git_repository(target)
    nested_target = target / "nested"
    nested_target.mkdir()
    workspace_id = str(uuid.uuid4())
    run_workbench(state_dir, "create-workspace", "--workspace-id", workspace_id)

    failed = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(nested_target),
        "--scope",
        ".",
        "--mode",
        "diff",
        "--diff-target-kind",
        "commit",
        "--diff-head-revision",
        revision,
        check=False,
    )

    assert failed["returncode"] != 0
    assert "repository root" in str(failed["stderr"])


def test_workbench_inspects_target_without_submitting_workspace(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "inspected-target"
    revision = initialize_git_repository(target)
    inspected = run_workbench(state_dir, "inspect-target", "--target-path", str(target))
    assert inspected["displayName"] == "inspected-target"
    assert inspected["targetPath"] == str(target.resolve())
    assert inspected["targetMetadata"]["reviewChangesSupported"] is True
    assert inspected["targetMetadata"]["revision"] == revision
    assert not (state_dir / "workbench.sqlite3").exists()

    workspace_id = str(uuid.uuid4())
    workspace = run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
    )
    assert workspace["setup"] == {"submitted": False}


def assert_unversioned_codebase_scan_starts(
    state_dir: Path,
    target: Path,
    *,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    inspected = run_workbench(
        state_dir,
        "inspect-target",
        "--target-path",
        str(target),
        environment=environment,
    )
    workspace_id = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        environment=environment,
    )
    saved = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "standard",
        environment=environment,
    )
    started = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        workspace_id,
        environment=environment,
    )

    assert saved["setup"] == {"submitted": True}
    assert started["results"]["targetRevision"] == "unversioned"
    assert started["results"]["contract"]["target"]["allowedKinds"] == ["directory_snapshot"]
    metadata = inspected["targetMetadata"]
    assert isinstance(metadata, dict)
    return metadata


def test_workbench_scans_codebase_without_git_on_path(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('fixture')\n")

    metadata = assert_unversioned_codebase_scan_starts(
        tmp_path / "state",
        target,
        environment={"PATH": str(tmp_path / "empty-bin")},
    )

    assert metadata == {
        "hasHead": False,
        "isGit": False,
        "isWorktree": False,
        "reviewChangesSupported": False,
    }


def test_workbench_scans_unborn_git_repository_as_codebase(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=target, check=True)
    (target / "app.py").write_text("print('fixture')\n")

    metadata = assert_unversioned_codebase_scan_starts(tmp_path / "state", target)

    assert metadata["isGit"] is True
    assert metadata["isWorktree"] is True
    assert metadata["hasHead"] is False
    assert metadata["reviewChangesSupported"] is False


def test_workbench_marks_nested_git_paths_as_review_changes_unsupported(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "inspected-target"
    initialize_git_repository(target)
    nested = target / "nested"
    nested.mkdir()

    inspected = run_workbench(state_dir, "inspect-target", "--target-path", str(nested))

    assert inspected["targetMetadata"]["isGit"] is True
    assert inspected["targetMetadata"]["isWorktree"] is True
    assert inspected["targetMetadata"]["hasHead"] is True
    assert inspected["targetMetadata"]["reviewChangesSupported"] is False


def test_workbench_opens_invalid_target_for_correction(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    missing = tmp_path / "missing"
    workspace = run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        str(uuid.uuid4()),
        "--target-path",
        str(missing),
        "--user-context",
        "Focus on authentication and uploaded archives.",
    )
    assert workspace["targetPath"] == str(missing)
    assert "targetMetadata" not in workspace
    assert workspace["setupValidation"]["valid"] is False
    assert "readable local directory" in workspace["setupValidation"]["error"]
    assert workspace["userContext"] == "Focus on authentication and uploaded archives."


def test_workbench_preserves_long_user_context(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    initialize_git_repository(target)
    workspace_id = str(uuid.uuid4())
    created_context = "Initial guidance " + "x" * 10_000
    created = run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--user-context",
        created_context,
    )
    assert created["userContext"] == created_context

    saved_context = "Updated guidance " + "y" * 10_000
    saved = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "standard",
        "--user-context",
        saved_context,
    )
    assert saved["userContext"] == saved_context


def test_workbench_preserves_url_user_context_on_workspace_creation(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    user_context = (
        "Repository: https://github.com/example/security-review\n"
        "OAuth callback: https://accounts.example.test/oauth/callback"
    )
    workspace = run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        str(uuid.uuid4()),
        "--target-path",
        str(target),
        "--user-context",
        user_context,
    )
    assert workspace["userContext"] == user_context
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT user_context FROM workspaces").fetchone() == (
            user_context,
        )


def test_workbench_replaces_context_only_for_running_owned_scan(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(workspace["id"]))
    scan_id = str(started["results"]["scanId"])

    updated = run_workbench(
        state_dir,
        "update-scan-context",
        "--scan-id",
        scan_id,
        "--workspace-id",
        str(workspace["id"]),
        "--user-context",
        "Prioritize tenant isolation.",
    )
    assert updated["scan"]["userContext"] == "Prioritize tenant isolation."
    assert updated["workspace"]["userContext"] == "Prioritize tenant isolation."

    rejected_workspace = run_workbench(
        state_dir,
        "update-scan-context",
        "--scan-id",
        scan_id,
        "--workspace-id",
        str(uuid.uuid4()),
        "--user-context",
        "Wrong owner.",
        check=False,
    )
    assert rejected_workspace["returncode"] != 0
    assert "selected workspace" in str(rejected_workspace["stderr"])

    url_context = "OAuth issuer: https://accounts.example.test/oauth/authorize"
    updated_url = run_workbench(
        state_dir,
        "update-scan-context",
        "--scan-id",
        scan_id,
        "--workspace-id",
        str(workspace["id"]),
        "--user-context",
        url_context,
    )
    assert updated_url["scan"]["userContext"] == url_context
    assert updated_url["workspace"]["userContext"] == url_context

    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "fixture")
    rejected_terminal = run_workbench(
        state_dir,
        "update-scan-context",
        "--scan-id",
        scan_id,
        "--workspace-id",
        str(workspace["id"]),
        "--user-context",
        "Too late.",
        check=False,
    )
    assert rejected_terminal["returncode"] != 0
    assert "Only a running scan" in str(rejected_terminal["stderr"])


def test_workbench_marks_invalid_initial_scope_for_correction(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace = run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        str(uuid.uuid4()),
        "--target-path",
        str(target),
        "--scope",
        "missing",
    )
    assert workspace["targetMetadata"]["isGit"] is False
    assert workspace["scope"] == "missing"
    assert workspace["setupValidation"]["valid"] is False
    assert "existing directory" in workspace["setupValidation"]["error"]


def test_workbench_resolves_structured_diff_target(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    revision = initialize_git_repository(target)
    inspected = run_workbench(
        state_dir,
        "inspect-setup",
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "diff",
        "--diff-target-kind",
        "commit",
        "--diff-head-revision",
        "HEAD",
    )
    assert inspected["diffTarget"]["kind"] == "commit"
    assert inspected["diffTarget"]["headRevision"] == revision
    assert inspected["diffTarget"]["baseRevision"]

    inspected_again = run_workbench(
        state_dir,
        "inspect-setup",
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "diff",
        "--diff-target-kind",
        "commit",
        "--diff-base-revision",
        inspected["diffTarget"]["baseRevision"],
        "--diff-head-revision",
        inspected["diffTarget"]["headRevision"],
    )
    assert inspected_again["diffTarget"] == inspected["diffTarget"]

    rejected = run_workbench(
        state_dir,
        "inspect-setup",
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "diff",
        "--diff-target-kind",
        "commit",
        "--diff-base-revision",
        revision,
        "--diff-head-revision",
        revision,
        check=False,
    )
    assert rejected["returncode"] == 1
    assert "must match the selected commit's parent" in rejected["stderr"]


def test_workbench_rejects_working_tree_target_after_head_moves(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    revision = initialize_git_repository(target)
    workspace_id = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--mode",
        "diff",
        "--diff-target-kind",
        "working_tree",
        "--diff-base-revision",
        revision,
        "--diff-head-revision",
        revision,
    )
    saved = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "diff",
        "--diff-target-kind",
        "working_tree",
        "--diff-base-revision",
        revision,
        "--diff-head-revision",
        revision,
    )
    assert saved["targetSummary"] == "Uncommitted changes"

    (target / "README.md").write_text("second commit\n")
    subprocess.run(["git", "add", "README.md"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "Second commit"], cwd=target, check=True)

    failed = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        workspace_id,
        check=False,
    )
    assert failed["returncode"] != 0
    assert "HEAD changed" in str(failed["stderr"])


def test_workbench_rejects_working_tree_target_after_contents_change(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    revision = initialize_git_repository(target)
    workspace_id = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--mode",
        "diff",
        "--diff-target-kind",
        "working_tree",
        "--diff-base-revision",
        revision,
    )
    saved = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "diff",
        "--diff-target-kind",
        "working_tree",
        "--diff-base-revision",
        revision,
    )
    assert str(saved["diffTarget"]["contentDigest"]).startswith(
        "codex-security-snapshot/v1:sha256:"
    )
    (target / "new-file.txt").write_text("new untracked content\n")

    failed = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        workspace_id,
        check=False,
    )
    assert failed["returncode"] != 0
    assert "contents changed" in str(failed["stderr"])


def test_workbench_warns_after_working_tree_changes(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    revision = initialize_git_repository(target)
    (target / "new-file.txt").write_text("selected content\n")
    workspace_id = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--mode",
        "diff",
        "--diff-target-kind",
        "working_tree",
        "--diff-base-revision",
        revision,
    )
    run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "diff",
        "--diff-target-kind",
        "working_tree",
        "--diff-base-revision",
        revision,
    )
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        workspace_id,
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    snapshot_digest = str(started["results"]["diffTarget"]["contentDigest"])
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        target_kind="git_diff",
        diff_base_revision=revision,
        diff_head_revision=revision,
        snapshot_digest=snapshot_digest,
        coverage_mode="working_tree",
    )
    (target / "new-file.txt").write_text("changed during scan\n")
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)
    assert completed["scan"]["progress"]["status"] == "complete"
    assert completed["scan"]["warnings"] == [WORKTREE_CHANGED_WARNING]
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["target"]["snapshotDigest"] == snapshot_digest
    assert json.loads((scan_dir / "coverage.json").read_text())["completeness"] == "complete"


def test_workbench_warns_after_working_tree_head_changes(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    revision = initialize_git_repository(target)
    workspace_id = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--mode",
        "diff",
        "--diff-target-kind",
        "working_tree",
        "--diff-base-revision",
        revision,
    )
    run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "diff",
        "--diff-target-kind",
        "working_tree",
        "--diff-base-revision",
        revision,
    )
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        workspace_id,
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    snapshot_digest = str(started["results"]["diffTarget"]["contentDigest"])
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        target_kind="git_diff",
        diff_base_revision=revision,
        diff_head_revision=revision,
        snapshot_digest=snapshot_digest,
        coverage_mode="working_tree",
    )

    (target / "new-file.txt").write_text("new committed content\n")
    subprocess.run(["git", "add", "new-file.txt"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "Move HEAD"], cwd=target, check=True)

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)
    assert completed["scan"]["progress"]["status"] == "complete"
    assert completed["scan"]["warnings"] == [HEAD_CHANGED_WARNING]
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["target"]["headRevision"] == revision
    assert manifest["scan"]["target"]["snapshotDigest"] == snapshot_digest


def test_workbench_can_validate_legacy_nested_working_tree_scan(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    revision = initialize_git_repository(target)
    nested_target = target / "nested"
    nested_target.mkdir()
    workspace_id = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--mode",
        "diff",
        "--diff-target-kind",
        "working_tree",
        "--diff-base-revision",
        revision,
    )
    run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "diff",
        "--diff-target-kind",
        "working_tree",
        "--diff-base-revision",
        revision,
    )
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        workspace_id,
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET target_path = ? WHERE id = ?",
            (str(nested_target.resolve()), scan_id),
        )

    failed = run_workbench(
        state_dir,
        "complete-scan",
        "--scan-id",
        scan_id,
        check=False,
    )
    assert failed["returncode"] != 0
    assert "repository root" not in str(failed["stderr"])
    assert "scan-manifest.json" in str(failed["stderr"])


def test_workbench_populates_manifest_with_working_tree_digest(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    revision = initialize_git_repository(target)
    (target / "new-file.txt").write_text("selected content\n")
    workspace_id = str(uuid.uuid4())
    created = run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--mode",
        "diff",
        "--diff-target-kind",
        "working_tree",
        "--diff-base-revision",
        revision,
    )
    diff_target = created["diffTarget"]
    run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "diff",
        "--diff-target-kind",
        "working_tree",
        "--diff-base-revision",
        str(diff_target["baseRevision"]),
        "--diff-head-revision",
        str(diff_target["headRevision"]),
        "--diff-content-digest",
        str(diff_target["contentDigest"]),
    )
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        workspace_id,
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        target_kind="git_diff",
        diff_base_revision=str(diff_target["baseRevision"]),
        diff_head_revision=str(diff_target["headRevision"]),
        coverage_mode="repository",
    )
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)
    assert completed["scan"]["progress"]["status"] == "complete"
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert manifest["scan"]["target"]["snapshotDigest"] == diff_target["contentDigest"]
    assert manifest["scan"]["scope"] == {"includePaths": ["."], "excludePaths": []}
    assert coverage["mode"] == "working_tree"
    assert coverage["includePaths"] == ["."]
    assert coverage["excludePaths"] == []


def test_workbench_rejects_commit_with_missing_shallow_parent(tmp_path: Path) -> None:
    source = tmp_path / "source"
    initialize_git_repository(source)
    (source / "README.md").write_text("second commit\n")
    subprocess.run(["git", "add", "README.md"], cwd=source, check=True)
    subprocess.run(["git", "commit", "-qm", "Second commit"], cwd=source, check=True)
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", source.as_uri(), str(shallow)],
        check=True,
    )

    failed = run_workbench(
        tmp_path / "state",
        "inspect-setup",
        "--target-path",
        str(shallow),
        "--scope",
        ".",
        "--mode",
        "diff",
        "--diff-target-kind",
        "commit",
        "--diff-head-revision",
        "HEAD",
        check=False,
    )
    assert failed["returncode"] != 0
    assert "Commit parent does not resolve" in str(failed["stderr"])


def test_workbench_populates_completed_manifest_with_exact_diff_target(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    revision = initialize_git_repository(target)
    workspace_id = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--mode",
        "diff",
        "--diff-target-kind",
        "commit",
        "--diff-head-revision",
        revision,
    )
    saved = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "diff",
        "--diff-target-kind",
        "commit",
        "--diff-head-revision",
        revision,
    )
    diff_target = saved["diffTarget"]
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        workspace_id,
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        target_kind="git_diff",
        diff_base_revision="wrong-base",
        diff_head_revision=str(diff_target["headRevision"]),
    )
    draft_manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    draft_target = draft_manifest["scan"]["target"]
    authored_snapshot_digest = draft_target["snapshotDigest"]
    draft_target["revision"] = "stale-revision"
    (scan_dir / "scan-manifest.json").write_text(json.dumps(draft_manifest))
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)
    assert completed["scan"]["progress"]["status"] == "complete"
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert "revision" not in manifest["scan"]["target"]
    assert manifest["scan"]["target"]["baseRevision"] == diff_target["baseRevision"]
    assert manifest["scan"]["target"]["headRevision"] == diff_target["headRevision"]
    assert manifest["scan"]["target"]["snapshotDigest"] == authored_snapshot_digest
    assert manifest["scan"]["scope"] == {"includePaths": ["."], "excludePaths": []}


def test_workbench_preserves_invalid_requested_initial_deep_scope(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "src").mkdir()
    workspace = run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        str(uuid.uuid4()),
        "--target-path",
        str(target),
        "--scope",
        "src",
        "--mode",
        "deep",
    )
    assert workspace["mode"] == "deep"
    assert workspace["scope"] == "src"
    assert workspace["setupValidation"]["valid"] is False
    assert "repository-wide" in str(workspace["setupValidation"]["error"])

    workspace = run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        str(uuid.uuid4()),
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "deep",
    )
    assert workspace["mode"] == "deep"
    assert workspace["scope"] == "."


def test_workbench_discards_diff_target_for_non_diff_mode(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace = run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        str(uuid.uuid4()),
        "--target-path",
        str(target),
        "--mode",
        "standard",
        "--diff-target-kind",
        "range",
        "--diff-base-revision",
        "base",
        "--diff-head-revision",
        "head",
        "--diff-content-digest",
        "digest",
    )
    assert workspace["diffTarget"] is None
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            """
            SELECT diff_target_kind, diff_base_revision, diff_head_revision, diff_content_digest
            FROM workspaces WHERE id = ?
            """,
            (workspace["id"],),
        ).fetchone() == (None, None, None, None)


def test_workbench_rejects_diff_target_when_saving_non_diff_mode(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace_id = str(uuid.uuid4())
    run_workbench(state_dir, "create-workspace", "--workspace-id", workspace_id)

    failed = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "standard",
        "--diff-target-kind",
        "range",
        "--diff-base-revision",
        "base",
        "--diff-head-revision",
        "head",
        check=False,
    )

    assert failed["returncode"] != 0
    assert "requires Review changes mode" in str(failed["stderr"])


def test_workbench_requires_exact_diff_target(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    initialize_git_repository(target)
    workspace_id = str(uuid.uuid4())
    run_workbench(state_dir, "create-workspace", "--workspace-id", workspace_id)
    failed = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "diff",
        check=False,
    )
    assert failed["returncode"] != 0
    assert "Choose which Git changes" in str(failed["stderr"])


def test_workbench_starts_diff_without_presentation_label(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    revision = initialize_git_repository(target)
    workspace_id = str(uuid.uuid4())
    run_workbench(state_dir, "create-workspace", "--workspace-id", workspace_id)
    run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "diff",
        "--target-summary",
        "Latest commit",
        "--diff-target-kind",
        "commit",
        "--diff-head-revision",
        revision,
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE workspaces SET target_summary = NULL WHERE id = ?", (workspace_id,)
        )
    started = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        workspace_id,
        "--scan-root",
        str(tmp_path / "scans"),
    )
    assert started["results"]["diffTarget"]["headRevision"] == revision
    assert started["results"]["targetSummary"] == f"Commit {revision[:7]}"


def test_workbench_rejects_bare_repository_for_audit(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "bare.git"
    subprocess.run(["git", "init", "-q", "--bare", str(target)], check=True)
    workspace_id = str(uuid.uuid4())
    run_workbench(state_dir, "create-workspace", "--workspace-id", workspace_id)
    failed = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "standard",
        check=False,
    )
    assert failed["returncode"] != 0
    assert "checked-out worktree" in str(failed["stderr"])


def test_workbench_target_inspection_requires_absolute_directory(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    failed = run_workbench(
        state_dir,
        "inspect-target",
        "--target-path",
        "relative-target",
        check=False,
    )
    assert failed["returncode"] != 0
    assert "absolute local directory" in str(failed["stderr"])


def test_workbench_refreshes_title_only_when_target_changes(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    original = tmp_path / "original"
    replacement = tmp_path / "replacement"
    original.mkdir()
    replacement.mkdir()
    workspace_id = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(original),
        "--target-title",
        "Friendly title",
        "--target-summary",
        "Original repository context.",
    )
    unchanged = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(original),
        "--scope",
        ".",
        "--mode",
        "standard",
    )
    assert unchanged["targetTitle"] == "Friendly title"
    assert unchanged["targetSummary"] == "Original repository context."
    changed = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(replacement),
        "--scope",
        ".",
        "--mode",
        "standard",
    )
    assert changed["targetTitle"] == "replacement"
    assert changed["targetSummary"] is None


def test_review_changes_rejects_unborn_and_bare_git_repositories(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    unborn = tmp_path / "unborn"
    unborn.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=unborn, check=True)
    bare = tmp_path / "bare.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)

    for index, target in enumerate((unborn, bare)):
        inspected = run_workbench(state_dir, "inspect-target", "--target-path", str(target))
        assert inspected["targetMetadata"]["reviewChangesSupported"] is False
        workspace_id = str(uuid.uuid4())
        run_workbench(state_dir, "create-workspace", "--workspace-id", workspace_id)
        failed = run_workbench(
            state_dir,
            "save-workspace",
            "--workspace-id",
            workspace_id,
            "--target-path",
            str(target),
            "--scope",
            ".",
            "--mode",
            "diff",
            check=False,
        )
        assert failed["returncode"] != 0, index
        expected = "non-bare Git worktree" if target == unborn else "checked-out worktree"
        assert expected in str(failed["stderr"])


def test_workbench_rejects_missing_or_file_scope(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "file.py").write_text("print('fixture')\n")
    workspace_id = str(uuid.uuid4())
    run_workbench(state_dir, "create-workspace", "--workspace-id", workspace_id)

    for scope in ("missing", "file.py"):
        failed = run_workbench(
            state_dir,
            "save-workspace",
            "--workspace-id",
            workspace_id,
            "--target-path",
            str(target),
            "--scope",
            scope,
            "--mode",
            "standard",
            check=False,
        )
        assert failed["returncode"] != 0
        assert "existing directory" in str(failed["stderr"])


def test_workbench_normalizes_absolute_scope_inside_target(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    scoped = target / "src"
    scoped.mkdir(parents=True)
    workspace_id = str(uuid.uuid4())
    run_workbench(state_dir, "create-workspace", "--workspace-id", workspace_id)

    workspace = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        str(scoped),
        "--mode",
        "standard",
    )
    assert workspace["scope"] == "src"

    workspace = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        str(target),
        "--mode",
        "standard",
    )
    assert workspace["scope"] == "."


def test_workbench_rejects_scope_escape(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace_id = str(uuid.uuid4())
    run_workbench(state_dir, "create-workspace", "--workspace-id", workspace_id)
    failed = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        "../outside",
        "--mode",
        "standard",
        check=False,
    )
    assert failed["returncode"] != 0
    assert "stay inside" in str(failed["stderr"])


def test_workbench_rejects_symlinked_scope_escape(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    outside = tmp_path / "outside"
    target.mkdir()
    outside.mkdir()
    (target / "linked").symlink_to(outside, target_is_directory=True)
    workspace_id = str(uuid.uuid4())
    run_workbench(state_dir, "create-workspace", "--workspace-id", workspace_id)
    failed = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        "linked",
        "--mode",
        "standard",
        check=False,
    )
    assert failed["returncode"] != 0
    assert "stay inside" in str(failed["stderr"])


def test_workbench_rejects_progress_completed_above_total(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    failed = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        str(started["results"]["scanId"]),
        "--review-items-total",
        "2",
        "--review-items-completed",
        "3",
        check=False,
    )
    assert failed["returncode"] != 0
    assert "cannot exceed" in str(failed["stderr"])


def test_workbench_rejects_regressive_progress(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        "validation",
        "--review-items-total",
        "10",
        "--review-items-completed",
        "6",
    )

    phase_failed = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        "discovery",
        check=False,
    )
    assert phase_failed["returncode"] != 0
    assert "earlier phase" in str(phase_failed["stderr"])

    coverage_failed = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--review-items-completed",
        "5",
        check=False,
    )
    assert coverage_failed["returncode"] != 0
    assert "cannot decrease" in str(coverage_failed["stderr"])


def test_workbench_tracks_review_pass_for_deep_scan_only(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace_id = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--mode",
        "deep",
    )
    saved = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "deep",
    )
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    assert started["results"]["progress"]["reviewPass"] is None

    run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        "discovery",
        "--deep-review-pass",
        "2",
        "--review-items-total",
        "31",
        "--review-items-completed",
        "0",
    )
    updated = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--review-items-completed",
        "22",
    )
    assert updated["scan"]["progress"]["reviewPass"] == 2
    assert updated["scan"]["progress"]["coverage"] == {
        "closedRows": 22,
        "filesTotal": 0,
        "worklistRows": 31,
    }

    standard_target = tmp_path / "standard-target"
    standard_target.mkdir()
    standard = create_saved_workspace(state_dir, standard_target)
    standard_scan = start_delivered_scan(
        state_dir,
        "--workspace-id",
        str(standard["id"]),
    )
    failed = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        str(standard_scan["results"]["scanId"]),
        "--deep-review-pass",
        "1",
        check=False,
    )
    assert failed["returncode"] != 0
    assert "Only Deep Scan" in str(failed["stderr"])


def test_workbench_updates_progress_timestamp_for_phase_and_failure(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    started_at = str(started["results"]["progress"]["updatedAt"])
    time.sleep(0.001)
    updated = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        "validation",
    )
    updated_at = str(updated["scan"]["progress"]["updatedAt"])
    assert updated_at > started_at
    time.sleep(0.001)
    failed = run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped.")
    assert str(failed["scan"]["progress"]["updatedAt"]) > updated_at


def test_workbench_preserves_scan_when_git_revision_cannot_be_rechecked(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute("UPDATE scans SET target_revision = 'deadbeef' WHERE id = ?", (scan_id,))
        connection.commit()
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        target_kind="git_worktree",
    )
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)

    assert completed["scan"]["progress"]["status"] == "complete"
    assert completed["scan"]["warnings"] == [GIT_UNAVAILABLE_WARNING]
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["target"]["revision"] == "deadbeef"


def test_completed_finding_projects_writeup_and_poc_artifact_paths(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target)

    slug = "unsafe-archive-extraction"
    report_path = f"findings/{slug}/{slug}.md"
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    findings["findings"][0]["writeup"] = {"reportPath": report_path}
    findings["findings"][0]["artifactPaths"] = ["../outside.txt"]
    findings_path.write_text(json.dumps(findings))

    report = scan_dir / report_path
    poc = report.parent / "poc"
    fixtures = poc / "fixtures"
    fixtures.mkdir(parents=True)
    report.write_text("# Unsafe archive extraction\n")
    (poc / "README.md").write_text("Run the reproduction in a disposable directory.\n")
    (poc / "reproduce.py").write_text("print('reproduced')\n")
    (fixtures / "payload.txt").write_text("../outside\n")
    outside = tmp_path / "outside.txt"
    outside.write_text("must not be projected\n")
    try:
        (poc / "outside-link.txt").symlink_to(outside)
    except OSError:
        pass

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)
    assert completed["scan"]["findings"][0]["artifactPaths"] == [
        report_path,
        f"findings/{slug}/poc/README.md",
        f"findings/{slug}/poc/reproduce.py",
        f"findings/{slug}/poc/fixtures/payload.txt",
    ]


def test_workbench_populates_clean_git_scan_revision_with_large_source_excerpt(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    initialize_git_repository(target)
    (target / "README.md").write_text(
        "\n".join(f"source line {line_number}" for line_number in range(1, 51))
        + "\n"
        + "x" * (1024 * 1024)
    )
    subprocess.run(["git", "add", "README.md"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "Add source fixture"], cwd=target, check=True)
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=target,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    saved = create_saved_git_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    assert started["results"]["contract"]["target"]["allowedKinds"] == ["git_revision"]
    assert "requiredSnapshotDigest" not in started["results"]["contract"]["target"]
    write_completed_contract(
        Path(str(started["results"]["scanDir"])),
        scan_id,
        target,
        relative_path="README.md",
        target_kind="git_revision",
        target_revision="wrong-revision",
    )
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)
    assert completed["scan"]["progress"]["status"] == "complete"
    manifest = json.loads(
        (Path(str(started["results"]["scanDir"])) / "scan-manifest.json").read_text()
    )
    assert manifest["scan"]["target"]["revision"] == revision
    assert "snapshotDigest" not in manifest["scan"]["target"]
    excerpt = completed["scan"]["findings"][0]["sourceExcerpt"]
    assert excerpt.startswith("38  source line 38")
    assert "41  source line 41" in excerpt
    assert excerpt.endswith("47  source line 47")

    (target / "README.md").write_text("replacement source\n")
    subprocess.run(["git", "add", "README.md"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "Replace source fixture"], cwd=target, check=True)
    refreshed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)
    assert refreshed["scan"]["findings"][0]["sourceExcerpt"] == excerpt


def test_workbench_preserves_in_flight_git_scan_during_migration_normalization(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    revision = initialize_git_repository(target)
    saved = create_saved_git_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    allowed_kinds = started["results"]["contract"]["target"]["allowedKinds"]
    database = state_dir / "workbench.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM schema_migrations WHERE version = 2")
        connection.execute(
            "UPDATE schema_migrations SET version = -version WHERE version BETWEEN 3 AND 5"
        )
        connection.execute("UPDATE schema_migrations SET version = 2 WHERE version = -3")
        connection.execute("UPDATE schema_migrations SET version = 3 WHERE version = -4")
        connection.execute("UPDATE schema_migrations SET version = 4 WHERE version = -5")
        connection.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
            (5, "scan target snapshot digests", "2026-06-01T00:00:00Z"),
        )
        connection.execute("ALTER TABLE workspaces DROP COLUMN capability_preflight_json")

    run_workbench(state_dir, "database-info")
    migrated = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)
    assert migrated["scan"]["contract"]["target"]["allowedKinds"] == allowed_kinds
    write_completed_contract(
        Path(str(started["results"]["scanDir"])),
        scan_id,
        target,
        target_kind="git_revision",
        target_revision=revision,
    )
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)
    assert completed["scan"]["progress"]["status"] == "complete"


def test_workbench_preserves_dirty_git_scan_after_worktree_changes(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    revision = initialize_git_repository(target)
    dirty_content = "fixture\nlocal change\n"
    (target / "README.md").write_text(dirty_content)
    saved = create_saved_git_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    contract = started["results"]["contract"]["target"]
    assert contract["allowedKinds"] == ["git_worktree"]
    snapshot_digest = str(contract["requiredSnapshotDigest"])
    write_completed_contract(
        Path(str(started["results"]["scanDir"])),
        scan_id,
        target,
        target_kind="git_revision",
        target_revision=revision,
    )
    failed = run_workbench(
        state_dir,
        "complete-scan",
        "--scan-id",
        scan_id,
        check=False,
    )
    assert failed["returncode"] != 0
    assert "scan.target.kind" in str(failed["stderr"])
    assert (
        run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]["progress"]["status"]
        == "running"
    )

    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    snapshot_digest = str(started["results"]["contract"]["target"]["requiredSnapshotDigest"])

    write_completed_contract(
        Path(str(started["results"]["scanDir"])),
        scan_id,
        target,
        target_kind="git_worktree",
        target_revision=revision,
        snapshot_digest=snapshot_digest,
    )
    (target / "README.md").write_text(f"{dirty_content}changed during scan\n")
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)
    assert completed["scan"]["progress"]["status"] == "complete"
    assert completed["scan"]["warnings"] == [WORKTREE_CHANGED_WARNING]
    manifest = json.loads(
        (Path(str(started["results"]["scanDir"])) / "scan-manifest.json").read_text()
    )
    assert manifest["scan"]["target"]["revision"] == revision
    assert manifest["scan"]["target"]["snapshotDigest"] == snapshot_digest


def test_workbench_generates_reports_during_completion(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target)
    (scan_dir / "report.html").write_text("<p>Stale HTML report</p>")
    (scan_dir / "report.md").write_text("# Untrusted report\n")

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)

    assert completed["scan"]["progress"]["status"] == "complete"
    assert not (scan_dir / "report.html").exists()
    assert "Untrusted report" not in (scan_dir / "report.md").read_text()


def test_workbench_omits_unsafe_symlink_source_path_without_hiding_finding(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    outside = tmp_path / "outside"
    target.mkdir()
    outside.mkdir()
    (target / "src").symlink_to(outside, target_is_directory=True)
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    write_completed_contract(Path(str(started["results"]["scanDir"])), scan_id, target)
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)
    location = completed["scan"]["findings"][0]["locations"][0]
    assert location["path"] == "src/extract.py"
    assert "absolutePath" not in location


def test_workbench_hides_missing_artifact_on_reopen(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target)
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)
    assert completed["scan"]["reportAvailable"] is True
    (scan_dir / "report.md").unlink()
    reopened = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)
    assert reopened["scan"]["reportAvailable"] is False
    assert "markdownReport" not in reopened["scan"]["artifacts"]
