from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from workbench_test_support import (
    create_saved_workspace,
    run_workbench,
    stable_target_id,
    write_completed_contract,
)


def complete_scan(
    state_dir: Path,
    target: Path,
    *,
    identity_anchor: str,
    completeness: str = "complete",
    finding: bool = True,
    include_paths: list[str] | None = None,
    relative_path: str = "src/extract.py",
) -> dict[str, object]:
    workspace = create_saved_workspace(state_dir, target)
    if include_paths is not None:
        workspace = run_workbench(
            state_dir,
            "save-workspace",
            "--workspace-id",
            str(workspace["id"]),
            "--target-path",
            str(target),
            "--scope",
            include_paths[0],
            "--mode",
            "standard",
        )
    started = run_workbench(state_dir, "start-scan", "--workspace-id", str(workspace["id"]))
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        coverage_mode="scoped_path" if include_paths is not None else "repository",
        identity_anchor=identity_anchor,
        include_paths=include_paths,
        inventory_strategy="scoped_path" if include_paths is not None else "repository",
        relative_path=relative_path,
    )
    if not finding:
        findings_path = scan_dir / "findings.json"
        findings = json.loads(findings_path.read_text())
        findings["findings"] = []
        findings_path.write_text(json.dumps(findings))
    if completeness != "complete":
        coverage_path = scan_dir / "coverage.json"
        coverage = json.loads(coverage_path.read_text())
        coverage["completeness"] = completeness
        coverage["surfaces"][0]["disposition"] = "needs_follow_up"
        coverage["deferred"] = [
            {"id": "unreviewed-path", "reason": "Review incomplete", "paths": ["src/extract.py"]}
        ]
        coverage_path.write_text(json.dumps(coverage))
    return run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]


@pytest.mark.parametrize(
    ("completeness", "include_paths"),
    [("complete", None), ("partial", None), ("complete", ["docs"])],
)
def test_later_scans_preserve_global_findings_and_repository_counts(
    tmp_path: Path, completeness: str, include_paths: list[str] | None
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "repo"
    target.mkdir()
    (target / "docs").mkdir()

    original = complete_scan(state_dir, target, identity_anchor="remaining-finding")
    complete_scan(
        state_dir,
        target,
        identity_anchor="clean-scan",
        completeness=completeness,
        finding=False,
        include_paths=include_paths,
    )

    findings = run_workbench(state_dir, "list-global-findings")["findings"]
    assert len(findings) == 1
    assert findings[0]["scanId"] == original["scanId"]
    assert findings[0]["status"] == "open"
    assert (
        run_workbench(state_dir, "list-repositories")["repositories"][0]["openFindingsCount"] == 1
    )


def test_global_findings_apply_pagination_to_historical_findings(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    historical_target = tmp_path / "historical-repo"
    first_active_target = tmp_path / "first-active-repo"
    second_active_target = tmp_path / "second-active-repo"
    for target in (historical_target, first_active_target, second_active_target):
        target.mkdir()

    historical = complete_scan(state_dir, historical_target, identity_anchor="historical-finding")
    complete_scan(state_dir, historical_target, identity_anchor="clean-scan", finding=False)
    first_active = complete_scan(
        state_dir, first_active_target, identity_anchor="first-active-finding"
    )
    second_active = complete_scan(
        state_dir, second_active_target, identity_anchor="second-active-finding"
    )

    first_page = run_workbench(state_dir, "list-global-findings", "--limit", "1")
    second_page = run_workbench(state_dir, "list-global-findings", "--limit", "1", "--offset", "1")
    third_page = run_workbench(state_dir, "list-global-findings", "--limit", "1", "--offset", "2")

    assert first_page["nextOffset"] == 1
    assert second_page["nextOffset"] == 2
    assert third_page["nextOffset"] is None
    assert {
        first_page["findings"][0]["scanId"],
        second_page["findings"][0]["scanId"],
        third_page["findings"][0]["scanId"],
    } == {
        historical["scanId"],
        first_active["scanId"],
        second_active["scanId"],
    }


def test_global_findings_keep_latest_occurrence_and_stable_target_identity(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    first_target = tmp_path / "first-repo"
    second_target = tmp_path / "second-repo"
    first_target.mkdir()
    (first_target / "docs").mkdir()
    second_target.mkdir()

    first_target_id = stable_target_id(first_target)
    second_target_id = stable_target_id(second_target)
    older_first = complete_scan(state_dir, first_target, identity_anchor="shared-finding")
    run_workbench(
        state_dir,
        "set-finding-triage",
        "--occurrence-id",
        str(older_first["findings"][0]["occurrenceId"]),
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Fixture close decision.",
    )
    latest_first = complete_scan(state_dir, first_target, identity_anchor="shared-finding")
    distinct_first = complete_scan(
        state_dir,
        first_target,
        identity_anchor="distinct-finding",
        include_paths=["docs"],
        relative_path="docs/extract.py",
    )
    latest_second = complete_scan(state_dir, second_target, identity_anchor="shared-finding")
    latest_first_occurrence = str(latest_first["findings"][0]["occurrenceId"])
    distinct_first_occurrence = str(distinct_first["findings"][0]["occurrenceId"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET updated_at = ? WHERE id = ?",
            ("2000-01-01T00:00:00Z", distinct_first["scanId"]),
        )
        connection.execute(
            """
            INSERT INTO finding_locations (
                occurrence_id, relative_path, start_line, end_line, role, sort_order
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (latest_first_occurrence, "src/control.py", 10, 12, "root_control", 1),
        )
    run_workbench(
        state_dir,
        "set-finding-triage",
        "--occurrence-id",
        distinct_first_occurrence,
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Fixture close decision.",
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        distinct_triage_updated_at = connection.execute(
            "SELECT updated_at FROM finding_triage WHERE occurrence_id = ?",
            (distinct_first_occurrence,),
        ).fetchone()[0]

    first_page = run_workbench(state_dir, "list-global-findings", "--limit", "1")
    second_page = run_workbench(state_dir, "list-global-findings", "--offset", "1", "--limit", "20")
    assert first_page["limit"] == 1
    assert first_page["nextOffset"] == 1
    assert first_page["offset"] == 0
    assert second_page["nextOffset"] is None
    findings = first_page["findings"] + second_page["findings"]
    findings_by_identity = {
        (finding["targetId"], finding["findingId"]): finding for finding in findings
    }
    first = findings_by_identity[(first_target_id, str(latest_first["findings"][0]["findingId"]))]
    distinct = findings_by_identity[
        (first_target_id, str(distinct_first["findings"][0]["findingId"]))
    ]
    second = findings_by_identity[
        (second_target_id, str(latest_second["findings"][0]["findingId"]))
    ]

    assert len(findings) == 3
    assert first["scanId"] == latest_first["scanId"]
    assert first["occurrenceId"] == latest_first_occurrence
    assert first["occurrenceCount"] == 2
    assert first["status"] == "closed"
    assert first["targetPath"] == str(first_target.resolve())
    assert first["locationPath"] == "src/control.py"
    assert distinct["scanId"] == distinct_first["scanId"]
    assert distinct["status"] == "closed"
    assert distinct["updatedAt"] == distinct_triage_updated_at
    assert second["scanId"] == latest_second["scanId"]
    assert second["occurrenceCount"] == 1
    assert second["status"] == "open"


def test_repository_index_reports_latest_scan_open_findings_and_missing_checkout(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    first_target = tmp_path / "first-repo"
    second_target = tmp_path / "second-repo"
    first_target.mkdir()
    (first_target / "docs").mkdir()
    second_target.mkdir()
    first_target_id = stable_target_id(first_target)
    second_target_id = stable_target_id(second_target)
    older_first = complete_scan(state_dir, first_target, identity_anchor="first-finding")
    run_workbench(
        state_dir,
        "set-finding-triage",
        "--occurrence-id",
        str(older_first["findings"][0]["occurrenceId"]),
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Fixture close decision.",
    )
    running_workspace = create_saved_workspace(state_dir, first_target)
    older_running = run_workbench(
        state_dir, "start-scan", "--workspace-id", str(running_workspace["id"])
    )
    complete_scan(state_dir, first_target, identity_anchor="first-finding")
    distinct_first = complete_scan(
        state_dir,
        first_target,
        identity_anchor="distinct-finding",
        include_paths=["docs"],
        relative_path="docs/extract.py",
    )
    latest_second = complete_scan(state_dir, second_target, identity_anchor="second-finding")
    run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        str(older_running["results"]["scanId"]),
        "--phase",
        "discovery",
    )
    second_target.rename(tmp_path / "moved-second-repo")

    repositories = run_workbench(state_dir, "list-repositories")["repositories"]
    repositories_by_target = {repository["targetId"]: repository for repository in repositories}

    first = repositories_by_target[first_target_id]
    second = repositories_by_target[second_target_id]
    assert first["checkoutAvailable"] is True
    assert first["latestScan"]["scanId"] == distinct_first["scanId"]
    assert first["openFindingsCount"] == 1
    assert first["scanCount"] == 4
    assert second["checkoutAvailable"] is False
    assert second["latestScan"]["scanId"] == latest_second["scanId"]
    assert second["openFindingsCount"] == 1
    assert second["scanCount"] == 1
