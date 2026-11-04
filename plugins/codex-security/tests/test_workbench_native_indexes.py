from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from workbench_test_support import (
    create_saved_workspace,
    create_workspace,
    run_workbench,
    save_workspace,
    scan_command,
    set_triage,
    stable_target_id,
    start_delivered_scan,
    update_progress,
    write_completed_contract,
)


def complete_scan(
    state_dir: Path,
    target: Path,
    *,
    identity_anchor: str,
    follow_up: bool = False,
    finding: bool = True,
    include_paths: list[str] | None = None,
    relative_path: str = "src/extract.py",
) -> dict[str, object]:
    workspace = create_saved_workspace(state_dir, target)
    if include_paths is not None:
        workspace = save_workspace(
            state_dir, str(workspace["id"]), str(target), include_paths[0], "standard"
        )
    started = start_delivered_scan(state_dir, str(workspace["id"]))
    scan_id = str(started["scanId"])
    scan_dir = Path(str(started["scanDir"]))
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
    if follow_up:
        coverage_path = scan_dir / "coverage.json"
        coverage = json.loads(coverage_path.read_text())
        coverage["surfaces"][0]["disposition"] = "needs_follow_up"
        coverage["deferred"] = [
            {"id": "unreviewed-path", "reason": "Review incomplete", "paths": ["src/extract.py"]}
        ]
        coverage_path.write_text(json.dumps(coverage))
    return scan_command(state_dir, "complete-scan", scan_id)["scan"]


@pytest.mark.parametrize(
    ("follow_up", "include_paths"),
    [(False, None), (True, None), (False, ["docs"])],
)
def test_later_scans_preserve_global_findings_and_repository_counts(
    tmp_path: Path, follow_up: bool, include_paths: list[str] | None
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
        follow_up=follow_up,
        finding=False,
        include_paths=include_paths,
    )

    page = run_workbench(state_dir, "list-global-findings", "--limit", "1")
    assert page["nextOffset"] is None
    (finding,) = page["findings"]
    assert finding["scanId"] == original["scanId"]
    assert finding["status"] == "open"
    assert (
        run_workbench(state_dir, "list-repositories")["repositories"][0]["openFindingsCount"] == 1
    )


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
    set_triage(
        state_dir,
        str(older_first["findings"][0]["occurrenceId"]),
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
    set_triage(
        state_dir,
        distinct_first_occurrence,
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

    pages = [
        run_workbench(state_dir, "list-global-findings", "--limit", "1", "--offset", str(offset))
        for offset in range(3)
    ]
    assert [(page["offset"], page["limit"], page["nextOffset"]) for page in pages] == [
        (0, 1, 1),
        (1, 1, 2),
        (2, 1, None),
    ]
    assert all(len(page["findings"]) == 1 for page in pages)
    findings = [page["findings"][0] for page in pages]
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


@pytest.mark.parametrize(
    ("target_path", "available"), [(".", False), ("~/repo", True), ("~/missing/../repo", True)]
)
def test_repository_index_probes_draft_checkout(
    tmp_path: Path, monkeypatch, target_path: str, available: bool
) -> None:
    state_dir = tmp_path / "state"
    (tmp_path / "repo").mkdir()
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    create_workspace(
        state_dir,
        "20000000-0000-4000-8000-000000000000",
        "--target-path",
        target_path,
        "--scope",
        "missing-directory",
    )

    (repository,) = run_workbench(state_dir, "list-repositories")["repositories"]
    assert repository["targetPath"] == target_path
    assert repository["checkoutAvailable"] is available


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
    create_workspace(
        state_dir, "20000000-0000-4000-8000-000000000000", "--target-path", str(first_target)
    )
    (unscanned,) = run_workbench(state_dir, "list-repositories", "--status", "not_scanned")[
        "repositories"
    ]
    assert unscanned == {
        "checkoutAvailable": True,
        "displayName": first_target.name,
        "latestScan": None,
        "openFindingsCount": 0,
        "scanCount": 0,
        "targetId": first_target_id,
        "targetPath": str(first_target.resolve()),
    }
    for status in ("scanned", "open_findings"):
        assert (
            run_workbench(state_dir, "list-repositories", "--status", status)["repositories"] == []
        )
    older_first = complete_scan(state_dir, first_target, identity_anchor="first-finding")
    assert (
        run_workbench(state_dir, "list-repositories", "--status", "not_scanned")["repositories"]
        == []
    )
    set_triage(
        state_dir,
        str(older_first["findings"][0]["occurrenceId"]),
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Fixture close decision.",
    )
    running_workspace = create_saved_workspace(state_dir, first_target)
    older_running = start_delivered_scan(state_dir, str(running_workspace["id"]))
    complete_scan(state_dir, first_target, identity_anchor="first-finding")
    distinct_first = complete_scan(
        state_dir,
        first_target,
        identity_anchor="distinct-finding",
        include_paths=["docs"],
        relative_path="docs/extract.py",
    )
    latest_second = complete_scan(state_dir, second_target, identity_anchor="second-finding")
    update_progress(state_dir, str(older_running["scanId"]), "--phase", "discovery")
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


def test_scan_and_finding_search_casefold_unicode(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "Straße ÉCLAIR"
    target.mkdir()
    first = complete_scan(state_dir, target, identity_anchor="first-finding")
    second = complete_scan(state_dir, target, identity_anchor="second-finding")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute("UPDATE finding_occurrences SET title = ?", ("Straße ÉCLAIR",))
    for query in ("strasse", "STRAẞE", "éclair", "ÉCLAIR"):
        page = run_workbench(state_dir, "list-scans", "--query", query, "--limit", "1")
        assert page["nextOffset"] == 1, query
        next_page = run_workbench(
            state_dir, "list-scans", "--query", query, "--limit", "1", "--offset", "1"
        )
        assert next_page["nextOffset"] is None, query
        (first_match,) = page["scans"]
        (second_match,) = next_page["scans"]
        assert {first_match["scanId"], second_match["scanId"]} == {
            first["scanId"],
            second["scanId"],
        }, query
        findings = run_workbench(
            state_dir, "list-findings", "--scan-id", str(first["scanId"]), "--query", query
        )
        assert len(findings["findingsPage"]["findings"]) == 1, query
