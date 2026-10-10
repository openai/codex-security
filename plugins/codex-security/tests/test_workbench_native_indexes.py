from __future__ import annotations

import json
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest
from workbench_test_support import (
    create_saved_workspace,
    initialize_git_repository,
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
    completeness: str = "complete",
    finding: bool = True,
    include_paths: list[str] | None = None,
    relative_path: str = "src/extract.py",
) -> dict[str, object]:
    workspace = create_saved_workspace(state_dir, target)
    if include_paths is not None:
        workspace = save_workspace(
            state_dir, str(workspace["id"]), str(target), include_paths[0], "standard"
        )
    started = start_delivered_scan(state_dir, "--workspace-id", str(workspace["id"]))
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
    return scan_command(state_dir, "complete-scan", scan_id)["scan"]


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
    older_running = start_delivered_scan(state_dir, "--workspace-id", str(running_workspace["id"]))
    complete_scan(state_dir, first_target, identity_anchor="first-finding")
    distinct_first = complete_scan(
        state_dir,
        first_target,
        identity_anchor="distinct-finding",
        include_paths=["docs"],
        relative_path="docs/extract.py",
    )
    latest_second = complete_scan(state_dir, second_target, identity_anchor="second-finding")
    update_progress(state_dir, str(older_running["results"]["scanId"]), "--phase", "discovery")
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


@pytest.mark.parametrize("legacy", (False, True))
@pytest.mark.parametrize("same_target", (False, True))
def test_native_completion_keeps_same_target_legacy_triage_without_matching(
    tmp_path: Path, legacy: bool, same_target: bool
) -> None:
    from test_workbench_scan_history import create_cli_scan
    from workbench_test_support import initialize_git_repository

    state = tmp_path / "state"
    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    first = create_cli_scan(
        state,
        tmp_path / "results",
        repository,
        identity_anchor="same-stable-finding",
        target_revision=revision,
    )
    first = run_workbench(state, "get-scan", "--scan-id", first["scanId"])["scan"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT repository_generation FROM scans WHERE id = ?", (first["scanId"],)
            ).fetchone()[0]
            is not None
        )
        if legacy:
            connection.execute(
                "UPDATE scans SET repository_generation = NULL WHERE id = ?",
                (first["scanId"],),
            )
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        str(first["findings"][0]["occurrenceId"]),
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Synthetic checked guard.",
    )
    next_target = repository
    if not same_target:
        next_target = tmp_path / "other"
        revision = initialize_git_repository(next_target)
    create_cli_scan(
        state,
        tmp_path / "results",
        next_target,
        identity_anchor="same-stable-finding",
        target_revision=revision,
    )
    findings = run_workbench(state, "list-global-findings")["findings"]
    assert len(findings) == (1 if same_target else 2)
    current = next(row for row in findings if row["targetId"] == stable_target_id(next_target))
    assert current["status"] == ("closed" if same_target else "open")
    assert current["occurrenceCount"] == (2 if same_target else 1)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scan_comparison_matches").fetchone() == (0,)


@pytest.mark.parametrize("saved_comparison", [False, True])
def test_legacy_linked_comparison_keeps_unbound_triage_target_local(
    tmp_path: Path, saved_comparison: bool
) -> None:
    from test_workbench_scan_history import confirmed_match, create_cli_scan, save_scan_matches

    state = tmp_path / "state"
    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    linked = tmp_path / "linked"
    subprocess.run(
        ["git", "-C", str(repository), "worktree", "add", "-q", "--detach", str(linked)],
        check=True,
    )
    first = create_cli_scan(state, tmp_path / "results", repository, target_revision=revision)
    later = create_cli_scan(state, tmp_path / "results", linked, target_revision=revision)
    first_finding = run_workbench(state, "get-scan", "--scan-id", first["scanId"])["scan"][
        "findings"
    ][0]
    later_finding = run_workbench(state, "get-scan", "--scan-id", later["scanId"])["scan"][
        "findings"
    ][0]
    assert first_finding["findingId"] != later_finding["findingId"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET repository_generation=NULL WHERE id IN (?,?)",
            (first["scanId"], later["scanId"]),
        )
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        first_finding["occurrenceId"],
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Synthetic checked guard.",
    )
    if saved_comparison:
        match = save_scan_matches(
            state,
            first,
            later,
            confirmed_match(first_finding["occurrenceId"], later_finding["occurrenceId"]),
        )
        assert match["comparable"] is True
    create_cli_scan(
        state, tmp_path / "results", repository, target_revision=revision, finding=False
    )
    create_cli_scan(state, tmp_path / "results", linked, target_revision=revision, finding=False)
    global_findings = run_workbench(state, "list-global-findings")["findings"]
    scoped_findings = run_workbench(state, "list-global-findings", "--repository", str(linked))[
        "findings"
    ]
    for findings in (global_findings, scoped_findings):
        finding = next(row for row in findings if row["findingId"] == later_finding["findingId"])
        assert finding["status"] == "open"


@pytest.mark.parametrize("legacy_first", [False, True])
@pytest.mark.parametrize("saved_current_match", [False, True])
def test_sealed_legacy_recurrence_match_keeps_linked_scope_status(
    tmp_path, monkeypatch, legacy_first, saved_current_match
):
    import test_workbench_scan_history as producer

    state = tmp_path / "state"
    repository = tmp_path / "repository"
    linked = tmp_path / "linked"
    revision = initialize_git_repository(repository)
    subprocess.run(
        ["git", "-C", str(repository), "worktree", "add", "-q", "--detach", str(linked)], check=True
    )
    original_write = producer.write_completed_contract

    def write_current_completion(scan_dir, scan_id, target, **values):
        original_write(scan_dir, scan_id, target, **values)
        p = scan_dir / "scan-manifest.json"
        manifest = json.loads(p.read_text())
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            started_at = connection.execute(
                "SELECT started_at FROM scans WHERE id=?", (scan_id,)
            ).fetchone()[0]
        manifest["scan"]["startedAt"] = started_at
        manifest["scan"]["completedAt"] = (
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        )
        p.write_text(json.dumps(manifest))

    monkeypatch.setattr(producer, "write_completed_contract", write_current_completion)
    first = producer.create_cli_scan(
        state, tmp_path / "results", repository, target_revision=revision
    )
    first_finding = run_workbench(state, "get-scan", "--scan-id", first["scanId"])["scan"][
        "findings"
    ][0]
    if legacy_first:
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE scans SET repository_generation=NULL WHERE id=?", (first["scanId"],)
            )
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        first_finding["occurrenceId"],
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Synthetic checked guard.",
    )
    current = producer.create_cli_scan(
        state, tmp_path / "results", repository, target_revision=revision
    )
    current_finding = run_workbench(state, "get-scan", "--scan-id", current["scanId"])["scan"][
        "findings"
    ][0]
    later = producer.create_cli_scan(state, tmp_path / "results", linked, target_revision=revision)
    later_finding = run_workbench(state, "get-scan", "--scan-id", later["scanId"])["scan"][
        "findings"
    ][0]
    assert first_finding["findingId"] == current_finding["findingId"]
    assert first_finding["findingId"] != later_finding["findingId"]
    assert current_finding["triage"]["status"] == later_finding["triage"]["status"] == "open"
    if saved_current_match:
        result = producer.save_scan_matches(
            state,
            current,
            later,
            producer.confirmed_match(
                current_finding["occurrenceId"], later_finding["occurrenceId"]
            ),
        )
        assert result["comparable"] is True
    global_rows = run_workbench(state, "list-global-findings")["findings"]
    scoped_rows = run_workbench(state, "list-global-findings", "--repository", str(linked))[
        "findings"
    ]
    open_rows = run_workbench(state, "list-global-findings", "--status", "open")["findings"]
    global_b = next(
        row for row in global_rows if later_finding["findingId"] in row["matchedFindingIds"]
    )
    scoped_b = next(
        row for row in scoped_rows if later_finding["findingId"] in row["matchedFindingIds"]
    )
    local_rows = run_workbench(state, "list-global-findings", "--repository", str(repository))[
        "findings"
    ]
    local_current = next(row for row in local_rows if current["scanId"] in row["knownScanIds"])
    assert local_current["status"] == "closed"
    expected = "closed" if saved_current_match and not legacy_first else "open"
    assert scoped_b["status"] == expected
    assert global_b["status"] == expected
    assert any(later_finding["findingId"] in row["matchedFindingIds"] for row in open_rows) == (
        expected == "open"
    )


@pytest.mark.parametrize("saved_legacy_alias", [False, True])
@pytest.mark.parametrize("saved_current_match", [False, True])
def test_saved_legacy_alias_survives_current_linked_match(
    tmp_path, monkeypatch, saved_legacy_alias, saved_current_match
):
    import test_workbench_scan_history as producer

    state = tmp_path / "state"
    repository = tmp_path / "repository"
    linked = tmp_path / "linked"
    revision = initialize_git_repository(repository)
    subprocess.run(
        ["git", "-C", str(repository), "worktree", "add", "-q", "--detach", str(linked)], check=True
    )
    original_write = producer.write_completed_contract

    def write_current_completion(scan_dir, scan_id, target, **values):
        original_write(scan_dir, scan_id, target, **values)
        p = scan_dir / "scan-manifest.json"
        manifest = json.loads(p.read_text())
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            started_at = connection.execute(
                "SELECT started_at FROM scans WHERE id=?", (scan_id,)
            ).fetchone()[0]
        manifest["scan"]["startedAt"] = started_at
        manifest["scan"]["completedAt"] = (
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        )
        p.write_text(json.dumps(manifest))

    monkeypatch.setattr(producer, "write_completed_contract", write_current_completion)
    first = producer.create_cli_scan(
        state,
        tmp_path / "results",
        repository,
        target_revision=revision,
        identity_anchor="synthetic-first-control",
    )
    first_finding = run_workbench(state, "get-scan", "--scan-id", first["scanId"])["scan"][
        "findings"
    ][0]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET repository_generation=NULL WHERE id=?", (first["scanId"],)
        )
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        first_finding["occurrenceId"],
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Synthetic checked guard.",
    )
    second = producer.create_cli_scan(
        state,
        tmp_path / "results",
        repository,
        target_revision=revision,
        identity_anchor="synthetic-second-control",
    )
    second_finding = run_workbench(state, "get-scan", "--scan-id", second["scanId"])["scan"][
        "findings"
    ][0]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET repository_generation=NULL WHERE id=?", (second["scanId"],)
        )
    assert first_finding["findingId"] != second_finding["findingId"]
    if saved_legacy_alias:
        result = producer.save_scan_matches(
            state,
            first,
            second,
            producer.confirmed_match(first_finding["occurrenceId"], second_finding["occurrenceId"]),
        )
        assert result["comparable"] is True
    current = producer.create_cli_scan(
        state,
        tmp_path / "results",
        repository,
        target_revision=revision,
        identity_anchor="synthetic-second-control",
    )
    current_finding = run_workbench(state, "get-scan", "--scan-id", current["scanId"])["scan"][
        "findings"
    ][0]
    later = producer.create_cli_scan(
        state,
        tmp_path / "results",
        linked,
        target_revision=revision,
        identity_anchor="synthetic-second-control",
    )
    later_finding = run_workbench(state, "get-scan", "--scan-id", later["scanId"])["scan"][
        "findings"
    ][0]
    assert second_finding["findingId"] == current_finding["findingId"]
    assert current_finding["findingId"] != later_finding["findingId"]
    if saved_current_match:
        result = producer.save_scan_matches(
            state,
            current,
            later,
            producer.confirmed_match(
                current_finding["occurrenceId"], later_finding["occurrenceId"]
            ),
        )
        assert result["comparable"] is True
    global_rows = run_workbench(state, "list-global-findings")["findings"]
    scoped_rows = run_workbench(state, "list-global-findings", "--repository", str(repository))[
        "findings"
    ]
    linked_rows = run_workbench(state, "list-global-findings", "--repository", str(linked))[
        "findings"
    ]
    for rows in [global_rows, scoped_rows]:
        first_row = next(row for row in rows if first["scanId"] in row["knownScanIds"])
        second_row = next(row for row in rows if second["scanId"] in row["knownScanIds"])
        assert first_row["status"] == "closed"
        assert second_row["status"] == ("closed" if saved_legacy_alias else "open")
        assert (first["scanId"] in second_row["knownScanIds"]) == saved_legacy_alias
    for rows in [global_rows, linked_rows]:
        linked_row = next(row for row in rows if later["scanId"] in row["knownScanIds"])
        assert linked_row["status"] == "open"


def test_overlapping_scans_mark_findings_present_in_latest_started_scan(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "repo"
    target.mkdir()
    first = complete_scan(state_dir, target, identity_anchor="recurring-finding")
    second = complete_scan(state_dir, target, identity_anchor="recurring-finding")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET started_at = ? WHERE id = ?",
            ("2026-01-01T00:00:00Z", first["scanId"]),
        )
        connection.execute(
            "UPDATE scans SET started_at = ? WHERE id = ?",
            ("2026-01-02T00:00:00Z", second["scanId"]),
        )
        connection.execute(
            "UPDATE finding_occurrences SET created_at = ? WHERE scan_id = ?",
            ("2026-01-04T00:00:00Z", first["scanId"]),
        )
        connection.execute(
            "UPDATE finding_occurrences SET created_at = ? WHERE scan_id = ?",
            ("2026-01-03T00:00:00Z", second["scanId"]),
        )
    finding = run_workbench(state_dir, "list-global-findings")["findings"][0]
    assert finding["confirmedInLatestScan"] is True
    assert set(finding["knownScanIds"]) == {first["scanId"], second["scanId"]}


@pytest.mark.parametrize("query", ["strasse", "STRAẞE", "éclair", "ÉCLAIR"])
def test_scan_and_finding_search_casefold_unicode(tmp_path: Path, query: str) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "Straße ÉCLAIR"
    target.mkdir()
    first = complete_scan(state_dir, target, identity_anchor="first-finding")
    complete_scan(state_dir, target, identity_anchor="second-finding")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute("UPDATE finding_occurrences SET title = ?", ("Straße ÉCLAIR",))
    page = run_workbench(state_dir, "list-scans", "--query", query, "--limit", "1")
    assert len(page["scans"]) == 1
    assert page["nextOffset"] == 1
    next_page = run_workbench(
        state_dir, "list-scans", "--query", query, "--limit", "1", "--offset", "1"
    )
    assert len(next_page["scans"]) == 1
    findings = run_workbench(
        state_dir, "list-findings", "--scan-id", str(first["scanId"]), "--query", query
    )
    assert len(findings["findingsPage"]["findings"]) == 1
