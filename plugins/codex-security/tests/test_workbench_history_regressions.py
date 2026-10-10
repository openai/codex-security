from __future__ import annotations

import argparse
import csv
import hashlib
import json
import runpy
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from test_workbench_scan_history import (
    FINALIZER,
    SCRIPT,
    compare_scan_pair,
    confirmed_match,
    create_cli_scan,
    run_workbench,
    save_scan_matches,
)
from workbench_test_support import initialize_git_repository, write_completed_contract


@pytest.fixture
def history(tmp_path: Path):
    repository = tmp_path / "repository"
    repository.mkdir()
    return tmp_path / "state", tmp_path / "scans", repository


@pytest.fixture
def linked_history(history):
    state, root, parent = history
    repository = parent / "checkout"
    revision = initialize_git_repository(repository)
    linked = repository.with_name("linked-worktree")
    subprocess.run(
        ["git", "-C", str(repository), "worktree", "add", "-q", "--detach", str(linked)],
        check=True,
    )
    return state, root, repository, linked, revision


def test_legacy_descendant_scans_stay_inside_the_current_checkout_owner(history) -> None:
    state, root, repository = history
    child = repository / "nested"
    child.mkdir()
    previous = create_cli_scan(state, root, repository)
    legacy = create_cli_scan(state, root, child)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET target_id = NULL, target_device = NULL, target_inode = NULL "
            "WHERE id = ?",
            (legacy["scanId"],),
        )
        connection.execute(
            "UPDATE workspaces SET target_id = NULL WHERE target_path = ?", (str(child),)
        )
        connection.execute("DELETE FROM security_targets WHERE current_path = ?", (str(child),))
    repository.rename(repository.with_name("previous-checkout"))
    child.mkdir(parents=True)
    current = create_cli_scan(state, root, repository)

    for requested in (repository, child):
        scans = run_workbench(state, "list-scans", "--repository", str(requested))["scans"]
        assert [scan["scanId"] for scan in scans] == [current["scanId"]]
    for scan in (previous, legacy):
        result = run_workbench(state, "get-scan", "--scan-id", scan["scanId"], check=False)
        assert result["returncode"] != 0
        assert "checkout owner" in result["stderr"]


@pytest.mark.parametrize("checkout", ["missing", "replaced", "previous-epoch-missing"])
def test_saved_comparisons_use_the_current_recorded_ownership_epoch(history, checkout) -> None:
    state, root, repository = history
    before = create_cli_scan(state, root, repository, identity_anchor="before")
    after = create_cli_scan(state, root, repository, identity_anchor="after")
    occurrences = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0][
            "occurrenceId"
        ]
        for scan in (before, after)
    ]
    saved = save_scan_matches(state, before, after, confirmed_match(*occurrences))
    repository.rename(repository.with_name("offline-checkout"))
    if checkout != "missing":
        repository.mkdir()
    if checkout == "previous-epoch-missing":
        create_cli_scan(state, root, repository)
        repository.rename(repository.with_name("newer-offline-checkout"))

    if checkout == "missing":
        assert compare_scan_pair(state, before, after) == saved
    else:
        result = compare_scan_pair(state, before, after, check=False)
        assert result["returncode"] != 0
        assert "same repository target" in result["stderr"]


def test_explicit_reopen_overrides_a_matched_occurrences_newer_closure(history) -> None:
    state, root, repository = history
    before = create_cli_scan(state, root, repository, identity_anchor="before")
    after = create_cli_scan(state, root, repository, identity_anchor="after")
    occurrences = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0][
            "occurrenceId"
        ]
        for scan in (before, after)
    ]
    run_workbench(
        state, "set-finding-triage", "--occurrence-id", occurrences[0], "--status", "open"
    )
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        occurrences[1],
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Synthetic triage decision.",
    )
    save_scan_matches(state, before, after, confirmed_match(*occurrences))
    assert (
        run_workbench(state, "get-finding", "--occurrence-id", occurrences[0])["scan"]["findings"][
            0
        ]["triage"]["status"]
        == "closed"
    )

    run_workbench(
        state, "set-finding-triage", "--occurrence-id", occurrences[0], "--status", "open"
    )
    for occurrence in occurrences:
        finding = run_workbench(state, "get-finding", "--occurrence-id", occurrence)["scan"][
            "findings"
        ][0]
        assert finding["triage"]["status"] == "open"
        assert finding["triage"].get("closeReason") is None
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM finding_decisions WHERE occurrence_id = ?", (occurrences[0],)
            ).fetchone()[0]
            == 2
        )


def test_finding_pages_honor_larger_limits(history) -> None:
    state, root, repository = history
    scan = create_cli_scan(
        state,
        root,
        repository,
        identity_anchor="first",
        extra_anchors=tuple(f"additional-{index}" for index in range(24)),
    )
    for arguments in (
        ("list-findings", "--scan-id", scan["scanId"]),
        ("list-global-findings", "--repository", str(repository)),
        ("list-global-findings",),
    ):
        result = run_workbench(state, *arguments, "--limit", "100")
        page = result.get("findingsPage", result)
        assert len(page["findings"]) == 25
        assert page["limit"] == 100
        assert page["nextOffset"] is None


@pytest.mark.parametrize("reason", ["already_fixed", "false_positive", "wont_fix"])
def test_matched_triage_agrees_in_details_comparisons_and_csv(history, reason) -> None:
    state, root, repository = history
    before = create_cli_scan(state, root, repository, identity_anchor="before")
    after = create_cli_scan(
        state, root, repository, identity_anchor="after", extra_anchors=("another-path",)
    )
    previous = run_workbench(state, "get-scan", "--scan-id", before["scanId"])["scan"]["findings"][
        0
    ]
    current = run_workbench(state, "get-scan", "--scan-id", after["scanId"])["scan"]["findings"]
    save_scan_matches(
        state,
        before,
        after,
        confirmed_match(previous["occurrenceId"], [row["occurrenceId"] for row in current]),
    )
    for status in ("closed", "open"):
        run_workbench(
            state,
            "set-finding-triage",
            "--occurrence-id",
            previous["occurrenceId"],
            "--status",
            status,
            *(
                ["--close-reason", reason, "--note", "Synthetic triage."]
                if status == "closed"
                else []
            ),
        )
        shown = run_workbench(state, "get-scan", "--scan-id", after["scanId"])["scan"]["findings"]
        assert {row["status"] for row in shown} == {status}
        comparison = compare_scan_pair(state, before, after)
        assert comparison["findings"][0]["triage"] == {
            "status": status,
            "closeReason": reason if status == "closed" else None,
        }
        if status == "closed":
            assert comparison["summary"]["reopened"] == 0
        exported = run_workbench(
            state, "export-findings", "--scan-id", after["scanId"], "--format", "csv"
        )["export"]
        with Path(exported["path"]).open(newline="") as source:
            rows = list(csv.DictReader(source))
        assert {row["status"] for row in rows} == {status}
        assert {row["close_reason"] for row in rows} == {reason if status == "closed" else ""}


@pytest.mark.parametrize("reason", ["already_fixed", "false_positive", "wont_fix"])
def test_explicit_triage_updates_every_matched_worktree_occurrence(linked_history, reason) -> None:
    state, root, repository, linked, revision = linked_history
    before = create_cli_scan(state, root, repository, target_revision=revision)
    after = create_cli_scan(state, root, linked, target_revision=revision)
    occurrences = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0][
            "occurrenceId"
        ]
        for scan in (before, after)
    ]
    save_scan_matches(state, before, after, confirmed_match(*occurrences))
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        targets = [row[0] for row in connection.execute("SELECT id FROM security_targets")]
    for status in ("closed", "open"):
        run_workbench(
            state,
            "set-finding-triage",
            "--occurrence-id",
            occurrences[0],
            "--status",
            status,
            *(
                ["--close-reason", reason, "--note", "Synthetic triage."]
                if status == "closed"
                else []
            ),
        )
        scopes = [
            ([], 2),
            (["--repository", str(repository)], 1),
            (["--repository", str(linked)], 1),
            *((["--target-id", target], 1) for target in targets),
        ]
        for scope, count in scopes:
            findings = run_workbench(state, "list-global-findings", *scope)["findings"]
            assert len(findings) == count
            assert {finding["status"] for finding in findings} == {status}


@pytest.mark.parametrize("checkout", ["missing", "replaced", "previous-epoch-missing"])
def test_saved_linked_history_keeps_only_current_checkout_owners(linked_history, checkout) -> None:
    state, root, repository, linked, revision = linked_history
    before = create_cli_scan(state, root, repository, target_revision=revision)
    after = create_cli_scan(state, root, linked, target_revision=revision)
    occurrences = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0][
            "occurrenceId"
        ]
        for scan in (before, after)
    ]
    save_scan_matches(state, before, after, confirmed_match(*occurrences))
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        occurrences[0],
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Synthetic linked triage.",
    )
    linked.rename(linked.with_name("offline-worktree"))
    if checkout != "missing":
        linked.mkdir()
    if checkout == "previous-epoch-missing":
        create_cli_scan(state, root, linked)
        linked.rename(linked.with_name("newer-offline-worktree"))

    if checkout == "missing":
        assert compare_scan_pair(state, before, after)["summary"]["persisting"] == 1
        for occurrence, scan in zip(occurrences, (before, after), strict=True):
            detail = run_workbench(state, "get-finding", "--occurrence-id", occurrence)["scan"][
                "findings"
            ][0]
            assert detail["occurrenceCount"] == 2
            assert detail["knownScanIds"] == [before["scanId"], after["scanId"]]
            assert detail["status"] == "closed"
            listed = run_workbench(state, "list-findings", "--scan-id", scan["scanId"])[
                "findingsPage"
            ]["findings"][0]
            assert listed["occurrenceCount"] == 2
    else:
        rejected = run_workbench(
            state, "get-finding", "--occurrence-id", occurrences[1], check=False
        )
        assert rejected["returncode"] != 0
        assert "checkout owner" in rejected["stderr"]
        detail = run_workbench(state, "get-finding", "--occurrence-id", occurrences[0])["scan"][
            "findings"
        ][0]
        assert "matches" not in detail
        assert "occurrenceCount" not in detail


@pytest.mark.parametrize("command", ["get-finding", "get-scan", "list-scans", "database-info"])
def test_saved_finding_reader_does_not_take_writer_admission(history, command) -> None:
    state, root, repository = history
    scan = create_cli_scan(state, root, repository)
    occurrence = run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][
        0
    ]["occurrenceId"]
    arguments = (
        ["--occurrence-id", occurrence]
        if command == "get-finding"
        else ["--scan-id", scan["scanId"]]
        if command == "get-scan"
        else []
    )
    with sqlite3.connect(state / "workbench.sqlite3") as writer:
        writer.execute("BEGIN IMMEDIATE")
        result = run_workbench(state, command, *arguments, check=False)
        assert result["returncode"] == 0, result["stderr"]
        assert writer.in_transaction


def test_uncertain_match_does_not_split_later_stable_finding_identity(history) -> None:
    state, root, repository = history
    before = create_cli_scan(state, root, repository, identity_anchor="stable-anchor")
    independent = create_cli_scan(state, root, repository, identity_anchor="independent-anchor")
    later = create_cli_scan(state, root, repository, identity_anchor="stable-anchor")
    rows = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0]
        for scan in (before, independent, later)
    ]
    save_scan_matches(
        state,
        before,
        independent,
        uncertain=(
            {
                "beforeOccurrenceId": rows[0]["occurrenceId"],
                "afterOccurrenceId": rows[1]["occurrenceId"],
                "reason": "Synthetic independent root causes.",
            },
        ),
    )
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        rows[0]["occurrenceId"],
        "--status",
        "closed",
        "--close-reason",
        "wont_fix",
        "--note",
        "Synthetic triage decision.",
    )
    assert rows[0]["findingId"] == rows[2]["findingId"]
    findings = run_workbench(state, "list-global-findings", "--include-resolved")["findings"]
    stable = [row for row in findings if row["findingId"] == rows[0]["findingId"]]
    assert len(stable) == 1
    assert stable[0]["occurrenceCount"] == 2
    assert stable[0]["status"] == "closed"


def test_late_worktree_comparison_keeps_index_and_detail_decision_consistent(
    linked_history,
) -> None:
    state, root, repository, linked, revision = linked_history
    before = create_cli_scan(
        state, root, repository, identity_anchor="before", target_revision=revision
    )
    after = create_cli_scan(state, root, linked, identity_anchor="after", target_revision=revision)
    occurrences = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0][
            "occurrenceId"
        ]
        for scan in (before, after)
    ]
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        occurrences[1],
        "--status",
        "closed",
        "--close-reason",
        "wont_fix",
        "--note",
        "Synthetic triage decision.",
    )
    save_scan_matches(state, before, after, confirmed_match(*occurrences))
    assert (
        run_workbench(state, "get-finding", "--occurrence-id", occurrences[0])["scan"]["findings"][
            0
        ]["status"]
        == "closed"
    )
    for scope, count in (
        ([], 2),
        (["--repository", str(repository)], 1),
        (["--repository", str(linked)], 1),
    ):
        findings = run_workbench(state, "list-global-findings", *scope, "--include-resolved")[
            "findings"
        ]
        assert len(findings) == count
        assert {row["status"] for row in findings} == {"closed"}


def test_late_comparison_does_not_reopen_scans_started_before_decision(history) -> None:
    state, root, repository = history
    before = create_cli_scan(state, root, repository, identity_anchor="before")
    after = create_cli_scan(state, root, repository, identity_anchor="after")
    occurrences = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0][
            "occurrenceId"
        ]
        for scan in (before, after)
    ]
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        occurrences[0],
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Synthetic triage decision.",
    )
    save_scan_matches(state, before, after, confirmed_match(*occurrences))
    assert (
        run_workbench(state, "get-finding", "--occurrence-id", occurrences[1])["scan"]["findings"][
            0
        ]["status"]
        == "closed"
    )
    findings = run_workbench(state, "list-global-findings", "--include-resolved")["findings"]
    assert len(findings) == 1
    assert findings[0]["status"] == "closed"


@pytest.mark.parametrize("legacy_order", ["timestamps", "equal-time", "modern-clock-skew"])
def test_legacy_decision_migration_preserves_chronology_and_appends(history, legacy_order) -> None:
    state, root, repository = history
    scans = [create_cli_scan(state, root, repository) for _ in range(2)]
    occurrences = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0][
            "occurrenceId"
        ]
        for scan in scans
    ]
    database = state / "workbench.sqlite3"
    namespace = runpy.run_path(str(SCRIPT), run_name="legacy_decision_history_fixture")
    migration15 = next(sql for version, _, sql in namespace["MIGRATIONS"] if version == 15)
    backfill = next(
        statement
        for statement in namespace["sql_statements"](migration15)
        if statement.startswith("INSERT INTO finding_decisions")
    )
    with sqlite3.connect(database) as connection:
        for column in ("scan_sequence", "decision_sequence"):
            if column in {
                row[1] for row in connection.execute("PRAGMA table_info(finding_decisions)")
            }:
                connection.execute(f"ALTER TABLE finding_decisions DROP COLUMN {column}")
        connection.execute(
            "DELETE FROM schema_migrations WHERE name IN (?, ?)",
            (
                "preserve finding decision append chronology",
                "bind new finding decisions to admitted scans",
            ),
        )
        connection.execute("DELETE FROM finding_decisions")
        connection.execute("DELETE FROM finding_triage")
        # A legacy update can be newer than a row inserted later in the triage table.
        ordered = sorted(occurrences, reverse=True) if legacy_order == "equal-time" else occurrences
        for index, occurrence in enumerate(ordered):
            connection.execute(
                "INSERT INTO finding_triage VALUES (?, ?, ?, ?, ?)",
                (
                    occurrence,
                    "closed" if index == 0 else "open",
                    "false_positive" if index == 0 else None,
                    "Synthetic legacy decision",
                    "2099-10-06T10:00:00Z"
                    if index == 0 or legacy_order == "equal-time"
                    else "2099-10-05T10:00:00Z",
                ),
            )
        connection.execute(backfill)
        if legacy_order == "modern-clock-skew":
            connection.execute(
                "INSERT INTO finding_decisions VALUES ('modern-append', ?, 'open', NULL, 'Synthetic later append', '2000-01-01T00:00:00Z')",
                (ordered[1],),
            )
            connection.execute(
                "UPDATE finding_triage SET status = 'open', close_reason = NULL, updated_at = '2000-01-01T00:00:00Z' WHERE occurrence_id = ?",
                (ordered[1],),
            )
        old_rows = connection.execute(
            "SELECT id, occurrence_id, status, close_reason, note, created_at FROM finding_decisions ORDER BY id"
        ).fetchall()
    run_workbench(state, "database-info")
    result = run_workbench(state, "list-global-findings", "--include-resolved")["findings"]
    assert len(result) == 1
    assert result[0]["status"] == ("open" if legacy_order == "modern-clock-skew" else "closed")
    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT id, occurrence_id, status, close_reason, note, created_at FROM finding_decisions ORDER BY id"
            ).fetchall()
            == old_rows
        )
        before_sequence = connection.execute(
            "SELECT MAX(decision_sequence) FROM finding_decisions"
        ).fetchone()[0]
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        occurrences[0],
        "--status",
        "open",
        "--note",
        "Synthetic reopened decision",
    )
    with sqlite3.connect(database) as connection:
        appended = connection.execute(
            "SELECT status, decision_sequence FROM finding_decisions WHERE decision_sequence > ? ORDER BY decision_sequence",
            (before_sequence,),
        ).fetchall()
    assert appended and all(status == "open" for status, _ in appended)
    assert [sequence for _, sequence in appended] == list(
        range(before_sequence + 1, before_sequence + len(appended) + 1)
    )


def test_stopped_sealed_occurrences_remain_in_complete_scan_history(history) -> None:
    state, root, repository = history
    stopped = create_cli_scan(state, root, repository, complete=False)
    scan_dir = Path(stopped["scanDir"])
    write_completed_contract(scan_dir, stopped["scanId"], repository)
    subprocess.run([sys.executable, str(FINALIZER), "--scan-dir", str(scan_dir)], check=True)
    stopped_context = run_workbench(
        state, "fail-scan", "--scan-id", stopped["scanId"], "--message", "Synthetic interruption"
    )
    stopped_finding = stopped_context["scan"]["findings"][0]
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        stopped_finding["occurrenceId"],
        "--status",
        "closed",
        "--close-reason",
        "wont_fix",
        "--note",
        "Synthetic accepted risk",
    )
    current = create_cli_scan(state, root, repository)
    finding = run_workbench(state, "list-global-findings", "--include-resolved")["findings"][0]
    assert finding["occurrenceCount"] == 2
    assert set(finding["knownScanIds"]) == {stopped["scanId"], current["scanId"]}
    assert finding["status"] == "closed"
    for scan in (stopped, current):
        indexed = run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][
            0
        ]
        assert indexed["occurrenceCount"] == 2
        assert set(indexed["knownScanIds"]) == {stopped["scanId"], current["scanId"]}
        assert indexed["status"] == "closed"


@pytest.mark.parametrize("uncertain", [False, True])
def test_stable_recurrence_keeps_prior_uncertainty_until_later_coverage(history, uncertain) -> None:
    state, root, repository = history
    first = create_cli_scan(state, root, repository, identity_anchor="stable")
    repeated = create_cli_scan(state, root, repository, identity_anchor="stable")
    independent = create_cli_scan(state, root, repository, identity_anchor="independent")
    rows = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0]
        for scan in (first, repeated, independent)
    ]
    assert rows[0]["findingId"] == rows[1]["findingId"]
    if uncertain:
        comparison = save_scan_matches(
            state,
            first,
            independent,
            uncertain=(
                {
                    "beforeOccurrenceId": rows[0]["occurrenceId"],
                    "afterOccurrenceId": rows[2]["occurrenceId"],
                    "reason": "Synthetic comparison remains uncertain.",
                },
            ),
        )
        assert comparison["summary"]["unknown"] == 2
    findings = run_workbench(state, "list-global-findings", "--repository", str(repository))[
        "findings"
    ]
    stable = [row for row in findings if row["findingId"] == rows[0]["findingId"]]
    assert len(stable) == int(uncertain)
    repositories = run_workbench(state, "list-repositories")["repositories"]
    assert repositories[0]["openFindingsCount"] == 1 + int(uncertain)
    create_cli_scan(state, root, repository, finding=False)
    assert (
        run_workbench(state, "list-global-findings", "--repository", str(repository))["findings"]
        == []
    )


@pytest.mark.parametrize("artifact", ["scan-manifest.json", "coverage.json"])
@pytest.mark.parametrize("missing", [False, True])
def test_pruned_coverage_keeps_history_but_tampering_is_rejected(
    history, artifact, missing
) -> None:
    state, root, repository = history
    earlier = create_cli_scan(state, root, repository)
    later = create_cli_scan(state, root, repository, finding=False)
    path = Path(later["scanDir"]) / artifact
    if missing:
        path.unlink()
        findings = run_workbench(state, "list-global-findings")["findings"]
        assert [finding["scanId"] for finding in findings] == [earlier["scanId"]]
    else:
        path.write_text(path.read_text() + "\n")
        result = run_workbench(state, "list-global-findings", check=False)
        assert result["returncode"] != 0
        assert "changed" in result["stderr"]


@pytest.mark.parametrize(
    "selector", ["target", "query", "empty-target", "empty-query", "not-scanned"]
)
def test_selected_repository_ignores_an_unrelated_tampered_scan(history, selector) -> None:
    state, root, repository = history
    selected = create_cli_scan(state, root, repository)
    unrelated = repository.with_name("unrelated")
    unrelated.mkdir()
    create_cli_scan(state, root, unrelated)
    later = create_cli_scan(state, root, unrelated, finding=False)
    manifest = Path(later["scanDir"]) / "scan-manifest.json"
    manifest.write_text(manifest.read_text() + "\n")
    result = run_workbench(
        state,
        "list-repositories",
        *{
            "target": ["--target-id", selected["targetId"]],
            "query": ["--query", str(repository)],
            "empty-target": ["--target-id", "synthetic-no-such-target"],
            "empty-query": ["--query", "synthetic-no-matching-repository"],
            "not-scanned": ["--status", "not_scanned"],
        }[selector],
    )
    if selector in {"target", "query"}:
        assert len(result["repositories"]) == 1
        assert result["repositories"][0]["targetId"] == selected["targetId"]
        assert result["repositories"][0]["openFindingsCount"] == 1
    else:
        assert result["repositories"] == []
    unfiltered = run_workbench(state, "list-repositories", check=False)
    assert unfiltered["returncode"] != 0
    assert "changed after completion" in unfiltered["stderr"]


@pytest.mark.parametrize("close_reason", ["already_fixed", "false_positive"])
def test_clock_rollback_keeps_a_new_decision_until_a_new_scan_is_admitted(
    history, close_reason
) -> None:
    state, root, repository = history
    first = create_cli_scan(state, root, repository)
    occurrence = run_workbench(state, "get-scan", "--scan-id", first["scanId"])["scan"]["findings"][
        0
    ]["occurrenceId"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET started_at = '2099-10-06T10:00:00Z' WHERE id = ?", (first["scanId"],)
        )
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        occurrence,
        "--status",
        "closed",
        "--close-reason",
        close_reason,
        "--note",
        "Synthetic explicit decision",
    )
    assert (
        run_workbench(state, "get-finding", "--occurrence-id", occurrence)["scan"]["findings"][0][
            "status"
        ]
        == "closed"
    )
    later = create_cli_scan(state, root, repository)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET started_at = '2000-01-01T00:00:00Z' WHERE id = ?", (later["scanId"],)
        )
    findings = run_workbench(state, "list-global-findings", "--include-resolved")["findings"]
    assert len(findings) == 1
    assert findings[0]["scanId"] == later["scanId"]
    assert findings[0]["status"] == "open"


def test_historical_latest_decision_does_not_reopen_without_a_later_scan(history) -> None:
    state, root, repository = history
    first = create_cli_scan(state, root, repository)
    occurrence = run_workbench(state, "get-scan", "--scan-id", first["scanId"])["scan"]["findings"][
        0
    ]["occurrenceId"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET started_at = '2099-10-06T10:00:00Z' WHERE id = ?", (first["scanId"],)
        )
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        occurrence,
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Synthetic historical dismissal",
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        # Rows preserved by the append-only migration have no recorded admission boundary.
        connection.execute("UPDATE finding_decisions SET scan_sequence = NULL")
    assert (
        run_workbench(state, "get-finding", "--occurrence-id", occurrence)["scan"]["findings"][0][
            "status"
        ]
        == "closed"
    )


@pytest.mark.parametrize("checkout", ["missing", "replaced", "previous-epoch-missing"])
def test_missing_repository_history(tmp_path: Path, history, checkout: str):
    state, root, repo = history
    scan = create_cli_scan(state, root, repo)
    repo.rename(tmp_path / "previous-repository")
    if checkout != "missing":
        repo.mkdir()
    if checkout == "previous-epoch-missing":
        scan = create_cli_scan(state, root, repo)
        repo.rename(tmp_path / "newer-offline-repository")
    missing = checkout != "replaced"
    listed = run_workbench(state, "list-scans", "--repository", str(repo))["scans"]
    assert [row["scanId"] for row in listed] == ([scan["scanId"]] if missing else [])
    findings = run_workbench(
        state, "list-global-findings", "--repository", str(repo), "--include-resolved"
    )["findings"]
    assert len(findings) == int(missing)


@pytest.mark.parametrize("reason", ["false_positive", "already_fixed"])
def test_newly_admitted_rediscovery_comparison(tmp_path: Path, history, reason: str):
    state, root, repo = history
    before = create_cli_scan(state, root, repo)
    occurrence = run_workbench(state, "get-scan", "--scan-id", before["scanId"])["scan"][
        "findings"
    ][0]["occurrenceId"]
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        occurrence,
        "--status",
        "closed",
        "--close-reason",
        reason,
        "--note",
        "Synthetic decision.",
    )
    after = create_cli_scan(state, root, repo)
    result = compare_scan_pair(state, before, after)
    assert result["summary"]["reopened"] == 1


def test_historical_comparison_does_not_use_later_rediscovery(tmp_path: Path, history):
    state, root, repo = history
    before = create_cli_scan(state, root, repo)
    after = create_cli_scan(state, root, repo)
    occurrence = run_workbench(state, "get-scan", "--scan-id", after["scanId"])["scan"]["findings"][
        0
    ]["occurrenceId"]
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        occurrence,
        "--status",
        "closed",
        "--close-reason",
        "already_fixed",
        "--note",
        "Synthetic decision.",
    )
    latest = create_cli_scan(state, root, repo)
    assert compare_scan_pair(state, after, latest)["summary"]["reopened"] == 1
    assert compare_scan_pair(state, before, after)["summary"]["reopened"] == 0


def test_semantic_alias_uncertainty_preserves_group(tmp_path: Path, history):
    state, root, repo = history
    scans = [
        create_cli_scan(state, root, repo, identity_anchor=a)
        for a in ["semantic-a", "semantic-b", "semantic-c"]
    ]
    rows = [
        run_workbench(state, "get-scan", "--scan-id", s["scanId"])["scan"]["findings"][0]
        for s in scans
    ]
    save_scan_matches(
        state, scans[0], scans[1], confirmed_match(rows[0]["occurrenceId"], rows[1]["occurrenceId"])
    )
    save_scan_matches(
        state,
        scans[0],
        scans[2],
        uncertain=(
            {
                "beforeOccurrenceId": rows[0]["occurrenceId"],
                "afterOccurrenceId": rows[2]["occurrenceId"],
                "reason": "Synthetic uncertain recurrence.",
            },
        ),
    )
    listed = run_workbench(state, "list-global-findings")["findings"]
    assert len(listed) == 2
    assert {r["findingId"] for r in listed} & {rows[0]["findingId"], rows[1]["findingId"]}
    create_cli_scan(state, root, repo, finding=False)
    assert run_workbench(state, "list-global-findings")["findings"] == []


def test_clean_diff_does_not_resolve_unchanged_source(tmp_path: Path, history):
    state, root, repo = history
    repo.rmdir()
    initialize_git_repository(repo)
    (repo / "src").mkdir()
    (repo / "src" / "extract.py").write_text("synthetic archive extraction\n")
    subprocess.run(["git", "-C", str(repo), "add", "src"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "Synthetic source"], check=True)
    base = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    previous = create_cli_scan(state, root, repo, target_revision=base)
    (repo / "README.md").write_text("Unrelated documentation change\n")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-qm", "Synthetic documentation change"], check=True
    )
    head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    scan = create_cli_scan(
        state,
        root,
        repo,
        complete=False,
        target={"kind": "refs", "paths": [], "base": base, "head": head},
    )
    directory = Path(scan["scanDir"])
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        snapshot = connection.execute(
            "SELECT target_snapshot_digest FROM scans WHERE id=?", (scan["scanId"],)
        ).fetchone()[0]
    write_completed_contract(
        directory,
        scan["scanId"],
        repo,
        target_kind="git_diff",
        target_revision=head,
        diff_base_revision=base,
        diff_head_revision=head,
        snapshot_digest=snapshot,
        coverage_mode="branch_diff",
        inventory_strategy="diff",
    )
    findings = json.loads((directory / "findings.json").read_text())
    findings["findings"] = []
    (directory / "findings.json").write_text(json.dumps(findings))
    subprocess.run([sys.executable, str(FINALIZER), "--scan-dir", str(directory)], check=True)
    run_workbench(state, "complete-scan", "--scan-id", scan["scanId"])
    assert [row["scanId"] for row in run_workbench(state, "list-global-findings")["findings"]] == [
        previous["scanId"]
    ]
    assert run_workbench(state, "list-repositories")["repositories"][0]["openFindingsCount"] == 1
    create_cli_scan(state, root, repo, finding=False, target_revision=head)
    assert run_workbench(state, "list-global-findings")["findings"] == []


@pytest.mark.parametrize("matched", [False, True])
def test_owned_remediation_finishes_after_match_closure(tmp_path: Path, history, matched: bool):
    state, root, repo = history
    before = create_cli_scan(state, root, repo, identity_anchor="older-source")
    before_occurrence = run_workbench(state, "get-scan", "--scan-id", before["scanId"])["scan"][
        "findings"
    ][0]["occurrenceId"]
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        before_occurrence,
        "--status",
        "closed",
        "--close-reason",
        "wont_fix",
        "--note",
        "Synthetic older decision.",
    )
    after = create_cli_scan(state, root, repo, identity_anchor="newer-source")
    after_occurrence = run_workbench(state, "get-scan", "--scan-id", after["scanId"])["scan"][
        "findings"
    ][0]["occurrenceId"]
    request, token = str(uuid.uuid4()), str(uuid.uuid4())
    run_workbench(
        state,
        "request-finding-remediation",
        "--occurrence-id",
        after_occurrence,
        "--request-id",
        request,
        "--action-token",
        token,
    )
    if matched:
        save_scan_matches(
            state, before, after, confirmed_match(before_occurrence, after_occurrence)
        )
    update = [
        "set-finding-remediation",
        "--occurrence-id",
        after_occurrence,
        "--request-id",
        request,
        "--action-token",
        token,
        "--expected-version",
        "1",
        "--state",
        "failed",
        "--summary",
        "Synthetic generation failure.",
    ]
    wrong = update.copy()
    wrong[wrong.index(token)] = str(uuid.uuid4())
    rejected = run_workbench(state, *wrong, check=False)
    assert rejected["returncode"] != 0
    assert "different action token" in rejected["stderr"]
    outcome = run_workbench(state, *update)
    row = next(r for r in outcome["scan"]["findings"] if r["occurrenceId"] == after_occurrence)
    assert row["remediationState"]["state"] == "failed"


@pytest.mark.parametrize("linked", [False, True])
def test_target_uncertainty_uses_confirmed_linked_history(tmp_path: Path, linked: bool):
    state, root = tmp_path / "state", tmp_path / "scans"
    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    sibling = tmp_path / "linked-worktree"
    subprocess.run(
        ["git", "-C", str(repository), "worktree", "add", "-q", "--detach", str(sibling)],
        check=True,
    )
    scans = [
        create_cli_scan(
            state, root, repository, identity_anchor="semantic-a", target_revision=revision
        ),
        create_cli_scan(
            state,
            root,
            sibling if linked else repository,
            identity_anchor="semantic-b",
            target_revision=revision,
        ),
        create_cli_scan(
            state, root, repository, identity_anchor="semantic-c", target_revision=revision
        ),
    ]
    rows = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0]
        for scan in scans
    ]
    save_scan_matches(
        state, scans[0], scans[1], confirmed_match(rows[0]["occurrenceId"], rows[1]["occurrenceId"])
    )
    save_scan_matches(
        state,
        scans[1],
        scans[2],
        uncertain=(
            {
                "beforeOccurrenceId": rows[1]["occurrenceId"],
                "afterOccurrenceId": rows[2]["occurrenceId"],
                "reason": "Synthetic uncertain recurrence.",
            },
        ),
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        target = connection.execute(
            "SELECT target_id FROM scans WHERE id=?", (scans[0]["scanId"],)
        ).fetchone()[0]
    unfiltered = run_workbench(state, "list-global-findings")["findings"]
    assert {r["findingId"] for r in unfiltered} & {rows[0]["findingId"], rows[1]["findingId"]}
    filtered = run_workbench(state, "list-global-findings", "--target-id", target)["findings"]
    assert {r["findingId"] for r in filtered} & {rows[0]["findingId"], rows[1]["findingId"]}
    assert len(filtered) == 2


@pytest.mark.parametrize("inherited", [False, True])
def test_reopened_comparison_reads_inherited_previous_closure(tmp_path: Path, inherited: bool):
    state, root = tmp_path / "state", tmp_path / "scans"
    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    sibling = tmp_path / "linked-worktree"
    subprocess.run(
        ["git", "-C", str(repository), "worktree", "add", "-q", "--detach", str(sibling)],
        check=True,
    )
    before = create_cli_scan(
        state, root, repository, identity_anchor="semantic-a", target_revision=revision
    )
    middle = create_cli_scan(
        state, root, sibling, identity_anchor="semantic-b", target_revision=revision
    )
    rows = [
        run_workbench(state, "get-scan", "--scan-id", s["scanId"])["scan"]["findings"][0]
        for s in [before, middle]
    ]
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        rows[0 if inherited else 1]["occurrenceId"],
        "--status",
        "closed",
        "--close-reason",
        "already_fixed",
        "--note",
        "Synthetic dismissal.",
    )
    save_scan_matches(
        state, before, middle, confirmed_match(rows[0]["occurrenceId"], rows[1]["occurrenceId"])
    )
    later = create_cli_scan(
        state, root, sibling, identity_anchor="semantic-b", target_revision=revision
    )
    comparison = compare_scan_pair(state, middle, later)
    assert comparison["summary"]["reopened"] == 1


@pytest.mark.parametrize("repeat", [False, True])
def test_repeated_inherited_action_keeps_ledger_order(tmp_path: Path, repeat: bool):
    state, root = tmp_path / "state", tmp_path / "scans"
    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    scans = [
        create_cli_scan(state, root, repository, identity_anchor=anchor, target_revision=revision)
        for anchor in ["semantic-a", "semantic-b", "semantic-c", "independent-source"]
    ]
    rows = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0]
        for scan in scans
    ]
    close = [
        "set-finding-triage",
        "--occurrence-id",
        rows[0]["occurrenceId"],
        "--status",
        "closed",
        "--close-reason",
        "wont_fix",
        "--note",
        "Synthetic dismissal.",
    ]
    run_workbench(state, *close)
    for index in [1, 2]:
        save_scan_matches(
            state,
            scans[0],
            scans[index],
            confirmed_match(rows[0]["occurrenceId"], rows[index]["occurrenceId"]),
        )
    if repeat:
        run_workbench(state, *close)
    run_workbench(
        state, "set-finding-triage", "--occurrence-id", rows[3]["occurrenceId"], "--status", "open"
    )
    save_scan_matches(
        state, scans[2], scans[3], confirmed_match(rows[2]["occurrenceId"], rows[3]["occurrenceId"])
    )
    detail = run_workbench(state, "get-finding", "--occurrence-id", rows[3]["occurrenceId"])[
        "scan"
    ]["findings"][0]
    assert detail["status"] == "open"


@pytest.mark.parametrize("unrelated_uncertainty", [False, True])
def test_unrelated_uncertainty_does_not_resurrect_resolved_alias(
    tmp_path: Path, unrelated_uncertainty: bool
):
    state, root = tmp_path / "state", tmp_path / "scans"
    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    (repository / "src").mkdir()
    for name in ["a.py", "b.py"]:
        (repository / "src" / name).write_text("Synthetic source.\n")
    subprocess.run(["git", "-C", str(repository), "add", "src"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-qm", "Synthetic finding sources"], check=True
    )
    revision = subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
    ).strip()

    def custom_scan(relative_path, anchor, *, paths=None, finding=True):
        scan = create_cli_scan(
            state,
            root,
            repository,
            complete=False,
            identity_anchor=anchor,
            paths=paths,
            target_revision=revision,
        )
        directory = Path(scan["scanDir"])
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            snapshot = connection.execute(
                "SELECT target_snapshot_digest FROM scans WHERE id=?", (scan["scanId"],)
            ).fetchone()[0]
        write_completed_contract(
            directory,
            scan["scanId"],
            repository,
            identity_anchor=anchor,
            relative_path=relative_path,
            include_paths=paths,
            coverage_mode="scoped_path" if paths else "repository",
            inventory_strategy="scoped_path" if paths else "repository",
            target_kind="git_revision",
            target_revision=revision,
            snapshot_digest=snapshot,
        )
        if not finding:
            artifact = directory / "findings.json"
            value = json.loads(artifact.read_text())
            value["findings"] = []
            artifact.write_text(json.dumps(value))
        subprocess.run([sys.executable, str(FINALIZER), "--scan-dir", str(directory)], check=True)
        run_workbench(state, "complete-scan", "--scan-id", scan["scanId"])
        return scan

    before = custom_scan("src/a.py", "semantic-a")
    after = custom_scan("src/b.py", "semantic-b")
    rows = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0]
        for scan in [before, after]
    ]
    save_scan_matches(
        state, before, after, confirmed_match(rows[0]["occurrenceId"], rows[1]["occurrenceId"])
    )
    custom_scan("src/b.py", "clean-scope", paths=["src/b.py"], finding=False)
    target = before["targetId"]
    assert run_workbench(state, "list-global-findings", "--target-id", target)["findings"] == []
    other = tmp_path / "unrelated-repository"
    other.mkdir()
    scans = [
        create_cli_scan(state, root, other, identity_anchor=anchor)
        for anchor in ["unrelated-a", "unrelated-b"]
    ]
    if unrelated_uncertainty:
        rows = [
            run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0]
            for scan in scans
        ]
        save_scan_matches(
            state,
            scans[0],
            scans[1],
            uncertain=(
                {
                    "beforeOccurrenceId": rows[0]["occurrenceId"],
                    "afterOccurrenceId": rows[1]["occurrenceId"],
                    "reason": "Synthetic unrelated uncertainty.",
                },
            ),
        )
    findings = run_workbench(state, "list-global-findings", "--target-id", target)["findings"]
    assert findings == []


@pytest.mark.parametrize("unrelated", [False, True])
def test_scoped_history_does_not_parse_unrelated_comparisons(tmp_path, unrelated):
    state, root = tmp_path / "state", tmp_path / "scans"
    other = tmp_path / "other"
    other.mkdir()
    unrelated_json = set()
    if unrelated:
        pair = [create_cli_scan(state, root, other, finding=False) for _ in range(2)]
        save_scan_matches(state, *pair)
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            unrelated_json = {
                r[0] for r in connection.execute("SELECT result_json FROM scan_comparisons")
            }
    repository = tmp_path / "repository"
    repository.mkdir()
    scan = create_cli_scan(state, root, repository)
    ns = runpy.run_path(str(SCRIPT), run_name="scoped_history_read_fixture")
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM scans WHERE id=?", (scan["scanId"],)).fetchone()
        parsed = []
        original = json.loads

        def loads(value, *args, **kwargs):
            if isinstance(value, str) and value in unrelated_json:
                parsed.append(value)
            return original(value, *args, **kwargs)

        with patch.object(json, "loads", loads):
            indexed = ns["_indexed_scan_findings"](connection, row)
        assert len(indexed) == 1
        assert parsed == []


def test_empty_comparison_does_not_rebuild_aggregate_triage(tmp_path):
    state, root = tmp_path / "state", tmp_path / "scans"
    repository = tmp_path / "repository"
    repository.mkdir()
    pair = [create_cli_scan(state, root, repository, finding=False) for _ in range(2)]
    save_scan_matches(state, *pair)
    ns = runpy.run_path(str(SCRIPT), run_name="empty_history_read_fixture")
    calls = []

    def triage(connection, scan):
        calls.append(scan["id"])
        return {}

    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        compared = ns["scan_history"].compare_scans(
            connection,
            argparse.Namespace(before_scan_id=pair[0]["scanId"], after_scan_id=pair[1]["scanId"]),
            require_scan=ns["require_scan"],
            read_coverage=ns["coverage_for_comparison"],
            finding_triage=triage,
        )
    assert compared["summary"]["persisting"] == 0
    assert calls == []


@pytest.mark.parametrize("identity", ["recorded", "legacy-null", "legacy-transition"])
def test_migrated_sealed_comparisons_keep_legacy_ownership(history, identity):
    state, root, repository = history
    scans = [
        create_cli_scan(state, root, repository, identity_anchor=anchor)
        for anchor in ("semantic-a", "semantic-b")
    ]
    rows = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0]
        for scan in scans
    ]
    if identity != "recorded":
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute("UPDATE scans SET target_device=NULL, target_inode=NULL")
    if identity == "legacy-transition":
        repository.rename(repository.with_name("previous-checkout"))
        repository.mkdir()
        create_cli_scan(state, root, repository)
        repository.rename(repository.with_name("replacement-checkout"))
        repository.with_name("previous-checkout").rename(repository)
        rejected = run_workbench(
            state,
            "save-scan-comparison",
            "--before-scan-id",
            scans[0]["scanId"],
            "--after-scan-id",
            scans[1]["scanId"],
            "--matches-json",
            json.dumps(
                {
                    "matches": [confirmed_match(rows[0]["occurrenceId"], rows[1]["occurrenceId"])],
                    "uncertain": [],
                }
            ),
            check=False,
        )
        assert rejected["returncode"] != 0
        assert "same repository target" in rejected["stderr"]
    else:
        result = save_scan_matches(
            state, *scans, confirmed_match(rows[0]["occurrenceId"], rows[1]["occurrenceId"])
        )
        assert result["summary"]["persisting"] == 1
        assert compare_scan_pair(state, *scans)["summary"]["persisting"] == 1


def test_scan_history_fixture_does_not_require_python_test_extras(history):
    state, root, repository = history
    script = "\n".join(
        [
            "import sys",
            "from pathlib import Path",
            "sys.path.insert(0, sys.argv[1])",
            "from workbench_test_support import create_cli_scan, run_workbench",
            "state, root, repository = map(Path, sys.argv[2:])",
            "scan = create_cli_scan(state, root, repository)",
            "assert run_workbench(state, 'get-scan', '--scan-id', scan['scanId'])['scan']['findings']",
        ]
    )
    subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            script,
            str(Path(__file__).parent),
            str(state),
            str(root),
            str(repository),
        ],
        check=True,
    )


@pytest.mark.parametrize("inaccessible", [False, True])
def test_scoped_history_ignores_unrelated_inaccessible_target(history, inaccessible):
    state, root, repository = history
    other = repository.with_name("unrelated-repository")
    other.mkdir()
    create_cli_scan(state, root, other)
    scan = create_cli_scan(state, root, repository)
    namespace = runpy.run_path(str(SCRIPT), run_name="scoped_ownership_fixture")
    original_stat = Path.stat

    def stat(path, *args, **kwargs):
        if inaccessible and path == other:
            raise PermissionError("Synthetic inaccessible unrelated checkout")
        return original_stat(path, *args, **kwargs)

    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        selected = connection.execute(
            "SELECT * FROM scans WHERE id = ?", (scan["scanId"],)
        ).fetchone()
        with patch.object(Path, "stat", stat):
            indexed = namespace["_indexed_scan_findings"](connection, selected)
        assert len(indexed) == 1


@pytest.mark.parametrize("identity", ["recorded", "all-legacy", "mixed", "transition"])
def test_bulk_matching_preserves_legacy_seals(tmp_path, identity):
    state, root, repo = tmp_path / "state", tmp_path / "scans", tmp_path / "repository"
    repo.mkdir()
    scans = [create_cli_scan(state, root, repo, identity_anchor=a) for a in ["before", "after"]]
    if identity != "recorded":
        with sqlite3.connect(state / "workbench.sqlite3") as db:
            db.execute(
                "UPDATE scans SET target_device=NULL,target_inode=NULL WHERE id IN (?,?)",
                tuple(s["scanId"] for s in scans),
            )
    if identity == "mixed":
        create_cli_scan(state, root, repo, identity_anchor="newer")
    if identity == "transition":
        repo.rename(repo.with_name("previous-owner"))
        repo.mkdir()
        create_cli_scan(state, root, repo)
        repo.rename(repo.with_name("replacement-owner"))
        repo.with_name("previous-owner").rename(repo)
    result = run_workbench(state, "list-unmatched-scan-pairs", "--repository", str(repo))
    print("ACTUAL BULK", identity, result["scanCount"], len(result["batches"]))
    assert result["scanCount"] == (
        0 if identity == "transition" else 3 if identity == "mixed" else 2
    )
    assert len(result["batches"]) == (
        0 if identity == "transition" else 2 if identity == "mixed" else 1
    )


@pytest.mark.parametrize("legacy", [False, True, "all-legacy"])
def test_offline_saved_comparison_keeps_pretransition_legacy_seals(tmp_path, legacy):
    state, root, repo = tmp_path / "state", tmp_path / "scans", tmp_path / "repository"
    repo.mkdir()
    scans = [create_cli_scan(state, root, repo, identity_anchor=a) for a in ["before", "after"]]
    rows = [
        run_workbench(state, "get-scan", "--scan-id", s["scanId"])["scan"]["findings"][0]
        for s in scans
    ]
    if legacy:
        with sqlite3.connect(state / "workbench.sqlite3") as db:
            db.execute("UPDATE scans SET target_device=NULL,target_inode=NULL")
        if legacy != "all-legacy":
            create_cli_scan(state, root, repo, identity_anchor="recorded-current-owner")
    saved = save_scan_matches(state, *scans, confirmed_match(*[r["occurrenceId"] for r in rows]))
    repo.rename(repo.with_name("offline-owner"))
    result = compare_scan_pair(state, *scans, check=False)
    print("ACTUAL OFFLINE", legacy, result)
    assert result["returncode"] == 0, result["stderr"]
    assert compare_scan_pair(state, *scans) == saved


def verified_patch(state, scan, occurrence, repo, revision):
    request, token = str(uuid.uuid4()), str(uuid.uuid4())
    patch = Path(scan["scanDir"]) / "remediation.patch"
    patch.write_text(
        "diff --git a/src/extract.py b/src/extract.py\n--- a/src/extract.py\n+++ b/src/extract.py\n@@ -1 +1 @@\n-vulnerable\n+fixed\n",
        newline="\n",
    )
    run_workbench(
        state,
        "request-finding-remediation",
        "--occurrence-id",
        occurrence,
        "--request-id",
        request,
        "--action-token",
        token,
    )
    run_workbench(
        state,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence,
        "--request-id",
        request,
        "--action-token",
        token,
        "--expected-version",
        "1",
        "--state",
        "generated",
        "--patch-path",
        patch.name,
        "--patch-digest",
        "sha256:" + hashlib.sha256(patch.read_bytes()).hexdigest(),
        "--summary",
        "Synthetic fix",
    )
    for action, state_name, version in [("apply", "applied", 2), ("verify", "verified", 4)]:
        token = str(uuid.uuid4())
        run_workbench(
            state,
            "request-finding-remediation-action",
            "--occurrence-id",
            occurrence,
            "--request-id",
            request,
            "--expected-version",
            str(version),
            "--action",
            action,
            "--action-token",
            token,
        )
        if action == "apply":
            (repo / "src/extract.py").write_text("fixed\n")
        if action == "verify":
            run_workbench(
                state,
                "set-finding-remediation",
                "--occurrence-id",
                occurrence,
                "--request-id",
                request,
                "--action-token",
                token,
                "--expected-version",
                str(version + 1),
                "--state",
                "verifying",
                "--base-revision",
                revision,
            )
        run_workbench(
            state,
            "set-finding-remediation",
            "--occurrence-id",
            occurrence,
            "--request-id",
            request,
            "--action-token",
            token,
            "--expected-version",
            str(version + 2 if action == "verify" else version + 1),
            "--state",
            state_name,
            "--base-revision",
            revision,
            *(
                ["--verification-summary", "Synthetic regression passed."]
                if action == "verify"
                else []
            ),
        )


@pytest.mark.parametrize("drift", [False, True])
def test_inherited_fixed_closure_verifies_each_active_worktree(tmp_path, drift):
    state, root, repo = tmp_path / "state", tmp_path / "scans", tmp_path / "repository"
    initialize_git_repository(repo)
    (repo / "src").mkdir()
    (repo / "src/extract.py").write_text("vulnerable\n")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-qm", "Synthetic remediation fixture"], check=True
    )
    revision = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
    ).strip()
    linked = tmp_path / "linked-worktree"
    subprocess.run(
        ["git", "-C", str(repo), "worktree", "add", "-q", "--detach", str(linked)], check=True
    )
    scans = [
        create_cli_scan(state, root, p, identity_anchor=a, target_revision=revision)
        for p, a in [(repo, "older-source"), (linked, "newer-source")]
    ]
    rows = [
        run_workbench(state, "get-scan", "--scan-id", s["scanId"])["scan"]["findings"][0]
        for s in scans
    ]
    occ = [r["occurrenceId"] for r in rows]
    save_scan_matches(state, *scans, confirmed_match(*occ))
    for s, o, p in zip(scans, occ, [repo, linked]):
        verified_patch(state, s, o, p, revision)
    if drift:
        (linked / "src/extract.py").write_text("drifted\n")
        direct = run_workbench(
            state,
            "set-finding-triage",
            "--occurrence-id",
            occ[1],
            "--status",
            "closed",
            "--close-reason",
            "already_fixed",
            check=False,
        )
        assert direct["returncode"] != 0 and "Working-tree contents changed" in direct["stderr"]
    inherited = run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        occ[0],
        "--status",
        "closed",
        "--close-reason",
        "already_fixed",
        check=False,
    )
    print("ACTUAL INHERITED CLOSURE", drift, inherited)
    assert (inherited["returncode"] != 0) == drift
    if drift:
        assert "Working-tree contents changed" in inherited["stderr"]


@pytest.mark.parametrize("reaffirm_after_admission", [False, True])
def test_identical_decision_refreshes_the_scan_admission_boundary(
    history, reaffirm_after_admission
):
    state, root, repository = history
    first = create_cli_scan(state, root, repository)
    occurrence = run_workbench(state, "get-scan", "--scan-id", first["scanId"])["scan"]["findings"][
        0
    ]["occurrenceId"]
    decision = (
        "set-finding-triage",
        "--occurrence-id",
        occurrence,
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Synthetic reaffirmed decision",
    )
    run_workbench(state, *decision)
    run_workbench(state, *decision)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM finding_decisions").fetchone()[0] == 1
    pending = create_cli_scan(state, root, repository, complete=False)
    if reaffirm_after_admission:
        run_workbench(state, *decision)
    scan_dir = Path(pending["scanDir"])
    write_completed_contract(scan_dir, pending["scanId"], repository)
    subprocess.run([sys.executable, str(FINALIZER), "--scan-dir", str(scan_dir)], check=True)
    run_workbench(state, "complete-scan", "--scan-id", pending["scanId"])
    findings = run_workbench(
        state, "list-global-findings", "--repository", str(repository), "--include-resolved"
    )["findings"]
    assert len(findings) == 1
    assert findings[0]["status"] == ("closed" if reaffirm_after_admission else "open")


@pytest.mark.parametrize(
    "nested", [False, True], ids=["registered-root", "unregistered-subdirectory"]
)
def test_bulk_matching_uses_registered_checkout_owner_for_same_origin_clones(tmp_path, nested):
    state, root = tmp_path / "state", tmp_path / "scans"
    repositories = [tmp_path / "first", tmp_path / "second"]
    scans = []
    for repository in repositories:
        revision = initialize_git_repository(repository)
        subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "remote",
                "add",
                "origin",
                "https://github.com/example/synthetic.git",
            ],
            check=True,
        )
        scans.append(create_cli_scan(state, root, repository, target_revision=revision))
    requested = repositories[0] / "nested" if nested else repositories[0]
    requested.mkdir(exist_ok=True)
    result = run_workbench(state, "list-unmatched-scan-pairs", "--repository", str(requested))
    assert result["scanCount"] == 2
    assert result["batches"][0]["beforeScans"][0]["scanId"] == scans[0]["scanId"]
    assert result["batches"][0]["afterScanId"] == scans[1]["scanId"]


@pytest.mark.parametrize("replace_match", [False, True])
def test_explicit_reopen_appends_own_decision_before_match_replacement(history, replace_match):
    state, root, repository = history
    scans = [
        create_cli_scan(state, root, repository, identity_anchor=anchor)
        for anchor in ["a", "b", "c"]
    ]
    occurrences = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0][
            "occurrenceId"
        ]
        for scan in scans
    ]
    for occurrence in [occurrences[0], occurrences[2]]:
        run_workbench(
            state,
            "set-finding-triage",
            "--occurrence-id",
            occurrence,
            "--status",
            "closed",
            "--close-reason",
            "false_positive",
            "--note",
            "Synthetic reviewed decision.",
        )
    run_workbench(
        state, "set-finding-triage", "--occurrence-id", occurrences[1], "--status", "open"
    )
    save_scan_matches(state, scans[0], scans[1], confirmed_match(occurrences[0], occurrences[1]))
    run_workbench(
        state, "set-finding-triage", "--occurrence-id", occurrences[0], "--status", "open"
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        latest = connection.execute(
            "SELECT status FROM finding_decisions WHERE occurrence_id = ? ORDER BY decision_sequence DESC LIMIT 1",
            (occurrences[0],),
        ).fetchone()
    assert latest == ("open",)
    if replace_match:
        save_scan_matches(state, scans[0], scans[1])
    save_scan_matches(state, scans[0], scans[2], confirmed_match(occurrences[0], occurrences[2]))
    assert (
        run_workbench(state, "get-finding", "--occurrence-id", occurrences[0])["scan"]["findings"][
            0
        ]["triage"]["status"]
        == "open"
    )


@pytest.mark.parametrize("drift", [False, True])
def test_inherited_fixed_closure_checks_nonrepresentative_active_alias(tmp_path, drift):
    state, root, repository = tmp_path / "state", tmp_path / "scans", tmp_path / "repository"
    initialize_git_repository(repository)
    (repository / "src").mkdir()
    (repository / "src/extract.py").write_text("vulnerable\n")
    subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-qm", "Synthetic alias remediation fixture"],
        check=True,
    )
    revision = subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
    ).strip()
    linked = tmp_path / "linked"
    subprocess.run(
        ["git", "-C", str(repository), "worktree", "add", "-q", "--detach", str(linked)], check=True
    )
    first = create_cli_scan(
        state,
        root,
        repository,
        identity_anchor="first",
        extra_anchors=("same-owner-alias",),
        target_revision=revision,
    )
    second = create_cli_scan(
        state, root, linked, identity_anchor="other-owner", target_revision=revision
    )
    aliases = run_workbench(state, "get-scan", "--scan-id", first["scanId"])["scan"]["findings"]
    other = run_workbench(state, "get-scan", "--scan-id", second["scanId"])["scan"]["findings"][0]
    ids = [row["occurrenceId"] for row in aliases]
    hidden = min(ids)
    save_scan_matches(state, first, second, confirmed_match(ids, other["occurrenceId"]))
    verified_patch(state, first, hidden, repository, revision)
    if drift:
        (repository / "src/extract.py").write_text("Synthetic changed applied contents.\n")
        direct = run_workbench(
            state,
            "set-finding-triage",
            "--occurrence-id",
            hidden,
            "--status",
            "closed",
            "--close-reason",
            "already_fixed",
            check=False,
        )
        assert direct["returncode"] != 0 and "Working-tree contents changed" in direct["stderr"]
    inherited = run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        other["occurrenceId"],
        "--status",
        "closed",
        "--close-reason",
        "already_fixed",
        check=False,
    )
    assert (inherited["returncode"] != 0) == drift
    if drift:
        assert "Working-tree contents changed" in inherited["stderr"]


@pytest.mark.parametrize("rediscover", [False, True])
def test_false_positive_feedback_follows_reopened_matched_group(history, rediscover):
    state, root, repository = history
    scans = [
        create_cli_scan(state, root, repository, identity_anchor=anchor)
        for anchor in ["previous-alias", "current-finding"]
    ]
    occurrences = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0][
            "occurrenceId"
        ]
        for scan in scans
    ]
    save_scan_matches(state, *scans, confirmed_match(*occurrences))
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        occurrences[1],
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Synthetic reviewed false positive.",
    )
    if rediscover:
        create_cli_scan(state, root, repository, identity_anchor="current-finding")
    current = create_cli_scan(state, root, repository, complete=False)
    feedback = run_workbench(state, "get-scan-feedback", "--scan-id", current["scanId"])[
        "falsePositives"
    ]
    assert bool(feedback) is not rediscover


@pytest.mark.parametrize("earlier", ["verified", "unverified", "explicit-request"])
def test_current_semantic_alias_excludes_superseded_checkout_verification(tmp_path, earlier):
    state, root, repository = tmp_path / "state", tmp_path / "scans", tmp_path / "repository"
    initialize_git_repository(repository)
    (repository / "src").mkdir()
    (repository / "src/extract.py").write_text("vulnerable\n")
    subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-qm", "Synthetic initial revision"], check=True
    )
    first_revision = subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
    ).strip()
    first = create_cli_scan(
        state, root, repository, identity_anchor="earlier-alias", target_revision=first_revision
    )
    first_id = run_workbench(state, "get-scan", "--scan-id", first["scanId"])["scan"]["findings"][
        0
    ]["occurrenceId"]
    if earlier != "unverified":
        verified_patch(state, first, first_id, repository, first_revision)
    (repository / "src/extract.py").write_text("vulnerable\n")
    (repository / "next-revision.txt").write_text("Synthetic later revision.\n")
    subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-qm", "Synthetic next revision"], check=True
    )
    second_revision = subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
    ).strip()
    second = create_cli_scan(
        state, root, repository, identity_anchor="current-alias", target_revision=second_revision
    )
    second_id = run_workbench(state, "get-scan", "--scan-id", second["scanId"])["scan"]["findings"][
        0
    ]["occurrenceId"]
    verified_patch(state, second, second_id, repository, second_revision)
    save_scan_matches(state, first, second, confirmed_match(first_id, second_id))
    requested = first_id if earlier == "explicit-request" else second_id
    result = run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        requested,
        "--status",
        "closed",
        "--close-reason",
        "already_fixed",
        check=False,
    )
    if earlier == "explicit-request":
        assert result["returncode"] != 0 and "Repository HEAD changed" in result["stderr"]
    else:
        assert result["returncode"] == 0, result["stderr"]


@pytest.mark.parametrize("selection", ["inherited", "unmatched", "local"])
def test_false_positive_feedback_projects_inherited_linked_decision(linked_history, selection):
    state, root, repository, linked, revision = linked_history
    first = create_cli_scan(
        state, root, repository, identity_anchor="reviewed", target_revision=revision
    )
    second = create_cli_scan(
        state, root, linked, identity_anchor="linked-alias", target_revision=revision
    )
    first_id, second_id = [
        run_workbench(state, "get-scan", "--scan-id", row["scanId"])["scan"]["findings"][0][
            "occurrenceId"
        ]
        for row in [first, second]
    ]
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        first_id,
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Synthetic inherited dismissal.",
    )
    if selection == "inherited":
        save_scan_matches(state, first, second, confirmed_match(first_id, second_id))
    selected = repository if selection == "local" else linked
    current = create_cli_scan(state, root, selected, complete=False, target_revision=revision)
    feedback = run_workbench(state, "get-scan-feedback", "--scan-id", current["scanId"])[
        "falsePositives"
    ]
    assert bool(feedback) is (selection != "unmatched")
    if feedback:
        assert feedback[0]["reason"] == "Synthetic inherited dismissal."


@pytest.mark.parametrize("terminal", ["failed", "complete-control", "no-recurrence"])
def test_false_positive_feedback_observes_sealed_stopped_recurrence(history, terminal):
    state, root, repository = history
    first = create_cli_scan(state, root, repository)
    first_id = run_workbench(state, "get-scan", "--scan-id", first["scanId"])["scan"]["findings"][
        0
    ]["occurrenceId"]
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        first_id,
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Synthetic stale dismissal.",
    )
    if terminal == "complete-control":
        create_cli_scan(state, root, repository)
    elif terminal == "failed":
        stopped = create_cli_scan(state, root, repository, complete=False)
        scan_dir = Path(stopped["scanDir"])
        write_completed_contract(scan_dir, stopped["scanId"], repository)
        subprocess.run([sys.executable, str(FINALIZER), "--scan-dir", str(scan_dir)], check=True)
        preserved = run_workbench(
            state,
            "fail-scan",
            "--scan-id",
            stopped["scanId"],
            "--message",
            "Synthetic interruption",
        )
        assert preserved["scan"]["findings"]
    current = create_cli_scan(state, root, repository, complete=False)
    feedback = run_workbench(state, "get-scan-feedback", "--scan-id", current["scanId"])[
        "falsePositives"
    ]
    assert bool(feedback) is (terminal == "no-recurrence")


@pytest.mark.parametrize("linked", [False, True])
def test_scope_expansion_skips_same_target_pairs_but_keeps_linked_comparisons(
    linked_history, linked
):
    state, root, repository, other, revision = linked_history
    scans = [
        create_cli_scan(state, root, repository, finding=False, target_revision=revision)
        for _ in range(3)
    ]
    for before, after in ((scans[0], scans[1]), (scans[0], scans[2]), (scans[1], scans[2])):
        save_scan_matches(state, before, after)
    if linked:
        related = create_cli_scan(state, root, other, finding=False, target_revision=revision)
        save_scan_matches(state, scans[0], related)
    ns = runpy.run_path(str(SCRIPT), run_name="scope_expansion_comparison_fixture")
    module = ns["scan_history"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM scans WHERE id=?", (scans[0]["scanId"],)).fetchone()
        with patch.object(
            module, "_same_registered_repository", wraps=module._same_registered_repository
        ) as same:
            targets = module.saved_repository_target_ids(connection, row)
        expected = {row["target_id"]}
        if linked:
            expected.add(
                connection.execute(
                    "SELECT target_id FROM scans WHERE id=?", (related["scanId"],)
                ).fetchone()[0]
            )
        assert targets == expected
        assert same.call_count == (1 if linked else 0)


@pytest.mark.parametrize("reason", ["false_positive", "already_fixed"])
def test_transitive_comparison_keeps_dismissal_for_predecision_scans(history, reason):
    state, root, repo = history
    scans = [
        create_cli_scan(state, root, repo, identity_anchor=anchor)
        for anchor in ("transitive-a", "transitive-b", "transitive-c")
    ]
    rows = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0]
        for scan in scans
    ]
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        rows[0]["occurrenceId"],
        "--status",
        "closed",
        "--close-reason",
        reason,
        "--note",
        "Synthetic transitive dismissal.",
    )
    save_scan_matches(state, scans[0], scans[1])
    save_scan_matches(
        state, scans[0], scans[2], confirmed_match(rows[0]["occurrenceId"], rows[2]["occurrenceId"])
    )
    save_scan_matches(
        state, scans[1], scans[2], confirmed_match(rows[1]["occurrenceId"], rows[2]["occurrenceId"])
    )
    detail = run_workbench(state, "get-finding", "--occurrence-id", rows[1]["occurrenceId"])[
        "scan"
    ]["findings"][0]
    assert detail["triage"]["status"] == "closed"
    result = compare_scan_pair(state, scans[0], scans[1])
    assert result["summary"]["reopened"] == 0
    assert result["summary"]["persisting"] == 1
    assert result["findings"][0]["triage"]["status"] == "closed"
