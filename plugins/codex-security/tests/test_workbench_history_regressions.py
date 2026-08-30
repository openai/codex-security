from __future__ import annotations

import csv
import sqlite3
import subprocess
from pathlib import Path

import pytest
from test_workbench_scan_history import (
    compare_scan_pair,
    confirmed_match,
    create_cli_scan,
    run_workbench,
    save_scan_matches,
)
from workbench_test_support import initialize_git_repository


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
