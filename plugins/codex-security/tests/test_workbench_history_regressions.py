from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from test_workbench_scan_history import (
    compare_scan_pair,
    confirmed_match,
    create_cli_scan,
    run_workbench,
    save_scan_matches,
)


@pytest.fixture
def history(tmp_path: Path):
    repository = tmp_path / "repository"
    repository.mkdir()
    return tmp_path / "state", tmp_path / "scans", repository


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
