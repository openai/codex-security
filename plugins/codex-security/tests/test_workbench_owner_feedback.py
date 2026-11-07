from __future__ import annotations

import json
import runpy
import sqlite3
import subprocess
import uuid
from pathlib import Path

import pytest
from test_workbench_scan_history import compare_scan_pair, create_cli_scan
from workbench_test_support import initialize_git_repository, run_workbench

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "workbench_db.py"


def finding(state, scan):
    return run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0]


@pytest.mark.parametrize("command", ["triage", "remediation"])
def test_previous_owner_cannot_mutate_or_replay_finding_actions(tmp_path, command):
    state, root, repository = tmp_path / "state", tmp_path / "scans", tmp_path / "repository"
    revision = initialize_git_repository(repository)
    previous = create_cli_scan(state, root, repository, target_revision=revision)
    occurrence = finding(state, previous)["occurrenceId"]
    request, token = str(uuid.uuid4()), str(uuid.uuid4())
    arguments = (
        ["set-finding-triage", "--occurrence-id", occurrence, "--status", "open"]
        if command == "triage"
        else [
            "request-finding-remediation",
            "--occurrence-id",
            occurrence,
            "--request-id",
            request,
            "--action-token",
            token,
        ]
    )
    run_workbench(state, *arguments)
    repository.rename(tmp_path / "previous-checkout")
    replacement_revision = initialize_git_repository(repository)
    create_cli_scan(state, root, repository, target_revision=replacement_revision)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        before = connection.execute("SELECT * FROM finding_triage").fetchall()
    result = run_workbench(state, *arguments, check=False)
    assert result["returncode"] != 0
    assert "checkout owner" in result["stderr"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT * FROM finding_triage").fetchall() == before


def test_replacement_checkout_does_not_receive_previous_owner_feedback(tmp_path):
    state, root, repository = tmp_path / "state", tmp_path / "scans", tmp_path / "repository"
    repository.mkdir()
    previous = create_cli_scan(state, root, repository)
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        finding(state, previous)["occurrenceId"],
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Synthetic previous-owner rationale.",
    )
    repository.rename(tmp_path / "previous-checkout")
    repository.mkdir()
    current = create_cli_scan(state, root, repository, complete=False)
    feedback = run_workbench(state, "get-scan-feedback", "--scan-id", current["scanId"])
    assert feedback["falsePositives"] == []


@pytest.mark.parametrize("replaced", [False, True])
def test_related_findings_respect_the_current_owner_of_both_scans(tmp_path, replaced):
    state, root, repository = tmp_path / "state", tmp_path / "scans", tmp_path / "repository"
    repository.mkdir()
    before = create_cli_scan(state, root, repository, identity_anchor="before")
    old_finding = finding(state, before)
    after = create_cli_scan(state, root, repository, identity_anchor="after")
    current_finding = finding(state, after)
    # A persisted comparison may survive a later checkout replacement.
    run_workbench(
        state,
        "save-scan-comparison",
        "--before-scan-id",
        before["scanId"],
        "--after-scan-id",
        after["scanId"],
        "--matches-json",
        json.dumps(
            {
                "matches": [],
                "uncertain": [],
                "related": [
                    {
                        "beforeOccurrenceId": old_finding["occurrenceId"],
                        "afterOccurrenceId": current_finding["occurrenceId"],
                        "reason": "Synthetic related issue.",
                    }
                ],
            }
        ),
    )
    if replaced:
        repository.rename(tmp_path / "previous-checkout")
        repository.mkdir()
        replacement = create_cli_scan(state, root, repository, identity_anchor="replacement")
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            replacement_identity = connection.execute(
                "SELECT target_device, target_inode FROM scans WHERE id = ?",
                (replacement["scanId"],),
            ).fetchone()
            # Keep the selected occurrence in the new owner; only its related peer is stale.
            connection.execute(
                "UPDATE scans SET target_device = ?, target_inode = ? WHERE id = ?",
                (*replacement_identity, after["scanId"]),
            )
            connection.execute("DELETE FROM scans WHERE id = ?", (replacement["scanId"],))
    detail = run_workbench(
        state, "get-finding", "--occurrence-id", current_finding["occurrenceId"]
    )["scan"]["findings"][0]
    assert len(detail.get("related", [])) == (0 if replaced else 1)


@pytest.mark.parametrize("claimed", [False, True])
def test_targetless_legacy_comparisons_require_unclaimed_paths(tmp_path, claimed):
    state, root, repository = tmp_path / "state", tmp_path / "scans", tmp_path / "repository"
    repository.mkdir()
    scans = [
        create_cli_scan(state, root, repository, identity_anchor=anchor)
        for anchor in ("before", "after")
    ]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET target_id = NULL, target_device = NULL, target_inode = NULL"
        )
        connection.execute("UPDATE workspaces SET target_id = NULL")
        connection.execute("DELETE FROM security_targets")
    if claimed:
        create_cli_scan(state, root, repository)
    result = compare_scan_pair(state, *scans, check=False)
    assert (result["returncode"] != 0) if claimed else result["returncode"] == 0


def test_finding_artifacts_include_all_safe_files_and_directories(tmp_path):
    namespace = runpy.run_path(str(SCRIPT.with_name("workbench_finding_results.py")))
    relative = Path("findings/synthetic/synthetic.md")
    (tmp_path / relative).parent.mkdir(parents=True)
    (tmp_path / relative).write_text("Synthetic report.")
    expected = [relative.as_posix()]
    poc = relative.parent / "poc"
    for index in range(90):
        path = poc / f"directory-{index:03}" / "example.txt"
        (tmp_path / path).parent.mkdir(parents=True)
        (tmp_path / path).write_text("Synthetic PoC data.")
        expected.append(path.as_posix())
    for index in range(50):
        path = poc / f"example-{index:03}.txt"
        (tmp_path / path).write_text("Synthetic PoC data.")
        expected.append(path.as_posix())
    actual = namespace["finding_artifact_paths"](
        tmp_path, {"writeup": {"reportPath": relative.as_posix()}}
    )
    assert set(actual) == set(expected)


@pytest.mark.parametrize(
    ("left_remote", "right_remote", "related"),
    [
        ("alice@git.example:project.git", "bob@git.example:project.git", False),
        ("alice@git.example:~", "bob@git.example:~", False),
        ("alice@git.example:project.git", "alice@git.example:project.git", True),
        ("Alice@git.example:project.git", "alice@git.example:project.git", False),
        ("alice@git.example:/srv/project.git", "bob@git.example:/srv/project.git", True),
        ("ssh://alice@git.example/srv/project.git", "ssh://bob@git.example/srv/project.git", True),
        ("alice@git.example:~owner/project.git", "bob@git.example:~owner/project.git", True),
        ("ssh://alice@git.example/~/project.git", "ssh://bob@git.example/~/project.git", False),
        ("https://github.com/example/project.git", "git@github.com:example/project.git", True),
        ("https://gitlab.com/group/project.git", "git@gitlab.com:group/project.git", True),
        (
            "https://gitlab.com/group/subgroup/project.git",
            "git@GITLAB.com:group/subgroup/project.git",
            True,
        ),
        (
            "git@gitlab.com:group/project.git",
            "ssh://git@gitlab.com:22/group/project.git",
            True,
        ),
        (
            "https://gitlab.com/group/project.git",
            "ssh://git@gitlab.com:2222/group/project.git",
            False,
        ),
        ("git@gitlab.com:group/project.git", "alice@gitlab.com:group/project.git", False),
        ("git@gitlab.com:group/project.git", "git@gitlab.com:~/group/project.git", False),
        (
            "git@gitlab.com:group/project.git",
            "ssh://git@gitlab.com/~/group/project.git",
            False,
        ),
        (
            "https://bitbucket.org/workspace/project.git",
            "git@bitbucket.org:workspace/project.git",
            True,
        ),
        (
            "https://alice@bitbucket.org/workspace/project.git",
            "git@BITBUCKET.org:workspace/project.git",
            True,
        ),
        (
            "git@bitbucket.org:workspace/project.git",
            "ssh://git@bitbucket.org:22/workspace/project.git",
            True,
        ),
        (
            "https://bitbucket.org/workspace/project.git",
            "ssh://git@bitbucket.org:2222/workspace/project.git",
            False,
        ),
        (
            "git@bitbucket.org:workspace/project.git",
            "alice@bitbucket.org:workspace/project.git",
            False,
        ),
        (
            "git@bitbucket.org:workspace/project.git",
            "git@bitbucket.org:~/workspace/project.git",
            False,
        ),
        (
            "git@bitbucket.org:workspace/project.git",
            "ssh://git@bitbucket.org/~/workspace/project.git",
            False,
        ),
        (
            "https://bitbucket.org.example/workspace/project.git",
            "git@bitbucket.org.example:workspace/project.git",
            False,
        ),
        ("https://git.example/group/project.git", "git@git.example:group/project.git", False),
    ],
)
def test_registered_clone_scope_preserves_ssh_accounts(
    tmp_path, left_remote, right_remote, related
):
    state, root = tmp_path / "state", tmp_path / "scans"
    scans = []
    repositories = [tmp_path / "left", tmp_path / "right"]
    for repository, remote in zip(repositories, (left_remote, right_remote), strict=True):
        revision = initialize_git_repository(repository)
        subprocess.run(
            ["git", "-C", str(repository), "remote", "add", "origin", remote], check=True
        )
        scans.append(create_cli_scan(state, root, repository, target_revision=revision))
    pending = run_workbench(
        state, "list-unmatched-scan-pairs", "--repository", str(repositories[0])
    )
    assert pending["scanCount"] == (2 if related else 1)
    compared = compare_scan_pair(state, *scans, check=False)
    assert compared["returncode"] == 0 if related else compared["returncode"] != 0
