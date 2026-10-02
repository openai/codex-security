from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from test_workbench_scan_history import create_cli_scan, run_workbench
from workbench_test_support import initialize_git_repository


def commit(repository: Path) -> str:
    subprocess.run(
        ["git", "-C", str(repository), "commit", "--allow-empty", "-qm", "Next revision"],
        check=True,
    )
    return subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
    ).strip()


def test_cli_resume_keeps_selected_refs_when_checkout_head_differs(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    base = initialize_git_repository(repository)
    selected_head = commit(repository)
    commit(repository)
    state = tmp_path / "state"
    (tmp_path / "results").mkdir(mode=0o700)
    scan = create_cli_scan(
        state,
        tmp_path / "results",
        repository,
        complete=False,
        target={"kind": "refs", "paths": [], "base": base, "head": selected_head},
    )

    resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"])

    assert resumed["scanId"] == scan["scanId"]
    assert resumed["recipe"]["target"]["head"] == selected_head


@pytest.mark.parametrize("change", ["contents", "head"])
def test_cli_resume_checks_the_saved_working_tree(tmp_path: Path, change: str) -> None:
    repository = tmp_path / "repository"
    base = initialize_git_repository(repository)
    head = commit(repository)
    (repository / "README.md").write_text("Selected working-tree contents\n")
    state = tmp_path / "state"
    (tmp_path / "results").mkdir(mode=0o700)
    scan = create_cli_scan(
        state,
        tmp_path / "results",
        repository,
        complete=False,
        target={"kind": "working_tree", "paths": [], "base": base, "head": head},
    )
    resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"])
    assert resumed["recipe"]["target"] == {
        "kind": "working_tree",
        "paths": [],
        "base": base,
        "head": head,
    }

    if change == "head":
        commit(repository)
    else:
        (repository / "README.md").write_text("Changed after registration\n")
    rejected = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"], check=False)
    assert rejected["returncode"] != 0
    assert "original checkout revision or contents changed" in rejected["stderr"]
