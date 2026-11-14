from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from test_workbench_history_regressions import verified_patch
from test_workbench_scan_history import FINALIZER, create_cli_scan, run_workbench
from workbench_test_support import initialize_git_repository, write_completed_contract


@pytest.mark.parametrize("review", ["complete", "deferred", "reopened"])
def test_stable_recurrence_keeps_older_patch_verification(tmp_path: Path, review: str) -> None:
    state, root, repository = tmp_path / "state", tmp_path / "scans", tmp_path / "repository"
    initialize_git_repository(repository)
    (repository / "src").mkdir()
    source = repository / "src/extract.py"
    source.write_text("vulnerable\n")
    subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-qm", "Synthetic stable finding"], check=True
    )
    revision = subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
    ).strip()
    earlier = create_cli_scan(state, root, repository, target_revision=revision)
    first = run_workbench(state, "get-scan", "--scan-id", earlier["scanId"])["scan"]["findings"][0]
    verified_patch(state, earlier, first["occurrenceId"], repository, revision)
    source.write_text("vulnerable\n")

    later = create_cli_scan(state, root, repository, complete=False)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        snapshot_digest = connection.execute(
            "SELECT target_snapshot_digest FROM scans WHERE id = ?", (later["scanId"],)
        ).fetchone()[0]
    directory = Path(later["scanDir"])
    write_completed_contract(
        directory,
        later["scanId"],
        repository,
        target_kind="git_revision",
        target_revision=revision,
        snapshot_digest=snapshot_digest,
    )
    if review == "deferred":
        coverage_path = directory / "coverage.json"
        coverage = json.loads(coverage_path.read_text())
        coverage["deferred"].append(
            {
                "id": "synthetic-follow-up",
                "reason": "Synthetic unfinished review.",
                "paths": ["src/extract.py"],
            }
        )
        coverage_path.write_text(json.dumps(coverage))
    subprocess.run([sys.executable, str(FINALIZER), "--scan-dir", str(directory)], check=True)
    run_workbench(state, "complete-scan", "--scan-id", later["scanId"])
    second = run_workbench(state, "get-scan", "--scan-id", later["scanId"])["scan"]["findings"][0]
    assert first["findingId"] == second["findingId"]
    if review == "reopened":
        run_workbench(
            state,
            "set-finding-triage",
            "--occurrence-id",
            second["occurrenceId"],
            "--status",
            "open",
        )

    result = run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        second["occurrenceId"],
        "--status",
        "closed",
        "--close-reason",
        "already_fixed",
        check=False,
    )
    if review == "complete":
        assert result["returncode"] == 0, result["stderr"]
    else:
        assert result["returncode"] != 0
        assert "Working-tree contents changed" in result["stderr"]
    finding = run_workbench(state, "get-scan", "--scan-id", earlier["scanId"])["scan"]["findings"][
        0
    ]
    assert finding["status"] == ("closed" if review == "complete" else "open")


def test_newer_stopped_recurrence_retains_completed_triage(tmp_path: Path) -> None:
    state, root, repository = tmp_path / "state", tmp_path / "scans", tmp_path / "repository"
    repository.mkdir()
    earlier = create_cli_scan(state, root, repository)
    finding = run_workbench(state, "get-scan", "--scan-id", earlier["scanId"])["scan"]["findings"][
        0
    ]
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        finding["occurrenceId"],
        "--status",
        "closed",
        "--close-reason",
        "wont_fix",
        "--note",
        "Synthetic accepted risk.",
    )
    stopped = create_cli_scan(state, root, repository, complete=False)
    directory = Path(stopped["scanDir"])
    write_completed_contract(directory, stopped["scanId"], repository)
    subprocess.run([sys.executable, str(FINALIZER), "--scan-dir", str(directory)], check=True)
    run_workbench(
        state, "fail-scan", "--scan-id", stopped["scanId"], "--message", "Synthetic interruption"
    )
    findings = run_workbench(state, "list-global-findings", "--include-resolved")["findings"]
    assert len(findings) == 1
    assert findings[0]["status"] == "closed"
    assert findings[0]["scanId"] == stopped["scanId"]
    assert findings[0]["occurrenceCount"] == 2
    assert findings[0]["knownScanIds"] == [earlier["scanId"], stopped["scanId"]]
