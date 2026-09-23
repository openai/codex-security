from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from workbench_test_support import create_saved_workspace, run_workbench, start_delivered_scan

OWNER = "dependency-submission-owner"
REQUEST = {
    "dependencies": [
        {
            "ecosystem": "npm",
            "registry": "https://registry.npmjs.org",
            "package": name,
            "oldVersion": None,
            "newVersion": "1.0.0",
        }
        for name in ("example-first", "example-second")
    ],
    "dependencyScanTarget": "malware-and-vulnerabilities",
}


def start_scan(tmp_path: Path, mode: str = "full_dependency") -> tuple[Path, str]:
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    workspace = create_saved_workspace(state, target, thread_id=OWNER, mode=mode)
    started = start_delivered_scan(state, "--workspace-id", str(workspace["id"]))
    return state, str(started["results"]["scanId"])


def claim(
    state: Path, scan_id: str, request: dict[str, object], *, check: bool = True
) -> dict[str, object]:
    return run_workbench(
        state,
        "claim-dependency-submission",
        "--scan-id",
        scan_id,
        "--thread-id",
        OWNER,
        "--request-json",
        json.dumps(request),
        check=check,
    )


def bind(state: Path, scan_id: str, *, check: bool = True) -> dict[str, object]:
    return run_workbench(
        state,
        "bind-dependency-job",
        "--scan-id",
        scan_id,
        "--thread-id",
        OWNER,
        "--job-id",
        "dps_fixture",
        check=check,
    )


def test_dependency_rejoin_requires_the_same_exact_request(tmp_path: Path) -> None:
    state, scan_id = start_scan(tmp_path)
    claim(state, scan_id, REQUEST)
    bind(state, scan_id)
    reordered = {**REQUEST, "dependencies": list(reversed(REQUEST["dependencies"]))}
    assert claim(state, scan_id, reordered)["scan"]["dependencyJobId"] == "dps_fixture"
    changed = {**REQUEST, "dependencies": [{**REQUEST["dependencies"][0], "newVersion": "2.0.0"}]}
    rejected = claim(state, scan_id, changed, check=False)
    assert rejected["returncode"] != 0
    assert "different dependency request" in rejected["stderr"]


def test_interrupted_submission_requires_recovering_the_existing_job(tmp_path: Path) -> None:
    state, scan_id = start_scan(tmp_path)
    claim(state, scan_id, REQUEST)
    rejected = claim(state, scan_id, REQUEST, check=False)
    assert rejected["returncode"] != 0
    assert "Recover and bind" in rejected["stderr"]
    bind(state, scan_id)
    assert claim(state, scan_id, REQUEST)["scan"]["dependencyJobId"] == "dps_fixture"


@pytest.mark.parametrize("state_change", ["complete", "failed", "canceled", "source_only"])
def test_dependency_submission_and_binding_require_an_active_dependency_scan(
    tmp_path: Path, state_change: str
) -> None:
    state, scan_id = start_scan(
        tmp_path, "standard" if state_change == "source_only" else "full_dependency"
    )
    if state_change != "source_only":
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE scans SET status = ?, canceled_at = ? WHERE id = ?",
                (
                    "failed" if state_change == "canceled" else state_change,
                    "2026-01-01T00:00:00Z" if state_change == "canceled" else None,
                    scan_id,
                ),
            )
    for result in (claim(state, scan_id, REQUEST, check=False), bind(state, scan_id, check=False)):
        assert result["returncode"] != 0
        assert "running scan with dependencies enabled" in result["stderr"]
