from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from workbench_test_support import run_workbench


def register_scan(
    state_dir: Path, repository: Path, scan_dir: Path, *arguments: str
) -> dict[str, object]:
    return run_workbench(
        state_dir,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(scan_dir),
        "--recipe-json",
        json.dumps(
            {
                "config": {},
                "mode": "standard",
                "repository": str(repository),
                "target": {"kind": "repository", "paths": []},
            }
        ),
        *arguments,
    )


def test_archived_output_preserves_old_scan_and_allows_fresh_registration(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    scan_dir = tmp_path / "scan"
    repository.mkdir()
    scan_dir.mkdir(mode=0o700)
    previous = register_scan(state_dir, repository, scan_dir)
    run_workbench(
        state_dir,
        "fail-scan",
        "--scan-id",
        str(previous["scanId"]),
        "--message",
        "The previous scan was interrupted.",
    )
    (scan_dir / "previous.txt").write_text("keep the previous scan\n")
    report_path = scan_dir / "report.md"
    report_path.write_text("# Previous scan\n")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "INSERT INTO scan_artifacts (scan_id, kind, path, created_at) VALUES (?, ?, ?, ?)",
            (
                str(previous["scanId"]),
                "markdownReport",
                str(report_path),
                "2026-08-13T00:00:00Z",
            ),
        )
    archived_scan_dir = tmp_path / "scan.previous-test"
    scan_dir.rename(archived_scan_dir)
    scan_dir.mkdir(mode=0o700)

    current = register_scan(
        state_dir,
        repository,
        scan_dir,
        "--archive-existing",
        "--archived-scan-dir",
        str(archived_scan_dir),
    )

    assert current["scanId"] != previous["scanId"]
    assert current["scanDir"] == str(scan_dir)
    assert (archived_scan_dir / "previous.txt").read_text() == "keep the previous scan\n"
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT scan_dir, status FROM scans WHERE id = ?",
            (str(previous["scanId"]),),
        ).fetchone() == (str(archived_scan_dir), "failed")
        assert connection.execute(
            "SELECT scan_dir, status FROM scans WHERE id = ?",
            (str(current["scanId"]),),
        ).fetchone() == (str(scan_dir), "running")
        assert connection.execute(
            "SELECT path FROM scan_artifacts WHERE scan_id = ?",
            (str(previous["scanId"]),),
        ).fetchone() == (str(archived_scan_dir / "report.md"),)


def test_empty_failed_scan_can_be_archived_and_reused(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    scan_dir = tmp_path / "scan"
    repository.mkdir()
    scan_dir.mkdir(mode=0o700)
    previous = register_scan(state_dir, repository, scan_dir)
    run_workbench(
        state_dir,
        "fail-scan",
        "--scan-id",
        str(previous["scanId"]),
        "--message",
        "The previous scan failed before writing artifacts.",
    )

    current = register_scan(state_dir, repository, scan_dir, "--archive-existing")

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        previous_directory = connection.execute(
            "SELECT scan_dir FROM scans WHERE id = ?", (str(previous["scanId"]),)
        ).fetchone()
    assert previous_directory is not None
    archived_scan_dir = Path(previous_directory[0])
    assert archived_scan_dir.parent == scan_dir.parent
    assert archived_scan_dir.name.startswith("scan.previous-")
    assert archived_scan_dir.is_dir()
    assert not any(archived_scan_dir.iterdir())
    assert current["scanDir"] == str(scan_dir)


def test_archive_requires_previous_directory_when_artifacts_exist(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    scan_dir = tmp_path / "scan"
    repository.mkdir()
    scan_dir.mkdir(mode=0o700)
    previous = register_scan(state_dir, repository, scan_dir)
    run_workbench(
        state_dir,
        "fail-scan",
        "--scan-id",
        str(previous["scanId"]),
        "--message",
        "The previous scan was interrupted.",
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "INSERT INTO scan_artifacts (scan_id, kind, path, created_at) VALUES (?, ?, ?, ?)",
            (
                str(previous["scanId"]),
                "markdownReport",
                str(scan_dir / "report.md"),
                "2026-08-13T00:00:00Z",
            ),
        )

    rejected = run_workbench(
        state_dir,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(scan_dir),
        "--recipe-json",
        json.dumps(
            {
                "config": {},
                "mode": "standard",
                "repository": str(repository),
                "target": {"kind": "repository", "paths": []},
            }
        ),
        "--archive-existing",
        check=False,
    )

    assert rejected["returncode"] != 0
    assert "archived scan directory is required" in str(rejected["stderr"])


def test_archive_does_not_replace_a_running_scan(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    scan_dir = tmp_path / "scan"
    repository.mkdir()
    scan_dir.mkdir(mode=0o700)
    previous = register_scan(state_dir, repository, scan_dir)

    rejected = run_workbench(
        state_dir,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(scan_dir),
        "--recipe-json",
        json.dumps(
            {
                "config": {},
                "mode": "standard",
                "repository": str(repository),
                "target": {"kind": "repository", "paths": []},
            }
        ),
        "--archive-existing",
        check=False,
    )

    assert rejected["returncode"] != 0
    assert "Cannot archive the output of a running scan." in str(rejected["stderr"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT scan_dir, status FROM scans WHERE id = ?", (str(previous["scanId"]),)
        ).fetchone() == (str(scan_dir), "running")
