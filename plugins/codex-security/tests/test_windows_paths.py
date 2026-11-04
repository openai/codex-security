from __future__ import annotations

import ntpath
import os
import sqlite3
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

import pytest
from test_workbench_scan_archive import register_scan
from workbench_test_support import fail_scan, load_script, run_workbench


@pytest.fixture
def windows_paths(monkeypatch):
    module = load_script("windows_paths")
    monkeypatch.setattr(module, "Path", PureWindowsPath)
    monkeypatch.setattr(module, "os", SimpleNamespace(name="nt", path=ntpath))
    return module


@pytest.mark.parametrize("root", ["C:/", "//server/share/"])
@pytest.mark.parametrize("character", ["a", "\U0001f600", "\ud800"])
def test_filesystem_path_counts_utf16_units_and_preserves_spelling(windows_paths, root, character):
    prefix = str(PureWindowsPath(root))
    units = len(character.encode("utf-16-le", errors="surrogatepass")) // 2
    for length in (247, 248):
        count, remainder = divmod(length - len(prefix), units)
        path = PureWindowsPath(prefix + character * count + "a" * remainder)
        expected = windows_paths.extended_path(path) if length == 248 else path
        assert windows_paths.filesystem_path(path) == expected
        assert windows_paths.portable_path(windows_paths.extended_path(path)) == path
        assert windows_paths.extended_path(
            windows_paths.extended_path(path)
        ) == windows_paths.extended_path(path)
        assert windows_paths.portable_relative_path(
            windows_paths.extended_path(path / "child"), path
        ) == PureWindowsPath("child")


def test_target_lookup_preserves_both_legacy_ids_after_a_path_spelling_collision(
    windows_paths, monkeypatch, workbench_db
):
    targets = load_script("workbench_target_state")
    monkeypatch.setattr(targets, "Path", PureWindowsPath)
    monkeypatch.setattr(targets, "portable_path", windows_paths.portable_path)
    monkeypatch.setattr(targets, "extended_path", windows_paths.extended_path)
    path = PureWindowsPath("C:/repository")
    alias = windows_paths.extended_path(path)
    for target_id, stored_path in (("original", alias), ("current", path)):
        workbench_db.execute(
            "INSERT INTO security_targets (id, current_path, display_name, created_at, updated_at) "
            "VALUES (?, ?, 'Repository', '2026-01-01', '2026-01-01')",
            (target_id, str(stored_path)),
        )
    assert targets.ensure_security_target(workbench_db, str(alias)) == "current"
    assert (
        targets.ensure_security_target(workbench_db, str(path), preferred_target_id="original")
        == "original"
    )
    assert {
        tuple(row) for row in workbench_db.execute("SELECT id, current_path FROM security_targets")
    } == {("original", str(alias)), ("current", str(path))}


@pytest.mark.native_windows
@pytest.mark.skipif(os.name != "nt", reason="exercise native Win32 files and SQLite paths")
def test_long_scan_archive_and_history_accept_legacy_extended_paths(tmp_path: Path):
    paths = load_script("windows_paths")
    root = tmp_path
    while len(str(root)) < 270:
        root = root / ("long-directory-" * 3)
    repository, state_dir, output = (root / part for part in ("repository", "state", "output"))
    paths.filesystem_path(repository).mkdir(parents=True)
    paths.filesystem_path(output).mkdir()
    first = register_scan(state_dir, repository, output)
    scan_id = first["scanId"]
    fail_scan(state_dir, scan_id, "Archive the previous run")
    paths.filesystem_path(output / "report.md").write_text("# Previous review\n")
    database = paths.filesystem_path(state_dir / "workbench.sqlite3")
    with sqlite3.connect(database) as connection:
        target_id = connection.execute(
            "SELECT target_id FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()[0]
        repository_alias = str(paths.extended_path(repository))
        connection.execute(
            "UPDATE security_targets SET current_path = ? WHERE id = ?",
            (repository_alias, target_id),
        )
        connection.execute(
            "UPDATE scans SET target_path = ?, scan_dir = ? WHERE id = ?",
            (repository_alias, str(paths.extended_path(output)), scan_id),
        )
        connection.execute(
            "INSERT INTO scan_artifacts (scan_id, kind, path, created_at) VALUES (?, ?, ?, ?)",
            (
                scan_id,
                "markdownReport",
                str(paths.extended_path(output / "report.md")),
                "2026-08-13T00:00:00Z",
            ),
        )
    for spelling in [repository, paths.extended_path(repository)]:
        listed = run_workbench(state_dir, "list-scans", "--repository", str(spelling))["scans"]
        assert [scan["scanId"] for scan in listed] == [scan_id]

    archived = root / "output.previous-test"
    paths.filesystem_path(output).rename(paths.filesystem_path(archived))
    paths.filesystem_path(output).mkdir()
    current = register_scan(
        state_dir, repository, output, "--archive-existing", "--archived-scan-dir", str(archived)
    )
    assert current["scanDir"] == str(output)
    assert current["archivedScanDir"] == str(archived)
    assert paths.filesystem_path(archived / "report.md").read_text() == "# Previous review\n"
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT scan_dir FROM scans WHERE id = ?", (scan_id,)
        ).fetchone() == (str(archived),)
        assert connection.execute(
            "SELECT path FROM scan_artifacts WHERE scan_id = ?", (scan_id,)
        ).fetchone() == (str(archived / "report.md"),)
