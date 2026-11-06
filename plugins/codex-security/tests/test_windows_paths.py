from __future__ import annotations

import ntpath
import os
import sqlite3
import subprocess
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


@pytest.mark.parametrize(
    "value",
    [
        "//?/C:/checkout./source",
        "//?/C:/checkout /source",
        "//?/C:/AUX.txt/source",
        "//?/C:/LPT¹ .log",
        "//?/C:/dir/file:stream",
        "//?/UNC/server/share/checkout.",
        "//?/UNC/./pipe/name",
        "//?/Volume{123}/source",
        "//./pipe/name",
    ],
)
def test_verbatim_only_names_preserve_their_namespace(windows_paths, value):
    path = PureWindowsPath(value)
    assert windows_paths.uses_windows_namespace(path)
    assert windows_paths.portable_path(path) == path
    assert windows_paths.filesystem_path(path) == path
    assert windows_paths.extended_path(path) == path


def test_windows_path_conversion_keeps_relative_spelling_and_literal_leaf(windows_paths):
    name = PureWindowsPath("sub/source.py")
    assert windows_paths.filesystem_path(name) == name
    checkout = PureWindowsPath("C:/checkout")
    literal = PureWindowsPath("//?/C:/checkout/reports.")
    assert windows_paths.portable_relative_path(literal, checkout) == PureWindowsPath("reports.")
    assert windows_paths.portable_is_relative_to(literal / "tool.exe", checkout)
    assert not windows_paths.portable_is_relative_to(literal, checkout / "reports")
    assert windows_paths.extended_path(checkout / "reports.") == checkout / "reports."
    assert not windows_paths.uses_windows_namespace(windows_paths.extended_path(checkout))


@pytest.mark.native_windows
@pytest.mark.skipif(os.name != "nt", reason="requires Windows namespace I/O")
def test_target_rejects_verbatim_only_sibling_without_changing_its_identity(tmp_path):
    paths = load_script("windows_paths")
    setup = load_script("workbench_setup")
    ordinary = tmp_path / "reports"
    ordinary.mkdir()
    literal = paths.extended_path(tmp_path) / "reports."
    literal.mkdir()
    try:
        assert not literal.samefile(ordinary)
        assert paths.portable_path(literal).samefile(literal)
        assert setup.require_target(str(ordinary)).samefile(ordinary)
        with pytest.raises(SystemExit, match="ordinary Windows drive or UNC"):
            setup.require_target(str(literal))
    finally:
        literal.rmdir()


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


@pytest.mark.native_windows
@pytest.mark.skipif(os.name != "nt", reason="requires native Windows path spelling")
def test_git_snapshot_digest_is_independent_of_root_spelling(tmp_path: Path):
    paths = load_script("windows_paths")
    target = load_script("workbench_target")
    subprocess.run(["git", "-C", str(tmp_path), "init", "-q"], check=True)
    (tmp_path / "z.txt").write_text("short")
    nested = tmp_path
    while len(str(nested / "a.txt")) < paths.WINDOWS_DIRECTORY_PATH_LIMIT:
        nested /= "alpha-" * 6
    paths.filesystem_path(nested).mkdir(parents=True, exist_ok=True)
    paths.filesystem_path(nested / "a.txt").write_text("long")
    assert target.directory_content_digest(tmp_path) == target.directory_content_digest(
        paths.extended_path(tmp_path)
    )


@pytest.mark.native_windows
@pytest.mark.skipif(os.name != "nt", reason="requires native Windows path spelling")
def test_git_discovery_rejects_a_tool_under_a_verbatim_only_directory(tmp_path, monkeypatch):
    paths = load_script("windows_paths")
    target = load_script("workbench_target")
    literal = paths.extended_path(tmp_path) / "tools."
    literal.mkdir()
    candidate = literal / "git.exe"
    try:
        candidate.touch()
        monkeypatch.setenv("CODEX_SECURITY_GIT", str(candidate))
        with pytest.raises(SystemExit, match="outside the protected repository"):
            target.trusted_git_executable(tmp_path)
    finally:
        candidate.unlink(missing_ok=True)
        literal.rmdir()


@pytest.mark.cross_platform
@pytest.mark.parametrize("extended_worker", [False, True])
def test_saved_worker_results_accept_mixed_scan_root_spellings(tmp_path, extended_worker):
    paths = load_script("windows_paths")
    sources = load_script("workbench/saved_sources")
    ordinary = paths.portable_path(tmp_path)
    extended = paths.extended_path(ordinary)
    root, stored = (ordinary, extended) if extended_worker else (extended, ordinary)
    worker = {
        "kind": "discovery",
        "artifact_dir": str(stored / "worker" / "output"),
        "result_manifest_path": str(stored / "worker" / "last-result.json"),
        "attempt": 2,
    }
    receipts = load_script("workbench_coverage_receipts")
    assert (
        receipts.resolve_coverage_receipts(
            root, {"receiptRefs": []}, worker, "worker/output/result.json"
        )
        == []
    )
    assert sources._worker_outputs(root, worker) == [("worker/output", 2)]
    assert ("worker/last-result.json", "discovery") in list(
        sources._saved_result_paths(root, [worker])
    )
    with pytest.raises(ValueError):
        sources._worker_outputs(root, {**worker, "artifact_dir": str(stored.parent / "sibling")})
