from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest


@pytest.fixture
def directory_aliases(tmp_path, monkeypatch, workbench_api):
    repository = tmp_path / "repository"
    repository.mkdir()
    stored = tmp_path / "stored-alias"
    requested = tmp_path / "requested-alias"
    for alias in (stored, requested):
        alias.symlink_to(repository, target_is_directory=True)
    assert stored.samefile(requested)
    original_resolve = Path.resolve

    def preserve_alias_spelling(path, *args, **kwargs):
        resolved = original_resolve(path, *args, **kwargs)
        return path if path in (stored, requested) else resolved

    # Emulate case-preserving resolution while retaining real directory metadata.
    monkeypatch.setattr(Path, "resolve", preserve_alias_spelling)
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript(
        "CREATE TABLE security_targets (id TEXT PRIMARY KEY, current_path TEXT);"
        "CREATE TABLE scans (id TEXT, target_id TEXT, target_path TEXT, "
        "target_device INTEGER, target_inode INTEGER, target_revision TEXT);"
    )
    from filesystem_identity import serialize_filesystem_identity

    metadata = repository.stat()
    identity = (
        serialize_filesystem_identity(metadata.st_dev),
        serialize_filesystem_identity(metadata.st_ino),
    )
    connection.execute("INSERT INTO security_targets VALUES (?, ?)", ("selected", str(stored)))
    for scan_id, device, inode in (
        ("previous-owner", -1, -1),
        ("current-owner", *identity),
        ("ambiguous-legacy", None, None),
    ):
        connection.execute(
            "INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, "selected", str(stored), device, inode, "unversioned"),
        )
    history = workbench_api["scan_history"]

    def selected_scans(path):
        clauses, values, _, _ = history.repository_scan_scope(connection, path)
        return [
            row["id"]
            for row in connection.execute(
                "SELECT id FROM scans WHERE " + " AND ".join(clauses), values
            )
        ]

    try:
        yield connection, repository, stored, requested, identity, selected_scans
    finally:
        connection.close()


def test_directory_alias_scope_keeps_only_the_current_ownership_epoch(directory_aliases):
    _, _, stored, requested, _, selected = directory_aliases
    assert selected(stored) == ["current-owner"]
    assert selected(requested) == ["current-owner"]


def test_exact_repository_path_precedes_a_same_directory_alias(directory_aliases):
    connection, _, _, requested, identity, selected = directory_aliases
    connection.execute("INSERT INTO security_targets VALUES (?, ?)", ("exact", str(requested)))
    connection.execute(
        "INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?)",
        ("exact-owner", "exact", str(requested), *identity, "unversioned"),
    )
    assert selected(requested) == ["exact-owner"]


@pytest.mark.parametrize("unavailable", ["missing", "replaced"])
def test_directory_alias_scope_rejects_an_unavailable_saved_owner(directory_aliases, unavailable):
    _, repository, stored, requested, _, selected = directory_aliases
    if unavailable == "missing":
        stored.unlink()
    else:
        repository.rename(repository.with_name("previous-directory"))
        repository.mkdir()
    assert selected(requested) == []
