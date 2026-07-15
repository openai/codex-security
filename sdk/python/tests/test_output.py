from __future__ import annotations

from pathlib import Path

import pytest

from openai_codex_security import OutputDirectoryError
from openai_codex_security.runtime import prepare_output_dir, validate_output_dir


def test_output_dir_may_be_absent_or_empty(tmp_path: Path) -> None:
    absent = tmp_path / "scan"
    assert prepare_output_dir(absent, "repo") == absent.resolve()

    empty = tmp_path / "empty"
    empty.mkdir()
    assert prepare_output_dir(empty, "repo") == empty.resolve()


def test_output_dir_rejects_existing_content(tmp_path: Path) -> None:
    path = tmp_path / "scan"
    path.mkdir()
    (path / "old.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(OutputDirectoryError, match="empty"):
        prepare_output_dir(path, "repo")


def test_output_dir_rejects_file_parent(tmp_path: Path) -> None:
    parent = tmp_path / "not-a-directory"
    parent.write_text("file\n", encoding="utf-8")

    with pytest.raises(OutputDirectoryError, match="Unable to create"):
        prepare_output_dir(parent / "scan", "repo")


def test_output_validation_does_not_create_absent_directory(tmp_path: Path) -> None:
    path = tmp_path / "new-parent" / "scan"

    assert validate_output_dir(path) == path.resolve()
    assert not path.exists()


def test_implicit_output_dir_persists() -> None:
    path = prepare_output_dir(None, "sample")
    assert path.is_dir()
    assert "codex-security-sample-" in path.name
