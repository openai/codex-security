from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SDK_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "stage_release", SDK_ROOT / "scripts/stage_release.py"
)
assert SPEC is not None and SPEC.loader is not None
stage_release_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stage_release_module)


def _source_tree(root: Path) -> Path:
    source = root / "source"
    source.mkdir()
    (source / "pyproject.toml").write_text(
        '[project]\nname = "openai-codex-security"\nversion = "0.0.0-dev"\n',
        encoding="utf-8",
    )
    (source / "uv.lock").write_text(
        '[[package]]\nname = "openai-codex-security"\nversion = "0.0.0.dev0"\n',
        encoding="utf-8",
    )
    (source / "src").mkdir()
    (source / "src/package.py").write_text("VALUE = 1\n", encoding="utf-8")
    return source


def test_stage_release_rewrites_versions(tmp_path: Path) -> None:
    destination = tmp_path / "stage"
    stage_release_module.stage_release(_source_tree(tmp_path), destination, "0.1.0b1")

    assert 'version = "0.1.0b1"' in (destination / "pyproject.toml").read_text()
    assert 'version = "0.1.0b1"' in (destination / "uv.lock").read_text()
    assert (destination / "src/package.py").is_file()


def test_stage_release_rejects_non_beta_versions(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="beta versions"):
        stage_release_module.stage_release(_source_tree(tmp_path), tmp_path / "stage", "1.0.0")


def test_stage_release_does_not_overwrite(tmp_path: Path) -> None:
    destination = tmp_path / "stage"
    destination.mkdir()
    with pytest.raises(FileExistsError, match="already exists"):
        stage_release_module.stage_release(_source_tree(tmp_path), destination, "0.1.0b1")
