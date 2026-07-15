from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path

PROJECT_NAME = "openai-codex-security"
VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+b[0-9]+")
IGNORED_NAMES = frozenset({".pytest_cache", ".ruff_cache", ".venv", "build", "dist"})


def stage_release(source: Path, destination: Path, version: str) -> Path:
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("Release versions must be beta versions such as 0.1.0b1.")
    if destination.exists():
        raise FileExistsError(f"Release stage already exists: {destination}")

    shutil.copytree(source, destination, ignore=shutil.ignore_patterns(*IGNORED_NAMES))
    _rewrite_project_version(destination / "pyproject.toml", version)
    lock_path = destination / "uv.lock"
    if lock_path.is_file():
        _rewrite_lock_version(lock_path, version)
    return destination


def _rewrite_project_version(path: Path, version: str) -> None:
    text = path.read_text(encoding="utf-8")
    rewritten, count = re.subn(
        r'(?m)^version = "0\.0\.0-dev"$',
        f'version = "{version}"',
        text,
    )
    if count != 1:
        raise ValueError(f"Expected one development project version in {path}.")
    path.write_text(rewritten, encoding="utf-8")


def _rewrite_lock_version(path: Path, version: str) -> None:
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(
        rf'(\[\[package\]\]\nname = "{re.escape(PROJECT_NAME)}"\nversion = ")[^"]+(")',
    )
    match = pattern.search(text)
    if match is None:
        raise ValueError(f"Could not find the project package in {path}.")
    start, end = match.span()
    rewritten = text[:start] + match.group(1) + version + match.group(2) + text[end:]
    path.write_text(rewritten, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stage a Codex Security Python release.")
    parser.add_argument("destination", type=Path)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--version", required=True)
    args = parser.parse_args(argv)
    stage_release(args.source.resolve(), args.destination.resolve(), args.version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
