from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

CHECKER = Path(__file__).with_name("check_plugin_source_compatibility.py")


def initialize_repository(root: Path) -> None:
    subprocess.run(["git", "init", "--quiet", str(root)], check=True)


def track(root: Path, *paths: str) -> None:
    subprocess.run(["git", "-C", str(root), "add", "--", *paths], check=True)


def run_checker(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), "--plugin-root", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def test_reports_tracked_source_violations_in_stable_order(tmp_path: Path) -> None:
    (tmp_path / "notes.md").write_text(
        "This prose continues in the middle of a sentence\nonto another source line.\n",
        encoding="utf-8",
    )
    (tmp_path / "oversized.py").write_bytes(b"x" * 150_001)
    initialize_repository(tmp_path)
    track(tmp_path, "oversized.py", "notes.md")

    result = run_checker(tmp_path)

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.splitlines() == [
        "notes.md:1: prose is hard-wrapped mid-sentence; use a natural Markdown line",
        "oversized.py: file is 150001 bytes; maximum is 150000 bytes",
    ]


def test_accepts_valid_source_and_ignores_untracked_files(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("A complete sentence.\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_bytes(b"x" * 150_001)
    (tmp_path / "untracked.md").write_text(
        "This untracked prose continues\nonto another source line.\n",
        encoding="utf-8",
    )
    initialize_repository(tmp_path)
    track(tmp_path, "README.md", "package-lock.json")

    result = run_checker(tmp_path)

    assert result.returncode == 0, result.stderr
    assert result.stdout == "Plugin source compatibility checks passed.\n"
    assert result.stderr == ""


def test_python_checkout_preserves_source_size_with_autocrlf(tmp_path: Path) -> None:
    attributes = CHECKER.parents[2] / ".gitattributes"
    (tmp_path / ".gitattributes").write_bytes(attributes.read_bytes())
    source = tmp_path / "module.py"
    content = b"pass\n" * 30_000
    source.write_bytes(content)
    initialize_repository(tmp_path)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "--local", "core.autocrlf", "true"],
        check=True,
    )
    track(tmp_path, ".gitattributes", "module.py")
    source.unlink()
    subprocess.run(
        ["git", "-C", str(tmp_path), "checkout-index", "--", "module.py"],
        check=True,
    )

    result = run_checker(tmp_path)

    assert result.returncode == 0, result.stderr
    assert source.read_bytes() == content


def test_accepts_prose_after_an_opening_thematic_break(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text(
        """---
This prose continues
onto another source line.
""",
        encoding="utf-8",
    )
    initialize_repository(tmp_path)
    track(tmp_path, "README.md")

    result = run_checker(tmp_path)

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "content",
    [
        "First clause,\ncontinues here.\n",
        "First clause\n**continues** here.\n",
    ],
)
def test_accepts_wraps_adjacent_to_inline_markup(tmp_path: Path, content: str) -> None:
    (tmp_path / "README.md").write_text(content, encoding="utf-8")
    initialize_repository(tmp_path)
    track(tmp_path, "README.md")

    result = run_checker(tmp_path)

    assert result.returncode == 0, result.stderr


def test_rejects_dependency_lock_files_above_two_megabytes(tmp_path: Path) -> None:
    (tmp_path / "pnpm-lock.yaml").write_bytes(b"x" * 2_000_001)
    initialize_repository(tmp_path)
    track(tmp_path, "pnpm-lock.yaml")

    result = run_checker(tmp_path)

    assert result.returncode == 1
    assert result.stderr == ("pnpm-lock.yaml: file is 2000001 bytes; maximum is 2000000 bytes\n")


@pytest.mark.skipif(os.name == "nt", reason="creating symlinks requires elevated Windows access")
def test_does_not_follow_tracked_symlinks_outside_the_plugin(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.md"
    outside.write_text(
        "This outside prose continues\nonto another source line.\n",
        encoding="utf-8",
    )
    (tmp_path / "linked.md").symlink_to(outside)
    initialize_repository(tmp_path)
    track(tmp_path, "linked.md")

    result = run_checker(tmp_path)

    assert result.returncode == 0, result.stderr


def test_help_describes_the_source_contract() -> None:
    result = subprocess.run(
        [sys.executable, str(CHECKER), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "tracked plugin source" in result.stdout
