#!/usr/bin/env python3
"""Check that tracked plugin source stays portable across repository imports."""

from __future__ import annotations

import argparse
import re
import stat
import subprocess
import sys
from pathlib import Path

MAX_SOURCE_FILE_BYTES = 150_000
MAX_DEPENDENCY_LOCK_BYTES = 2_000_000
DEPENDENCY_LOCK_NAMES = {
    "Cargo.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "requirements.txt",
    "uv.lock",
    "yarn.lock",
}
LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
HTML_BLOCK = re.compile(r"^\s*</?[A-Za-z][^>]*>\s*$")
NATURAL_LINE_ENDINGS = tuple(".?!:;。！？：；)]}'\"`>")


def tracked_files(plugin_root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "-C", str(plugin_root), "ls-files", "-z", "--", "."],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(detail or "git ls-files failed")
    return [Path(value.decode()) for value in sorted(result.stdout.split(b"\0")) if value]


def is_markdown_structure(line: str) -> bool:
    stripped = line.strip()
    return (
        not stripped
        or stripped.startswith(("#", ">", "|", "<!--", "::", "```", "~~~"))
        or stripped in {"---", "***", "___"}
        or HTML_BLOCK.match(stripped) is not None
        or line.startswith(("    ", "\t"))
    )


def line_ends_naturally(line: str) -> bool:
    stripped = line.rstrip()
    return (
        line.endswith("  ")
        or stripped.endswith(("\\", *NATURAL_LINE_ENDINGS))
        or re.search(r"https?://\S+$", stripped) is not None
    )


def hard_wrapped_lines(content: str) -> list[int]:
    lines = content.splitlines()
    offenders: list[int] = []
    in_fence = False
    in_frontmatter = content.startswith("---\n")

    for line_number, line in enumerate(lines[:-1], start=1):
        stripped = line.strip()
        if stripped.startswith(("```", "~~~")):
            in_fence = not in_fence
            continue
        if line_number > 1 and in_frontmatter and stripped == "---":
            in_frontmatter = False
            continue
        if in_fence or in_frontmatter:
            continue

        following_line = lines[line_number]
        following_stripped = following_line.strip()
        if is_markdown_structure(line) or is_markdown_structure(following_line):
            continue
        if LIST_ITEM.match(following_line) or line_ends_naturally(line):
            continue
        if re.search(r"[A-Za-z0-9`]$", stripped) is None:
            continue
        if re.match(r"[A-Za-z0-9`(]", following_stripped) is None:
            continue
        offenders.append(line_number)

    return offenders


def source_compatibility_errors(plugin_root: Path) -> list[str]:
    errors: list[str] = []
    for relative_path in tracked_files(plugin_root):
        path = plugin_root / relative_path
        if not stat.S_ISREG(path.lstat().st_mode):
            continue

        maximum = (
            MAX_DEPENDENCY_LOCK_BYTES
            if relative_path.name in DEPENDENCY_LOCK_NAMES
            else MAX_SOURCE_FILE_BYTES
        )
        size = path.stat().st_size
        if size > maximum:
            errors.append(
                f"{relative_path.as_posix()}: file is {size} bytes; maximum is {maximum} bytes"
            )

        if relative_path.suffix.lower() != ".md":
            continue
        for line_number in hard_wrapped_lines(path.read_text(encoding="utf-8")):
            errors.append(
                f"{relative_path.as_posix()}:{line_number}: prose is hard-wrapped "
                "mid-sentence; use a natural Markdown line"
            )

    return sorted(errors)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check tracked plugin source for deterministic import compatibility."
    )
    parser.add_argument(
        "--plugin-root",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "plugins" / "codex-security",
        help="plugin source root (default: plugins/codex-security in this repository)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    plugin_root = args.plugin_root.resolve()
    try:
        errors = source_compatibility_errors(plugin_root)
    except (OSError, RuntimeError, UnicodeError) as exc:
        print(f"source compatibility check failed: {exc}", file=sys.stderr)
        return 2

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    print("Plugin source compatibility checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
