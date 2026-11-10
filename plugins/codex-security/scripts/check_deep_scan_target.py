"""Reject registered Deep Scan targets containing only empty directories."""

from __future__ import annotations

import errno
import json
import os
import stat
import sys
from pathlib import Path


def check_selected_targets(root: Path, selections: list[str], file_paths: list[str]) -> None:
    files = set(file_paths)

    def check_path(selection: str) -> tuple[Path, bool]:
        relative = Path(selection)
        if (
            not selection
            or relative.anchor
            or ".." in relative.parts
            or (os.name == "nt" and ":" in selection)
        ):
            raise ValueError(f"Scope must be inside repo: {selection}")
        mode = root.lstat().st_mode
        if not stat.S_ISDIR(mode):
            raise ValueError(f"Deep Scan repository is no longer a directory: {root}")
        target = root
        for part in relative.parts:
            target /= part
            info = target.lstat()
            mode = info.st_mode
            if stat.S_ISLNK(mode) or getattr(info, "st_reparse_tag", 0) & 0x20000000:
                raise ValueError(f"Requested scope must not contain symbolic links: {target}")
        if not target.resolve(strict=True).is_relative_to(root):
            raise ValueError(f"Scope must be inside repo: {target}")
        regular = stat.S_ISREG(mode)
        if selection in files and not regular:
            raise ValueError(f"Selected file is no longer a regular file: {selection}")
        if not regular and not stat.S_ISDIR(mode):
            raise OSError(errno.ENOTDIR, "Expected a regular file or directory", str(target))
        return target, regular

    # Every selection must be valid, even when another file or directory is usable.
    for selection in selections:
        check_path(selection)

    def has_content(selection: str) -> bool:
        pending = [selection]
        failure = None
        while pending:
            current = pending.pop()
            try:
                target, regular = check_path(current)
                if regular:
                    return True
                with os.scandir(target) as entries:
                    for entry in entries:
                        if not entry.is_dir(follow_symlinks=False):
                            return True
                        # Preserve link entries as content without traversing their targets.
                        if (
                            getattr(entry.stat(follow_symlinks=False), "st_reparse_tag", 0)
                            & 0x20000000
                        ):
                            return True
                        pending.append(str(Path(entry.path).relative_to(root)))
            except OSError as exc:
                if failure is None:
                    failure = exc
        if failure is not None:
            raise failure
        return False

    failure = None
    for selection in selections:
        try:
            if has_content(selection):
                return
        except OSError as exc:
            if selection in files:
                raise
            if failure is None:
                failure = exc
    if failure is not None:
        raise failure
    raise ValueError("Deep Scan target is empty; no security audit was performed.")


if __name__ == "__main__":
    request = json.load(sys.stdin)
    try:
        check_selected_targets(
            Path(request["targetPath"]), request["includePaths"], request["filePaths"]
        )
    except (OSError, ValueError) as exc:
        sys.exit(str(exc))
