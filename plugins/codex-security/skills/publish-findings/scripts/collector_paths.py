"""Identify the selected source checkout and paths it controls."""

import os
import stat
from pathlib import Path


def is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or (
        os.name == "nt" and info.st_reparse_tag == stat.IO_REPARSE_TAG_MOUNT_POINT
    )


def source_root(target: Path | None) -> Path | None:
    if target is not None and (not target.is_absolute() or not target.is_dir()):
        raise ValueError("Select an existing absolute source directory.")
    source = (target or Path.cwd()).resolve()
    # A nested checkout or submodule is still part of the enclosing source tree.
    for parent in (*reversed(source.parents), source):
        marker = parent / ".git"
        try:
            info = marker.lstat()
            if stat.S_ISDIR(info.st_mode) and not is_link(info):
                info = (marker / "HEAD").lstat()
        except (FileNotFoundError, NotADirectoryError):
            continue
        if stat.S_ISREG(info.st_mode) or is_link(info):
            return parent
    return source if target is not None else None


def in_source(path: Path, source: Path | None) -> bool:
    if source is None:
        return False
    if path.is_relative_to(source):
        return True
    identity = source.stat()
    current = Path()
    parts = list(reversed(path.absolute().parts))
    active_links = set()
    while parts:
        part = parts.pop()
        if isinstance(part, Path):
            # The link target's components have all been checked.
            active_links.remove(part)
            continue
        current = current.parent if part == ".." else current / part
        if current == source:
            return True
        try:
            info = current.lstat()
        except (FileNotFoundError, NotADirectoryError):
            continue
        if os.path.samestat(info, identity):
            return True
        if is_link(info):
            if current in active_links:
                raise OSError(f"Symbolic link loop at {current}")
            active_links.add(current)
            parts.append(current)
            parts.extend(reversed(current.readlink().parts))
            current = current.parent
    return False
