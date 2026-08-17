"""Portable filesystem path spelling for Windows long-path support."""

from __future__ import annotations

import os
from pathlib import Path

WINDOWS_DIRECTORY_PATH_LIMIT = 248


def extended_path(path: Path) -> Path:
    """Use absolute Win32 extended-length spelling for a filesystem path."""
    if os.name != "nt":
        return path
    value = os.path.abspath(path)
    if value.startswith("\\\\?\\"):
        return Path(value)
    if value.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + value[2:])
    return Path("\\\\?\\" + value)


def filesystem_path(path: Path) -> Path:
    """Use Win32 extended-length spelling when a path is near legacy limits."""

    if os.name != "nt":
        return path
    value = os.path.abspath(path)
    path_length = len(value.encode("utf-16-le")) // 2
    if value.startswith("\\\\?\\") or path_length >= WINDOWS_DIRECTORY_PATH_LIMIT:
        return extended_path(Path(value))
    return Path(value)


def portable_path(path: Path) -> Path:
    """Remove Win32 extended-length spelling before persisting a path."""

    value = str(path)
    if os.name != "nt":
        return path
    if value.startswith("\\\\?\\UNC\\"):
        return Path("\\\\" + value[8:])
    if value.startswith("\\\\?\\"):
        return Path(value[4:])
    return path
