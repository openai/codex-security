"""Portable filesystem path spelling for Windows long-path support."""

from __future__ import annotations

import argparse
import os
import string
from pathlib import Path

WINDOWS_DIRECTORY_PATH_LIMIT = 248


def extended_path(path: Path) -> Path:
    """Use absolute Win32 extended-length spelling for a filesystem path."""
    if os.name != "nt":
        return path
    value = os.path.abspath(path)
    if value.startswith(("\\\\?\\", "\\\\.\\")):
        return Path(value)
    if value.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + value[2:])
    return Path("\\\\?\\" + value)


def filesystem_path(path: Path) -> Path:
    """Use Win32 extended-length spelling when a path is near legacy limits."""

    if os.name != "nt":
        return path
    value = os.path.abspath(path)
    path_length = len(value.encode("utf-16-le", errors="surrogatepass")) // 2
    if value.startswith("\\\\?\\") or path_length >= WINDOWS_DIRECTORY_PATH_LIMIT:
        return extended_path(Path(value))
    return path


def portable_path(path: Path) -> Path:
    """Remove Win32 extended-length spelling before persisting a path."""

    if os.name != "nt":
        return path
    value = str(path)
    if value[:8].lower() == "\\\\?\\unc\\":
        return Path("\\\\" + value[8:])
    if value.startswith("\\\\?\\") and value[4:5] in string.ascii_letters and value[5:7] == ":\\":
        return Path(value[4:])
    return path


def portable_relative_path(path: Path, root: Path) -> Path:
    return portable_path(path).relative_to(portable_path(root))


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()
