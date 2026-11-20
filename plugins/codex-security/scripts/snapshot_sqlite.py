#!/usr/bin/env python3
"""Create a transactionally consistent SQLite database snapshot."""

from __future__ import annotations

import argparse
import ntpath
import os
import sqlite3
from pathlib import Path
from urllib.parse import quote

_WINDOWS_LONG_PATH_THRESHOLD = 248


def windows_long_path(path: Path | str) -> str:
    """Return a Win32 extended-length path on Windows when a path approaches MAX_PATH."""
    raw = os.fspath(path)
    if os.name != "nt":
        return raw
    if raw.startswith("\\\\?\\"):
        return raw
    resolved = ntpath.abspath(raw)
    if len(resolved) < _WINDOWS_LONG_PATH_THRESHOLD:
        return raw
    if resolved.startswith("\\\\"):
        return "\\\\?\\UNC\\" + resolved[2:]
    return "\\\\?\\" + resolved


def readonly_sqlite_uri(path: Path) -> str:
    """Escape the native filename, including separators, without introducing a URI authority."""
    filename: bytes | str = os.fsencode(path) if os.name == "posix" else windows_long_path(path)
    return f"file:{quote(filename, safe='')}?mode=ro"


def main() -> None:
    """Back up the read-only source database into a separate destination using SQLite’s backup API."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    source = args.source.expanduser().resolve(strict=True)
    destination = args.destination.expanduser().absolute()
    # SQLite backup cannot make progress when both connections use the same file.
    if destination.exists() and destination.samefile(source):
        parser.error(f"Destination must not be the same file as source: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(readonly_sqlite_uri(source), uri=True) as source_connection:
        creation_destination = destination.resolve()
        try:
            creation_destination.touch(mode=0o600, exist_ok=False)
        except FileExistsError:
            pass
        else:
            creation_destination.chmod(0o600)
        with sqlite3.connect(destination) as destination_connection:
            source_connection.backup(destination_connection)
    destination.chmod(0o600)


if __name__ == "__main__":
    main()
