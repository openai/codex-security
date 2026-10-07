#!/usr/bin/env python3
"""Create a transactionally consistent SQLite database snapshot."""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path


def main() -> None:
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
    with sqlite3.connect(f"{source.as_uri()}?mode=ro", uri=True) as source_connection:
        with sqlite3.connect(destination) as destination_connection:
            source_connection.backup(destination_connection)
    destination.chmod(0o600)


if __name__ == "__main__":
    main()
