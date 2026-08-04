"""SQLite-safe serialization for platform filesystem identity values."""

from __future__ import annotations

import argparse


def serialize_filesystem_identity(value: int) -> int | str:
    """Preserve filesystem IDs that can exceed SQLite's signed 64-bit range.

    Python 3.12 can expose 64-bit device IDs and 128-bit inode IDs on Windows.
    Values that already fit remain integers for compatibility with older plugin
    versions. The prefix prevents SQLite from coercing larger hexadecimal values
    through the INTEGER affinity of the existing columns.
    """
    if -(1 << 63) <= value < (1 << 63):
        return value
    return f"stat:{value:x}"


def stored_filesystem_identity_matches(stored: object, current: int) -> bool:
    return stored == serialize_filesystem_identity(current)


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()
