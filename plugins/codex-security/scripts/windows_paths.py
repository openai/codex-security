"""Portable filesystem path spelling for Windows long-path support."""

from __future__ import annotations

import argparse
import os
import re
import string
from pathlib import Path

WINDOWS_DIRECTORY_PATH_LIMIT = 248
_NAMESPACE_PREFIXES = ("\\\\?\\", "\\\\.\\")
_DOS_DEVICE = re.compile(r"(?:AUX|CON|CONIN\$|CONOUT\$|NUL|PRN|(?:COM|LPT)[1-9¹²³])", re.ASCII)


def _ordinary_component(name: str) -> bool:
    # Verbatim paths bypass the DOS parsing of names, trailing dots/spaces and streams.
    return bool(
        name
        and not name.endswith((" ", "."))
        and not any(ord(c) < 32 or c in '<>:"|?*' for c in name)
        and not _DOS_DEVICE.fullmatch(name.partition(".")[0].rstrip(" ").upper())
    )


def extended_path(path: Path) -> Path:
    """Use absolute Win32 extended-length spelling for an equivalent filesystem path."""
    if os.name != "nt" or str(path).startswith(_NAMESPACE_PREFIXES):
        return path
    value = os.path.abspath(path)
    candidate = Path("\\\\?\\UNC\\" + value[2:] if value.startswith("\\\\") else "\\\\?\\" + value)
    return candidate if portable_path(candidate) != candidate else path


def filesystem_path(path: Path) -> Path:
    """Use Win32 extended-length spelling when a path is near legacy limits."""

    if os.name != "nt" or str(path).startswith(_NAMESPACE_PREFIXES):
        return path
    value = os.path.abspath(path)
    path_length = len(value.encode("utf-16-le", errors="surrogatepass")) // 2
    return extended_path(Path(value)) if path_length >= WINDOWS_DIRECTORY_PATH_LIMIT else path


def portable_path(path: Path) -> Path:
    """Remove an extended-length prefix only when DOS addresses the same path."""

    if os.name != "nt":
        return path
    value = str(path)
    if value[:8].lower() == "\\\\?\\unc\\":
        tail = value[8:].rstrip("\\")
        components = tail.split("\\")
        if len(components) >= 2 and all(_ordinary_component(part) for part in components):
            return Path("\\\\" + value[8:])
    elif value.startswith("\\\\?\\") and value[4:5] in string.ascii_letters and value[5:7] == ":\\":
        tail = value[7:]
        if not tail or all(_ordinary_component(part) for part in tail.split("\\")):
            return Path(value[4:])
    return path


def uses_windows_namespace(path: Path) -> bool:
    """Whether ordinary drive/UNC spelling cannot represent the selected object."""
    return os.name == "nt" and str(portable_path(path)).startswith(_NAMESPACE_PREFIXES)


def portable_relative_path(path: Path, root: Path) -> Path:
    if os.name == "nt" and path.anchor != root.anchor and path.is_absolute() and root.is_absolute():
        # An extended child can contain a verbatim-only name below an ordinary root.
        return extended_path(path).relative_to(extended_path(root))
    return path.relative_to(root)


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()
