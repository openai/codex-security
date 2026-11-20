"""Storage paths shared by workbench persistence and MCP artifact selection."""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

if os.name == "nt":
    import windows_scan_local_files as windows_files


def state_dir(*, canonical: bool = True) -> Path:
    """Return the workbench state path, resolving symlinks unless canonical is false."""
    configured = os.environ.get("CODEX_SECURITY_STATE_DIR")
    if configured:
        path = Path(configured).expanduser()
    else:
        codex_home = Path(
            os.environ["CODEX_HOME"] if os.environ.get("CODEX_HOME", "").strip() else "~/.codex"
        ).expanduser()
        path = codex_home / "state" / "plugins" / "codex-security"
    return path.resolve() if canonical else path.absolute()


def resolve_scan_root(scan_root: str | None) -> Path:
    """Resolve an explicit scan output root, defaulting to the scans directory under workbench state."""
    return Path(scan_root).expanduser().resolve() if scan_root else state_dir() / "scans"


def worker_usage_directory(scan_id: str) -> Path:
    """Bind host-observed receipts beneath the persistent protected native home."""
    return state_dir() / "codex-home" / "worker-usage" / scan_id


def _ordinary_windows_name(name: str) -> bool:
    from finalize_scan_contract import _windows_unsafe_path_component

    return (
        name not in {".", ".."}
        and not _windows_unsafe_path_component(name)
        and not _windows_unsafe_path_component(name.partition(".")[0].rstrip(" "))
    )


def scan_directory_spellings(directory: Path) -> tuple[Path, ...]:
    """Return equivalent ordinary and extended Win32 names for a workbench directory."""
    if os.name != "nt":
        return (directory,)
    from windows_scan_local_files import _extended_path

    value = str(directory)
    if value[:8].upper() == "\\\\?\\UNC\\":
        alternate = Path("\\\\" + value[8:])
    elif re.fullmatch(r"\\\\\?\\[A-Za-z]:", directory.drive):
        alternate = Path(value[4:])
    elif value.startswith(("\\\\?\\", "\\\\.\\")):
        return (directory,)
    else:
        alternate = Path(_extended_path(directory))

    ordinary = alternate if value.startswith("\\\\?\\") else directory
    parts = ordinary.parts[1:]
    if ordinary.drive.startswith("\\\\"):
        server, share = ordinary.drive[2:].split("\\", 1)
        if server in {".", "?"}:
            return (directory,)
        parts = (server, share, *parts)
    if not all(_ordinary_windows_name(name) for name in parts):
        # DOS may name a different object. Accept an alias only if both handles agree.
        try:
            equivalent = directory.samefile(alternate)
        except OSError:
            equivalent = False
        if not equivalent:
            return (directory,)
    # Safe components identify the same destination even when legacy policy prevents
    # opening the ordinary spelling or the original leaf is absent during restoration.
    return directory, alternate


def same_directory_spelling(path: Path, other: Path) -> bool | None:
    """Compare one namespace spelling, verifying different casing on the filesystem."""
    if str(path) == str(other):
        return True
    if path != other:
        return False
    for candidate in scan_directory_spellings(path):
        for reference in scan_directory_spellings(other):
            try:
                return candidate.samefile(reference)
            except OSError:
                continue
    return None


def scan_relative_path(path: Path, scan_dir: Path) -> Path:
    for root in scan_directory_spellings(scan_dir):
        if path.is_relative_to(root):
            relative = path.relative_to(root)
            if ".." not in relative.parts:
                return relative
    raise ValueError("Path must be inside the scan directory.")


def worker_contract_relative_path(path: Path, scan_dir: Path) -> Path:
    relative = scan_relative_path(path, scan_dir)
    if Path(path.anchor) != Path(scan_dir.anchor) and not all(
        _ordinary_windows_name(name) for name in relative.parts
    ):
        raise ValueError("Verbatim-only worker paths cannot be opened through another namespace.")
    return relative


def require_worker_path(path: Path, scan_dir: Path) -> None:
    """Corroborate the physical scan root when a resolved worker path uses another spelling."""
    relative = scan_relative_path(path, scan_dir)
    parent = path.parents[len(relative.parts) - 1] if relative.parts else path
    if str(parent) != str(scan_dir) and not parent.samefile(scan_dir):
        raise ValueError("Worker artifact does not belong to the scan directory.")


def relocate_scan_artifact(
    scan_dir: Path, archive: Path, value: str | None, *, keep_extended: bool = False
) -> str | None:
    """Keep extended access after archive growth, preserving namespace-specific filenames."""
    if value is None:
        return None
    path = Path(value)
    try:
        relative = scan_relative_path(path, scan_dir)
    except ValueError:
        return value
    if (
        keep_extended
        and str(archive).startswith("\\\\?\\")
        and all(_ordinary_windows_name(name) for name in relative.parts)
    ):
        # A short root can have descendants whose new paths exceed MAX_PATH.
        return str(archive / relative)
    for spelling in scan_directory_spellings(archive):
        if Path(spelling.anchor) == Path(path.anchor):
            archive = spelling
            break
    relocated = archive / relative
    if (
        os.name == "nt"
        and len(str(relocated).encode("utf-16-le", errors="surrogatepass")) // 2 >= 260
    ):
        for candidate in scan_directory_spellings(relocated):
            if str(candidate).startswith("\\\\?\\"):
                return str(candidate)
    return str(relocated)


def short_archive_prefix(original_name: str) -> str:
    """Bind a short archive name to the complete original filename."""
    return f".previous-{hashlib.sha256(os.fsencode(original_name)).hexdigest()}-"


def archive_source_directory(archive: Path, source: Path) -> Path | None:
    """Return the original sibling when the archived name identifies it."""
    if not source.is_relative_to(archive.parent):
        return None
    parts = source.relative_to(archive.parent).parts
    if not parts or ".." in parts:
        return None
    parent = source.parents[len(parts) - 1]
    if not same_directory_spelling(parent, archive.parent):
        return None
    name = parts[0]
    original = parent / name
    if archive.name[len(name) :].startswith(".previous-") and same_directory_spelling(
        original, parent / archive.name[: len(name)]
    ):
        return original
    if archive.name.startswith(".previous-") and archive.name.startswith(
        short_archive_prefix(name)
    ):
        return original
    return None


def archived_deep_path(scan_dir: Path, value: str | None) -> str | None:
    """Resolve old archive rows that still name the original sibling output."""
    if value is None or ".previous-" not in scan_dir.name:
        return value
    path = Path(value)
    for parent in scan_directory_spellings(scan_dir.parent):
        original = archive_source_directory(parent / scan_dir.name, path)
        if original is not None:
            # Missing files belong to the archive, too.
            return relocate_scan_artifact(original, scan_dir, value)
    return value


def saved_deep_workers(connection: sqlite3.Connection, scan: sqlite3.Row) -> list[Any]:
    workers = connection.execute(
        "SELECT * FROM deep_scan_workers WHERE scan_id = ? ORDER BY created_at, id",
        (scan["id"],),
    ).fetchall()
    scan_dir = Path(scan["scan_dir"])
    if ".previous-" not in scan_dir.name:
        return workers
    return [
        {
            **worker,
            **{
                key: archived_deep_path(scan_dir, worker[key])
                for key in ("artifact_dir", "prompt_path", "result_manifest_path")
            },
        }
        for worker in workers
    ]


def create_private_directory(path: Path, *, scan_output: bool = False) -> None:
    """Create missing directories privately without changing existing permissions."""
    if path.parent != path and not path.parent.is_dir():
        create_private_directory(path.parent, scan_output=scan_output)
    if os.name != "nt":
        path.mkdir(mode=0o700, exist_ok=True)
    elif not path.is_dir():
        windows_files.create_private_directory(path, exist_ok=True, scan_output=scan_output)
    elif scan_output:
        windows_files.require_windows_output_path(path)


def create_private_temporary_directory(parent: Path, *, prefix: str) -> Path:
    """Create a unique private child without inheriting a permissive Windows DACL."""
    if os.name != "nt":
        return Path(tempfile.mkdtemp(prefix=prefix, dir=parent)).resolve()

    import secrets

    for _ in range(100):
        path = parent / f"{prefix}{secrets.token_hex(4)}"
        try:
            return windows_files.create_private_directory(path, exist_ok=False, scan_output=True)
        except FileExistsError:
            continue
    raise FileExistsError(f"Could not create a unique directory beneath {parent}.")
