"""Identify Markdown instructions in a plugin installation selected by the scan host."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from pathlib import Path, PurePosixPath
from typing import Any

from finalize_scan_contract import (
    _open_posix_file_with_path,
    _read_scan_local_json_bytes,
    open_scan_local_file_descriptor,
)
from workbench_constants import ARTIFACTS


def scan_instruction_digests(connection: sqlite3.Connection, scan: sqlite3.Row) -> list[str] | None:
    if (prepared := scan["prepared_instruction_digests_json"]) is not None:
        return json.loads(prepared)
    parent = scan["instruction_digest"]
    if parent is None:
        return None
    digests = [parent]
    if scan["mode"] == "deep":
        workers = connection.execute(
            """
            SELECT instruction_digest FROM deep_scan_workers
            WHERE scan_id = ? AND kind IN ('discovery', 'dedup') AND started_at IS NOT NULL
            GROUP BY instruction_digest
            -- A whole UTC second sorts before its fractions once the trailing Z is removed.
            ORDER BY MIN(rtrim(started_at, 'Z')), instruction_digest
            """,
            (scan["id"],),
        )
        for (digest,) in workers:
            if digest is None:
                return None
            if digest != parent:
                digests.append(digest)
    return digests


def pin_prepared_instruction_digests(
    connection: sqlite3.Connection, scan_id: str, producer: dict[str, Any]
) -> None:
    connection.execute(
        """UPDATE scans SET prepared_instruction_digests_json = ?
           WHERE id = ? AND prepared_instruction_digests_json IS NULL""",
        (json.dumps(producer.get("instructionDigests")), scan_id),
    )


def verify_sealed_instruction_digests(
    scan: sqlite3.Row, manifest_scan: dict[str, Any], connection: sqlite3.Connection
) -> None:
    # SQL NULL is unprepared. JSON null pins the absence of a list in an admitted seal.
    prepared = scan["prepared_instruction_digests_json"]
    producer = manifest_scan.get("producer")
    if prepared is not None:
        if not isinstance(producer, dict) or json.loads(prepared) != producer.get(
            "instructionDigests"
        ):
            raise SystemExit("manifest.scan.producer.instructionDigests changed after preparation.")
    elif isinstance(producer, dict) and "instructionDigests" in producer:
        if (recorded := scan["seal_manifest_digest"]) is not None:
            manifest, raw = _read_scan_local_json_bytes(
                Path(scan["scan_dir"]), ARTIFACTS["manifest"], "scan manifest"
            )
            if (
                f"sha256:{hashlib.sha256(raw).hexdigest()}" != recorded
                or manifest.get("scan") != manifest_scan
            ):
                raise SystemExit("The sealed scan manifest changed after completion.")
        elif producer["instructionDigests"] != scan_instruction_digests(connection, scan):
            raise SystemExit(
                "manifest.scan.producer.instructionDigests must match the workbench scan."
            )


def selected_instruction_digest(expected_sources: dict[str, str] | None = None) -> str | None:
    return bundled_instruction_digest(
        os.environ.get("_CODEX_SECURITY_INSTRUCTION_ROOT"), expected_sources=expected_sources
    )


def _open_instruction_file(root: Path, relative: PurePosixPath) -> int:
    context = "plugin instructions"
    if os.name == "posix" and os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW"):
        return _open_posix_file_with_path(root, relative, context)[0]
    return open_scan_local_file_descriptor(root, relative.as_posix(), context)


def _file_stamp(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _instruction_inventory(root: Path) -> dict[str, tuple[int, ...]] | None:
    # Use the stored names for digest paths. Decline installations whose layout
    # requires filesystem aliases to locate the instruction directories.
    entries = {entry.name for entry in root.iterdir()}
    if not {"skills", "references"} <= entries:
        return None
    pending = [root / "skills", root / "references"]
    if not all(stat.S_ISDIR(directory.lstat().st_mode) for directory in pending):
        return None
    files = {}
    while pending:
        path = pending.pop()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or (
            getattr(metadata, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
        ):
            return None
        if stat.S_ISDIR(metadata.st_mode):
            pending.extend(path.iterdir())
        elif path.name.lower().endswith(".md"):
            if not stat.S_ISREG(metadata.st_mode):
                return None
            relative = path.relative_to(root).as_posix()
            if os.name == "posix" and os.fsencode(relative) != relative.encode("utf-8"):
                return None
            if relative in files:
                return None
            files[relative] = _file_stamp(metadata)
    return files


def bundled_instruction_digest(
    root: str | Path | None,
    deep_role_digests: dict[str, str] | None = None,
    *,
    expected_sources: dict[str, str] | None = None,
) -> str | None:
    """Hash the selected bundle; unknown or unreadable installations have no measurement."""
    if not root or not Path(root).is_absolute() or ".." in Path(root).parts:
        return None
    try:
        selected = Path(root)
        root = selected.resolve(strict=True)
        installation = root.stat()
        compiled: dict[str, bytes] = {}
        if deep_role_digests is not None:
            # Earlier coordinators also supplied a compiled reducer template.
            roles = ("discovery", "dedup") if "dedup" in deep_role_digests else ("discovery",)
            for role in roles:
                value = deep_role_digests.get(role)
                if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                    return None
                compiled[f"references/deep-scan/{role}.md"] = bytes.fromhex(value)

        inventory = _instruction_inventory(root)
        if inventory is None:
            return None
        # A role present under a filesystem alias has no unambiguous logical name.
        if any(path not in inventory and (root / path).exists() for path in compiled):
            return None
        files = compiled.copy()
        for relative in inventory:
            if relative in compiled:
                continue  # Deep uses its compiled role prompts.
            descriptor = _open_instruction_file(root, PurePosixPath(relative))
            digest = hashlib.sha256()
            with os.fdopen(descriptor, "rb") as source:
                opened = _file_stamp(os.fstat(descriptor))
                # Windows path and descriptor stats can report different ctime values.
                if opened[:-1] != inventory[relative][:-1]:
                    return None
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
                if _file_stamp(os.fstat(descriptor)) != opened:
                    return None
            files[relative] = digest.digest()
        if expected_sources and any(
            path not in files or files[path].hex() != expected
            for path, expected in expected_sources.items()
        ):
            return None
        # A release update can also replace individual files inside the selected root.
        if (
            not files
            or _instruction_inventory(root) != inventory
            or not os.path.samestat(installation, selected.stat())
        ):
            return None
        bundle = hashlib.sha256()
        for relative, content_digest in sorted(files.items()):
            bundle.update(relative.encode("utf-8") + b"\0" + content_digest)
        return f"sha256:{bundle.hexdigest()}"
    except (OSError, ValueError, RuntimeError):
        return None
