"""Snapshot and restore scan outputs around publication transactions."""

from __future__ import annotations

import os
from pathlib import Path

from finalize_scan_contract import (
    ContractError,
    _remove_scan_local_file_if_exists,
    open_scan_local_file_descriptor,
    write_scan_local_bytes,
)

_PUBLISHED_OUTPUTS = (
    "findings.json",
    "coverage.json",
    "scan-manifest.json",
    "report.md",
    "threatmodel.md",
    "report.html",
    "exports/results.sarif",
)


def _snapshot_published_outputs(
    scan_dir: Path, relative_paths: tuple[str, ...] = _PUBLISHED_OUTPUTS
) -> dict[str, tuple[bytes, os.stat_result] | None]:
    snapshots: dict[str, tuple[bytes, os.stat_result] | None] = {}
    for relative in relative_paths:
        descriptor = -1
        try:
            descriptor = open_scan_local_file_descriptor(
                scan_dir, relative, "Published scan output"
            )
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                metadata = os.fstat(handle.fileno())
                snapshots[relative] = (handle.read(), metadata)
        except ContractError:
            path = scan_dir / relative
            if path.exists() or path.is_symlink():
                if relative == "threatmodel.md":
                    # This optional projection will not replace an unsafe destination.
                    continue
                raise
            snapshots[relative] = None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    return snapshots


def _restore_published_outputs(
    scan_dir: Path,
    snapshots: dict[str, tuple[bytes, os.stat_result] | None],
    created_paths: set[str] | None = None,
) -> None:
    for relative, snapshot in snapshots.items():
        if snapshot is None:
            path = scan_dir / relative
            if path.exists() or path.is_symlink():
                _remove_scan_local_file_if_exists(scan_dir, relative)
        else:
            contents, metadata = snapshot
            write_scan_local_bytes(scan_dir, relative, contents)
            os.utime(scan_dir / relative, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    for relative in sorted(created_paths or ()):
        # A journaled write can fail before creating its parent directory.
        path = scan_dir / relative
        if path.exists() or path.is_symlink():
            _remove_scan_local_file_if_exists(scan_dir, relative)
