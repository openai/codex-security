"""Bind explicit Standard review declarations to bytes in the registered scan target."""

from __future__ import annotations

import argparse
import hashlib
import os
import sqlite3
import sys
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))
from finalize_scan_contract import (
    ContractError,
    _require_safe_relative_path,
    open_scan_local_file_descriptor,
)
from workbench_source_scopes import (
    existing_tree_path,
    load_source_scopes,
    requested_scan_paths,
)
from workbench_target import (
    SOURCE_METADATA_DIRECTORIES,
    checked_scan_target,
    directory_content_digest,
)


def _git_file_digest(target: Path, path: str, blob: str) -> str:
    descriptor = open_scan_local_file_descriptor(target, path, "reviewed file", portable=False)
    with os.fdopen(descriptor, "rb") as stream:
        size = os.fstat(stream.fileno()).st_size
        identity = hashlib.new(
            "sha1" if len(blob) == 40 else "sha256",
            f"blob {size}\0".encode(),
            usedforsecurity=False,
        )
        content = hashlib.sha256()
        while block := stream.read(1024 * 1024):
            identity.update(block)
            content.update(block)
    if identity.hexdigest() != blob:
        raise SystemExit(f"Reviewed file no longer matches its registered Git blob: {path}")
    return content.hexdigest()


def _directory_receipts(
    scan: sqlite3.Row, target: Path, paths: set[str], scopes: set[PurePosixPath]
) -> dict[str, str]:
    for path in paths:
        entry = PurePosixPath(path)
        if not any(entry.is_relative_to(scope) for scope in scopes):
            raise SystemExit(f"Reviewed file is outside the registered scope: {path}")
    files = dict.fromkeys(paths, "")
    digest = directory_content_digest(
        target, excluded=(Path(scan["scan_dir"]),), capture_file_digests=files
    )
    if digest != scan["target_snapshot_digest"]:
        raise SystemExit(
            "Reviewed files do not match the registered directory snapshot. Start a new scan."
        )
    for path, value in files.items():
        if not value:
            raise SystemExit(
                f"Reviewed file is not a regular file in the registered snapshot: {path}"
            )
    return files


def review_file_digests(scan: sqlite3.Row, reviewed_files: list[str]) -> dict[str, str]:
    """Return SHA-256 by distinct declared path after verifying its saved scope and source bytes."""
    if not isinstance(reviewed_files, list):
        raise SystemExit("reviewedFiles must be a list of repository-relative paths.")
    if not reviewed_files:
        return {}
    if scan["mode"] != "standard":
        raise SystemExit("Reviewed files can only be declared for a Standard scan.")
    try:
        paths = set()
        for path in reviewed_files:
            if _require_safe_relative_path(
                path, "reviewed file"
            ) != path or not SOURCE_METADATA_DIRECTORIES.isdisjoint(PurePosixPath(path).parts):
                raise SystemExit(f"Expected a canonical repository-relative reviewed file: {path}")
            paths.add(path)
        requested = requested_scan_paths(scan)
        with checked_scan_target(scan) as target:
            if scan["target_revision"] == "unversioned":
                return _directory_receipts(
                    scan, target, paths, {PurePosixPath(s) for s in requested}
                )
            context = (
                load_source_scopes(scan, target, requested) if scan["source_scopes_json"] else None
            )
            if context is None:
                raise SystemExit(
                    "Cannot bind reviewed files to a saved Git tree. Use a clean checkout for file receipts."
                )
            repository, tree, scopes = context
            files = {}
            for path in paths:
                relative = PurePosixPath(path)
                if not any(
                    relative == PurePosixPath(scope["canonicalPath"])
                    or scope["kind"] == "directory"
                    and relative.is_relative_to(scope["canonicalPath"])
                    for scope in scopes
                ):
                    raise SystemExit(f"Reviewed file is outside the registered scope: {path}")
                entry = existing_tree_path(repository, tree, path, target)
                if entry is None or entry[:2] != (path, "file"):
                    raise SystemExit(
                        f"Reviewed file is not a regular file in the registered Git tree: {path}"
                    )
                files[path] = _git_file_digest(target, path, entry[2])
            return files
    except (ContractError, OSError) as exc:
        raise SystemExit(f"Could not verify reviewed file: {exc}") from exc


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
