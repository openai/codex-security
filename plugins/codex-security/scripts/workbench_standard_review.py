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
    offline_git_bytes,
    requested_exclude_paths,
    requested_scan_paths,
)
from workbench_target import (
    SOURCE_METADATA_DIRECTORIES,
    checked_scan_target,
    directory_content_digest,
    path_in_scopes,
)


def _permits_crlf_normalization(target: Path, path: str) -> bool:
    """Ask Git whether its indexed blob permits CRLF normalization without invoking filters."""
    metadata = offline_git_bytes(target, "ls-files", "--eol", "-z", "--", path)
    fields = (metadata or b"").partition(b"\t")[0].split()
    if len(fields) < 3:
        return False
    indexed, working, attribute = fields[:3]
    if attribute == b"attr/text":
        return True
    if indexed in (b"i/crlf", b"i/mixed") or working not in (b"w/crlf", b"w/mixed"):
        return False
    if attribute == b"attr/text=auto":
        return True
    if attribute == b"attr/":
        autocrlf = offline_git_bytes(
            target, "config", "--type=bool-or-str", "--get", "core.autocrlf"
        )
        return (autocrlf or b"").strip().lower() in (b"true", b"input")
    return False


def _git_file_digest(target: Path, path: str, blob: str) -> str:
    descriptor = open_scan_local_file_descriptor(target, path, "reviewed file", portable=False)
    with os.fdopen(descriptor, "rb") as stream:
        for normalize in (False, True):
            if normalize:
                if not _permits_crlf_normalization(target, path):
                    break
                blob_size = offline_git_bytes(target, "cat-file", "-s", blob)
                if blob_size is None:
                    break
                size = int(blob_size)
                stream.seek(0)
            else:
                size = os.fstat(stream.fileno()).st_size
            identity = hashlib.new(
                "sha1" if len(blob) == 40 else "sha256",
                f"blob {size}\0".encode(),
                usedforsecurity=False,
            )
            content = hashlib.sha256()
            pending = b""
            while block := stream.read(1024 * 1024):
                content.update(block)
                if normalize:
                    block = pending + block
                    pending = b"\r" if block.endswith(b"\r") else b""
                    block = block.removesuffix(pending).replace(b"\r\n", b"\n")
                identity.update(block)
            identity.update(pending)
            if identity.hexdigest() == blob:
                return content.hexdigest()
    raise SystemExit(f"Reviewed file no longer matches its registered Git blob: {path}")


def _require_scope(scan: sqlite3.Row, paths: set[str], includes: list[str]) -> None:
    exclusions = requested_exclude_paths(scan)
    for path in paths:
        if not path_in_scopes(path, includes) or path_in_scopes(path, exclusions):
            raise SystemExit(f"Reviewed file is outside the registered scope: {path}")


def _directory_receipts(scan: sqlite3.Row, target: Path, paths: set[str]) -> dict[str, str]:
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
                _require_scope(scan, paths, requested)
                return _directory_receipts(scan, target, paths)
            context = (
                load_source_scopes(scan, target, requested) if scan["source_scopes_json"] else None
            )
            if context is None:
                raise SystemExit(
                    "Cannot bind reviewed files to a saved Git tree. Use a clean checkout for file receipts."
                )
            repository, tree, scopes = context
            _require_scope(scan, paths, [scope["canonicalPath"] for scope in scopes])
            files = {}
            for path in paths:
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
