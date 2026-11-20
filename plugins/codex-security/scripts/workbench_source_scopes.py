"""Bind finding excerpts and file review receipts to the sources selected at scan start."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
from functools import cache
from pathlib import Path, PurePosixPath
from typing import Any
from unicodedata import normalize

sys.path.insert(0, str(Path(__file__).resolve().parent))
from workbench_target import (
    SOURCE_METADATA_DIRECTORIES,
    checked_scan_target,
    clean_worktree_content_digest,
    directory_content_digest,
    git_command,
    git_worktree_context,
    open_review_source,
    path_in_scopes,
)
from workbench_validation import reject_non_finite_json

OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


def expected_target_kinds(scan: sqlite3.Row) -> list[str]:
    """Return the manifest target kinds compatible with the stored scan mode, revision, and snapshot digest."""
    if scan["mode"] == "diff":
        return ["git_diff"]
    if scan["target_revision"] == "unversioned":
        return ["directory_snapshot"]
    if scan["target_snapshot_digest"] is None:
        return ["git_worktree", "git_revision"]
    if scan["target_snapshot_digest"] == clean_worktree_content_digest():
        return ["git_revision"]
    return ["git_worktree"]


def requested_scan_paths(scan: sqlite3.Row) -> list[str]:
    """Return the explicit paths in the saved launch recipe, falling back to the scan’s original scope."""
    if "recipe_json" in scan.keys() and scan["recipe_json"] is not None:
        recipe = json.loads(scan["recipe_json"], parse_constant=reject_non_finite_json)
        target = recipe["target"]
        if target["kind"] == "paths":
            return target["paths"]
    return [scan["scope"]]


def requested_exclude_paths(scan: sqlite3.Row) -> list[str]:
    if scan["recipe_json"] is None:
        return []
    return json.loads(scan["recipe_json"], parse_constant=reject_non_finite_json).get(
        "excludePaths", []
    )


def public_scan_recipe(scan: sqlite3.Row) -> dict[str, Any]:
    """Return the decoded launch recipe with the internal file-scope metadata removed."""
    recipe = json.loads(scan["recipe_json"], parse_constant=reject_non_finite_json)
    recipe.pop("_codexSecurityFileScopes", None)
    return recipe


def normalized_path_component(value: str) -> str:
    return normalize("NFC", normalize("NFD", value).casefold())


def relative_path(value: str) -> PurePosixPath | None:
    path = PurePosixPath(value)
    return None if "\\" in value or path.is_absolute() or ".." in path.parts else path


def safe_source_path(target: Path, value: str) -> Path | None:
    """Resolve a repository-relative POSIX path and return None if it is invalid or resolves outside the target."""
    parsed = relative_path(value)
    if parsed is None:
        return None
    try:
        path = (target / parsed.as_posix()).resolve()
        path.relative_to(target)
        return path
    except (OSError, RuntimeError, ValueError):
        return None


def offline_git_bytes(repository: Path, *arguments: str) -> bytes | None:
    """Return raw stdout for a successful offline Git command with replacement objects disabled, otherwise None."""
    result = git_command(
        repository,
        *arguments,
        text=False,
        offline=True,
        environment_overrides={"GIT_NO_REPLACE_OBJECTS": "1"},
    )
    return result.stdout if result.returncode == 0 else None


@cache
def tree_entries(repository: Path, tree: str) -> dict[str, tuple[tuple[str, str, str], ...]] | None:
    """Index a Git tree by normalized name, retaining every original name, entry kind, and object ID in each group."""
    content = offline_git_bytes(repository, "ls-tree", "-z", tree)
    if content is None:
        return None
    entries: dict[str, list[tuple[str, str, str]]] = {}
    for record in content.split(b"\0"):
        if not record:
            continue
        metadata, separator, name = record.partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3:
            return None
        mode, object_type, raw_object = fields
        object_id = raw_object.decode("ascii")
        if not OBJECT_ID.fullmatch(object_id):
            return None
        kind = (
            "directory"
            if mode == b"040000" and object_type == b"tree"
            else "file"
            if mode in {b"100644", b"100755"} and object_type == b"blob"
            else "other"
        )
        decoded_name = os.fsdecode(name)
        entries.setdefault(normalized_path_component(decoded_name), []).append(
            (decoded_name, kind, object_id)
        )
    return {name: tuple(matches) for name, matches in entries.items()}


def exact_tree_path(repository: Path, tree: str, value: str) -> tuple[str, str, str] | None:
    path = relative_path(value)
    if path is None:
        return None
    kind, object_id = "directory", tree
    for name in path.parts:
        if kind != "directory":
            return None
        entries = tree_entries(repository, object_id) or {}
        aliases = entries.get(normalized_path_component(name), ())
        if len(aliases) != 1:
            return None
        entry_name, kind, object_id = aliases[0]
        if entry_name != name:
            return None
    return path.as_posix(), kind, object_id


def ordinary_path(metadata: os.stat_result) -> bool:
    return not (
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    ) and (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode))


def filesystem_alias(selected: Path, candidate: Path) -> bool:
    if normalized_path_component(selected.name) != normalized_path_component(candidate.name):
        return False
    try:
        if not all(ordinary_path(path.lstat()) for path in (selected, candidate)):
            return False
        if not selected.samefile(candidate):
            return False
        with os.scandir(selected.parent) as entries:
            return (
                sum(
                    normalized_path_component(entry.name)
                    == normalized_path_component(selected.name)
                    for entry in entries
                )
                == 1
            )
    except OSError:
        return False


def existing_tree_path(
    repository: Path, tree: str, value: str, filesystem_root: Path
) -> tuple[str, str, str] | None:
    path = relative_path(value)
    if path is None:
        return None
    canonical: list[str] = []
    kind, object_id = "directory", tree
    for index, name in enumerate(path.parts, start=1):
        if kind != "directory":
            return None
        entries = tree_entries(repository, object_id) or {}
        aliases = entries.get(normalized_path_component(name), ())
        selected = filesystem_root / PurePosixPath(*path.parts[:index])
        matches = []
        try:
            if not ordinary_path(selected.lstat()):
                return None
            for entry in aliases:
                candidate = filesystem_root / PurePosixPath(*canonical, entry[0])
                # Every colliding Git name needs a filesystem witness. Missing
                # names cannot establish which entry the user selected.
                if not ordinary_path(candidate.lstat()):
                    return None
                if selected.samefile(candidate) and (
                    entry[0] == name or filesystem_alias(selected, candidate)
                ):
                    matches.append(entry)
        except OSError:
            return None
        if len(matches) != 1:
            return None
        name, kind, object_id = matches[0]
        canonical.append(name)
    return PurePosixPath(*canonical).as_posix(), kind, object_id


def target_tree(target: Path, revision: str) -> tuple[Path, str] | None:
    repository, prefix = git_worktree_context(target)
    raw_tree = offline_git_bytes(repository, "rev-parse", "--verify", f"{revision}^{{tree}}")
    tree = raw_tree.decode("ascii").strip() if raw_tree is not None else ""
    if not OBJECT_ID.fullmatch(tree):
        return None
    selected = existing_tree_path(repository, tree, prefix, repository)
    if selected is None or selected[1] != "directory":
        return None
    return repository, selected[2]


def capture_source_scopes(
    target: Path,
    target_identity: tuple[str, str | None, int | str, int | str],
    paths: list[str],
    *,
    diff_target_kind: str | None = None,
) -> dict[str, Any]:
    """Bind requested paths to the local Git objects that may supply excerpts later.

    Return the revision and the file or tree IDs that can be verified locally.
    A working-tree diff, dirty snapshot, or replacement ref leaves the scope list
    empty. A path that cannot be bound adds no authority to read other paths.
    """
    revision, snapshot = target_identity[:2]
    result: dict[str, Any] = {"version": 1, "revision": revision, "scopes": []}
    # HEAD cannot represent the uncommitted bytes reviewed by a working-tree scan.
    if diff_target_kind == "working_tree":
        return result
    if revision == "unversioned" or (
        snapshot is not None and snapshot != clean_worktree_content_digest()
    ):
        return result
    try:
        repository, _ = git_worktree_context(target)
        if offline_git_bytes(repository, "replace", "--list") != b"":
            # A revision alone does not identify the replacement view scanned.
            return result
        context = target_tree(target, revision)
        if context is None:
            return result
        repository, tree = context
        result["targetTree"] = tree
        for requested in paths:
            selected = safe_source_path(target, requested)
            if selected is None:
                continue
            canonical = existing_tree_path(repository, tree, requested, target)
            if canonical is None or canonical[1] not in {"file", "directory"}:
                continue
            try:
                metadata = selected.stat()
            except OSError:
                continue
            if (canonical[1] == "directory") != stat.S_ISDIR(metadata.st_mode):
                continue
            result["scopes"].append(
                {
                    "path": PurePosixPath(requested).as_posix(),
                    "canonicalPath": canonical[0],
                    "kind": canonical[1],
                    "objectId": canonical[2],
                }
            )
    except (OSError, RuntimeError, SystemExit, UnicodeError, ValueError):
        # Excerpts are optional. Failure to bind a scope never widens it and
        # must not prevent the scan itself from starting.
        pass
    return result


def load_source_scopes(
    scan: sqlite3.Row, target: Path, requested: list[str]
) -> tuple[Path, str, list[dict[str, str]]] | None:
    """Return the repository, tree ID, and valid source scopes, or None when none can be established.

    Use saved object IDs for current records. For a legacy scan, reconstruct only
    unambiguous entries from its original revision and respect any recorded file kinds.
    """
    kind = scan["diff_target_kind"] if "diff_target_kind" in scan.keys() else None
    if kind == "working_tree" or (
        "mode" in scan.keys() and scan["mode"] == "diff" and kind not in ("commit", "range")
    ):
        return None
    saved = scan["source_scopes_json"] if "source_scopes_json" in scan.keys() else None
    paths = {PurePosixPath(path).as_posix() for path in requested}
    if saved is not None:
        metadata = json.loads(saved)
        if (
            not isinstance(metadata, dict)
            or metadata.get("version") != 1
            or metadata.get("revision") != scan["target_revision"]
        ):
            return None
        tree = metadata.get("targetTree")
        records = metadata.get("scopes")
        if (
            not isinstance(tree, str)
            or not OBJECT_ID.fullmatch(tree)
            or not isinstance(records, list)
        ):
            return None
        scopes = [
            record
            for record in records
            if isinstance(record, dict)
            and isinstance(record.get("path"), str)
            and record.get("path") in paths
            and isinstance(record.get("canonicalPath"), str)
            and relative_path(record["canonicalPath"]) is not None
            and record.get("kind") in ("file", "directory")
            and isinstance(record.get("objectId"), str)
            and OBJECT_ID.fullmatch(record["objectId"])
        ]
        return (git_worktree_context(target)[0], tree, scopes) if scopes else None

    # Exact, unambiguous historical entries establish legacy scope kinds.
    # Keep any previously recorded file kinds as an additional constraint.
    recipe = scan["recipe_json"] if "recipe_json" in scan.keys() else None
    legacy_recipe = json.loads(recipe) if recipe else None
    legacy_files = (
        legacy_recipe.get("_codexSecurityFileScopes") if isinstance(legacy_recipe, dict) else None
    )
    repository, _ = git_worktree_context(target)
    if offline_git_bytes(repository, "replace", "--list") != b"":
        # Old records do not say which replacement view was scanned.
        return None
    context = target_tree(target, scan["target_revision"])
    if context is None:
        return None
    repository, tree = context
    scopes = []
    for path in paths:
        entry = exact_tree_path(repository, tree, path)
        if entry is None or entry[1] not in {"file", "directory"}:
            continue
        kind = entry[1]
        if isinstance(legacy_files, list) and kind != (
            "file" if path in legacy_files else "directory"
        ):
            continue
        scopes.append(
            {
                "path": path,
                "canonicalPath": path,
                "kind": kind,
                "objectId": entry[2],
            }
        )
    return (repository, tree, scopes) if scopes else None


def source_object_for_path(
    repository: Path, tree: str, target: Path, value: str, scope: dict[str, str]
) -> str | None:
    """Return the Git blob ID for a file covered by the recorded scope, or None if the path cannot be verified."""
    path = relative_path(value)
    if path is None or safe_source_path(target, value) is None:
        return None
    prefixes = {PurePosixPath(scope[name]).parts for name in ("path", "canonicalPath")}
    suffix: tuple[str, ...] | None = None
    for prefix in sorted(prefixes, key=len, reverse=True):
        if path.parts[: len(prefix)] == prefix:
            suffix = path.parts[len(prefix) :]
            break
    if suffix is None:
        for length in {len(prefix) for prefix in prefixes}:
            if length > len(path.parts) or scope["kind"] == "file" and length != len(path.parts):
                continue
            selected = existing_tree_path(
                repository, tree, PurePosixPath(*path.parts[:length]).as_posix(), target
            )
            if selected == (scope["canonicalPath"], scope["kind"], scope["objectId"]):
                suffix = path.parts[length:]
                break
    if suffix is None:
        return None
    if scope["kind"] == "file":
        return scope["objectId"] if not suffix else None
    relative = PurePosixPath(*suffix).as_posix()
    entry = exact_tree_path(repository, scope["objectId"], relative)
    if entry is None:
        selected = safe_source_path(target, scope["canonicalPath"])
        if selected is not None:
            entry = existing_tree_path(repository, scope["objectId"], relative, selected)
    return entry[2] if entry is not None and entry[1] == "file" else None


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
    with open_review_source(target, path) as stream:
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
    from finalize_scan_contract import ContractError, _require_safe_relative_path

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


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()
