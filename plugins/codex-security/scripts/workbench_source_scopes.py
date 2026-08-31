"""Bind optional finding excerpts to the Git objects selected at scan start."""

from __future__ import annotations

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
    clean_worktree_content_digest,
    git_bytes,
    git_worktree_context,
)

OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


def normalized_path_component(value: str) -> str:
    return normalize("NFC", normalize("NFD", value).casefold())


def relative_path(value: str) -> PurePosixPath | None:
    path = PurePosixPath(value)
    return None if "\\" in value or path.is_absolute() or ".." in path.parts else path


def safe_source_path(target: Path, value: str) -> Path | None:
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
    names = ("GIT_NO_LAZY_FETCH", "GIT_ALLOW_PROTOCOL", "GIT_NO_REPLACE_OBJECTS")
    previous = {name: os.environ.get(name) for name in names}
    os.environ["GIT_NO_LAZY_FETCH"] = "1"
    os.environ["GIT_ALLOW_PROTOCOL"] = ""
    os.environ["GIT_NO_REPLACE_OBJECTS"] = "1"
    try:
        return git_bytes(repository, *arguments)
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


@cache
def tree_entries(repository: Path, tree: str) -> dict[str, tuple[tuple[str, str, str], ...]] | None:
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


def exact_tree_path(
    repository: Path, tree: str, value: str, *, require_unambiguous: bool = False
) -> tuple[str, str, str] | None:
    path = relative_path(value)
    if path is None:
        return None
    kind, object_id = "directory", tree
    for name in path.parts:
        if kind != "directory":
            return None
        entries = tree_entries(repository, object_id) or {}
        aliases = entries.get(normalized_path_component(name), ())
        if require_unambiguous and len(aliases) != 1:
            return None
        entry = next((entry for entry in aliases if entry[0] == name), None)
        if entry is None:
            return None
        _, kind, object_id = entry
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
    if "diff_target_kind" in scan.keys() and scan["diff_target_kind"] == "working_tree":
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
        entry = exact_tree_path(repository, tree, path, require_unambiguous=True)
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
    entry = exact_tree_path(repository, scope["objectId"], relative, require_unambiguous=True)
    if entry is None:
        selected = safe_source_path(target, scope["canonicalPath"])
        if selected is not None:
            entry = existing_tree_path(repository, scope["objectId"], relative, selected)
    return entry[2] if entry is not None and entry[1] == "file" else None
