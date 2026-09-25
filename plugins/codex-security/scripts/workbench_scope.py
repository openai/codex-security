"""Validate literal directory selections while preserving legacy scalar scopes."""

import json
import os
from pathlib import Path


def require_scope(scope: str, mode: str, target: Path) -> str:
    value = scope.strip() or "."
    requested_scope = Path(value)
    if "\\" in value and (os.name != "nt" or not requested_scope.is_absolute()):
        raise SystemExit("Scan scope must use repository-relative POSIX paths.")
    if ".." in requested_scope.parts:
        raise SystemExit("Scan scope must stay inside the scanned target.")
    try:
        resolved_scope = (
            requested_scope if requested_scope.is_absolute() else target / requested_scope
        ).resolve()
        relative_scope = resolved_scope.relative_to(target)
    except (RuntimeError, ValueError) as exc:
        raise SystemExit("Scan scope must stay inside the scanned target.") from exc
    normalized = relative_scope.as_posix() or "."
    if mode == "deep" and normalized != ".":
        raise SystemExit("Deep Scan is repository-wide and cannot use a scoped path.")
    if not resolved_scope.is_dir():
        raise SystemExit("Scan scope must reference an existing directory inside the target.")
    return normalized


def require_include_paths(value: str, target: Path) -> list[str]:
    try:
        paths = json.loads(value)
    except ValueError as exc:
        raise SystemExit("include_paths must be a JSON array of directories.") from exc
    if not isinstance(paths, list) or not 1 <= len(paths) <= 32:
        raise SystemExit("include_paths must contain between 1 and 32 directories.")
    normalized: set[str] = set()
    for path in paths:
        if (
            not isinstance(path, str)
            or not path
            or len(path.encode()) > 1024
            or path.startswith("/")
            or (len(path) > 1 and path[1] == ":")
            or any(character in path for character in "\\*?[]")
            or any(ord(character) < 32 or ord(character) == 127 for character in path)
            or ".." in path.split("/")
            or any(part.casefold() == ".git" for part in path.split("/"))
        ):
            raise SystemExit("include_paths must contain literal repository-relative directories.")
        canonical = "/".join(part for part in path.split("/") if part not in {"", "."}) or "."
        if require_scope(canonical, "standard", target) != canonical:
            raise SystemExit("include_paths must not resolve through a directory symlink.")
        normalized.add(canonical)
    if "." in normalized and len(normalized) != 1:
        raise SystemExit("Whole repository cannot be combined with selected directories.")
    result: list[str] = []
    for path in sorted(normalized):
        if not any(path.startswith(parent + "/") for parent in result):
            result.append(path)
    return result
