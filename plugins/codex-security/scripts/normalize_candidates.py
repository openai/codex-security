#!/usr/bin/env python3
"""Validate and combine security-scan candidates into deterministic JSONL."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

CWE = re.compile(r"(?i)CWE-(\d+)")
ROLES = {
    "entrypoint": 0,
    "entrypoint/wrapper": 1,
    "source": 2,
    "root_control": 3,
    "sink": 4,
    "concrete_implementation": 5,
    "evidence": 6,
}
FIELDS = {
    "candidate_id",
    "cwe_ids",
    "locations",
    "summary",
    "evidence",
    "context",
    "instance",
}


def text_field(row: dict[str, Any], field: str, *, required: bool = True) -> str | None:
    value = row.get(field)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field}: expected a non-empty string")
    return value.strip()


def cwe_ids(row: dict[str, Any]) -> list[str]:
    value = row.get("cwe_ids")
    if not isinstance(value, list):
        raise ValueError("cwe_ids: expected an array")
    found: set[int] = set()
    for item in value:
        if not isinstance(item, str):
            raise ValueError("cwe_ids: expected CWE strings")
        match = CWE.fullmatch(item.strip())
        if match is None or int(match[1]) < 1:
            raise ValueError(f"cwe_ids: unsupported value {item!r}")
        found.add(int(match[1]))
    return [f"CWE-{number}" for number in sorted(found)]


def relative_file(value: Any, repo_root: Path) -> tuple[str, Path]:
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError("path: expected a non-empty repository-relative path")
    raw = value
    if sys.platform == "win32":
        raw = raw.replace("\\", "/")
    path = PurePosixPath(raw)
    if (
        path.is_absolute()
        or ".." in path.parts
        or (sys.platform == "win32" and re.match(r"^[A-Za-z]:", raw))
    ):
        raise ValueError("path: expected a repository-relative path without traversal")
    resolved = (repo_root / raw).resolve(strict=True)
    try:
        relative = resolved.relative_to(repo_root).as_posix()
    except ValueError as error:
        raise ValueError("path: must resolve inside --repo-root") from error
    if not resolved.is_file():
        raise ValueError("path: expected a regular file")
    return relative, resolved


def positive_line(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{field}: expected a positive integer")
    return value


def normalize_locations(
    row: dict[str, Any], repo_root: Path, line_counts: dict[Path, int]
) -> list[dict[str, Any]]:
    value = row.get("locations")
    if not isinstance(value, list) or not value:
        raise ValueError("locations: expected a non-empty array")
    normalized: dict[tuple[str, int, int, str], dict[str, Any]] = {}
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("locations: expected location objects")
        unknown = set(item) - {"path", "start_line", "end_line", "role"}
        if unknown:
            raise ValueError(f"locations: unsupported fields {', '.join(sorted(unknown))}")
        relative, source = relative_file(item.get("path"), repo_root)
        if (
            not relative.strip()
            or "\\" in relative
            or any(":" in part for part in PurePosixPath(relative).parts)
        ):
            raise ValueError("path: expected a safe repository-relative POSIX path")
        start = positive_line(item.get("start_line"), "start_line")
        end = positive_line(item.get("end_line", start), "end_line")
        if end < start:
            raise ValueError("end_line: must be greater than or equal to start_line")
        if source not in line_counts:
            line_counts[source] = len(source.read_bytes().splitlines())
        if end > line_counts[source]:
            raise ValueError(f"line range {start}-{end} exceeds {relative}:{line_counts[source]}")
        role = item.get("role")
        if not isinstance(role, str) or role not in ROLES:
            raise ValueError(f"role: unsupported value {role!r}")
        key = (relative, start, end, role)
        normalized[key] = {
            "path": relative,
            "start_line": start,
            "end_line": end,
            "role": role,
        }
    return sorted(
        normalized.values(),
        key=lambda item: (
            ROLES[item["role"]],
            item["path"],
            item["start_line"],
            item["end_line"],
        ),
    )


def read_scope(path: Path, repo_root: Path, *, allow_missing: bool = False) -> set[str]:
    contents = path.read_bytes().decode("utf-8")
    lines = contents.split("\n")
    listed_rows = set(lines)

    def is_scope_file(value: str) -> bool:
        try:
            relative_file(value, repo_root)
        except (OSError, ValueError):
            return False
        return True

    carriage_rows = {
        line: (is_scope_file(line), is_scope_file(line.removesuffix("\r")))
        for line in lines
        if line.endswith("\r") and line != "\r" and sys.platform != "win32"
    }
    crlf_evidence = any(line == "\r" for line in lines) or any(
        stripped and not literal for literal, stripped in carriage_rows.values()
    )
    literal_evidence = any(literal and not stripped for literal, stripped in carriage_rows.values())

    scope: set[str] = set()
    for number, line in enumerate(lines, 1):
        if sys.platform == "win32" or line == "\r":
            line = line.removesuffix("\r")
        elif line.endswith("\r"):
            literal, stripped = carriage_rows[line]
            if stripped and not literal:
                line = line.removesuffix("\r")
            elif stripped and literal:
                if number == len(lines) and not contents.endswith("\n"):
                    pass
                elif line.removesuffix("\r") in listed_rows:
                    pass
                elif crlf_evidence and not literal_evidence:
                    line = line.removesuffix("\r")
                elif literal_evidence and not crlf_evidence:
                    pass
                else:
                    raise ValueError(f"in-scope file row {number}: ambiguous carriage-return paths")
            elif not literal and crlf_evidence:
                line = line.removesuffix("\r")
        if not line:
            continue
        try:
            relative, _ = relative_file(line, repo_root)
        except (OSError, ValueError) as error:
            if allow_missing and isinstance(error, FileNotFoundError):
                candidate = PurePosixPath(line)
                if candidate.is_absolute() or ".." in candidate.parts or "\0" in line:
                    raise ValueError(f"in-scope file row {number}: unsafe deleted path") from error
                resolved = (repo_root / line).resolve(strict=False)
                try:
                    relative = resolved.relative_to(repo_root).as_posix()
                except ValueError as escaped:
                    raise ValueError(
                        f"in-scope file row {number}: path escapes repository"
                    ) from escaped
                scope.add(relative)
                continue
            raise ValueError(f"in-scope file row {number}: {error}") from error
        scope.add(relative)
    return scope


def normalize_candidate(
    row: dict[str, Any], repo_root: Path, scope: set[str], line_counts: dict[Path, int]
) -> dict[str, Any]:
    unknown = set(row) - FIELDS
    if unknown:
        raise ValueError(f"unsupported fields {', '.join(sorted(unknown))}")
    if "candidate_id" in row:
        text_field(row, "candidate_id")
    candidate_locations = normalize_locations(row, repo_root, line_counts)
    if not any(item["path"] in scope for item in candidate_locations):
        raise ValueError("locations: expected at least one in-scope file")
    result: dict[str, Any] = {
        "cwe_ids": cwe_ids(row),
        "locations": candidate_locations,
        "summary": text_field(row, "summary"),
        "evidence": text_field(row, "evidence"),
    }
    context = text_field(row, "context", required=False)
    if context is not None:
        result["context"] = context
    instance = text_field(row, "instance", required=False)
    if instance is not None:
        result["instance"] = instance
    return result


def identity(row: dict[str, Any]) -> str:
    return json.dumps(
        {
            "cwe_ids": row["cwe_ids"],
            "locations": row["locations"],
            "instance": row.get("instance"),
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def merged_text(group: list[dict[str, Any]], field: str) -> str:
    return "\n".join(sorted({item[field] for item in group if field in item}))


def combine(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(identity(row), []).append(row)
    combined: list[dict[str, Any]] = []
    for key, group in sorted(groups.items()):
        candidate_id = hashlib.sha256(key.encode()).hexdigest()[:16]

        result = {
            "candidate_id": f"candidate-{candidate_id}",
            "cwe_ids": group[0]["cwe_ids"],
            "locations": group[0]["locations"],
            "summary": merged_text(group, "summary"),
            "evidence": merged_text(group, "evidence"),
        }
        context = merged_text(group, "context")
        if context:
            result["context"] = context
        if "instance" in group[0]:
            result["instance"] = group[0]["instance"]
        combined.append(result)
    return combined


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", nargs="+", required=True, help="Candidate JSONL inputs.")
    parser.add_argument("--out", required=True, help="Combined candidate JSONL output.")
    parser.add_argument("--repo-root", required=True, help="Repository root for candidate paths.")
    parser.add_argument("--in-scope-files", required=True, help="Repository-relative file list.")
    parser.add_argument(
        "--allow-missing-in-scope",
        action="store_true",
        help="Keep deleted Git paths in a diff inventory while validating existing candidate files.",
    )
    args = parser.parse_args()
    try:
        repo_root = Path(args.repo_root).expanduser().resolve(strict=True)
        if not repo_root.is_dir():
            raise ValueError("--repo-root: expected a directory")
        output = Path(args.out).expanduser().resolve(strict=False)
        scope_path = Path(args.in_scope_files).expanduser().resolve(strict=True)
        inputs = sorted({Path(value).expanduser().resolve(strict=True) for value in args.input})
        if output in inputs:
            raise ValueError("--out: must not also be an input")
        if output == scope_path:
            raise ValueError("--out: must not replace --in-scope-files")
        scope = read_scope(scope_path, repo_root, allow_missing=args.allow_missing_in_scope)
        line_counts: dict[Path, int] = {}
        rows: list[dict[str, Any]] = []
        for source in inputs:
            with source.open(encoding="utf-8") as handle:
                for number, line in enumerate(handle, 1):
                    if not line.strip():
                        continue
                    try:
                        row = json.loads(line)
                        if not isinstance(row, dict):
                            raise ValueError("expected a JSON object")
                        rows.append(normalize_candidate(row, repo_root, scope, line_counts))
                    except (ValueError, TypeError, OSError) as error:
                        raise ValueError(f"{source} row {number}: {error}") from error
        combined = combine(rows)
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=output.parent,
                prefix=f".{output.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary = Path(handle.name)
                for row in combined:
                    handle.write(
                        json.dumps(row, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
                        + "\n"
                    )
            temporary.replace(output)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        print(f"Combined {len(rows)} candidate rows into {len(combined)} rows in {output}")
    except (OSError, ValueError) as error:
        print(f"normalize_candidates: {error}", file=sys.stderr)
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()
