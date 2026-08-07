#!/usr/bin/env python3
"""Inventory the remote entry points of a repository for Codex Security scans.

This script is deliberately model-free. It reports where untrusted input can
first reach the target, derived only from source text, so a scan can prioritize
reachable surface instead of treating every file as equally likely to matter.

An entry point is a place an outside party can cause code to run: an HTTP route,
a GraphQL server, a serverless handler, a message consumer, a server bind, or a
CI workflow trigger. The inventory is a prior, not a verdict. A file with no
entry point is still reviewable, and a file with one is not automatically
vulnerable.

Two blind spots in the shared worklist constants are deliberately not inherited
here, because both hide real remote surface:

- `generate_rank_input.EXCLUDED_DIRS` contains `.github`, so workflow files are
  invisible to worklist-driven scans even though a workflow trigger is one of
  the most directly attacker-reachable entry points a repository has.
- `rank_preview.TEXT_CODE_EXTENSIONS` omits `.tf`, so Terraform is invisible.

Usage:
    inventory_entry_points.py --repo <root> [--scope <path>]... --out <path|->
                              [--summary <path|->]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from rank_preview import TEXT_CODE_EXTENSIONS

# Bounds. Every one of these exists so a hostile or merely enormous repository
# cannot turn the inventory into an unbounded read.
MAX_FILES = 20_000
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 64_000_000
MAX_ROWS = 5_000
MAX_LINE_CHARS = 4_000
SYMBOL_LOOKAHEAD_LINES = 4
EVIDENCE_CHARS = 200

# Directories that never hold reviewable first-party source. `.github` is
# intentionally absent: workflows are entry points.
EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".idea",
        ".vscode",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "bower_components",
        "coverage",
        "dist",
        "node_modules",
        "site-packages",
        "target",
        "vendor",
        "venv",
    }
)

EXTRA_EXTENSIONS = frozenset({".tf", ".tfvars", ".hcl"})
SCANNED_EXTENSIONS = frozenset(TEXT_CODE_EXTENSIONS) | EXTRA_EXTENSIONS

KIND_HTTP = "http_route"
KIND_GRAPHQL = "graphql"
KIND_SERVERLESS = "serverless_handler"
KIND_CONSUMER = "message_consumer"
KIND_BIND = "server_bind"
KIND_CI = "ci_trigger"

# (kind, framework, pattern). Patterns are kept anchored and free of nested
# quantifiers so the inventory cannot be made to backtrack pathologically by a
# crafted source file. Group `sym` supplies a symbol when the syntax carries one.
PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    # --- Python -----------------------------------------------------------
    (KIND_HTTP, "flask", re.compile(r"@\w+\.(?:route|get|post|put|patch|delete)\s*\(")),
    (KIND_HTTP, "fastapi", re.compile(r"@(?:app|router|api)\s*\.\s*(?:get|post|put|patch|delete|websocket)\s*\(")),
    (KIND_HTTP, "django", re.compile(r"^\s*(?:path|re_path|url)\s*\(", re.MULTILINE)),
    (KIND_HTTP, "django", re.compile(r"^\s*urlpatterns\s*=", re.MULTILINE)),
    (KIND_HTTP, "tornado", re.compile(r"class\s+(?P<sym>\w+)\s*\(\s*(?:tornado\.web\.)?RequestHandler\b")),
    # Stdlib http.server, not Tornado. Kept distinct so the framework label is
    # not merely "something ending in RequestHandler".
    (KIND_HTTP, "http_server", re.compile(r"class\s+(?P<sym>\w+)\s*\(\s*\w*(?:BaseHTTPRequestHandler|SimpleHTTPRequestHandler)\b")),
    (KIND_HTTP, "aiohttp", re.compile(r"\brouter\s*\.\s*add_(?:get|post|route|put|delete)\s*\(")),
    (KIND_HTTP, "sanic", re.compile(r"@\w+\.(?:websocket|route)\s*\(")),
    (KIND_HTTP, "falcon", re.compile(r"\badd_route\s*\(")),
    # `lambda_handler` is conventional and unambiguous. A bare `handler` is not,
    # so it only counts when it carries Lambda's own (event, context) signature.
    (KIND_SERVERLESS, "aws_lambda", re.compile(r"^\s*def\s+(?P<sym>lambda_handler)\s*\(", re.MULTILINE)),
    (KIND_SERVERLESS, "aws_lambda", re.compile(r"^\s*def\s+(?P<sym>\w+)\s*\(\s*event\s*,\s*context\b", re.MULTILINE)),
    (KIND_CONSUMER, "celery", re.compile(r"@\w*(?:app|celery)\s*\.\s*task\b")),
    (KIND_BIND, "python", re.compile(r"\b(?:app|application)\s*\.\s*run\s*\(")),
    (KIND_BIND, "python", re.compile(r"\buvicorn\s*\.\s*run\s*\(")),
    # --- JavaScript and TypeScript ---------------------------------------
    (KIND_HTTP, "express", re.compile(r"\b(?:app|router|server)\s*\.\s*(?:get|post|put|patch|delete|all|use)\s*\(\s*[\"'`/]")),
    (KIND_HTTP, "fastify", re.compile(r"\bfastify\s*\.\s*(?:get|post|put|patch|delete|route)\s*\(")),
    (KIND_HTTP, "koa", re.compile(r"\b(?:router)\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*[\"'`/]")),
    (KIND_HTTP, "nestjs", re.compile(r"@(?:Get|Post|Put|Patch|Delete|All|Controller)\s*\(")),
    (KIND_HTTP, "hapi", re.compile(r"\bserver\s*\.\s*route\s*\(")),
    (KIND_SERVERLESS, "node", re.compile(r"\b(?:exports\s*\.\s*handler|module\s*\.\s*exports\s*\.\s*handler)\s*=")),
    (KIND_GRAPHQL, "apollo", re.compile(r"\bnew\s+ApolloServer\s*\(")),
    (KIND_GRAPHQL, "graphql", re.compile(r"\b(?:graphqlHTTP|createYoga|createHandler)\s*\(")),
    (KIND_GRAPHQL, "graphql", re.compile(r"^\s*(?:const|let|var|export\s+const)\s+(?P<sym>\w*[tT]ypeDefs)\s*=", re.MULTILINE)),
    (KIND_CONSUMER, "kafka", re.compile(r"\b(?:consumer\s*\.\s*subscribe|eachMessage)\s*[:(]")),
    (KIND_BIND, "node", re.compile(r"\b(?:app|server)\s*\.\s*listen\s*\(")),
    # --- Go ---------------------------------------------------------------
    (KIND_HTTP, "net_http", re.compile(r"\bhttp\s*\.\s*(?:HandleFunc|Handle)\s*\(")),
    # Any receiver except `http` itself, which the net_http pattern already owns.
    (KIND_HTTP, "gorilla", re.compile(r"\b(?!http\b)\w+\s*\.\s*HandleFunc\s*\(")),
    (KIND_HTTP, "gin", re.compile(r"\b\w+\s*\.\s*(?:GET|POST|PUT|PATCH|DELETE|Any)\s*\(\s*\"")),
    (KIND_BIND, "go", re.compile(r"\bhttp\s*\.\s*ListenAndServe(?:TLS)?\s*\(")),
    # --- Java and Kotlin --------------------------------------------------
    (KIND_HTTP, "spring", re.compile(r"@(?:Request|Get|Post|Put|Patch|Delete)Mapping\s*[(\s]")),
    (KIND_HTTP, "spring", re.compile(r"@(?:RestController|Controller)\b")),
    (KIND_HTTP, "jaxrs", re.compile(r"@(?:Path|GET|POST|PUT|DELETE)\b")),
    (KIND_HTTP, "servlet", re.compile(r"\bextends\s+HttpServlet\b")),
    # --- Ruby, PHP, C# ----------------------------------------------------
    (KIND_HTTP, "rails", re.compile(r"^\s*(?:get|post|put|patch|delete|resources|resource)\s+[\"':]", re.MULTILINE)),
    (KIND_HTTP, "sinatra", re.compile(r"^\s*(?:get|post|put|patch|delete)\s+[\"']/", re.MULTILINE)),
    (KIND_HTTP, "laravel", re.compile(r"\bRoute\s*::\s*(?:get|post|put|patch|delete|any|match)\s*\(")),
    (KIND_HTTP, "aspnet", re.compile(r"\[(?:Http(?:Get|Post|Put|Patch|Delete)|Route)\b")),
)

# Workflow triggers are matched separately: the interesting unit is the trigger
# name under `on:`, which is not a single-line construct in general, so a plain
# per-line pattern would either miss the block form or match prose.
CI_TRIGGER_RE = re.compile(r"^\s{0,8}(?P<sym>pull_request_target|pull_request|issue_comment|issues|workflow_run|workflow_dispatch|repository_dispatch|push|schedule)\s*:")
CI_ON_RE = re.compile(r"^\s{0,4}on\s*:")

SYMBOL_DEF_RE = re.compile(
    r"^\s*(?:async\s+)?(?:def|function|func|fn|sub)\s+(?P<sym>[A-Za-z_]\w*)"
    r"|^\s*(?:export\s+)?(?:const|let|var)\s+(?P<sym2>[A-Za-z_]\w*)\s*="
    r"|^\s*(?:public|private|protected|static|\s)*[\w<>\[\],.]+\s+(?P<sym3>[A-Za-z_]\w*)\s*\("
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inventory deterministic remote entry points for a repository."
    )
    parser.add_argument("--repo", required=True, help="Repository root.")
    parser.add_argument(
        "--scope",
        action="append",
        default=None,
        help="Repository-relative path to restrict the inventory; repeat for several.",
    )
    parser.add_argument("--out", required=True, help="Output JSONL path, or - for stdout.")
    parser.add_argument(
        "--summary",
        default=None,
        help="Optional summary JSON path, or - for stdout.",
    )
    return parser.parse_args()


def path_is_excluded(relative: Path) -> bool:
    if any(part in EXCLUDED_DIRS for part in relative.parts):
        return True
    return relative.name.endswith((".min.js", ".min.css", ".map"))


def resolve_scopes(repo: Path, scopes: list[str] | None) -> list[Path]:
    if not scopes:
        return [repo]
    resolved: list[Path] = []
    for scope in scopes:
        candidate = Path(scope)
        if not candidate.is_absolute():
            candidate = repo / candidate
        try:
            candidate = candidate.resolve(strict=True)
            candidate.relative_to(repo)
        except (OSError, ValueError) as exc:
            raise SystemExit(f"Scope must be an existing path inside repo: {scope}") from exc
        resolved.append(candidate)
    return resolved


def iter_files(repo: Path, scopes: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    for scope in scopes:
        candidates = [scope] if scope.is_file() else sorted(scope.rglob("*"))
        for path in candidates:
            if len(seen) >= MAX_FILES:
                return sorted(seen)
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                path.resolve(strict=True).relative_to(repo)
            except (OSError, ValueError):
                continue
            relative = path.relative_to(repo)
            if path_is_excluded(relative):
                continue
            if path.suffix.lower() not in SCANNED_EXTENSIONS:
                continue
            seen.add(path)
    return sorted(seen)


def read_lines(path: Path) -> list[str] | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if "\x00" in text[:8192]:
        return None
    return text.splitlines()


def symbol_near(lines: list[str], index: int) -> str | None:
    for offset in range(0, SYMBOL_LOOKAHEAD_LINES + 1):
        position = index + offset
        if position >= len(lines):
            break
        match = SYMBOL_DEF_RE.match(lines[position][:MAX_LINE_CHARS])
        if match is None:
            continue
        for group in ("sym", "sym2", "sym3"):
            value = match.groupdict().get(group)
            if value:
                return value
    return None


def workflow_rows(relative: Path, lines: list[str]) -> list[dict[str, Any]]:
    """Match trigger names only inside the `on:` block of a workflow file."""
    rows: list[dict[str, Any]] = []
    in_on_block = False
    for index, raw in enumerate(lines):
        line = raw[:MAX_LINE_CHARS]
        if CI_ON_RE.match(line):
            in_on_block = True
            inline = line.split(":", 1)[1].strip()
            if inline and not inline.startswith("#"):
                for name in re.findall(r"[a-z_]+", inline):
                    if CI_TRIGGER_RE.match(f"{name}:"):
                        rows.append(_row(relative, index + 1, KIND_CI, "github_actions", name, line))
                in_on_block = False
            continue
        if in_on_block:
            if line.strip() and not line.startswith((" ", "\t", "#")):
                in_on_block = False
                continue
            match = CI_TRIGGER_RE.match(line)
            if match is not None:
                rows.append(
                    _row(relative, index + 1, KIND_CI, "github_actions", match.group("sym"), line)
                )
    return rows


def _row(
    relative: Path,
    line_number: int,
    kind: str,
    framework: str,
    symbol: str | None,
    evidence: str,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "path": relative.as_posix(),
        "line": line_number,
        "kind": kind,
        "framework": framework,
        "evidence": evidence.strip()[:EVIDENCE_CHARS],
    }
    if symbol:
        row["symbol"] = symbol
    return row


def is_workflow(relative: Path) -> bool:
    parts = relative.parts
    return (
        len(parts) >= 3
        and parts[0] == ".github"
        and parts[1] == "workflows"
        and relative.suffix.lower() in {".yml", ".yaml"}
    )


def inventory(repo: Path, scopes: list[Path]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    files = iter_files(repo, scopes)
    total_bytes = 0
    scanned = 0
    skipped_large = 0
    truncated = False

    for path in files:
        if total_bytes >= MAX_TOTAL_BYTES or len(rows) >= MAX_ROWS:
            truncated = True
            break
        lines = read_lines(path)
        if lines is None:
            skipped_large += 1
            continue
        scanned += 1
        total_bytes += sum(len(line) for line in lines)
        relative = path.relative_to(repo)

        if is_workflow(relative):
            rows.extend(workflow_rows(relative, lines))
            continue

        for index, raw in enumerate(lines):
            line = raw[:MAX_LINE_CHARS]
            stripped = line.lstrip()
            if stripped.startswith(("#", "//", "*")):
                continue
            for kind, framework, pattern in PATTERNS:
                match = pattern.search(line)
                if match is None:
                    continue
                symbol = match.groupdict().get("sym") if "sym" in pattern.groupindex else None
                if symbol is None and kind in {KIND_HTTP, KIND_SERVERLESS}:
                    symbol = symbol_near(lines, index)
                rows.append(_row(relative, index + 1, kind, framework, symbol, line))

    # Two patterns can legitimately describe the same construct, for example a
    # Lambda entry point matched both by its conventional name and by its
    # (event, context) signature. Report each construct once.
    deduplicated: list[dict[str, Any]] = []
    seen_rows: set[tuple[str, int, str, str, str]] = set()
    for row in rows:
        identity = (
            row["path"],
            row["line"],
            row["kind"],
            row["framework"],
            row.get("symbol") or "",
        )
        if identity in seen_rows:
            continue
        seen_rows.add(identity)
        deduplicated.append(row)
    rows = deduplicated

    rows.sort(key=lambda row: (row["path"], row["line"], row["kind"], row["framework"]))
    if len(rows) > MAX_ROWS:
        rows = rows[:MAX_ROWS]
        truncated = True

    by_kind = Counter(row["kind"] for row in rows)
    by_framework = Counter(row["framework"] for row in rows)
    per_file = Counter(row["path"] for row in rows)
    summary = {
        "documentType": "codex-security.entry-point-inventory",
        "schemaVersion": "1.0",
        "filesScanned": scanned,
        "filesSkippedTooLarge": skipped_large,
        "entryPointCount": len(rows),
        "truncated": truncated,
        "byKind": dict(sorted(by_kind.items())),
        "byFramework": dict(sorted(by_framework.items())),
        "files": [
            {"path": path, "entryPointCount": count}
            for path, count in sorted(per_file.items(), key=lambda item: (-item[1], item[0]))
        ],
    }
    return rows, summary


def emit_jsonl(destination: str, rows: list[dict[str, Any]]) -> None:
    payload = "".join(
        f"{json.dumps(row, ensure_ascii=True, sort_keys=True, separators=(',', ':'))}\n"
        for row in rows
    )
    if destination == "-":
        sys.stdout.write(payload)
        return
    out = Path(destination)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(payload, encoding="utf-8")


def emit_json(destination: str, payload: dict[str, Any]) -> None:
    text = json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    if destination == "-":
        sys.stdout.write(text)
        return
    out = Path(destination)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")


def main() -> None:
    args = parse_args()
    repo = Path(args.repo).expanduser()
    try:
        repo = repo.resolve(strict=True)
    except OSError as exc:
        raise SystemExit(f"Repo path not found: {args.repo}") from exc
    if not repo.is_dir():
        raise SystemExit(f"Repo path is not a directory: {repo}")

    rows, summary = inventory(repo, resolve_scopes(repo, args.scope))
    emit_jsonl(args.out, rows)
    if args.summary is not None:
        emit_json(args.summary, summary)


if __name__ == "__main__":
    main()
