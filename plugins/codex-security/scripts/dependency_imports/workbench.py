"""Import scanner claims and bind selected assessments to repository evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from dependency_imports.formats import MAX_REPORT_BYTES, parse_report
from workbench_target import git_bytes, git_revision, worktree_content_digest

MAX_SELECTION = 100
MAX_ASSESSMENT_BYTES = 64 * 1024
VERDICTS = ("affects_application", "not_applicable", "inconclusive")
ASSESSMENT_BASES = (
    "advisory_mismatch",
    "package_absent",
    "version_not_affected",
    "code_path",
    "execution_excluded",
    "unresolved",
)
REPORT_COLUMNS = (
    "id, target_path, target_revision, report_name, vendor, created_at, "
    "finding_count, warnings_json, report_digest"
)


def add_arguments(subparsers: Any) -> None:
    """Register the shared CLI used by the plugin and SDK."""
    command = subparsers.add_parser("import-dependency-findings")
    command.add_argument("--target-path", required=True)
    command.add_argument("--report-path", required=True)
    command.add_argument("--report-name")
    command.add_argument("--vendor", choices=("endor", "snyk", "socket"), required=True)
    command = subparsers.add_parser("list-dependency-reports")
    command.add_argument("--target-path")
    command.add_argument("--offset", type=int, default=0)
    command.add_argument("--limit", type=int, default=100)
    command = subparsers.add_parser("get-dependency-report")
    command.add_argument("--report-id", required=True)
    command.add_argument("--offset", type=int, default=0)
    command.add_argument("--limit", type=int, default=100)
    command.add_argument("--verdict", choices=(*VERDICTS, "pending"))
    command = subparsers.add_parser("get-dependency-finding")
    command.add_argument("--report-id", required=True)
    command.add_argument("--finding-id", required=True)
    command.add_argument("--require-current", action="store_true")
    command = subparsers.add_parser("start-dependency-assessment")
    command.add_argument("--report-id", required=True)
    command.add_argument("--finding-id", action="append", required=True)
    command = subparsers.add_parser("get-dependency-assessment")
    command.add_argument("--assessment-id", required=True)
    command = subparsers.add_parser("record-dependency-assessments")
    command.add_argument("--assessment-id", required=True)
    command.add_argument("--results-path", required=True)

    for name in (
        "claim-dependency-task-launch",
        "settle-dependency-task-launch",
        "get-dependency-task-launches",
    ):
        command = subparsers.add_parser(name)
        command.add_argument("--account-id")
        command.add_argument("--host-id", required=True)
        if name == "settle-dependency-task-launch":
            command.add_argument("--launch-id", required=True)
            command.add_argument("--attempt-id", required=True)
            command.add_argument(
                "--status", choices=("outcome_unknown", "failed", "settled"), required=True
            )
            command.add_argument("--thread-id")
            command.add_argument("--error")
        else:
            command.add_argument("--report-id", required=True)
        if name == "claim-dependency-task-launch":
            command.add_argument("--kind", choices=("assessment", "fix"), required=True)
            command.add_argument("--assessment-id", required=True)
            command.add_argument("--finding-id")
            command.add_argument("--retry-attempt-id")


def _json(value: object) -> str:
    return json.dumps(value, allow_nan=False, sort_keys=True)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read(path: Path, maximum: int = MAX_REPORT_BYTES) -> bytes:
    with path.open("rb") as stream:
        content = stream.read(maximum + 1)
    if len(content) > maximum:
        raise ValueError(f"Input exceeds the {maximum // 1024} KiB size limit.")
    return content


def _decode(content: bytes, *, vendor: str | None = None) -> object:
    def reject_constant(value: str) -> None:
        raise ValueError(f"Non-finite JSON value {value} is not supported.")

    text = content.decode("utf-8-sig")
    try:
        payload = json.loads(text, parse_constant=reject_constant)
    except json.JSONDecodeError:
        if vendor == "endor" and not text.lstrip().startswith(("{", "[")):
            return text
        if vendor != "socket":
            raise ValueError("The report must contain valid JSON.") from None
        # Socket's full-scan endpoint exports one package per NDJSON line.
        return [
            json.loads(line, parse_constant=reject_constant)
            for line in text.splitlines()
            if line.strip()
        ]
    # A one-event Socket NDJSON stream is also a valid JSON object.
    if (
        vendor == "socket"
        and isinstance(payload, dict)
        and "ok" not in payload
        and (payload.get("_type") == "scores" or ("type" in payload and "alerts" in payload))
    ):
        return [payload]
    return payload


def _snapshot(target: Path) -> tuple[str, str]:
    if not target.is_dir():
        raise ValueError("The repository directory does not exist.")
    revision = git_revision(target)
    if revision == "unversioned":
        raise ValueError("Dependency assessment requires a repository with a Git commit.")
    return revision, worktree_content_digest(target)


def _report(connection: sqlite3.Connection, report_id: str) -> sqlite3.Row:
    row = connection.execute(
        f"SELECT {REPORT_COLUMNS} FROM dependency_reports WHERE id = ?", (report_id,)
    ).fetchone()
    if row is None:
        raise ValueError("Imported dependency report not found.")
    return row


def _report_result(row: sqlite3.Row) -> dict[str, object]:
    return {
        "id": row["id"],
        "targetPath": row["target_path"],
        "targetRevision": row["target_revision"],
        "reportName": row["report_name"],
        "vendor": row["vendor"],
        "createdAt": row["created_at"],
        "findingCount": row["finding_count"],
        "warnings": json.loads(row["warnings_json"]),
        "reportDigest": row["report_digest"],
    }


def _finding_result(row: sqlite3.Row) -> dict[str, Any]:
    finding = json.loads(row["claim_json"])
    finding.update(
        id=row["id"],
        reportId=row["report_id"],
        assessment=json.loads(row["assessment_json"]) if row["assessment_json"] else None,
    )
    return finding


def _safe_file(target: Path, relative: str) -> Path:
    path = Path(relative)
    if (
        path.is_absolute()
        or ".." in path.parts
        or "\\" in relative
        or re.match(r"^[A-Za-z]:", relative)
    ):
        raise ValueError("Evidence paths must be relative paths inside the repository.")
    resolved = (target / path).resolve()
    if not resolved.is_relative_to(target) or not resolved.is_file():
        raise ValueError(f"Evidence file is missing or outside the repository: {relative}")
    return resolved


def _check_inputs(target_revision: str, claim: dict[str, Any]) -> dict[str, Any]:
    """Keep source identity and revision gaps separate from native resolution."""
    claim = dict(claim)
    warnings: list[str] = []
    package = claim["package"]
    if not all(package.get(key) for key in ("name", "version", "ecosystem")):
        warnings.append("The scanner did not supply an exact package identity and version.")
    original_spec = claim.get("original", {}).get("spec")
    source_version = (
        original_spec.get("source_code_version") if isinstance(original_spec, dict) else None
    )
    source_revision = source_version.get("sha") if isinstance(source_version, dict) else None
    if source_revision is None:
        source_revision = claim.get("sourceRevision")
    if isinstance(source_revision, str) and source_revision:
        claim["sourceRevision"] = source_revision
        if source_revision != target_revision:
            warnings.append(
                "The scanner repository revision differs from the current repository revision."
            )
    claim["inputWarnings"] = warnings
    return claim


def _file_digest(path: Path) -> str:
    """Hash resolver inputs without interpreting their package-manager format."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_resolution_unchanged(target: Path, results: list[dict[str, Any]]) -> None:
    """Check recorded resolver inputs, including ignored installation metadata."""
    for result in results:
        resolution = result.get("resolution")
        if resolution is None:
            continue
        for item in resolution["inputFiles"]:
            if _file_digest(_safe_file(target, item["path"])) != item["sha256"]:
                raise ValueError("A native resolver input changed. Run a new assessment.")


def import_report(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, object]:
    """Persist a report as unassessed claims without creating a completed scan."""
    target = Path(args.target_path).expanduser().resolve()
    revision, snapshot = _snapshot(target)
    content = _read(Path(args.report_path))
    parsed = parse_report(_decode(content, vendor=args.vendor), args.vendor)
    claims = [_check_inputs(revision, claim) for claim in parsed["findings"]]
    if _snapshot(target) != (revision, snapshot):
        raise ValueError("Repository changed during import. Try again.")
    report_id, timestamp = str(uuid.uuid4()), _now()
    warnings = list(parsed["warnings"])
    if any(not claim.get("sourceRevision") for claim in claims):
        warnings.append(
            "The report does not supply an immutable repository revision for every finding; "
            "assessment uses the recorded local revision."
        )
    report_name = args.report_name or Path(args.report_path).name
    if not report_name.strip() or len(report_name) > 512:
        raise ValueError("Report name must contain 1 to 512 characters.")
    with connection:
        connection.execute(
            "INSERT INTO dependency_reports VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                report_id,
                str(target),
                revision,
                snapshot,
                args.vendor,
                report_name,
                hashlib.sha256(content).hexdigest(),
                content.decode("utf-8-sig"),
                _json(warnings),
                len(claims),
                timestamp,
            ),
        )
        for position, claim in enumerate(claims):
            connection.execute(
                "INSERT INTO dependency_imported_findings (id, report_id, position, claim_json) VALUES (?, ?, ?, ?)",
                (str(uuid.uuid4()), report_id, position, _json(claim)),
            )
    return {"report": _report_result(_report(connection, report_id))}


def list_reports(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, object]:
    """List a bounded page of imported report summaries."""
    _page(args.offset, args.limit)
    target = str(Path(args.target_path).expanduser().resolve()) if args.target_path else None
    rows = connection.execute(
        f"SELECT {REPORT_COLUMNS} FROM dependency_reports WHERE (? IS NULL OR target_path = ?) ORDER BY created_at DESC, id LIMIT ? OFFSET ?",
        (target, target, args.limit + 1, args.offset),
    ).fetchall()
    return {
        "reports": [_report_result(row) for row in rows[: args.limit]],
        "nextOffset": args.offset + args.limit if len(rows) > args.limit else None,
    }


def _page(offset: int, limit: int) -> None:
    if offset < 0 or not 1 <= limit <= MAX_SELECTION:
        raise ValueError("Use a nonnegative offset and a limit between 1 and 100.")


def get_report(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, object]:
    """Read report claims, optionally filtered by their latest assessment."""
    report = _report(connection, args.report_id)
    _page(args.offset, args.limit)
    predicate = "report_id = ?"
    parameters = [args.report_id]
    if args.verdict == "pending":
        predicate += " AND assessment_json IS NULL"
    elif args.verdict:
        predicate += " AND json_extract(assessment_json, '$.verdict') = ?"
        parameters.append(args.verdict)
    connection.execute("BEGIN")
    with connection:
        total = connection.execute(
            f"SELECT COUNT(*) FROM dependency_imported_findings WHERE {predicate}",
            parameters,
        ).fetchone()[0]
        rows = connection.execute(
            f"""
            SELECT id, report_id, json_remove(claim_json, '$.original') AS claim_json,
                   assessment_json
            FROM dependency_imported_findings WHERE {predicate}
            ORDER BY position LIMIT ? OFFSET ?
            """,
            (*parameters, args.limit, args.offset),
        ).fetchall()
    return {
        "report": _report_result(report),
        "findings": [_finding_result(row) for row in rows],
        "total": total,
        "nextOffset": args.offset + args.limit if total > args.offset + args.limit else None,
    }


def _finding(connection: sqlite3.Connection, report_id: str, finding_id: str) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM dependency_imported_findings WHERE report_id = ? AND id = ?",
        (report_id, finding_id),
    ).fetchone()
    if row is None:
        raise ValueError("Finding does not belong to this imported report.")
    return row


def get_finding(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, object]:
    """Read the original scanner claim and its separate latest assessment."""
    report = _report(connection, args.report_id)
    finding = _finding_result(_finding(connection, args.report_id, args.finding_id))
    if args.require_current:
        result = finding["assessment"]
        if result is None or result["verdict"] != "affects_application":
            raise ValueError(
                "Confirm this finding affects the application before requesting a fix."
            )
        assessment = _assessment(connection, result["assessmentId"])
        if _snapshot(Path(report["target_path"])) != (
            assessment["target_revision"],
            assessment["target_snapshot_digest"],
        ):
            raise ValueError(
                "The repository changed since this assessment. Assess it again before requesting a fix."
            )
        _require_resolution_unchanged(Path(report["target_path"]), [result])
    return {
        "report": _report_result(report),
        "finding": finding,
    }


def _assessment(connection: sqlite3.Connection, assessment_id: str) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM dependency_assessments WHERE id = ?", (assessment_id,)
    ).fetchone()
    if row is None:
        raise ValueError("Dependency assessment not found.")
    return row


def _assessment_result(row: sqlite3.Row, target_path: str) -> dict[str, object]:
    return {
        "id": row["id"],
        "reportId": row["report_id"],
        "findingIds": json.loads(row["finding_ids_json"]),
        "targetPath": target_path,
        "targetRevision": row["target_revision"],
        "state": row["state"],
    }


def start_assessment(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, object]:
    """Record an explicit selection and pin the current repository snapshot."""
    report = _report(connection, args.report_id)
    ids = sorted(args.finding_id)
    if not 1 <= len(ids) <= MAX_SELECTION or len(set(ids)) != len(ids):
        raise ValueError("Select between 1 and 100 distinct imported findings.")
    target = Path(report["target_path"])
    revision, snapshot = _snapshot(target)
    claims = [
        _check_inputs(revision, _finding_result(_finding(connection, args.report_id, item)))
        for item in ids
    ]
    if _snapshot(target) != (revision, snapshot):
        raise ValueError("Repository changed during selection. Try again.")
    assessment_id = str(uuid.uuid4())
    connection.execute("BEGIN IMMEDIATE")
    try:
        existing = connection.execute(
            "SELECT id FROM dependency_assessments WHERE report_id = ? AND finding_ids_json = ? "
            "AND target_revision = ? AND target_snapshot_digest = ? AND claims_json = ? "
            "AND state = 'pending'",
            (args.report_id, _json(ids), revision, snapshot, _json(claims)),
        ).fetchone()
        if existing is not None:
            connection.commit()
            return get_assessment(connection, argparse.Namespace(assessment_id=existing["id"]))
        connection.execute(
            "INSERT INTO dependency_assessments VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, NULL)",
            (assessment_id, args.report_id, _json(ids), revision, snapshot, _json(claims), _now()),
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return get_assessment(connection, argparse.Namespace(assessment_id=assessment_id))


def get_assessment(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, object]:
    """Read precisely the claims selected for an assessment."""
    row = _assessment(connection, args.assessment_id)
    report = _report(connection, row["report_id"])
    return {
        "assessment": _assessment_result(row, report["target_path"]),
        "report": _report_result(report),
        "findings": json.loads(row["claims_json"]),
        "results": json.loads(row["results_json"]) if row["results_json"] else None,
    }


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 12000:
        raise ValueError(f"{label} must contain 1 to 12000 characters.")
    return value


def _require_assessment_size(result: dict[str, object]) -> None:
    """Bound authored prose and source excerpts without truncating native output."""
    measured = dict(result)
    resolution = measured.get("resolution")
    if isinstance(resolution, dict):
        measured["resolution"] = {**resolution, "stdout": "", "stderr": ""}
    if len(_json(measured).encode("utf-8")) > MAX_ASSESSMENT_BYTES:
        raise ValueError("Each assessment, including source excerpts, must fit within 64 KiB.")


def _strings(value: object, label: str) -> list[str]:
    """Require a JSON array of nonempty strings."""
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise ValueError(f"{label} must be an array of nonempty strings.")
    return value


def _validate_resolution(target: Path, value: object) -> dict[str, Any] | None:
    """Record native output and model interpretation without claiming to re-resolve it."""
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("resolution must describe native resolver evidence or be null.")
    argv = _strings(value.get("argv"), "resolution argv")
    if not argv:
        raise ValueError("resolution argv must include the native resolver command.")
    cwd = _text(value.get("cwd"), "resolution cwd")
    relative = Path(cwd)
    directory = (target / relative).resolve()
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or "\\" in cwd
        or re.match(r"^[A-Za-z]:", cwd)
        or not directory.is_relative_to(target)
        or not directory.is_dir()
    ):
        raise ValueError("Resolver cwd must be a directory inside the repository.")
    exit_code = value.get("exitCode")
    if type(exit_code) is not int:
        raise ValueError("resolution exitCode must be an integer.")
    stdout, stderr = value.get("stdout"), value.get("stderr")
    if not isinstance(stdout, str) or not isinstance(stderr, str):
        raise ValueError("resolution stdout and stderr must preserve the native text output.")
    package = value.get("package")
    if not isinstance(package, dict):
        raise ValueError("resolution package must identify the interpreted package.")
    package = {
        key: _text(package.get(key), f"resolution package {key}") for key in ("ecosystem", "name")
    }
    input_files = value.get("inputFiles")
    if not isinstance(input_files, list):
        raise ValueError("resolution inputFiles must describe the native resolver inputs.")
    checked_files: list[dict[str, str]] = []
    for item in input_files:
        if not isinstance(item, dict):
            raise ValueError("Each resolver input requires a path and SHA-256 digest.")
        path = _text(item.get("path"), "resolver input path")
        digest = _file_digest(_safe_file(target, path))
        if item.get("sha256") != digest:
            raise ValueError("A native resolver input changed. Run a new assessment.")
        checked_files.append({"path": path, "sha256": digest})
    return {
        "argv": argv,
        "cwd": cwd,
        "exitCode": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "package": package,
        "selectedVersions": _strings(value.get("selectedVersions"), "selectedVersions"),
        "explanation": _text(value.get("explanation"), "resolution explanation"),
        "inputFiles": checked_files,
        "issues": _strings(value.get("issues"), "resolution issues"),
    }


def _source_url(value: object) -> str:
    """Require a web citation without fetching model-provided URLs."""
    url = _text(value, "source URL")
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Source citations require an HTTP(S) URL.")
    return url


def _validate_external_evidence(value: object) -> list[dict[str, Any]]:
    """Preserve inspected artifact observations, not certify their remote provenance."""
    if not isinstance(value, list):
        raise ValueError("externalEvidence must be an array of inspected public artifacts.")
    checked: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("Each external artifact requires a source and inspected evidence.")
        digest = item.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("External evidence requires the complete file's SHA-256 digest.")
        kind = item.get("kind")
        if kind not in ("manifest", "source", "shipped_code"):
            raise ValueError("External evidence kind must be manifest, source, or shipped_code.")
        revision = item.get("revision")
        if revision is not None:
            revision = _text(revision, "external revision")
        package = item.get("package")
        if package is not None:
            if not isinstance(package, dict):
                raise ValueError("External package evidence must identify its name and version.")
            package = {
                key: _text(package.get(key), f"external package {key}")
                for key in ("ecosystem", "name", "version")
            }
        checked.append(
            {
                "url": _source_url(item.get("url")),
                "revision": revision,
                "sha256": digest,
                "kind": kind,
                "package": package,
                "excerpt": _text(item.get("excerpt"), "external excerpt"),
                "explanation": _text(item.get("explanation"), "external explanation"),
            }
        )
    return checked


def _validate_result(
    target: Path,
    result: object,
    claim: dict[str, Any],
    *,
    assessment_id: str,
    target_revision: str,
    created_at: str,
) -> dict[str, object]:
    if not isinstance(result, dict) or result.get("verdict") not in VERDICTS:
        raise ValueError("Each assessment requires a supported verdict.")
    summary = _text(result.get("summary"), "summary")
    applicability = _text(result.get("applicability"), "applicability")
    unknowns = result.get("unknowns")
    if not isinstance(unknowns, list) or len(unknowns) > 100:
        raise ValueError("unknowns must be a bounded list of evidence gaps.")
    unknowns = [_text(value, "unknown") for value in unknowns]
    limitations = [
        _text(value, "limitation") for value in _strings(result.get("limitations"), "limitations")
    ]
    basis = result.get("basis")
    if basis not in ASSESSMENT_BASES:
        raise ValueError("basis must identify the evidence supporting the conclusion.")
    version_basis = result.get("versionBasis")
    if "versionBasis" not in result or version_basis not in (
        None,
        "declared",
        "resolved",
        "artifact",
    ):
        raise ValueError("versionBasis must be declared, resolved, artifact, or null.")
    external_evidence = _validate_external_evidence(result.get("externalEvidence"))
    investigation = result.get("investigation")
    if not isinstance(investigation, list) or any(
        not isinstance(item, dict) for item in investigation
    ):
        raise ValueError("investigation must describe actions taken and their observed results.")
    investigation = [
        {key: _text(item.get(key), f"investigation {key}") for key in ("action", "result")}
        for item in investigation
    ]
    attack_path = result.get("attackPath")
    if "attackPath" not in result or (
        attack_path is not None and not isinstance(attack_path, dict)
    ):
        raise ValueError("attackPath must describe the evidenced attacker path or be null.")
    if attack_path is not None:
        attack_path = {
            key: _text(attack_path.get(key), f"attackPath {key}")
            for key in ("entryPoint", "attackerControl", "vulnerableOperation", "prerequisites")
        }
    advisory_evidence = result.get("advisoryEvidence")
    if not isinstance(advisory_evidence, list):
        raise ValueError("advisoryEvidence must be an array of public source citations.")
    checked_advisories: list[dict[str, str]] = []
    for citation in advisory_evidence:
        if not isinstance(citation, dict):
            raise ValueError("Each advisory citation requires a URL and explanation.")
        checked_advisories.append(
            {
                "url": _source_url(citation.get("url")),
                "explanation": _text(citation.get("explanation"), "advisory explanation"),
            }
        )
    evidence = result.get("codeEvidence")
    if not isinstance(evidence, list) or len(evidence) > 100:
        raise ValueError("codeEvidence must be a bounded list of repository locations.")
    version = result.get("packageVersion")
    if version is not None:
        version = _text(version, "packageVersion")
    resolution = _validate_resolution(target, result.get("resolution"))
    checked_evidence: list[dict[str, object]] = []
    validated: dict[str, object] = {
        "findingId": claim["id"],
        "verdict": result["verdict"],
        "summary": summary,
        "packageVersion": version,
        "versionBasis": version_basis,
        "basis": basis,
        "limitations": limitations,
        "advisoryEvidence": checked_advisories,
        "externalEvidence": external_evidence,
        "investigation": investigation,
        "attackPath": attack_path,
        "resolution": resolution,
        "codeEvidence": checked_evidence,
        "applicability": applicability,
        "unknowns": unknowns,
        "assessmentId": assessment_id,
        "targetRevision": target_revision,
        "createdAt": created_at,
    }
    _require_assessment_size(validated)
    for location in evidence:
        if not isinstance(location, dict):
            raise ValueError("Code evidence must describe a repository location.")
        path = _text(location.get("path"), "evidence path")
        source = _safe_file(target, path)
        if not git_bytes(
            target,
            "ls-files",
            "--cached",
            "--recurse-submodules",
            "-z",
            "--",
            source.relative_to(target).as_posix(),
        ) and not git_bytes(
            target,
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            source.relative_to(target).as_posix(),
        ):
            raise ValueError(
                "Ignored files are not covered by the assessment snapshot. Cite application source tracked by Git or non-ignored files."
            )
        start, end = location.get("startLine"), location.get("endLine", location.get("startLine"))
        if type(start) is not int or type(end) is not int or not 1 <= start <= end:
            raise ValueError("Code evidence must have a valid line range.")
        if end - start > 200:
            raise ValueError("Code evidence line range does not match the repository file.")
        with source.open(encoding="utf-8") as stream:
            lines = [line.rstrip("\r\n") for line in islice(stream, start - 1, end)]
        if len(lines) != end - start + 1:
            raise ValueError("Code evidence line range does not match the repository file.")
        checked_evidence.append(
            {
                "path": path,
                "startLine": start,
                "endLine": end,
                "explanation": _text(location.get("explanation"), "evidence explanation"),
                "excerpt": "\n".join(lines),
            }
        )
        _require_assessment_size(validated)
    if version_basis is None and version is not None:
        raise ValueError(
            "An assessed packageVersion requires declared, resolved, or artifact evidence."
        )
    if version_basis == "declared" and (version is None or not checked_evidence):
        raise ValueError("A declared version requires an exact version and a repository citation.")
    if version_basis == "artifact" and (
        version is None
        or not any(
            item["kind"] in ("manifest", "shipped_code")
            and item["package"]
            == {
                "ecosystem": claim["package"].get("ecosystem"),
                "name": claim["package"].get("name"),
                "version": version,
            }
            for item in external_evidence
        )
    ):
        raise ValueError(
            "An artifact version requires matching package evidence in an inspected manifest or shipped code."
        )
    if version_basis == "resolved":
        if (
            resolution is None
            or resolution["exitCode"] != 0
            or not resolution["stdout"].strip()
            or resolution["issues"]
            or not resolution["inputFiles"]
            or any(
                resolution["package"][key] != claim["package"].get(key)
                for key in ("ecosystem", "name")
            )
        ):
            raise ValueError(
                "A resolved version requires complete native evidence for the reported package in this repository."
            )
        selected_versions = resolution["selectedVersions"]
        if (version is None and selected_versions) or (
            version is not None and version not in selected_versions
        ):
            raise ValueError(
                "The assessed version must be selected by the native graph; null requires an absent package."
            )
    if result["verdict"] == "inconclusive":
        if basis != "unresolved" or not unknowns:
            raise ValueError(
                "An inconclusive assessment requires unresolved basis and material missing evidence."
            )
        if not investigation:
            raise ValueError(
                "An inconclusive assessment requires attempted investigation and observed results."
            )
    else:
        if unknowns or basis == "unresolved":
            raise ValueError(
                "A conclusion cannot have material unresolved evidence gaps. Use inconclusive."
            )
        if basis != "code_path" and result["verdict"] != "not_applicable":
            raise ValueError("This basis only supports a not_applicable conclusion.")
        if basis in ("advisory_mismatch", "version_not_affected") and not checked_advisories:
            raise ValueError(
                "An advisory mismatch or unaffected version requires public advisory evidence."
            )
        if basis in ("package_absent", "version_not_affected") and version_basis != "resolved":
            raise ValueError(
                "Package absence or an unaffected resolved version requires a native dependency graph."
            )
        if basis == "package_absent" and version is not None:
            raise ValueError("Package absence requires no selected versions.")
        if basis == "version_not_affected" and version is None:
            raise ValueError("An unaffected version conclusion requires a selected version.")
        if basis == "code_path" and (version is None or not checked_evidence):
            raise ValueError(
                "A code-path conclusion requires version evidence and repository citations."
            )
        if basis == "execution_excluded" and not checked_evidence:
            raise ValueError(
                "Execution exclusion requires repository citations establishing the excluded path."
            )
        if result["verdict"] == "affects_application" and attack_path is None:
            raise ValueError(
                "An affected application requires an evidenced attacker path and prerequisites."
            )
    return validated


def record_assessments(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, object]:
    """Atomically accept complete, current, evidence-backed assessment results."""
    row = _assessment(connection, args.assessment_id)
    if row["state"] != "pending":
        raise ValueError(
            "This assessment is already complete. Start a new assessment to revise it."
        )
    report = _report(connection, row["report_id"])
    target = Path(report["target_path"])
    results = _decode(Path(args.results_path).read_bytes())
    claims = {claim["id"]: claim for claim in json.loads(row["claims_json"])}
    if (
        not isinstance(results, list)
        or any(
            not isinstance(result, dict) or not isinstance(result.get("findingId"), str)
            for result in results
        )
        or len(results) != len(claims)
        or {result.get("findingId") for result in results} != set(claims)
    ):
        raise ValueError(
            "Results must include every selected finding exactly once and no other findings."
        )
    expected_snapshot = (row["target_revision"], row["target_snapshot_digest"])
    if _snapshot(target) != expected_snapshot:
        raise ValueError("Repository changed after assessment started. Start a new assessment.")
    timestamp = _now()
    validated = [
        _validate_result(
            target,
            result,
            claims[result["findingId"]],
            assessment_id=args.assessment_id,
            target_revision=row["target_revision"],
            created_at=timestamp,
        )
        for result in results
    ]
    if _snapshot(target) != expected_snapshot:
        raise ValueError("Repository changed while checking evidence. Start a new assessment.")
    _require_resolution_unchanged(target, validated)
    connection.execute("BEGIN IMMEDIATE")
    try:
        updated = connection.execute(
            "UPDATE dependency_assessments SET state = 'complete', results_json = ? WHERE id = ? AND state = 'pending'",
            (_json(validated), args.assessment_id),
        )
        if updated.rowcount != 1:
            raise ValueError("This assessment was already completed by another writer.")
        for result in validated:
            connection.execute(
                "UPDATE dependency_imported_findings SET assessment_json = ? WHERE report_id = ? AND id = ?",
                (_json(result), row["report_id"], result["findingId"]),
            )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return {
        "assessment": _assessment_result(
            _assessment(connection, args.assessment_id), report["target_path"]
        ),
        "results": validated,
    }


def _launch_result(row: sqlite3.Row) -> dict[str, object]:
    return {
        "id": row["id"],
        "accountId": row["account_id"] or None,
        "hostId": row["host_id"],
        "reportId": row["report_id"],
        "kind": row["kind"],
        "assessmentId": row["assessment_id"],
        "findingId": row["finding_id"] or None,
        "attemptId": row["attempt_id"],
        "status": row["status"],
        "threadId": row["thread_id"],
        "error": row["error"],
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }


def _task_launch(connection: sqlite3.Connection, args: argparse.Namespace) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM dependency_task_launches WHERE id = ? AND account_id = ? AND host_id = ?",
        (args.launch_id, args.account_id or "", args.host_id),
    ).fetchone()
    if row is None:
        raise ValueError("Dependency task launch not found for this account and host.")
    return row


def _require_current_launch(
    connection: sqlite3.Connection, args: argparse.Namespace, assessment: sqlite3.Row
) -> dict[str, Any] | None:
    if args.kind == "fix":
        saved = get_finding(
            connection,
            argparse.Namespace(
                report_id=args.report_id, finding_id=args.finding_id, require_current=True
            ),
        )["finding"]["assessment"]
        if saved["assessmentId"] != args.assessment_id:
            raise ValueError("The finding has a different saved assessment. Refresh before fixing.")
        return saved
    report = _report(connection, args.report_id)
    if assessment["state"] != "pending":
        raise ValueError("This assessment is already complete.")
    if _snapshot(Path(report["target_path"])) != (
        assessment["target_revision"],
        assessment["target_snapshot_digest"],
    ):
        raise ValueError("The repository changed. Start a new assessment before launching.")
    return None


def _launch_claim_state(
    connection: sqlite3.Connection, identity: tuple[str, ...], retry_attempt_id: str | None
) -> tuple[sqlite3.Row | None, bool]:
    existing = connection.execute(
        "SELECT * FROM dependency_task_launches WHERE account_id = ? AND host_id = ? "
        "AND report_id = ? AND kind = ? AND assessment_id = ? AND finding_id = ?",
        identity,
    ).fetchone()
    if retry_attempt_id:
        if existing is None or existing["attempt_id"] != retry_attempt_id:
            raise ValueError("The task launch attempt changed. Refresh before retrying.")
        if existing["thread_id"] is not None:
            raise ValueError("This launch already has a task. Open the saved task instead.")
    elif existing is not None and existing["status"] != "failed":
        return existing, False
    return existing, True


def claim_task_launch(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, object]:
    """Claim once, or replace a failed or explicitly checked unknown attempt."""
    if args.kind not in ("assessment", "fix") or bool(args.finding_id) != (args.kind == "fix"):
        raise ValueError("Fix launches require a finding; assessment launches do not.")
    assessment = _assessment(connection, args.assessment_id)
    if assessment["report_id"] != args.report_id:
        raise ValueError("Assessment does not belong to this imported report.")
    identity = (
        args.account_id or "",
        args.host_id,
        args.report_id,
        args.kind,
        args.assessment_id,
        args.finding_id or "",
    )
    existing, claimable = _launch_claim_state(connection, identity, args.retry_attempt_id)
    if not claimable:
        return {"claimed": False, "launch": _launch_result(existing)}
    saved = _require_current_launch(connection, args, assessment)
    connection.execute("BEGIN IMMEDIATE")
    with connection:
        existing, claimable = _launch_claim_state(connection, identity, args.retry_attempt_id)
        if not claimable:
            return {"claimed": False, "launch": _launch_result(existing)}
        if _assessment(connection, args.assessment_id) != assessment:
            raise ValueError(
                "The assessment changed during launch checks. Refresh before launching."
            )
        if (
            args.kind == "fix"
            and json.loads(
                _finding(connection, args.report_id, args.finding_id)["assessment_json"] or "null"
            )
            != saved
        ):
            raise ValueError("The finding's saved assessment changed. Refresh before fixing.")
        timestamp, attempt_id = _now(), str(uuid.uuid4())
        launch_id = existing["id"] if existing is not None else str(uuid.uuid4())
        if existing is None:
            connection.execute(
                "INSERT INTO dependency_task_launches VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL, NULL, ?, ?)",
                (launch_id, *identity, attempt_id, timestamp, timestamp),
            )
        else:
            connection.execute(
                "UPDATE dependency_task_launches SET attempt_id = ?, status = 'pending', "
                "thread_id = NULL, error = NULL, updated_at = ? WHERE id = ?",
                (attempt_id, timestamp, launch_id),
            )
        row = _task_launch(connection, argparse.Namespace(**vars(args), launch_id=launch_id))
        return {"claimed": True, "launch": _launch_result(row)}


def settle_task_launch(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, object]:
    """Save an outcome only while the caller still owns this attempt."""
    if args.status not in ("settled", "failed", "outcome_unknown") or bool(args.thread_id) != (
        args.status == "settled"
    ):
        raise ValueError("Only a settled launch requires and accepts a task ID.")
    connection.execute("BEGIN IMMEDIATE")
    with connection:
        existing = _task_launch(connection, args)
        if existing["attempt_id"] != args.attempt_id:
            raise ValueError("The task launch attempt changed. This outcome is stale.")
        if existing["status"] == "failed" and args.status == "outcome_unknown":
            return {"launch": _launch_result(existing)}
        if existing["thread_id"] is not None:
            if args.status != "settled":
                return {"launch": _launch_result(existing)}
            if args.thread_id != existing["thread_id"]:
                raise ValueError(
                    "This launch already has a task. Its saved link cannot be replaced."
                )
        connection.execute(
            "UPDATE dependency_task_launches SET status = ?, thread_id = ?, error = ?, "
            "updated_at = ? WHERE id = ?",
            (args.status, args.thread_id, args.error, _now(), args.launch_id),
        )
        return {"launch": _launch_result(_task_launch(connection, args))}


def get_task_launches(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, object]:
    """Read report assessment history and this account/host's durable task links."""
    connection.execute("BEGIN")
    with connection:
        report = _report(connection, args.report_id)
        assessments = connection.execute(
            "SELECT id, report_id, finding_ids_json, target_revision, state, created_at "
            "FROM dependency_assessments WHERE report_id = ? ORDER BY created_at DESC, id",
            (args.report_id,),
        ).fetchall()
        launches = connection.execute(
            "SELECT * FROM dependency_task_launches WHERE account_id = ? AND host_id = ? "
            "AND report_id = ? ORDER BY created_at DESC, id",
            (args.account_id or "", args.host_id, args.report_id),
        ).fetchall()
    return {
        "assessments": [
            {**_assessment_result(row, report["target_path"]), "createdAt": row["created_at"]}
            for row in assessments
        ],
        "launches": [_launch_result(row) for row in launches],
    }


def run_command(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, object]:
    """Dispatch an import command with the workbench's concise CLI errors."""
    try:
        return COMMANDS[args.command](connection, args)
    except (OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from None


COMMANDS = {
    "claim-dependency-task-launch": claim_task_launch,
    "settle-dependency-task-launch": settle_task_launch,
    "get-dependency-task-launches": get_task_launches,
    "import-dependency-findings": import_report,
    "list-dependency-reports": list_reports,
    "get-dependency-report": get_report,
    "get-dependency-finding": get_finding,
    "start-dependency-assessment": start_assessment,
    "get-dependency-assessment": get_assessment,
    "record-dependency-assessments": record_assessments,
}
