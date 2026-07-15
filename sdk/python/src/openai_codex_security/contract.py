from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from jsonschema import Draft202012Validator
from pydantic import ValidationError

from .errors import ContractValidationError
from .models import CoverageDocument, FindingsDocument, ScanManifest
from .runtime import bundled_plugin_root
from .targets import NormalizedTarget, ScanMode

_DOCUMENTS = {
    "scan-manifest.json": ("scan-manifest.schema.json", ScanManifest),
    "findings.json": ("findings.schema.json", FindingsDocument),
    "coverage.json": ("coverage.schema.json", CoverageDocument),
}
_PRODUCER_NAME = "codex-security-plugin"


@dataclass(frozen=True, slots=True)
class ScanExpectation:
    repository: Path
    repository_revision: str | None
    target: NormalizedTarget
    mode: ScanMode
    plugin_version: str


def load_contract(
    scan_dir: Path,
    *,
    plugin_root: Path | None = None,
    expectation: ScanExpectation | None = None,
) -> tuple[ScanManifest, FindingsDocument, CoverageDocument]:
    scan_dir = _require_scan_directory(scan_dir)
    loaded: dict[str, Any] = {}
    schema_dir = (plugin_root or bundled_plugin_root()) / "schemas"
    payloads = {filename: _read_scan_json(scan_dir, filename) for filename in _DOCUMENTS}
    _validate_raw_artifact_paths(payloads["scan-manifest.json"])
    for filename, (schema_name, model) in _DOCUMENTS.items():
        payload = payloads[filename]
        schema = _read_json(schema_dir / schema_name)
        errors = sorted(
            Draft202012Validator(schema).iter_errors(payload), key=lambda err: list(err.path)
        )
        if errors:
            first = errors[0]
            location = ".".join(str(part) for part in first.path) or "<root>"
            raise ContractValidationError(f"{filename}:{location}: {first.message}")
        try:
            loaded[filename] = model.model_validate(payload)
        except ValidationError as exc:
            raise ContractValidationError(f"{filename}: {exc}") from exc

    manifest = loaded["scan-manifest.json"]
    findings = loaded["findings.json"]
    coverage = loaded["coverage.json"]
    if findings.scan_id != manifest.scan.id or coverage.scan_id != manifest.scan.id:
        raise ContractValidationError("Canonical contract scan IDs do not match.")
    if coverage.include_paths != manifest.scan.scope.include_paths:
        raise ContractValidationError("Coverage include paths do not match the manifest scope.")
    if coverage.exclude_paths != manifest.scan.scope.exclude_paths:
        raise ContractValidationError("Coverage exclude paths do not match the manifest scope.")

    _validate_seal(scan_dir, manifest, coverage)
    if expectation is not None:
        _validate_expectation(manifest, coverage, expectation)
    return manifest, findings, coverage


def require_scan_file(scan_dir: Path, relative_path: str, context: str) -> Path:
    scan_dir = _require_scan_directory(scan_dir)
    relative = _safe_relative_path(relative_path, context)
    path = scan_dir.joinpath(*relative.parts)
    current = scan_dir
    try:
        for part in relative.parts[:-1]:
            current /= part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise ContractValidationError(
                    f"{context}: expected a file inside the scan directory."
                )
        metadata = path.lstat()
    except OSError as exc:
        raise ContractValidationError(
            f"{context}: expected a file inside the scan directory."
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ContractValidationError(f"{context}: expected a regular non-symlink file.")
    try:
        path.resolve(strict=True).relative_to(scan_dir)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ContractValidationError(
            f"{context}: expected a file inside the scan directory."
        ) from exc
    return path


def _validate_seal(
    scan_dir: Path,
    manifest: ScanManifest,
    coverage: CoverageDocument,
) -> None:
    scan = manifest.scan
    if scan.sealed_at != scan.completed_at:
        raise ContractValidationError("Manifest sealedAt must match completedAt.")

    artifact_paths: set[str] = set()
    for index, artifact in enumerate(scan.artifacts):
        context = f"manifest.scan.artifacts[{index}]"
        relative = _safe_relative_path(artifact.path, f"{context}.path").as_posix()
        if relative in artifact_paths:
            raise ContractValidationError(f"{context}.path: duplicate artifact path.")
        artifact_paths.add(relative)
        path = require_scan_file(scan_dir, relative, context)
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != artifact.sha256:
            raise ContractValidationError(f"{context}: sealed artifact changed or is missing.")

    for surface in coverage.surfaces:
        for receipt in surface.receipt_refs:
            normalized = _safe_relative_path(receipt, "coverage receipt").as_posix()
            if not normalized.startswith("artifacts/"):
                raise ContractValidationError(
                    f"Coverage receipt must be under artifacts/: {receipt}"
                )
            if normalized not in artifact_paths:
                raise ContractValidationError(
                    f"Coverage receipt is missing from sealed artifacts: {receipt}"
                )


def _validate_raw_artifact_paths(manifest: dict[str, Any]) -> None:
    scan = manifest.get("scan")
    artifacts = scan.get("artifacts") if isinstance(scan, dict) else None
    if not isinstance(artifacts, list):
        return
    paths: set[str] = set()
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict) or not isinstance(artifact.get("path"), str):
            continue
        path = _safe_relative_path(
            artifact["path"], f"manifest.scan.artifacts[{index}].path"
        ).as_posix()
        if path in paths:
            raise ContractValidationError(
                f"manifest.scan.artifacts[{index}].path: duplicate artifact path."
            )
        paths.add(path)


def _validate_expectation(
    manifest: ScanManifest,
    coverage: CoverageDocument,
    expectation: ScanExpectation,
) -> None:
    scan = manifest.scan
    if scan.producer.name != _PRODUCER_NAME:
        raise ContractValidationError(
            f"Manifest producer must be {_PRODUCER_NAME}, got {scan.producer.name}."
        )
    if scan.producer.version != expectation.plugin_version:
        raise ContractValidationError(
            "Manifest producer version does not match the installed Codex Security plugin."
        )

    expected_mode = _expected_coverage_mode(expectation.target, expectation.mode)
    if coverage.mode.value != expected_mode:
        raise ContractValidationError(
            f"Coverage mode must be {expected_mode}, got {coverage.mode.value}."
        )

    target = scan.target
    requested = expectation.target
    if requested.kind in ("refs", "working_tree"):
        if target.kind.value != "git_diff":
            raise ContractValidationError("Diff scan manifest target must be git_diff.")
        if target.base_revision != requested.base:
            raise ContractValidationError("Diff scan base revision does not match the request.")
        if target.head_revision != requested.head:
            raise ContractValidationError("Diff scan head revision does not match the request.")
    elif expectation.repository_revision is None:
        if target.kind.value != "directory_snapshot":
            raise ContractValidationError(
                "Unversioned scan manifest target must be directory_snapshot."
            )
    else:
        if target.kind.value not in ("git_revision", "git_worktree"):
            raise ContractValidationError("Repository scan manifest target must be Git-backed.")
        if target.revision != expectation.repository_revision:
            raise ContractValidationError("Scan target revision does not match the repository.")

    if requested.kind == "paths":
        actual = [_safe_scope_path(path) for path in scan.scope.include_paths]
        if len(actual) != len(set(actual)) or set(actual) != set(requested.paths):
            raise ContractValidationError(
                "Manifest include paths do not match the requested path target."
            )


def _expected_coverage_mode(target: NormalizedTarget, mode: ScanMode) -> str:
    if target.kind == "paths":
        return "scoped_path"
    if target.kind == "refs":
        return "branch_diff"
    if target.kind == "working_tree":
        return "working_tree"
    return "deep_repository" if mode == "deep" else "repository"


def _require_scan_directory(scan_dir: Path) -> Path:
    scan_dir = scan_dir.absolute()
    try:
        metadata = scan_dir.lstat()
        resolved = scan_dir.resolve(strict=True)
    except OSError as exc:
        raise ContractValidationError(
            "Scan directory must be an existing non-symlink directory."
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ContractValidationError("Scan directory must be an existing non-symlink directory.")
    if resolved != scan_dir:
        raise ContractValidationError("Scan directory must use its canonical path.")
    return resolved


def _safe_relative_path(value: str, context: str) -> PurePosixPath:
    path = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        not value
        or path.as_posix() == "."
        or path.is_absolute()
        or windows.drive
        or ".." in path.parts
        or "\\" in value
        or "\0" in value
        or any(":" in part for part in path.parts)
    ):
        raise ContractValidationError(f"{context}: expected a safe scan-relative POSIX path.")
    return path


def _safe_scope_path(value: str) -> str:
    if value == ".":
        return value
    return _safe_relative_path(value, "manifest scope include path").as_posix()


def _read_scan_json(scan_dir: Path, relative_path: str) -> dict[str, Any]:
    path = require_scan_file(scan_dir, relative_path, relative_path)
    return _read_json(path)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ContractValidationError(f"Missing required contract document: {path.name}") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise ContractValidationError(f"{path.name}: unreadable JSON document.") from exc
    except json.JSONDecodeError as exc:
        raise ContractValidationError(f"{path.name}: invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ContractValidationError(f"{path.name}: expected a JSON object.")
    return payload
