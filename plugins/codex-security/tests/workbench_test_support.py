from __future__ import annotations

import hashlib
import json
import os
import shlex
import sqlite3
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "workbench_db.py"
SNAPSHOT_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "snapshot_sqlite.py"
PLUGIN_MANIFEST = Path(__file__).resolve().parents[1] / ".codex-plugin" / "plugin.json"


def source_plugin_version() -> str:
    manifest = json.loads(PLUGIN_MANIFEST.read_text(encoding="utf-8"))
    version = manifest.get("version")
    assert isinstance(version, str) and version
    return version


def write_checkpoint(checkpoint_dir: Path, payload: Any) -> Path:
    encoded = json.dumps(payload).encode()
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_path = checkpoint_dir / f"{hashlib.sha256(encoded).hexdigest()}.json"
    checkpoint_path.write_bytes(encoded)
    return checkpoint_path


def stable_target_id(target: Path) -> str:
    digest = hashlib.sha256(f"local-workspace\0{target.resolve()}".encode()).hexdigest()
    return f"target_sha256_{digest}"


def update_digest_field(digest: Any, label: bytes, value: bytes) -> None:
    digest.update(len(label).to_bytes(4, "big"))
    digest.update(label)
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def directory_snapshot_digest(target: Path, *, excluded: tuple[Path, ...] = ()) -> str:
    excluded_relative = []
    for path in excluded:
        try:
            excluded_relative.append(path.relative_to(target))
        except ValueError:
            continue
    digest = hashlib.sha256()
    update_digest_field(digest, b"format", b"codex-security-directory/v1")
    for path in sorted(target.rglob("*")):
        relative = path.relative_to(target)
        if any(
            relative == excluded_path or excluded_path in relative.parents
            for excluded_path in excluded_relative
        ):
            continue
        metadata = path.lstat()
        update_digest_field(digest, b"path", os.fsencode(relative.as_posix()))
        update_digest_field(digest, b"mode", str(stat.S_IMODE(metadata.st_mode)).encode())
        if stat.S_ISLNK(metadata.st_mode):
            update_digest_field(digest, b"kind", b"symlink")
            update_digest_field(digest, b"content", os.fsencode(os.readlink(path)))
        elif stat.S_ISDIR(metadata.st_mode):
            update_digest_field(digest, b"kind", b"directory")
        elif stat.S_ISREG(metadata.st_mode):
            contents = path.read_bytes()
            update_digest_field(digest, b"kind", b"file")
            update_digest_field(digest, b"size", str(len(contents)).encode())
            update_digest_field(
                digest,
                b"content-sha256",
                hashlib.sha256(contents).digest(),
            )
    return f"codex-security-snapshot/v1:sha256:{digest.hexdigest()}"


def run_workbench(
    state_dir: Path,
    *args: str,
    check: bool = True,
    environment: dict[str, str] | None = None,
    input_text: str | None = None,
    deliver_unclaimed_scan_before_mutation: bool = True,
) -> dict[str, object]:
    state_database = state_dir / "workbench.sqlite3"
    # Lifecycle tests that omit a capability model a delivered, non-handoff scan.
    if (
        deliver_unclaimed_scan_before_mutation
        and args[0] in {"begin-deep-scan", "update-progress", "complete-scan", "fail-scan"}
        and "--scan-id" in args
        and "--claim-token" not in args
        and state_database.exists()
    ):
        scan_id = args[args.index("--scan-id") + 1]
        with sqlite3.connect(state_database) as connection:
            connection.execute(
                """
                UPDATE scans
                SET handoff_status = 'delivered'
                WHERE id = ? AND status = 'running' AND handoff_status = 'pending'
                    AND handoff_claim_token IS NULL AND continuation_thread_id IS NULL
                """,
                (scan_id,),
            )
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        check=check,
        capture_output=True,
        env={
            **os.environ,
            "CODEX_SECURITY_STATE_DIR": str(state_dir),
            **(environment or {}),
        },
        input=input_text,
        text=True,
    )
    if not check:
        return {"returncode": completed.returncode, "stderr": completed.stderr}
    return json.loads(completed.stdout)


def initialize_git_repository(target: Path) -> str:
    target.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=target, check=True)
    subprocess.run(["git", "config", "user.email", "fixture@example.com"], cwd=target, check=True)
    subprocess.run(["git", "config", "user.name", "Fixture"], cwd=target, check=True)
    (target / "README.md").write_text("fixture\n")
    subprocess.run(["git", "add", "README.md"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "Initial commit"], cwd=target, check=True)
    subprocess.run(["git", "branch", "-M", "main"], cwd=target, check=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=target,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def configure_git_command(target: Path, key: str, script: Path) -> None:
    subprocess.run(
        ["git", "config", key, shlex.join([sys.executable, str(script)])],
        cwd=target,
        check=True,
    )


def create_saved_workspace(
    state_dir: Path, target: Path, *, thread_id: str | None = None, mode: str = "standard"
) -> dict[str, object]:
    workspace_id = str(uuid.uuid4())
    created = run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        *(["--thread-id", thread_id] if thread_id else []),
        "--target-path",
        str(target),
        "--target-title",
        "Fixture Repository",
        "--target-summary",
        "Resolved fixture repository.",
    )
    assert created["setup"] == {"submitted": False}
    assert created["targetMetadata"] == {
        "hasHead": False,
        "isGit": False,
        "isWorktree": False,
        "reviewChangesSupported": False,
    }
    return run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        mode,
        "--user-context",
        "Pay attention to uploaded archives.",
    )


def create_saved_git_workspace(state_dir: Path, target: Path) -> dict[str, object]:
    workspace_id = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
    )
    return run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "standard",
    )


def mark_deep_coordinator_succeeded(state_dir: Path, scan_id: str, scan_dir: Path) -> Path:
    manifest = scan_dir / "artifacts" / "deep_discovery" / "coordinator-manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text('{"status":"succeeded"}\n')
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            """
            UPDATE deep_scan_runs
            SET status = 'succeeded', phase = 'terminal', terminal_reason = 'saturated',
                manifest_path = ?, completed_at = updated_at
            WHERE scan_id = ?
            """,
            (str(manifest), scan_id),
        )
    return manifest


def write_completed_contract(
    scan_dir: Path,
    scan_id: str,
    target: Path,
    *,
    artifact_scan_id: str | None = None,
    exclude_paths: list[str] | None = None,
    identity_anchor: str = "archive-entry-write-without-containment",
    include_paths: list[str] | None = None,
    relative_path: str = "src/extract.py",
    target_kind: str = "directory_snapshot",
    target_revision: str | None = None,
    diff_base_revision: str | None = None,
    diff_head_revision: str | None = None,
    snapshot_digest: str | None = None,
    target_id: str | None = None,
    coverage_mode: str = "repository",
    inventory_strategy: str = "repository",
) -> None:
    artifact_scan_id = artifact_scan_id or scan_id
    exclude_paths = exclude_paths or []
    include_paths = include_paths or ["."]
    target_contract = {
        "kind": target_kind,
        "targetId": target_id or stable_target_id(target),
        "displayName": target.name,
        "snapshotDigest": snapshot_digest
        or (
            directory_snapshot_digest(target, excluded=(scan_dir,))
            if target_kind == "directory_snapshot"
            else f"codex-security-snapshot/v1:sha256:{'a' * 64}"
        ),
    }
    if target_revision is not None:
        target_contract["revision"] = target_revision
    if diff_base_revision is not None:
        target_contract["baseRevision"] = diff_base_revision
    if diff_head_revision is not None:
        target_contract["headRevision"] = diff_head_revision
    findings = {
        "documentType": "codex-security.findings",
        "schemaVersion": "1.0",
        "scanId": artifact_scan_id,
        "findings": [
            {
                "ruleId": "path-traversal.archive-extraction",
                "identity": {"anchor": identity_anchor},
                "title": "Unsafe archive extraction can escape the output directory",
                "summary": "An attacker-controlled path reaches a filesystem write.",
                "severity": {
                    "level": "high",
                    "rationale": "The reachable write can escape the extraction root.",
                },
                "confidence": {"level": "high", "rationale": "Direct source trace."},
                "taxonomy": {"category": "path-traversal", "cwe": ["CWE-22"]},
                "locations": [
                    {"path": relative_path, "startLine": 41, "endLine": 44, "role": "sink"}
                ],
                "codeEvidence": [
                    {
                        "id": "archive-write",
                        "label": "Unchecked archive write",
                        "path": relative_path,
                        "startLine": 41,
                        "endLine": 44,
                        "language": "python",
                        "code": "destination.write_bytes(entry.read())",
                        "explanation": "The destination is written before containment is checked.",
                    }
                ],
                "validation": {
                    "method": "archive extraction test",
                    "summary": "A crafted entry wrote outside the extraction root.",
                    "evidenceRefs": ["archive-write"],
                    "assertions": ["The archive entry controls the destination path."],
                    "limitations": ["The test used a temporary extraction directory."],
                },
                "rootCause": {
                    "summary": "The archive destination is written before containment is enforced.",
                    "evidenceRefs": ["archive-write"],
                },
                "evidenceExcerpt": "destination.write_bytes(entry.read())",
                "attackPath": {
                    "dataFlow": "archive entry -> destination path -> filesystem write",
                    "reachability": "An archive uploader can supply the crafted entry.",
                    "evidenceRefs": ["archive-write"],
                    "impact": {
                        "level": "high",
                        "why": "The write can replace files outside the extraction root.",
                    },
                    "likelihood": {
                        "level": "high",
                        "why": "No containment check blocks the crafted path.",
                    },
                    "limitations": ["Writable targets depend on process permissions."],
                },
                "preventiveControls": ["Use a containment-checking extraction helper."],
                "remediation": "Reject archive entries that escape the extraction root.",
                "remediationTests": ["Reject traversal entries during extraction."],
                "provenance": {"source": "local_plugin"},
            }
        ],
    }
    coverage = {
        "documentType": "codex-security.coverage",
        "schemaVersion": "1.0",
        "scanId": artifact_scan_id,
        "mode": coverage_mode,
        "completeness": "complete",
        "inventoryStrategy": inventory_strategy,
        "includePaths": include_paths,
        "excludePaths": exclude_paths,
        "surfaces": [
            {
                "id": "surface_archive_extraction",
                "label": "Archive extraction",
                "disposition": "reported",
                "receiptRefs": [],
            }
        ],
        "explicitExclusions": [],
        "deferred": [],
    }
    manifest = {
        "documentType": "codex-security.scan-manifest",
        "schemaVersion": "1.0",
        "scan": {
            "id": artifact_scan_id,
            "producer": {
                "name": "codex-security-plugin",
                "version": source_plugin_version(),
            },
            "status": "completed",
            "startedAt": "2026-06-02T18:00:00Z",
            "completedAt": "2026-06-02T18:09:00Z",
            "target": target_contract,
            "scope": {"includePaths": include_paths, "excludePaths": exclude_paths},
            "coverageRef": "coverage.json",
            "findingsRef": "findings.json",
        },
    }
    (scan_dir / "findings.json").write_text(json.dumps(findings))
    (scan_dir / "coverage.json").write_text(json.dumps(coverage))
    (scan_dir / "scan-manifest.json").write_text(json.dumps(manifest))
    (scan_dir / "report.md").write_text("# Fixture report\n")
