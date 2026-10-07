from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shlex
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest import TestCase, mock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "workbench_db.py"
SNAPSHOT_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "snapshot_sqlite.py"
PLUGIN_MANIFEST = Path(__file__).resolve().parents[1] / ".codex-plugin" / "plugin.json"


def load_script(name: str, *, module_name: str | None = None) -> ModuleType:
    script = SCRIPT.parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(module_name or name, script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def saved_coverage(*, deferred=(), surfaces=(), completeness=None):
    return {
        "completeness": completeness or ("partial" if deferred else "complete"),
        "surfaces": list(surfaces),
        "explicitExclusions": [],
        "deferred": list(deferred),
    }


def saved_draft(
    scan_id: str,
    *,
    deferred=(),
    surfaces=(),
    closures=(),
    complete=False,
    findings=(),
    completeness=None,
):
    return {
        "scanId": scan_id,
        "complete": complete,
        "findings": list(findings),
        "coverage": {
            **saved_coverage(deferred=deferred, surfaces=surfaces, completeness=completeness),
            **({"resolvedDeferred": list(closures)} if closures else {}),
        },
    }


def saved_binding(coverage_mode="repository", *, repository="test", status="interrupted"):
    return {
        "status": status,
        "allowedTargetKinds": ["git_revision"],
        "target": {"kind": "git_revision", "repository": repository, "revision": "head"},
        "scope": {"includePaths": ["."], "excludePaths": []},
        "coverageMode": coverage_mode,
    }


def saved_discovery_worker(output: Path, worker_id: str = "worker", attempt: int = 1) -> dict:
    return {
        "id": worker_id,
        "kind": "discovery",
        "artifact_dir": str(output),
        "result_manifest_path": None,
        "attempt": attempt,
    }


def replay_saved_results(
    module, documents, scan_dir, scan_id, binding, workers=(), *, stopped=True
):
    return module.merge_saved_results(
        scan_dir,
        scan_id,
        binding,
        list(workers),
        [],
        stopped=stopped,
        reason="interrupted",
        frozen_source_digests=documents[0]["scan"]["preservedSources"],
    )


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
    umask: int = -1,
) -> dict[str, object]:
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
        umask=umask,
    )
    if not check:
        return {"returncode": completed.returncode, "stderr": completed.stderr}
    return json.loads(completed.stdout)


def begin_deep_scan(
    state_dir: Path, thread_id: str, *extra: str, **options: Any
) -> dict[str, object]:
    return run_workbench(state_dir, "begin-deep-scan", "--thread-id", thread_id, *extra, **options)


def resume_deep_scan(
    state_dir: Path, scan_id: str, thread_id: str, *extra: str, **options: Any
) -> dict[str, object]:
    return scan_command(
        state_dir, "begin-deep-scan", scan_id, "--thread-id", thread_id, *extra, **options
    )


def get_deep_scan(
    state_dir: Path, scan_id: str, thread_id: str, **options: Any
) -> dict[str, object]:
    return scan_command(state_dir, "get-deep-scan", scan_id, "--thread-id", thread_id, **options)


def upsert_deep_worker(
    state_dir: Path,
    scan_id: str,
    worker_id: str,
    kind: str,
    status: str,
    prompt_path: str,
    artifact_dir: str,
    *extra: str,
    **options: Any,
) -> dict[str, object]:
    return scan_command(
        state_dir,
        "upsert-deep-scan-worker",
        scan_id,
        "--worker-id",
        worker_id,
        "--kind",
        kind,
        "--status",
        status,
        "--prompt-path",
        prompt_path,
        "--artifact-dir",
        artifact_dir,
        *extra,
        **options,
    )


def claim_deep_scan_dedup(
    state_dir: Path,
    scan_id: str,
    worker_id: str,
    prompt_path: str,
    artifact_dir: str,
    *extra: str,
    check: bool = True,
    environment: dict[str, str] | None = None,
) -> dict[str, object]:
    return scan_command(
        state_dir,
        "claim-deep-scan-dedup",
        scan_id,
        "--worker-id",
        worker_id,
        "--prompt-path",
        prompt_path,
        "--artifact-dir",
        artifact_dir,
        *extra,
        check=check,
        environment=environment,
    )


def commit_deep_dedup(
    state_dir: Path,
    scan_id: str,
    worker_id: str,
    result_manifest_path: str,
    new_findings_count: str,
    *extra: str,
    **options: Any,
) -> dict[str, object]:
    return scan_command(
        state_dir,
        "commit-deep-scan-dedup",
        scan_id,
        "--worker-id",
        worker_id,
        "--result-manifest-path",
        result_manifest_path,
        "--new-findings-count",
        new_findings_count,
        *extra,
        **options,
    )


def finish_deep_scan(
    state_dir: Path,
    scan_id: str,
    terminal_reason: str,
    manifest_path: str,
    *extra: str,
    check: bool = True,
    environment: dict[str, str] | None = None,
) -> dict[str, object]:
    return scan_command(
        state_dir,
        "finish-deep-scan",
        scan_id,
        "--terminal-reason",
        terminal_reason,
        "--manifest-path",
        manifest_path,
        *extra,
        check=check,
        environment=environment,
    )


def set_triage(
    state_dir: Path, occurrence_id: str, status: str, *extra: str, **options: Any
) -> dict[str, object]:
    return run_workbench(
        state_dir,
        "set-finding-triage",
        "--occurrence-id",
        occurrence_id,
        "--status",
        status,
        *extra,
        **options,
    )


def mark_handoff_delivered(
    state_dir: Path, scan_id: str, claim_token: str, *extra: str, **options: Any
) -> dict[str, object]:
    return scan_claim_command(
        state_dir, "mark-handoff-delivered", scan_id, claim_token, *extra, **options
    )


def attach_continuation(
    state_dir: Path, scan_id: str, claim_token: str, thread_id: str, **options: Any
) -> dict[str, object]:
    return scan_claim_command(
        state_dir,
        "attach-scan-continuation-thread",
        scan_id,
        claim_token,
        "--thread-id",
        thread_id,
        **options,
    )


def cancel_scan(state_dir: Path, scan_id: str, thread_id: str, **options: Any) -> dict[str, object]:
    return scan_command(state_dir, "cancel-scan", scan_id, "--thread-id", thread_id, **options)


def preserve_scan_results(
    state_dir: Path, scan_id: str, thread_id: str, **options: Any
) -> dict[str, object]:
    return scan_command(
        state_dir, "preserve-scan-results", scan_id, "--thread-id", thread_id, **options
    )


def start_scan_command(
    state_dir: Path, workspace_id: str, *extra: str, **options: Any
) -> dict[str, object]:
    return workspace_command(state_dir, "start-scan", workspace_id, *extra, **options)


def get_scan(state_dir: Path, scan_id: str, *extra: str, **options: Any) -> dict[str, object]:
    return scan_command(state_dir, "get-scan", scan_id, *extra, **options)


def fail_scan(
    state_dir: Path, scan_id: str, message: str, *extra: str, **options: Any
) -> dict[str, object]:
    return scan_command(state_dir, "fail-scan", scan_id, "--message", message, *extra, **options)


def scan_command(
    state_dir: Path, command: str, scan_id: str, *extra: str, **options: Any
) -> dict[str, object]:
    return run_workbench(state_dir, command, "--scan-id", scan_id, *extra, **options)


def scan_claim_command(
    state_dir: Path, command: str, scan_id: str, claim_token: str, *extra: str, **options: Any
) -> dict[str, object]:
    return run_workbench(
        state_dir, command, "--scan-id", scan_id, "--claim-token", claim_token, *extra, **options
    )


def workspace_command(
    state_dir: Path, command: str, workspace_id: str, *extra: str, **options: Any
) -> dict[str, object]:
    return run_workbench(state_dir, command, "--workspace-id", workspace_id, *extra, **options)


def request_remediation(
    state_dir: Path,
    occurrence_id: str,
    request_id: str,
    action_token: str,
    *,
    check: bool = True,
) -> dict[str, object]:
    return run_workbench(
        state_dir,
        "request-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        action_token,
        check=check,
    )


def set_remediation(
    state_dir: Path,
    occurrence_id: str,
    request_id: str,
    action_token: str,
    expected_version: str,
    state: str,
    *extra: str,
    check: bool = True,
) -> dict[str, object]:
    return run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        action_token,
        "--expected-version",
        expected_version,
        "--state",
        state,
        *extra,
        check=check,
    )


def request_remediation_action(
    state_dir: Path,
    occurrence_id: str,
    request_id: str,
    expected_version: str,
    action: str,
    action_token: str,
    *,
    check: bool = True,
) -> dict[str, object]:
    return run_workbench(
        state_dir,
        "request-finding-remediation-action",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--expected-version",
        expected_version,
        "--action",
        action,
        "--action-token",
        action_token,
        check=check,
    )


def save_workspace(
    state_dir: Path,
    workspace_id: str,
    target_path: str,
    scope: str,
    mode: str,
    *extra: str,
    check: bool = True,
    environment: dict[str, str] | None = None,
) -> dict[str, object]:
    return workspace_command(
        state_dir,
        "save-workspace",
        workspace_id,
        "--target-path",
        target_path,
        "--scope",
        scope,
        "--mode",
        mode,
        *extra,
        check=check,
        environment=environment,
    )


def create_workspace(
    state_dir: Path,
    workspace_id: str,
    *extra: str,
    environment: dict[str, str] | None = None,
) -> dict[str, object]:
    return workspace_command(
        state_dir, "create-workspace", workspace_id, *extra, environment=environment
    )


def update_progress(
    state_dir: Path,
    scan_id: str,
    *extra: str,
    check: bool = True,
    environment: dict[str, str] | None = None,
) -> dict[str, object]:
    return scan_command(
        state_dir, "update-progress", scan_id, *extra, check=check, environment=environment
    )


def claim_remediation_resend(
    state_dir: Path,
    occurrence_id: str,
    request_id: str,
    action_token: str,
    *,
    check: bool = True,
) -> dict[str, object]:
    return run_workbench(
        state_dir,
        "claim-finding-remediation-resend",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        action_token,
        check=check,
    )


def cancel_remediation_request(
    state_dir: Path,
    occurrence_id: str,
    request_id: str,
    action_token: str,
) -> dict[str, object]:
    return run_workbench(
        state_dir,
        "cancel-finding-remediation-request",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        action_token,
    )


def mark_remediation_delivered(
    state_dir: Path,
    occurrence_id: str,
    request_id: str,
    action_token: str,
) -> dict[str, object]:
    return run_workbench(
        state_dir,
        "mark-finding-remediation-delivered",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        action_token,
    )


def fail_deep_scan(state_dir, codex_home, scan_id, *, message="Worker stopped.", deep_status=None):
    return scan_command(
        state_dir,
        "fail-deep-scan",
        scan_id,
        "--message",
        message,
        *(["--deep-status", deep_status] if deep_status is not None else []),
        environment={"CODEX_HOME": str(codex_home)},
    )


def start_delivered_scan(
    state_dir: Path,
    *args: str,
    environment: dict[str, str] | None = None,
) -> dict[str, object]:
    """Prepare an unclaimed, delivered scan for tests outside handoff ownership."""
    started = run_workbench(state_dir, "start-scan", *args, environment=environment)
    scan = started["results"]
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET handoff_status = 'delivered' WHERE id = ?", (scan["scanId"],)
        )
    scan["handoffStatus"] = "delivered"
    return started


def start_workspace_scan(state_dir: Path, workspace_id: str, scan_root: Path) -> tuple[str, Path]:
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        workspace_id,
        "--scan-root",
        str(scan_root),
    )["results"]
    return str(started["scanId"]), Path(str(started["scanDir"]))


def start_saved_scan(state_dir: Path, target: Path, scan_root: Path) -> tuple[str, Path]:
    saved = create_saved_workspace(state_dir, target)
    return start_workspace_scan(state_dir, str(saved["id"]), scan_root)


def empty_target_scan(tmp_path: Path) -> tuple[Path, Path, str, Path]:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    scan_id, scan_dir = start_saved_scan(state_dir, target, tmp_path / "scans")
    return state_dir, target, scan_id, scan_dir


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
    created = create_workspace(
        state_dir,
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
    return save_workspace(
        state_dir,
        workspace_id,
        str(target),
        ".",
        mode,
        "--user-context",
        "Pay attention to uploaded archives.",
    )


def create_saved_git_workspace(
    state_dir: Path, target: Path, *, mode: str = "standard"
) -> dict[str, object]:
    workspace_id = str(uuid.uuid4())
    create_workspace(state_dir, workspace_id, "--target-path", str(target))
    return save_workspace(state_dir, workspace_id, str(target), ".", mode)


def worker_paths(scan_dir: Path, name: str) -> tuple[Path, Path, Path]:
    artifact_dir = scan_dir / "artifacts" / "deep_discovery" / name
    artifact_dir.mkdir(parents=True)
    prompt_path = artifact_dir / "prompt.md"
    prompt_path.write_text(f"Prompt for {name}\n")
    result_path = artifact_dir / "result.json"
    return prompt_path, artifact_dir, result_path


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
    identity_anchor: str = "archive-entry-write-without-containment",
    include_paths: list[str] | None = None,
    relative_path: str = "src/extract.py",
    target_kind: str = "directory_snapshot",
    target_revision: str | None = None,
    diff_base_revision: str | None = None,
    diff_head_revision: str | None = None,
    snapshot_digest: str | None = None,
    coverage_mode: str = "repository",
    inventory_strategy: str = "repository",
) -> None:
    include_paths = include_paths or ["."]
    target_contract = {
        "kind": target_kind,
        "targetId": stable_target_id(target),
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
        "scanId": scan_id,
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
        "scanId": scan_id,
        "mode": coverage_mode,
        "completeness": "complete",
        "inventoryStrategy": inventory_strategy,
        "includePaths": include_paths,
        "excludePaths": [],
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
            "id": scan_id,
            "producer": {
                "name": "codex-security-plugin",
                "version": source_plugin_version(),
            },
            "status": "completed",
            "startedAt": "2026-06-02T18:00:00Z",
            "completedAt": "2026-06-02T18:09:00Z",
            "target": target_contract,
            "scope": {"includePaths": include_paths, "excludePaths": []},
            "coverageRef": "coverage.json",
            "findingsRef": "findings.json",
        },
    }
    (scan_dir / "findings.json").write_text(json.dumps(findings))
    (scan_dir / "coverage.json").write_text(json.dumps(coverage))
    (scan_dir / "scan-manifest.json").write_text(json.dumps(manifest))
    (scan_dir / "report.md").write_text("# Fixture report\n")


def windows_file_backend() -> mock.Mock:
    backend = mock.Mock()

    def open_read_fd(scan_dir: Path, relative_path: str, _context: str) -> int:
        return os.open(scan_dir / relative_path, os.O_RDONLY)

    def atomic_write(
        scan_dir: Path,
        relative_path: str,
        payload: bytes,
        *,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> None:
        path = scan_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    def unlink_if_exists(scan_dir: Path, relative_path: str) -> None:
        (scan_dir / relative_path).unlink(missing_ok=True)

    backend.open_read_fd.side_effect = open_read_fd
    backend.atomic_write.side_effect = atomic_write
    backend.unlink_if_exists.side_effect = unlink_if_exists
    return backend


class ScanFixtureTestCase(TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.scan_dir = Path(self.temp_dir.name) / "scan"
        shutil.copytree(self.example_scan, self.scan_dir)
        manifest = json.loads((self.scan_dir / "scan-manifest.json").read_text())
        findings = json.loads((self.scan_dir / "findings.json").read_text())
        coverage = json.loads((self.scan_dir / "coverage.json").read_text())
        report = self.validator.FINALIZER._generate_report_projection(manifest, findings, coverage)
        (self.scan_dir / "report.md").write_bytes(report)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def read_json(self, name: str) -> dict[str, object]:
        return json.loads((self.scan_dir / name).read_text(encoding="utf-8"))

    def sha256_file(self, name: str) -> str:
        return hashlib.sha256((self.scan_dir / name).read_bytes()).hexdigest()
