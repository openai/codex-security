"""Build temporary workbench targets, scan artifacts, and database state for integration tests."""

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
from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest import TestCase, mock

BUDGET_COST = {
    "model": "gpt-5.6-sol",
    "inputTokens": 1250,
    "cachedInputTokens": 200,
    "cacheWriteInputTokens": 0,
    "outputTokens": 30,
    "estimatedUsd": 0.00625,
}


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "workbench_db.py"


SNAPSHOT_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "snapshot_sqlite.py"


PLUGIN_MANIFEST = Path(__file__).resolve().parents[1] / ".codex-plugin" / "plugin.json"


def load_script(name: str, *, module_name: str | None = None) -> ModuleType:
    """Load a fresh module from the plugin scripts directory, optionally overriding its import name."""
    script = SCRIPT.parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(module_name or name, script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_review_state(state_dir: Path | sqlite3.Connection, scan_dir: Path) -> dict[str, Any]:
    """Reconstruct internal review state from the retained publication inputs."""
    review = load_script("review_state")

    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    summary = manifest["scan"]
    if review.uses_legacy_review(summary):
        return json.loads((scan_dir / "coverage.json").read_text())
    if "reviewState" in summary:
        return review.review_state(summary)
    if "preservedSources" not in summary:
        head = json.loads((scan_dir / "checkpoint-head.json").read_text())
        checkpoint = json.loads((scan_dir / "checkpoints" / head["checkpoint"]).read_text())
        return review.review_state({**summary, "reviewState": checkpoint["reviewState"]})
    db = load_script("workbench_db")
    saved = load_script("workbench_saved_results")
    with (
        nullcontext(state_dir)
        if isinstance(state_dir, sqlite3.Connection)
        else sqlite3.connect(state_dir / "workbench.sqlite3")
    ) as connection:
        connection.row_factory = sqlite3.Row
        scan = connection.execute("SELECT * FROM scans WHERE id = ?", (summary["id"],)).fetchone()
        workers = connection.execute(
            "SELECT * FROM deep_scan_workers WHERE scan_id = ? ORDER BY created_at, id",
            (summary["id"],),
        ).fetchall()
    if summary["status"] == "completed" and scan["mode"] == "deep":
        # Deep completion saves the accepted parent aggregate before sealing,
        # including deadline recovery's validated records and pending tasks.
        head = json.loads((scan_dir / "checkpoint-head.json").read_text())
        checkpoint = json.loads((scan_dir / "checkpoints" / head["checkpoint"]).read_text())
        return review.review_state({**summary, "reviewState": checkpoint["reviewState"]})
    binding = db.workbench_completion_binding(scan, summary["completedAt"], manifest)
    # This read-only helper reconstructs bookkeeping rather than reusing a sealed publication.
    binding["status"] = "inspect-retained-review"
    documents = saved.merge_saved_results(
        scan_dir,
        summary["id"],
        binding,
        workers,
        [],
        stopped=summary["status"] != "completed",
        reason=(
            f"Scan {summary['status']}; saved findings and pending review were preserved. {scan['failure_message'] or ''}"
        ).strip(),
        frozen_source_digests=summary["preservedSources"],
        checkpoint_heads=summary.get("preservedCheckpointHeads", {}).copy(),
        scan_mode=scan["mode"],
        finding_scope=db.requested_finding_scope(scan) if scan["mode"] == "deep" else None,
        project_worker_coverage=scan["mode"] == "deep",
    )
    assert documents is not None
    binding["status"] = summary["status"]
    return (
        load_script("finalize_scan_contract")
        ._prepare_scan_finalization(
            scan_dir,
            expected_coverage_mode=db.expected_coverage_mode(scan),
            completion_binding=binding,
            draft_documents=documents,
            recover_unsealed=True,
            allow_missing_writeups=summary["status"] == "completed",
            finding_scope=db.requested_finding_scope(scan) if scan["mode"] == "deep" else None,
        )
        .coverage
    )


def source_plugin_version() -> str:
    manifest = json.loads(PLUGIN_MANIFEST.read_text(encoding="utf-8"))
    version = manifest.get("version")
    assert isinstance(version, str) and version
    return version


def write_checkpoint(checkpoint_dir: Path, payload: Any, *, mtime_ns: int | None = None) -> Path:
    """Write the serialized payload as a SHA-256-named checkpoint and optionally set its timestamp for ordering tests."""
    encoded = json.dumps(payload).encode()
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_path = checkpoint_dir / f"{hashlib.sha256(encoded).hexdigest()}.json"
    if checkpoint_dir.name == "checkpoints":
        (checkpoint_dir / "pending").mkdir(exist_ok=True)
        (checkpoint_dir / "pending" / checkpoint_path.name).write_bytes(b"")
    checkpoint_path.write_bytes(encoded)
    if mtime_ns is not None:
        os.utime(checkpoint_path, ns=(mtime_ns, mtime_ns))
    return checkpoint_path


def select_checkpoint(output: Path, checkpoint: Path, *, mtime_ns: int | None = None) -> Path:
    """Write a head pointing to the checkpoint filename and return the head path for further fixture changes."""
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    if mtime_ns is not None:
        os.utime(head, ns=(mtime_ns, mtime_ns))
    return head


def write_result_draft(path: Path, draft: dict, *, mtime_ns: int) -> None:
    path.write_text(json.dumps(draft))
    os.utime(path, ns=(mtime_ns, mtime_ns))


def sort_checkpoint_entries(monkeypatch, *, key=None, reverse=False):
    """Control checkpoint enumeration order so a test can distinguish filesystem order from source precedence."""
    from workbench import saved_sources

    children = saved_sources._children
    monkeypatch.setattr(
        saved_sources,
        "_children",
        lambda root, relative: sorted(children(root, relative), key=key, reverse=reverse),
    )


def interrupt_publication(*args, **kwargs):
    raise OSError("Synthetic publication interruption")


def saved_coverage(*, deferred=(), surfaces=()):
    return {
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
):
    return {
        "scanId": scan_id,
        "complete": complete,
        "findings": list(findings),
        "coverage": {
            **saved_coverage(deferred=deferred, surfaces=surfaces),
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
        "status": "running",
        "merge_state": "buffered",
        "artifact_dir": str(output),
        "result_manifest_path": None,
        "attempt": attempt,
    }


def replay_saved_results(
    module, documents, scan_dir, scan_id, binding, workers=(), *, stopped=True
):
    """Rebuild the interrupted result using the source digests frozen in the supplied manifest."""
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
    """Compute the expected snapshot digest from fixture paths, entry modes, link targets, and file contents."""
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
    """Run the workbench CLI with a fixture state directory and capture its output.

    By default, decode JSON from stdout and raise CalledProcessError on failure.
    With check=False, return the exit code and stderr for diagnostic assertions.
    Entries in environment override the inherited environment and state setting.
    """
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


def write_remediation_patch(patch_path: Path, **text_options: Any) -> None:
    patch_path.write_text(
        "diff --git a/source.txt b/source.txt\n"
        "--- a/source.txt\n"
        "+++ b/source.txt\n"
        "@@ -1 +1 @@\n"
        "-vulnerable\n"
        "+fixed\n",
        **text_options,
    )


@dataclass(frozen=True)
class RemediationRequest:
    """Run remediation commands for one occurrence using the same request ID across retries and state changes."""

    state_dir: Path
    occurrence_id: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def _run(
        self, command: str, *args: str, check: bool = True, input_text: str | None = None
    ) -> dict[str, object]:
        return run_workbench(
            self.state_dir,
            command,
            "--occurrence-id",
            self.occurrence_id,
            "--request-id",
            self.id,
            *args,
            check=check,
            input_text=input_text,
        )

    def start(self, token: str, *, check: bool = True) -> dict[str, object]:
        return self._run("request-finding-remediation", "--action-token", token, check=check)

    def update(
        self,
        token: str,
        version: str,
        state: str,
        *args: str,
        check: bool = True,
        input_text: str | None = None,
    ) -> dict[str, object]:
        return self._run(
            "set-finding-remediation",
            "--action-token",
            token,
            "--expected-version",
            version,
            "--state",
            state,
            *args,
            check=check,
            input_text=input_text,
        )

    def generate(
        self, token: str, patch: Path, *args: str, check: bool = True
    ) -> dict[str, object]:
        digest = hashlib.sha256(patch.read_bytes()).hexdigest()
        return self.update(
            token,
            "1",
            "generated",
            "--patch-path",
            patch.name,
            "--patch-digest",
            f"sha256:{digest}",
            *args,
            check=check,
        )

    def request_action(
        self, version: str, action: str, token: str, *, check: bool = True
    ) -> dict[str, object]:
        return self._run(
            "request-finding-remediation-action",
            "--expected-version",
            version,
            "--action",
            action,
            "--action-token",
            token,
            check=check,
        )

    def claim_resend(self, token: str, *, check: bool = True) -> dict[str, object]:
        return self._run("claim-finding-remediation-resend", "--action-token", token, check=check)

    def cancel(self, token: str) -> dict[str, object]:
        return self._run("cancel-finding-remediation-request", "--action-token", token)

    def mark_delivered(self, token: str) -> dict[str, object]:
        return self._run("mark-finding-remediation-delivered", "--action-token", token)

    def release_claim(self, token: str) -> dict[str, object]:
        return self._run("release-finding-remediation-claim", "--action-token", token)


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


def fail_deep_scan(state_dir, codex_home, scan_id, *, message="Worker stopped.", deep_status=None):
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET status = ?, phase = 'terminal', error_message = ? "
            "WHERE scan_id = ?",
            (deep_status or "failed", message, scan_id),
        )
    return run_workbench(
        state_dir,
        "fail-scan",
        "--scan-id",
        scan_id,
        "--message",
        message,
        environment={"CODEX_HOME": str(codex_home)},
    )


def start_delivered_scan(
    state_dir: Path,
    workspace_id: str,
    *args: str,
    environment: dict[str, str] | None = None,
) -> dict[str, object]:
    """Prepare an unclaimed, delivered scan for tests outside handoff ownership."""
    scan = start_scan_command(state_dir, workspace_id, *args, environment=environment)["results"]
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET handoff_status = 'delivered' WHERE id = ?", (scan["scanId"],)
        )
    scan["handoffStatus"] = "delivered"
    return scan


def start_workspace_scan(state_dir: Path, workspace_id: str, scan_root: Path) -> tuple[str, Path]:
    started = start_delivered_scan(
        state_dir,
        workspace_id,
        "--scan-root",
        str(scan_root),
    )
    return str(started["scanId"]), Path(str(started["scanDir"]))


def start_saved_scan(state_dir: Path, target: Path, scan_root: Path) -> tuple[str, Path]:
    saved = create_saved_workspace(state_dir, target)
    return start_workspace_scan(state_dir, str(saved["id"]), scan_root)


def empty_target_paths(tmp_path: Path) -> tuple[Path, Path]:
    target = tmp_path / "target"
    target.mkdir()
    return tmp_path / "state", target


def empty_target_scan(tmp_path: Path) -> tuple[Path, Path, str, Path]:
    state_dir, target = empty_target_paths(tmp_path)
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


def mark_deep_aggregate_ready(state_dir: Path, scan_id: str, scan_dir: Path) -> Path:
    checkpoint = scan_dir / "artifacts" / "deep-scan" / "checkpoint.json"
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    document = (
        json.loads(checkpoint.read_text())
        if checkpoint.exists()
        else {
            "version": 2,
            "startedAt": "2026-01-01T00:00:00Z",
            "passes": [],
            "mergedScanIds": [],
            "aggregate": [],
            "noNewStreak": 4,
            "consecutiveErrors": 0,
        }
    )
    document["terminalReason"] = "saturated"
    checkpoint.write_text(json.dumps(document))
    return checkpoint


def begin_legacy_scan(
    state_dir: Path, codex_home: Path, target: Path, scan_root: Path, *, thread_id: str
) -> dict[str, object]:
    """Seed a v1 saved scan to test historical artifact/usage readers without its retired engine."""
    started = run_workbench(
        state_dir,
        "begin-deep-scan",
        "--thread-id",
        thread_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--scan-root",
        str(scan_root),
        environment={"CODEX_HOME": str(codex_home)},
    )
    scan = started["scan"]
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET handoff_claim_token = NULL, continuation_thread_id = NULL WHERE id = ?",
            (scan["scanId"],),
        )
        connection.execute(
            "INSERT INTO deep_scan_runs (scan_id,schema_version,workflow_version,status,phase,workers,"
            "subagents,stop_after_no_new,max_discovery_runs,created_at,updated_at) "
            "SELECT id,1,'deep-security-scan/v1','running','discovery',4,3,4,8,started_at,updated_at "
            "FROM scans WHERE id = ?",
            (scan["scanId"],),
        )
    scan["createdAt"] = scan["updatedAt"]
    return {"deepScan": scan}


def finding_fixture(
    *,
    relative_path: str = "src/extract.py",
    identity_anchor: str = "archive-entry-write-without-containment",
) -> dict[str, Any]:
    return {
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
        "locations": [{"path": relative_path, "startLine": 41, "endLine": 44, "role": "sink"}],
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
            "dataflow": "archive entry -> destination path -> filesystem write",
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


def worker_paths(scan_dir: Path, name: str) -> tuple[Path, Path, Path]:
    artifact_dir = scan_dir / "artifacts" / "deep_discovery" / name
    artifact_dir.mkdir(parents=True)
    prompt_path = artifact_dir / "prompt.md"
    prompt_path.write_text(f"Prompt for {name}\n")
    result_path = artifact_dir / "result.json"
    return prompt_path, artifact_dir, result_path


def read_draft_documents(scan_dir: Path) -> dict:
    return {
        "manifest": json.loads((scan_dir / "scan-manifest.json").read_text()),
        "findings": json.loads((scan_dir / "findings.json").read_text()),
        "coverage": json.loads((scan_dir / "coverage.json").read_text()),
    }


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
        "findings": [finding_fixture(relative_path=relative_path, identity_anchor=identity_anchor)],
    }
    coverage = {
        "documentType": "codex-security.coverage",
        "schemaVersion": "1.0",
        "scanId": artifact_scan_id,
        "mode": coverage_mode,
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


def recipe(target: Path, mode: str = "standard") -> dict:
    return {
        "repository": str(target),
        "target": {"kind": "repository", "paths": []},
        "mode": mode,
        "config": {"model": "synthetic-model", "model_reasoning_effort": "high"},
        **({"deepScan": {"maxDiscoveryRuns": 8}} if mode == "deep" else {}),
    }


def register(
    state: Path, target: Path, directory: Path, *, mode="standard", parent=None, role=None, paths=()
) -> dict:
    missing = []
    current = directory
    while not current.exists():
        missing.append(current)
        current = current.parent
    for path in reversed(missing):
        path.mkdir(mode=0o700)
    saved_recipe = recipe(target, mode)
    if paths:
        saved_recipe["target"] = {"kind": "paths", "paths": list(paths)}
    return run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(target),
        "--scan-dir",
        str(directory),
        "--registration-json-stdin",
        *(("--parent-scan-id", parent) if parent else ()),
        input_text=json.dumps({"recipe": saved_recipe, "parentScanRole": role}),
    )


def checkpoint(state: Path, scan: dict, *, passes=(), merged=(), terminal=None) -> dict:
    value = {
        "version": 2,
        "startedAt": "2026-01-01T00:00:00Z",
        "passes": list(passes),
        "mergedScanIds": list(merged),
        "aggregate": None,
        "noNewStreak": 0,
        "consecutiveErrors": 0,
        **({"terminalReason": terminal} if terminal else {}),
    }
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        scan["scanId"],
        "--artifact-path",
        "artifacts/deep-scan/checkpoint.json",
        input_text=json.dumps(value),
    )
    return value


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
        replace_existing: bool = True,
    ) -> None:
        path = scan_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb" if replace_existing else "xb") as handle:
            handle.write(payload)

    def unlink_if_exists(
        scan_dir: Path,
        relative_path: str,
        *,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> None:
        (scan_dir / relative_path).unlink(missing_ok=True)

    backend.open_read_fd.side_effect = open_read_fd
    backend.atomic_write.side_effect = atomic_write
    backend.unlink_if_exists.side_effect = unlink_if_exists
    return backend


class ScanFixtureTestCase(TestCase):
    """Copy the example scan into a fresh temporary directory and rebuild its report for each test."""

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

    def write_json(self, relative_path: str, payload: object) -> None:
        path = self.scan_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def rewrite_sealed_artifact(self, relative_path: str, payload: object) -> None:
        """Rewrite the JSON artifact and update its hash in the fixture manifest so the seal matches the new bytes."""
        self.write_json(relative_path, payload)
        manifest = self.read_json("scan-manifest.json")
        for artifact in manifest["scan"]["artifacts"]:
            if artifact["path"] == relative_path:
                artifact["sha256"] = self.sha256_file(relative_path)
                break
        else:
            raise AssertionError(f"missing sealed artifact: {relative_path}")
        self.write_json("scan-manifest.json", manifest)

    def sha256_file(self, name: str) -> str:
        return hashlib.sha256((self.scan_dir / name).read_bytes()).hexdigest()


def usage_counts(
    input_tokens: int,
    cached_input_tokens: int,
    output_tokens: int,
    *,
    cache_write_input_tokens: int = 0,
) -> dict[str, int]:
    return {
        "inputTokens": input_tokens,
        "cachedInputTokens": cached_input_tokens,
        "cacheWriteInputTokens": cache_write_input_tokens,
        "outputTokens": output_tokens,
        "reasoningOutputTokens": 0,
        "totalTokens": input_tokens + output_tokens,
    }
