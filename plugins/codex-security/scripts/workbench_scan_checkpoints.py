"""Durable semantic checkpoints for running CLI scans."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import stat
import uuid
from contextlib import nullcontext
from pathlib import Path, PurePosixPath
from typing import Any

from finalize_scan_contract import (
    ContractError,
    _read_scan_local_json,
    _read_sealed_scan,
    _recover_unsealed_coverage,
    _recover_unsealed_findings,
    _require_scan_directory,
    open_scan_local_file_descriptor,
    write_scan_local_bytes,
)
from generate_rank_input import repo_scope_paths
from workbench_target import require_scan_target_identity
from workbench_validation import path_within_scope


def review_file_inventory(repository: Path, scopes: list[str]) -> list[tuple[str, str]]:
    """Read source bytes before a scan acquires the shared database write lock."""
    paths: dict[str, Path] = {}
    for scope in scopes or ["."]:
        selected = repository / scope
        metadata = selected.lstat()
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_reparse_tag", 0) & 0x20000000:
            continue
        for path in repo_scope_paths(
            repository, selected, allow_unfiltered_fallback=selected == repository
        ):
            paths[str(path)] = path
    inventory = []
    for name in sorted(paths):
        path = paths[name]
        if not stat.S_ISREG(path.lstat().st_mode) or not path.resolve().is_relative_to(repository):
            continue
        inventory.append((path.relative_to(repository).as_posix(), file_digest(path)))
    return inventory


def review_path_value(path: str) -> str | bytes:
    """Keep ordinary names as TEXT and losslessly store POSIX filesystem bytes."""
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        return os.fsencode(path)
    return path


def freeze_review_files(
    connection: sqlite3.Connection, scan_id: str, inventory: list[tuple[str, str]]
) -> None:
    connection.executemany(
        "INSERT INTO scan_review_files (scan_id, relative_path, content_sha256) VALUES (?, ?, ?)",
        ((scan_id, review_path_value(path), digest) for path, digest in inventory),
    )


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prepare_review_files(
    connection: sqlite3.Connection, scan: sqlite3.Row
) -> list[tuple[str, str]] | None:
    """Prepare a missing inventory from the original source before acquiring a write lock."""
    if connection.execute(
        "SELECT 1 FROM scan_review_files WHERE scan_id = ? LIMIT 1", (scan["id"],)
    ).fetchone():
        return None
    from workbench_scan_start import scan_target_identity

    repository = require_scan_target_identity(scan)
    if scan_target_identity(repository, None) != (
        scan["target_revision"],
        scan["target_snapshot_digest"],
        scan["target_device"],
        scan["target_inode"],
    ):
        raise SystemExit("Cannot initialize checkpoints: the original source changed.")
    scopes = (
        json.loads(scan["recipe_json"])["target"]["paths"]
        if scan["recipe_json"]
        else [scan["scope"]]
    )
    return review_file_inventory(repository, scopes)


def ensure_review_files(connection: sqlite3.Connection, scan: sqlite3.Row) -> None:
    inventory = prepare_review_files(connection, scan)
    if inventory is not None:
        freeze_review_files(connection, scan["id"], inventory)


def record_scan_checkpoint(db: Any, connection: sqlite3.Connection, args: Any) -> dict[str, Any]:
    scan = db.require_scan(connection, args.scan_id)
    with db.scan_completion_lock(scan["id"]):
        return record_checkpoint(
            connection,
            scan,
            Path(args.checkpoint_path),
            db.now(),
            custom_validation_complete=args.custom_validation_complete,
        )


def record_checkpoint(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    checkpoint_path: Path,
    timestamp: str,
    *,
    commit: bool = True,
    publish_head: bool = True,
    acceptance_id: str | None = None,
    custom_validation_complete: bool = False,
) -> dict[str, Any]:
    """Accept a bound artifact, or replay the exact acceptance named by its durable head."""
    root = Path(scan["scan_dir"])
    try:
        relative = checkpoint_path.relative_to(root)
    except ValueError as exc:
        raise SystemExit("A scan checkpoint must be inside its registered scan directory.") from exc
    source = relative.parent.parent.as_posix()
    if custom_validation_complete and (
        source != "."
        or scan["mode"] not in {"standard", "diff"}
        or not scan["recipe_json"]
        or json.loads(scan["recipe_json"]).get("validationMode") != "custom"
    ):
        raise SystemExit("Custom validation completion requires its original root scan recipe.")
    if relative.parent.name != "checkpoints":
        raise SystemExit("A scan checkpoint must belong to a checkpoint directory.")
    if source != ".":
        worker = connection.execute(
            "SELECT kind FROM deep_scan_workers WHERE scan_id = ? AND artifact_dir = ?",
            (scan["id"], str(root / source)),
        ).fetchone()
        if worker is None:
            raise SystemExit("The checkpoint does not belong to a registered scan worker.")
    descriptor = open_scan_local_file_descriptor(root, relative.as_posix(), "scan checkpoint")
    with os.fdopen(descriptor, "rb") as handle:
        contents = handle.read()
    digest = hashlib.sha256(contents).hexdigest()
    if relative.name != f"{digest}.json":
        # Older worker writers named pretty-printed files with the compact JSON
        # digest. Preserve their string escapes and number spelling when matching
        # that name; decoding and re-encoding JSON can change JavaScript's bytes.
        compact = re.sub(
            rb'"(?:\\.|[^"\\])*"|[ \t\r\n]+',
            lambda match: match[0] if match[0].startswith(b'"') else b"",
            contents,
        )
        if relative.name != f"{hashlib.sha256(compact).hexdigest()}.json":
            raise SystemExit("The checkpoint filename does not match its saved content.")
    snapshot = json.loads(contents)
    if (
        not isinstance(snapshot, dict)
        or snapshot.get("scanId") != scan["id"]
        or not isinstance(snapshot.get("findings"), list)
        or any(not isinstance(finding, dict) for finding in snapshot["findings"])
    ):
        raise SystemExit("The checkpoint does not contain semantic results for this scan.")
    coverage = snapshot.get("coverage", {})
    if not isinstance(coverage, dict):
        raise SystemExit("The checkpoint has invalid semantic coverage.")
    reviewed = coverage.get("reviewedFiles", [])
    if not isinstance(reviewed, list) or any(not isinstance(path, str) for path in reviewed):
        raise SystemExit("Checkpoint reviewedFiles must contain repository-relative file paths.")
    reviewed = [PurePosixPath(path).as_posix() for path in reviewed]
    if reviewed:
        ensure_review_files(connection, scan)
    for path in reviewed:
        row = connection.execute(
            "SELECT content_sha256 FROM scan_review_files WHERE scan_id = ? AND relative_path = ?",
            (scan["id"], review_path_value(path)),
        ).fetchone()
        target = Path(scan["target_path"]) / path
        if (
            row is None
            or not path_within_scope(path, ".")
            or not target.resolve().is_relative_to(Path(scan["target_path"]))
            or target.is_symlink()
            or not target.is_file()
            or file_digest(target) != row["content_sha256"]
        ):
            raise SystemExit(f"Reviewed file is outside the saved inventory or changed: {path}")
    acceptance_id = acceptance_id or uuid.uuid4().hex
    result = {
        "scanId": scan["id"],
        "checkpointPath": relative.as_posix(),
        "digest": digest,
        "acceptanceId": acceptance_id,
    }
    existing = connection.execute(
        "SELECT content_sha256 FROM scan_checkpoints "
        "WHERE scan_id = ? AND source_path = ? AND acceptance_id = ?",
        (scan["id"], source, acceptance_id),
    ).fetchone()
    if existing:
        if existing["content_sha256"] != digest:
            raise SystemExit("The checkpoint acceptance refers to different saved content.")
        if custom_validation_complete:
            with connection if commit else nullcontext():
                connection.execute(
                    "UPDATE scans SET custom_validation_checkpoint_acceptance_id = ? WHERE id = ?",
                    (acceptance_id, scan["id"]),
                )
        return result
    # Content can recur after a different decision. The head identifies this acceptance,
    # so a crash before its SQLite commit can be replayed without confusing it with an
    # older receipt for identical bytes.
    if publish_head:
        _write_checkpoint_head(root, relative, acceptance_id)
    # A transaction commits both the semantic projection and completed source coverage.
    with connection if commit else nullcontext():
        for path in set(reviewed):
            connection.execute(
                "UPDATE scan_review_files SET reviewed_at = COALESCE(reviewed_at, ?) "
                "WHERE scan_id = ? AND relative_path = ?",
                (timestamp, scan["id"], review_path_value(path)),
            )
        connection.execute(
            "INSERT INTO scan_checkpoints (scan_id, source_path, checkpoint_path, content_sha256, "
            "snapshot_json, recorded_at, acceptance_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                scan["id"],
                source,
                relative.as_posix(),
                digest,
                json.dumps(snapshot),
                timestamp,
                acceptance_id,
            ),
        )
        if custom_validation_complete:
            connection.execute(
                "UPDATE scans SET custom_validation_checkpoint_acceptance_id = ? WHERE id = ?",
                (acceptance_id, scan["id"]),
            )
    return result


def _write_checkpoint_head(root: Path, relative: Path, acceptance_id: str) -> None:
    write_scan_local_bytes(
        root,
        (relative.parent.parent / "checkpoint-head.json").as_posix(),
        (json.dumps({"checkpoint": relative.name, "acceptanceId": acceptance_id}) + "\n").encode(),
    )


def checkpoint_state(connection: sqlite3.Connection, scan_id: str) -> dict[str, Any] | None:
    rows = connection.execute(
        "SELECT * FROM scan_checkpoints WHERE sequence IN (SELECT MAX(sequence) "
        "FROM scan_checkpoints WHERE scan_id = ? GROUP BY source_path) OR "
        "(scan_id = ? AND acceptance_id = "
        "(SELECT continuation_checkpoint_acceptance_id FROM scans WHERE id = ?)) "
        "ORDER BY source_path, sequence",
        (scan_id, scan_id, scan_id),
    ).fetchall()
    if not rows:
        return None
    validated = connection.execute(
        "SELECT custom_validation_checkpoint_acceptance_id FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()["custom_validation_checkpoint_acceptance_id"]
    reviewed = connection.execute(
        "SELECT relative_path, reviewed_at FROM scan_review_files WHERE scan_id = ? "
        "ORDER BY relative_path",
        (scan_id,),
    ).fetchall()
    sources = []
    for row in rows:
        snapshot = json.loads(row["snapshot_json"])
        sources.append(
            {
                "source": row["source_path"],
                "checkpointPath": row["checkpoint_path"],
                "acceptanceId": row["acceptance_id"],
                "customValidationComplete": row["source_path"] == "."
                and row["acceptance_id"] == validated,
                "digest": row["content_sha256"],
                "savedAt": row["recorded_at"],
                "complete": snapshot.get("complete", True),
                **{key: snapshot[key] for key in ("scope", "threatModel") if key in snapshot},
                "findings": snapshot["findings"],
                "coverage": snapshot.get("coverage", {}),
            }
        )
    return {
        "status": "provisional",
        "savedAt": max(row["recorded_at"] for row in rows),
        "sources": sources,
        "reviewedFiles": [
            os.fsdecode(row["relative_path"]) for row in reviewed if row["reviewed_at"]
        ],
        "remainingFiles": [
            os.fsdecode(row["relative_path"]) for row in reviewed if not row["reviewed_at"]
        ],
    }


def checkpoint_summary(connection: sqlite3.Connection, scan_id: str) -> dict[str, Any] | None:
    """Keep ordinary progress responses small; resume reads the full semantic state."""
    rows = connection.execute(
        "SELECT source_path, checkpoint_path, content_sha256, recorded_at, "
        "json_array_length(snapshot_json, '$.findings') AS findings, "
        "COALESCE(json_array_length(snapshot_json, '$.coverage.deferred'), 0) AS pending, "
        "COALESCE(json_extract(snapshot_json, '$.complete'), 1) AND "
        "json_extract(snapshot_json, '$.coverage.completeness') = 'complete' AS complete "
        "FROM scan_checkpoints WHERE sequence IN (SELECT MAX(sequence) FROM scan_checkpoints "
        "WHERE scan_id = ? GROUP BY source_path) OR "
        "(scan_id = ? AND acceptance_id = "
        "(SELECT continuation_checkpoint_acceptance_id FROM scans WHERE id = ?)) "
        "ORDER BY source_path, sequence",
        (scan_id, scan_id, scan_id),
    ).fetchall()
    if not rows:
        return None
    files = connection.execute(
        "SELECT COUNT(reviewed_at) AS reviewed, COUNT(*) - COUNT(reviewed_at) AS remaining "
        "FROM scan_review_files WHERE scan_id = ?",
        (scan_id,),
    ).fetchone()
    return {
        "status": "provisional",
        "savedAt": max(row["recorded_at"] for row in rows),
        "findingCount": sum(row["findings"] for row in rows),
        "pendingCount": sum(row["pending"] for row in rows),
        "coverageComplete": all(row["complete"] for row in rows),
        "reviewedFileCount": files["reviewed"],
        "remainingFileCount": files["remaining"],
        "sources": [
            {
                "source": row["source_path"],
                "checkpointPath": row["checkpoint_path"],
                "digest": row["content_sha256"],
                "savedAt": row["recorded_at"],
            }
            for row in rows
        ],
    }


def reconcile_checkpoints(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    timestamp: str,
    *,
    commit: bool = True,
    sources: list[Path] | None = None,
) -> None:
    """Complete artifact-to-database writes before a resumed scan incurs more work."""
    root = Path(scan["scan_dir"])
    if sources is None:
        sources = [
            root,
            *(
                Path(row["artifact_dir"])
                for row in connection.execute(
                    "SELECT artifact_dir FROM deep_scan_workers WHERE scan_id = ?", (scan["id"],)
                )
            ),
        ]
    for source in sources:
        if not source.is_relative_to(root):
            raise SystemExit("The saved checkpoint directory is outside its bound scan.")
        head = source / "checkpoint-head.json"
        if not head.exists():
            continue
        descriptor = open_scan_local_file_descriptor(
            root, head.relative_to(root).as_posix(), "scan checkpoint head"
        )
        with os.fdopen(descriptor, "rb") as handle:
            saved_head = json.load(handle)
        name = saved_head.get("checkpoint")
        if not isinstance(name, str) or not re.fullmatch(r"[0-9a-f]{64}\.json", name):
            raise SystemExit("The saved checkpoint head does not name a semantic checkpoint.")
        acceptance_id = saved_head.get("acceptanceId")
        if acceptance_id is None:
            # Legacy heads only identify content. An already indexed snapshot is a replay,
            # never a new decision; otherwise accept it once and upgrade its head.
            existing = connection.execute(
                "SELECT acceptance_id FROM scan_checkpoints WHERE scan_id = ? AND checkpoint_path = ? "
                "ORDER BY sequence DESC LIMIT 1",
                (scan["id"], (source / "checkpoints" / name).relative_to(root).as_posix()),
            ).fetchone()
            if existing:
                acceptance_id = existing["acceptance_id"]
        elif not isinstance(acceptance_id, str) or not acceptance_id:
            raise SystemExit("The saved checkpoint head has an invalid acceptance identity.")
        checkpoint = source / "checkpoints" / name
        if source != root and not checkpoint.exists():
            # A worker validation retry can archive its accepted output before
            # the next attempt begins. Restore the exact named bytes for replay
            # under the worker's registered source path.
            archived = next(
                (source.parent / "attempts").glob(f"attempt-*/checkpoints/{name}"), None
            )
            if archived is not None:
                descriptor = open_scan_local_file_descriptor(
                    root, archived.relative_to(root).as_posix(), "archived scan checkpoint"
                )
                with os.fdopen(descriptor, "rb") as handle:
                    contents = handle.read()
                write_scan_local_bytes(root, checkpoint.relative_to(root).as_posix(), contents)
        record_checkpoint(
            connection,
            scan,
            checkpoint,
            timestamp,
            commit=commit,
            acceptance_id=acceptance_id,
        )


def checkpoint_completion_ready(checkpoint: dict[str, Any], mode: str) -> bool:
    return (
        mode == "standard"
        and not checkpoint["remainingFiles"]
        and all(
            source["complete"]
            and source["coverage"].get("completeness") == "complete"
            and not source["coverage"].get("deferred")
            for source in checkpoint["sources"]
        )
    )


def rebase_checkpoint_receipts(
    value: dict[str, Any], source: str, *, to_source: bool = False
) -> dict[str, Any]:
    """Translate structured receipt references between a worker and its scan."""
    result = json.loads(json.dumps(value))
    if source == ".":
        return result
    prefix = source + "/"

    def rebase(receipt: Any) -> Any:
        if not isinstance(receipt, str):
            return receipt
        if to_source:
            return receipt.removeprefix(prefix)
        if receipt.startswith("artifacts/") and not receipt.startswith(prefix):
            return prefix + receipt
        return receipt

    def references(item: Any) -> None:
        if isinstance(item, list):
            for child in item:
                references(child)
        elif isinstance(item, dict):
            receipts = item.get("receiptRefs")
            if isinstance(receipts, list):
                item["receiptRefs"] = [rebase(receipt) for receipt in receipts]
            for child in item.values():
                references(child)

    references(result)
    return result


def checkpoint_artifact_sources(
    root: Path,
    source: str,
    checkpoint_path: str,
    digest: str,
    acceptance_id: str | None,
) -> list[Path]:
    """Find current and archived outputs bound to this accepted checkpoint."""
    output = root / source
    if source == ".":
        return [output]
    name = Path(checkpoint_path).name
    archived = sorted(
        (
            path
            for path in (output.parent / "attempts").glob(f"attempt-*/checkpoints/{name}")
            if re.fullmatch(r"attempt-\d+", path.parent.parent.name)
        ),
        key=lambda path: int(path.parent.parent.name.removeprefix("attempt-")),
        reverse=True,
    )
    sources = []
    for checkpoint in [output / "checkpoints" / name, *archived]:
        directory = checkpoint.parent.parent
        head = directory / "checkpoint-head.json"
        if head.exists() or head.is_symlink():
            saved = _read_scan_local_json(
                root, head.relative_to(root).as_posix(), "Archived checkpoint head"
            )
            if saved.get("checkpoint") != name or (
                saved.get("acceptanceId") is not None and saved["acceptanceId"] != acceptance_id
            ):
                continue
        try:
            descriptor = open_scan_local_file_descriptor(
                root, checkpoint.relative_to(root).as_posix(), "Saved checkpoint"
            )
        except ContractError as exc:
            if isinstance(exc.__cause__, FileNotFoundError):
                continue
            raise
        with os.fdopen(descriptor, "rb") as handle:
            if hashlib.sha256(handle.read()).hexdigest() != digest:
                raise ContractError("The saved checkpoint changed after acceptance.")
        sources.append(directory)
    return sources or [output]


def copy_checkpoint_writeups(
    parent_root: Path,
    child_root: Path,
    value: dict[str, Any],
    source: str,
    *,
    locations: list[Path] | None = None,
    report_paths: dict[str, str] | None = None,
    sealed_artifacts: dict[str, str] | None = None,
    worker_sources: dict[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, str], bool]:
    """Copy a source's reports and PoCs while preserving valid scan-local report paths."""
    result = json.loads(json.dumps(value))
    paths: dict[tuple[str, str], str] = {}
    writeups: list[tuple[dict[str, Any], tuple[str, str]]] = []
    locations = locations or [parent_root / source]
    sealed_artifacts = sealed_artifacts or {}

    def references(item: Any, owner: str) -> None:
        if isinstance(item, list):
            for child in item:
                references(child, owner)
        elif isinstance(item, dict):
            # The reducer host retains exact discovery originals. Their report
            # paths still belong to those discoveries, not the reducer output.
            provenance = item.get("provenance")
            originals = provenance.get("sourceFindings", []) if isinstance(provenance, dict) else []
            writeup = item.get("writeup")
            report = writeup.get("reportPath") if isinstance(writeup, dict) else None
            if isinstance(report, str) and re.fullmatch(
                r"findings/([a-z0-9][a-z0-9._-]*)/\1\.md", report
            ):
                matching = [
                    original
                    for original in (originals if isinstance(originals, list) else [])
                    if isinstance(original, dict)
                    and isinstance(original.get("id"), str)
                    and original["id"].rsplit(":", 1)[0] in (worker_sources or {})
                    and isinstance(original.get("finding"), dict)
                    and isinstance(original["finding"].get("writeup"), dict)
                    and original["finding"].get("writeup", {}).get("reportPath") == report
                ]
                identity_matches = [
                    original
                    for original in matching
                    if original["finding"].get("identity") == item.get("identity")
                ]
                origin = owner
                if matching:
                    original = (identity_matches or matching)[0]
                    origin = worker_sources[original["id"].rsplit(":", 1)[0]]
                if report_paths is not None:
                    destination = report_paths.get(report, report)
                elif origin == ".":
                    destination = report
                else:
                    slug = hashlib.sha256(f"{origin}\0{report}".encode()).hexdigest()
                    destination = f"findings/{slug}/{slug}.md"
                paths[(origin, report)] = destination
                writeups.append((writeup, (origin, report)))
            for key, child in item.items():
                child_owner = owner
                if key == "finding" and isinstance(item.get("id"), str) and worker_sources:
                    child_owner = worker_sources.get(item["id"].rsplit(":", 1)[0], owner)
                references(child, child_owner)

    references(result, source)

    def read_file(
        root: Path, path: Path, *, optional: bool = False, verify_seal: bool = False
    ) -> bytes | None:
        relative = path.relative_to(root).as_posix()
        sealed = sealed_artifacts.get(relative) if verify_seal else None
        try:
            descriptor = open_scan_local_file_descriptor(root, relative, "Saved writeup")
        except ContractError as exc:
            if optional and sealed is None and isinstance(exc.__cause__, FileNotFoundError):
                return None
            raise
        with os.fdopen(descriptor, "rb") as handle:
            contents = handle.read()
        if sealed is not None and hashlib.sha256(contents).hexdigest() != sealed:
            raise ContractError(f"{relative}: sealed artifact changed after completion")
        return contents

    def bundle(
        root: Path, origins: list[Path], report: str, *, verify_seals: bool = False
    ) -> dict[str, tuple[Path, str]]:
        files = {}
        for location in origins:
            path = location / report
            contents = read_file(root, path, optional=True, verify_seal=verify_seals)
            if contents is not None:
                files[""] = (path, hashlib.sha256(contents).hexdigest())
                break
        for location in reversed(origins):
            poc = location / Path(report).parent / "poc"
            if not poc.exists() and not poc.is_symlink():
                continue
            for directory, directories, filenames in os.walk(poc, followlinks=False):
                for path in (Path(directory), *(Path(directory) / name for name in directories)):
                    _require_scan_directory(path)
                for filename in filenames:
                    path = Path(directory) / filename
                    contents = read_file(root, path, verify_seal=verify_seals)
                    files[(Path("poc") / path.relative_to(poc)).as_posix()] = (
                        path,
                        hashlib.sha256(contents).hexdigest(),
                    )
        return files

    missing = False
    for (origin, report), destination in paths.items():
        origins = locations if origin == source else [parent_root / origin]
        files = bundle(parent_root, origins, report, verify_seals=True)
        missing |= "" not in files
        hashes = {name: digest for name, (_, digest) in files.items()}
        version = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
        existing = bundle(child_root, [child_root], destination)
        # Canonical reports can be edited after a worker checkpoint. Keep each
        # report and its exact PoC set together instead of overwriting that version.
        while existing and {name: digest for name, (_, digest) in existing.items()} != hashes:
            slug = hashlib.sha256(f"{destination}\0{version}".encode()).hexdigest()
            destination = f"findings/{slug}/{slug}.md"
            existing = bundle(child_root, [child_root], destination)
        paths[(origin, report)] = destination
        if not existing:
            for name, (path, digest) in files.items():
                contents = read_file(parent_root, path, verify_seal=True)
                if hashlib.sha256(contents).hexdigest() != digest:
                    raise ContractError("Saved writeup changed while copying its report and PoCs")
                target = Path(destination).parent / name if name else Path(destination)
                write_scan_local_bytes(child_root, target.as_posix(), contents)
    for writeup, key in writeups:
        writeup["reportPath"] = paths[key]
    return result, {destination: report for (_, report), destination in paths.items()}, missing


def copy_checkpoint_artifacts(
    db: Any, parent: sqlite3.Row, child_root: Path, checkpoint: dict[str, Any]
) -> tuple[dict[str, str] | None, bool, dict[str, str]]:
    """Keep referenced evidence and derived hardening files with their saved result."""
    parent_root = db.require_canonical_scan_directory(Path(parent["scan_dir"]))
    parent_manifest = (
        _read_scan_local_json(parent_root, "scan-manifest.json", "Saved scan manifest")
        if parent["seal_manifest_digest"] is not None
        else None
    )
    sealed_artifacts = (
        {item["path"]: item["sha256"] for item in parent_manifest["scan"]["artifacts"]}
        if parent_manifest is not None
        else {}
    )
    files: set[str] = set()
    receipt_files: set[str] = set()
    sources = {}

    def references(value: Any) -> None:
        if isinstance(value, list):
            for item in value:
                references(item)
        elif isinstance(value, dict):
            for receipt in (
                value.get("receiptRefs", []) if isinstance(value.get("receiptRefs"), list) else []
            ):
                if isinstance(receipt, str) and receipt.startswith("artifacts/"):
                    files.add(receipt)
                    receipt_files.add(receipt)
            for item in value.values():
                references(item)

    for source in checkpoint["sources"]:
        references(rebase_checkpoint_receipts(source, source["source"]))
        if source["source"] != ".":
            sources[source["source"]] = (
                [parent_root / source.get("artifactSource", source["source"])]
                if source.get("acceptanceId") is None
                else checkpoint_artifact_sources(
                    parent_root,
                    source["source"],
                    source["checkpointPath"],
                    source["digest"],
                    source["acceptanceId"],
                )
            )
    portfolio = "hardening/hardening.md"
    has_portfolio = bool(parent_manifest and parent_manifest["scan"].get("hardening")) or (
        (parent_root / portfolio).exists() or (parent_root / portfolio).is_symlink()
    )
    if has_portfolio:
        files.add(portfolio)
    for evidence_dir in [parent_root / "hardening"]:
        if not evidence_dir.exists() and not evidence_dir.is_symlink():
            continue
        db.deep_scan.deep_scan_path(
            parent, str(evidence_dir), "Saved report evidence", kind="directory"
        )
        for directory, directories, filenames in os.walk(evidence_dir, followlinks=False):
            for path in (Path(directory), *(Path(directory) / name for name in directories)):
                db.deep_scan.deep_scan_path(
                    parent, str(path), "Saved report evidence", kind="directory"
                )
            files.update(
                (Path(directory) / name).relative_to(parent_root).as_posix() for name in filenames
            )
    missing_receipts = False
    for relative in sorted(files):
        locations = [relative]
        for source in sorted(sources, key=len, reverse=True):
            directories = sources[source]
            if relative.startswith(source + "/"):
                locations = [
                    (directory / relative.removeprefix(source + "/"))
                    .relative_to(parent_root)
                    .as_posix()
                    for directory in directories
                ]
                break
        for index, source_relative in enumerate(locations):
            try:
                descriptor = open_scan_local_file_descriptor(
                    parent_root, source_relative, "Saved checkpoint artifact"
                )
                break
            except ContractError as exc:
                if (
                    relative not in sealed_artifacts
                    and source_relative not in sealed_artifacts
                    and isinstance(exc.__cause__, FileNotFoundError)
                ):
                    if index + 1 < len(locations):
                        continue
                    if relative in receipt_files:
                        missing_receipts = True
                        descriptor = None
                        break
                raise
        if descriptor is None:
            continue
        with os.fdopen(descriptor, "rb") as source:
            contents = source.read()
        for sealed_path in {relative, source_relative}:
            if (
                sealed_path in sealed_artifacts
                and hashlib.sha256(contents).hexdigest() != sealed_artifacts[sealed_path]
            ):
                raise ContractError(f"{sealed_path}: sealed artifact changed after completion")
        write_scan_local_bytes(child_root, relative, contents)
    return (
        {"portfolioPath": portfolio} if has_portfolio else None,
        missing_receipts,
        sealed_artifacts,
    )


def start_inference(db: Any, connection: sqlite3.Connection, args: Any) -> dict[str, Any]:
    with db.scan_completion_lock(args.scan_id), connection:
        scan = db.require_scan(connection, args.scan_id)
        if scan["status"] not in {"running", "complete"}:
            raise SystemExit("Only a running or completed scan can start inference.")
        connection.execute(
            "UPDATE scans SET inference_started = 1, updated_at = ? WHERE id = ?",
            (db.now(), scan["id"]),
        )
    return {"scanId": scan["id"], "inferenceStarted": True}


def continue_checkpoint(db: Any, connection: sqlite3.Connection, args: Any) -> dict[str, Any]:
    """Seed a new bound scan from saved semantic results without reopening its parent."""
    # Reuse the stopped-result merger so finding identity and evidence retention have one owner.
    from workbench_saved_results import (
        _candidate_owner,
        _digest,
        _finding_content,
        _finding_key,
        _read_saved_parent_result,
        _read_saved_result,
        _saved_result_sources,
        merge_saved_results,
    )

    with (
        db.scan_completion_lock(args.parent_scan_id),
        db.scan_completion_lock(args.scan_id),
        connection,
    ):
        parent = db.require_scan(connection, args.parent_scan_id)
        child = db.require_scan(connection, args.scan_id)
        if child["parent_scan_id"] != parent["id"] or child["status"] != "running":
            raise SystemExit(
                "Checkpoint continuation requires a new running child of the saved scan."
            )
        for field in (
            "target_path",
            "target_revision",
            "target_snapshot_digest",
            "target_device",
            "target_inode",
            "mode",
        ):
            if child[field] != parent[field]:
                raise SystemExit(
                    "Checkpoint continuation must use the original source and scan mode."
                )
        child_recipe, parent_recipe = (
            json.loads(child["recipe_json"]),
            json.loads(parent["recipe_json"]),
        )
        child_recipe.pop("pluginVersion", None)
        parent_recipe.pop("pluginVersion", None)
        if child_recipe != parent_recipe:
            raise SystemExit(
                "Checkpoint continuation must use the original target and launch recipe."
            )
        if parent["seal_manifest_digest"] is not None:
            db.require_recorded_manifest_digest(parent, Path(parent["scan_dir"]))
        reconcile_checkpoints(connection, parent, db.now())
        checkpoint = checkpoint_state(connection, parent["id"])
        if checkpoint is None:
            raise SystemExit("The parent scan has no saved semantic checkpoint to continue.")
        changed = connection.execute(
            "SELECT parent.relative_path FROM scan_review_files AS parent "
            "LEFT JOIN scan_review_files AS child ON child.scan_id = ? "
            "AND child.relative_path = parent.relative_path "
            "WHERE parent.scan_id = ? AND parent.reviewed_at IS NOT NULL "
            "AND (child.content_sha256 IS NULL OR child.content_sha256 != parent.content_sha256) "
            "LIMIT 1",
            (child["id"], parent["id"]),
        ).fetchone()
        if changed is not None:
            raise SystemExit(
                "Checkpoint continuation must use the original reviewed source: "
                f"{os.fsdecode(changed['relative_path'])}"
            )
        first_seed = (
            connection.execute(
                "SELECT 1 FROM scan_checkpoints WHERE scan_id = ? LIMIT 1", (child["id"],)
            ).fetchone()
            is None
        )
        completion_ready = checkpoint_completion_ready(checkpoint, parent["mode"])
        worker_ids = db.deep_scan.restore_checkpoint_workers(connection, parent, child, db.now())
        root = db.require_canonical_scan_directory(Path(child["scan_dir"]))
        missing_reports = False
        worker_report_paths = {}
        workers = connection.execute(
            "SELECT * FROM deep_scan_workers WHERE scan_id = ?", (child["id"],)
        ).fetchall()
        worker_sources = {
            worker["id"]: Path(worker["artifact_dir"]).relative_to(root).as_posix()
            for worker in workers
            if worker["kind"] == "discovery"
        }
        sequence = {
            row["acceptance_id"]: row["sequence"]
            for row in connection.execute(
                "SELECT acceptance_id, sequence FROM scan_checkpoints WHERE scan_id = ?",
                (parent["id"],),
            )
        }
        sources = sorted(
            checkpoint["sources"],
            key=lambda source: sequence[source["acceptanceId"]],
            reverse=True,
        )
        warnings: list[str] = []
        if parent["seal_manifest_digest"] is not None:
            parent_manifest, retained, retained_coverage, _ = _read_sealed_scan(
                Path(parent["scan_dir"]), None, "Checkpoint continuation"
            )
            # Stopped-scan publication can retain findings from files written
            # before acceptance. Keep that evidence without promoting its work
            # to a current validation decision or credited source coverage.
            sources.append(
                {
                    "source": ".",
                    "findings": retained["findings"],
                    "coverage": {
                        **retained_coverage,
                        "completeness": "partial",
                        "reviewedFiles": [],
                        "deferred": [
                            item
                            for item in retained_coverage.get("deferred", [])
                            if item.get("id") != "scan-stopped"
                        ],
                    },
                    **{
                        key: parent_manifest["scan"][key]
                        for key in ("scope", "threatModel")
                        if key in parent_manifest["scan"]
                    },
                }
            )
        else:
            parent_root = Path(parent["scan_dir"])
            accepted = {
                (row["source_path"], _digest(json.loads(row["snapshot_json"])))
                for row in connection.execute(
                    "SELECT source_path, snapshot_json FROM scan_checkpoints WHERE scan_id = ?",
                    (parent["id"],),
                )
            }
            try:
                _, canonical = _read_saved_parent_result(parent_root, parent["id"])
            except (ContractError, OSError, ValueError) as exc:
                if (parent_root / "scan-manifest.json").exists():
                    warnings.append(f"Could not read the saved parent draft: {exc}")
            else:
                if (".", _digest(canonical)) not in accepted:
                    coverage = {
                        **canonical["coverage"],
                        "completeness": "partial",
                        "reviewedFiles": [],
                    }
                    if isinstance(coverage.get("deferred"), list):
                        coverage["deferred"] = [
                            item
                            for item in coverage["deferred"]
                            if not isinstance(item, dict) or item.get("id") != "scan-stopped"
                        ]
                    sources.append({**canonical, "source": ".", "coverage": coverage})
            accepted_sources = {source["source"] for source in sources}
            parent_workers = connection.execute(
                "SELECT * FROM deep_scan_workers WHERE scan_id = ?", (parent["id"],)
            ).fetchall()
            derived_sources = json.loads(parent["continuation_sources_json"] or "{}")
            retained_sources = set()
            for relative, worker in _saved_result_sources(parent_root, parent_workers):
                try:
                    draft, digest = _read_saved_result(
                        parent_root,
                        relative,
                        parent["id"],
                        kind=worker["kind"] if worker else None,
                    )
                except (ContractError, OSError, ValueError) as exc:
                    if (parent_root / relative).exists():
                        warnings.append(f"Preserved unreadable checkpoint {relative}: {exc}")
                    continue
                logical_source = (
                    Path(worker["artifact_dir"]).relative_to(parent_root).as_posix()
                    if worker
                    else "."
                )
                source = Path(relative).parent
                if source.name == "checkpoints":
                    source = source.parent
                source_path = source.as_posix()
                if (
                    (logical_source, digest) in accepted
                    or derived_sources.get(relative) == digest
                    or (source_path, digest) in retained_sources
                ):
                    continue
                retained_sources.add((source_path, digest))
                coverage = {
                    **draft.get("coverage", {}),
                    "completeness": "partial",
                    "reviewedFiles": [],
                }
                if isinstance(coverage.get("deferred"), list):
                    coverage["deferred"] = [
                        item
                        for item in coverage["deferred"]
                        if not isinstance(item, dict) or item.get("id") != "scan-stopped"
                    ]
                # A file written before acceptance retains evidence, not completed
                # work or a newer validation decision. Keep its physical archive
                # location separate from its registered worker's candidate owner.
                destination = source_path
                if source_path != "." and source_path in accepted_sources:
                    # Current raw evidence may reuse an accepted archive's filenames.
                    # Keep both versions while reading from the original directory.
                    destination = f"{source_path}/artifacts/checkpoints/{digest}"
                sources.append(
                    {
                        "source": destination,
                        "artifactSource": source_path,
                        "workerId": worker["id"] if worker else None,
                        "findings": draft["findings"],
                        "coverage": coverage,
                        **{key: draft[key] for key in ("scope", "threatModel") if key in draft},
                    }
                )
        hardening, missing_receipts, sealed_artifacts = copy_checkpoint_artifacts(
            db, parent, root, {"sources": sources}
        )
        current_checkpoints = []
        retained_checkpoints = set()
        seed_sources = {}
        validated_findings = set()
        for source in sources:
            snapshot = {
                "scanId": child["id"],
                "complete": False,
                **{key: source[key] for key in ("scope", "threatModel") if key in source},
                "findings": source["findings"],
                "coverage": source["coverage"],
            }
            worker = connection.execute(
                "SELECT id, kind FROM deep_scan_workers WHERE scan_id = ? AND "
                + ("id = ?" if source.get("workerId") else "artifact_dir = ?"),
                (
                    parent["id"],
                    source.get("workerId") or str(Path(parent["scan_dir"]) / source["source"]),
                ),
            ).fetchone()
            snapshot = db.deep_scan.rebind_checkpoint_result(
                snapshot,
                child["id"],
                worker_ids,
                source_worker_id=worker["id"] if worker and worker["kind"] == "discovery" else None,
            )
            snapshot = rebase_checkpoint_receipts(snapshot, source["source"])
            snapshot, report_paths, missing = copy_checkpoint_writeups(
                Path(parent["scan_dir"]),
                root,
                snapshot,
                source["source"],
                locations=[
                    Path(parent["scan_dir"]) / source.get("artifactSource", source["source"])
                ]
                if source.get("acceptanceId") is None
                else checkpoint_artifact_sources(
                    Path(parent["scan_dir"]),
                    source["source"],
                    source["checkpointPath"],
                    source["digest"],
                    source["acceptanceId"],
                ),
                sealed_artifacts=sealed_artifacts,
                worker_sources=worker_sources if worker and worker["kind"] == "dedup" else None,
            )
            if source.get("customValidationComplete"):
                validated_findings.update(
                    (_finding_key(finding), _digest(_finding_content(finding)))
                    for finding in snapshot["findings"]
                )
            missing_reports |= missing
            if missing:
                # A stronger retained copy can become canonical during merging.
                # Report the missing source writeup before that selection occurs.
                _recover_unsealed_findings(
                    {
                        "scan": {
                            "id": child["id"],
                            "target": db.workbench_completion_binding(child, db.now())["target"],
                        }
                    },
                    {
                        "scanId": child["id"],
                        "findings": json.loads(json.dumps(snapshot["findings"])),
                    },
                    Path(__file__).resolve().parent.parent / "schemas",
                    root,
                    warnings,
                )
            if worker and worker["kind"] == "discovery" and worker["id"] in worker_ids:
                worker_report_paths[worker_ids[worker["id"]]] = report_paths
            contents = (json.dumps(snapshot, indent=2) + "\n").encode()
            relative = f"checkpoints/{hashlib.sha256(contents).hexdigest()}.json"
            write_scan_local_bytes(root, relative, contents)
            seed_sources[relative] = _digest(snapshot)
            if (
                source.get("acceptanceId") is not None
                and source["acceptanceId"] != parent["continuation_checkpoint_acceptance_id"]
            ):
                current_checkpoints.append(relative)
            elif source.get("acceptanceId") is None:
                retained_checkpoints.add(relative)
        merged = merge_saved_results(
            root,
            child["id"],
            db.workbench_completion_binding(child, db.now()),
            workers,
            warnings,
            stopped=False,
            reason="Continue saved source work",
            include_parent=False,
            preserve_sources=retained_checkpoints,
            current_checkpoint_paths=current_checkpoints,
            rebase_receipts=True,
        )
        if merged is None:
            raise SystemExit("The saved semantic checkpoint could not seed the continuation.")
        manifest, findings, coverage = merged
        if missing_reports:
            recovered = {"scanId": child["id"], **findings}
            _recover_unsealed_findings(
                {"scan": {"id": child["id"], "target": manifest["scan"]["target"]}},
                recovered,
                Path(__file__).resolve().parent.parent / "schemas",
                root,
                warnings,
            )
            findings["findings"] = recovered["findings"]
        if missing_receipts:
            _recover_unsealed_coverage(
                coverage, Path(__file__).resolve().parent.parent / "schemas", root, warnings, []
            )
            completion_ready = completion_ready and coverage.get("completeness") == "complete"
        for worker in workers:
            if worker["kind"] != "discovery" or worker["status"] != "queued":
                continue
            source_path = Path(worker["artifact_dir"]).relative_to(root).as_posix()
            saved = connection.execute(
                "SELECT snapshot_json FROM scan_checkpoints WHERE scan_id = ? AND source_path = ? "
                "ORDER BY sequence DESC LIMIT 1",
                (child["id"], source_path),
            ).fetchone()
            worker_snapshot = json.loads(saved["snapshot_json"])
            # The aggregate contains the latest decisions for each mapped owner.
            # Keep per-pass source coverage and scope, and carry those decisions
            # into the actual checkpoint the queued worker will read.
            worker_snapshot["findings"] = [
                finding
                for finding in findings["findings"]
                if _candidate_owner(finding, None) == worker["id"]
            ]
            for field in ("surfaces", "explicitExclusions", "deferred"):
                worker_snapshot["coverage"][field] = [
                    item
                    for item in coverage.get(field, [])
                    if _candidate_owner(item, None) == worker["id"]
                ]
            worker_snapshot = rebase_checkpoint_receipts(
                worker_snapshot, source_path, to_source=True
            )
            worker_snapshot, _, _ = copy_checkpoint_writeups(
                root,
                Path(worker["artifact_dir"]),
                worker_snapshot,
                ".",
                report_paths=worker_report_paths.get(worker["id"], {}),
            )
            worker_contents = (json.dumps(worker_snapshot, indent=2) + "\n").encode()
            worker_path = (
                f"{source_path}/checkpoints/{hashlib.sha256(worker_contents).hexdigest()}.json"
            )
            write_scan_local_bytes(root, worker_path, worker_contents)
            record_checkpoint(connection, child, root / worker_path, db.now(), commit=False)
        root_source = next((source for source in sources if source["source"] == "."), None)
        if root_source is not None and isinstance(root_source.get("scope"), dict):
            manifest["scan"]["scope"] = {
                **root_source["scope"],
                **manifest["scan"]["scope"],
            }
        if root_source is not None and isinstance(root_source.get("threatModel"), dict):
            manifest["scan"]["threatModel"] = root_source["threatModel"]
        if hardening is not None:
            manifest["scan"]["hardening"] = hardening
        completion_ready = (
            completion_ready
            and not coverage.get("deferred")
            and not any(
                item.get("disposition") == "needs_follow_up"
                for item in coverage.get("surfaces", [])
            )
        )
        manifest["scan"]["complete"] = completion_ready
        coverage["completeness"] = "complete" if completion_ready else "partial"
        coverage["reviewedFiles"] = checkpoint["reviewedFiles"]
        snapshot = {
            "scanId": child["id"],
            "complete": completion_ready,
            **{
                key: manifest["scan"][key]
                for key in ("scope", "threatModel")
                if key in manifest["scan"]
            },
            "findings": findings["findings"],
            "coverage": coverage,
        }
        contents = (json.dumps(snapshot, indent=2) + "\n").encode()
        path = root / "checkpoints" / f"{hashlib.sha256(contents).hexdigest()}.json"
        write_scan_local_bytes(root, path.relative_to(root).as_posix(), contents)
        receipt = record_checkpoint(
            connection,
            child,
            path,
            db.now(),
            commit=False,
            publish_head=False,
            custom_validation_complete=all(
                source["customValidationComplete"] for source in checkpoint["sources"]
            )
            and all(
                (_finding_key(finding), _digest(_finding_content(finding))) in validated_findings
                for finding in findings["findings"]
            ),
        )
        connection.execute(
            "UPDATE scans SET continuation_cost_json = ?, continuation_checkpoint_path = ?, "
            "continuation_checkpoint_acceptance_id = ?, continuation_sources_json = ?, "
            "inference_started = "
            "CASE WHEN ? AND inference_started IS NULL THEN 0 ELSE inference_started END "
            "WHERE id = ?",
            (
                db.parse_scan_cost(args.cost_json),
                path.relative_to(root).as_posix() if child["mode"] == "deep" else None,
                receipt["acceptanceId"] if child["mode"] == "deep" else None,
                json.dumps(seed_sources),
                first_seed,
                child["id"],
            ),
        )
        if warnings:
            connection.execute(
                "UPDATE scans SET completion_warnings_json = ? WHERE id = ?",
                (json.dumps(list(dict.fromkeys(warnings))), child["id"]),
            )
        for filename, document in (
            ("findings.json", findings),
            ("coverage.json", coverage),
            ("scan-manifest.json", manifest),
        ):
            write_scan_local_bytes(root, filename, (json.dumps(document, indent=2) + "\n").encode())
        # Worker receipts, inherited spend, and the aggregate baseline become durable
        # together. Until then, no root head may expose this child to reconciliation.
        # Commit explicitly even when record_checkpoint replayed an existing receipt.
        connection.commit()
        _write_checkpoint_head(root, path.relative_to(root), receipt["acceptanceId"])
        if parent["status"] == "running":
            timestamp = db.now()
            message = f"Interrupted; continued from saved checkpoints in scan {child['id']}."
            with connection:
                connection.execute(
                    "UPDATE scans SET status = 'failed', failure_message = ?, completed_at = ?, "
                    "updated_at = ? WHERE id = ? AND status = 'running'",
                    (message, timestamp, timestamp, parent["id"]),
                )
                connection.execute(
                    "UPDATE scan_progress SET updated_at = ? WHERE scan_id = ?",
                    (timestamp, parent["id"]),
                )
                db.deep_scan.fail_from_parent_scan(connection, parent["id"], message, timestamp)
        return {
            "checkpoint": checkpoint_state(connection, child["id"]),
            "completionReady": completion_ready,
            "restoredWorkers": len(worker_ids),
        }


def continued_deep_documents(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    binding: dict[str, Any],
    warnings: list[str],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    """Preserve inherited work when a continued coordinator publishes its result.

    A partial worker is not a completed independent pass. Its saved findings and
    pending evidence still belong in the final result, even if the deadline means
    that the resumed coordinator cannot dispatch another discovery.
    """
    from workbench_saved_results import _digest, _read_saved_result, merge_saved_results

    relative = scan["continuation_checkpoint_path"]
    if scan["mode"] != "deep" or relative is None:
        return None
    saved = connection.execute(
        "SELECT sequence, snapshot_json FROM scan_checkpoints WHERE scan_id = ? AND checkpoint_path = ? "
        "AND acceptance_id = ?",
        (scan["id"], relative, scan["continuation_checkpoint_acceptance_id"]),
    ).fetchone()
    if saved is None:
        raise SystemExit("The continuation's inherited checkpoint is missing from saved state.")
    root = Path(scan["scan_dir"])
    _, digest = _read_saved_result(root, relative, scan["id"])
    if digest != _digest(json.loads(saved["snapshot_json"])):
        raise SystemExit("The continuation's inherited checkpoint changed after it was saved.")
    workers = connection.execute(
        "SELECT * FROM deep_scan_workers WHERE scan_id = ?",
        (scan["id"],),
    ).fetchall()
    frozen = {relative: digest}
    worker_sources = {
        Path(worker["artifact_dir"]).relative_to(root).as_posix(): worker
        for worker in workers
        if worker["kind"] in {"discovery", "dedup"}
    }
    current_checkpoints = []
    accepted = connection.execute(
        "SELECT * FROM scan_checkpoints WHERE scan_id = ? AND sequence > ? AND sequence IN "
        "(SELECT MAX(sequence) FROM scan_checkpoints WHERE scan_id = ? GROUP BY source_path) "
        "ORDER BY sequence DESC",
        (scan["id"], saved["sequence"], scan["id"]),
    ).fetchall()
    for checkpoint in accepted:
        source = checkpoint["source_path"]
        worker = worker_sources.get(source)
        if (source != "." and worker is None) or (worker and worker["status"] == "succeeded"):
            continue
        path = checkpoint["checkpoint_path"]
        locations = checkpoint_artifact_sources(
            root, source, path, checkpoint["content_sha256"], checkpoint["acceptance_id"]
        )
        path = (locations[0] / "checkpoints" / Path(path).name).relative_to(root).as_posix()
        _, accepted_digest = _read_saved_result(
            root, path, scan["id"], kind=worker["kind"] if worker else None
        )
        if accepted_digest != _digest(json.loads(checkpoint["snapshot_json"])):
            raise SystemExit("An accepted continuation checkpoint changed after it was saved.")
        frozen[path] = accepted_digest
        current_checkpoints.append(path)
    for worker in workers:
        if worker["status"] != "succeeded" or worker["kind"] not in {"discovery", "dedup"}:
            continue
        result_path = Path(worker["result_manifest_path"]).relative_to(root).as_posix()
        _, worker_digest = _read_saved_result(root, result_path, scan["id"], kind=worker["kind"])
        frozen[result_path] = worker_digest
    return merge_saved_results(
        root,
        scan["id"],
        binding,
        workers,
        warnings,
        stopped=False,
        reason="",
        frozen_source_digests=frozen,
        allow_frozen_legacy_parent=True,
        preserve_sources={relative},
        current_checkpoint_paths=current_checkpoints,
        rebase_receipts=True,
    )


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
