"""Read and freeze saved scan source identities and checkpoint order."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from finalize_scan_contract import (
    ContractError,
    _read_scan_local_json,
    _read_scan_local_json_with_metadata,
    write_scan_local_bytes,
)


def _encoded(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_encoded(value)).hexdigest()


def _children(scan_dir: Path, relative: str) -> list[str]:
    cursor = scan_dir
    for part in Path(relative).parts:
        if part in {"..", "."}:
            return []
        cursor = cursor / part
        try:
            if not stat.S_ISDIR(cursor.lstat().st_mode):
                return []
        except FileNotFoundError:
            return []
    return sorted(child.name for child in cursor.iterdir())


def _saved_workers(connection: Any, scan_id: str) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT worker.*, attempt.accepted_result_path FROM deep_scan_workers AS worker "
        "LEFT JOIN deep_scan_attempts AS attempt "
        "ON attempt.worker_id = worker.id AND attempt.attempt = worker.attempt "
        "WHERE worker.scan_id = ? ORDER BY worker.created_at, worker.id",
        (scan_id,),
    ).fetchall()
    return [
        {
            **dict(row),
            "result_manifest_path": row["accepted_result_path"] or row["result_manifest_path"],
        }
        for row in rows
    ]


def _accepted_source_digests(connection: Any, scan_id: str) -> dict[str, str]:
    return {
        row["accepted_result_path"]: row["accepted_result_sha256"]
        for row in connection.execute(
            "SELECT accepted_result_path, accepted_result_sha256 FROM deep_scan_attempts "
            "WHERE scan_id = ? AND accepted_result_path IS NOT NULL "
            "AND accepted_result_sha256 IS NOT NULL",
            (scan_id,),
        )
    }


def _latest_successful_reducer(workers: list[Any]) -> Any | None:
    return max(
        (
            worker
            for worker in workers
            if worker["kind"] == "dedup"
            and worker["status"] == "succeeded"
            and worker["result_manifest_path"]
        ),
        key=lambda worker: (worker["completed_at"] or "", worker["id"]),
        default=None,
    )


def _checkpoint_paths(scan_dir: Path, directory: str) -> list[str]:
    return [
        f"{directory}/{name}"
        for name in _children(scan_dir, directory)
        if re.fullmatch(r"[0-9a-f]{64}\.json", name)
    ]


def _worker_outputs(scan_dir: Path, worker: Any) -> list[tuple[str, int]]:
    output = Path(worker["artifact_dir"]).relative_to(scan_dir)
    attempts = (output.parent if output.name == "output" else output) / "attempts"
    archived = [
        ((attempts / name).as_posix(), int(name.split("-")[1]))
        for name in _children(scan_dir, attempts.as_posix())
        if re.fullmatch(r"attempt-\d+", name)
    ]
    attempt = int(worker["attempt"] or 0) if "attempt" in worker.keys() else 0
    if worker["kind"] == "discovery" and not attempt:
        attempt = max((attempt for _, attempt in archived), default=0) + 1
    return [(output.as_posix(), attempt), *archived]


def _saved_result_paths(scan_dir: Path, workers: list[Any]) -> Iterator[tuple[str, str | None]]:
    latest_reducer = _latest_successful_reducer(workers)
    yield "checkpoint-head.json", None
    for directory in ("checkpoint-heads", "checkpoints"):
        yield from ((path, None) for path in _checkpoint_paths(scan_dir, directory))
    for worker in workers:
        if worker["kind"] not in {"dedup", "discovery"}:
            continue
        try:
            outputs = _worker_outputs(scan_dir, worker)
        except (TypeError, ValueError):
            continue
        for directory, _ in outputs:
            if worker["kind"] == "discovery":
                yield f"{directory}/checkpoint-head.json", worker["kind"]
                yield from (
                    (path, worker["kind"])
                    for path in _checkpoint_paths(scan_dir, f"{directory}/checkpoint-heads")
                )
            checkpoint_paths = _checkpoint_paths(scan_dir, f"{directory}/checkpoints")
            if worker["kind"] == "discovery" or checkpoint_paths:
                yield f"{directory}/result.json", worker["kind"]
                yield from ((path, worker["kind"]) for path in checkpoint_paths)
        if worker["result_manifest_path"] and (
            worker["kind"] == "discovery"
            or (latest_reducer is not None and worker["id"] == latest_reducer["id"])
        ):
            try:
                yield (
                    Path(worker["result_manifest_path"]).relative_to(scan_dir).as_posix(),
                    worker["kind"],
                )
            except ValueError:
                continue


def _checkpoint_head_directory(relative: str) -> Path | None:
    path = Path(relative)
    if path.name == "checkpoint-head.json":
        return path.parent
    if path.parent.name == "checkpoint-heads":
        return path.parent.parent
    return None


def _capture_saved_source(
    scan_dir: Path,
    relative: str,
    scan_id: str,
    *,
    kind: str | None = None,
    snapshot_head: bool = True,
    write: bool = True,
    accepted_source_digests: dict[str, str] | None = None,
) -> dict[str, tuple[str, int]]:
    if not snapshot_head or Path(relative).name != "checkpoint-head.json":
        _, digest, observed = _read_saved_result(
            scan_dir, relative, scan_id, kind=kind, accepted_source_digests=accepted_source_digests
        )
        return {relative: (digest, observed)}
    head, _, observed = _read_saved_result(
        scan_dir, relative, scan_id, accepted_source_digests=accepted_source_digests
    )
    observation = {"checkpoint": head["checkpoint"], "observedAtNs": str(observed)}
    directory = Path(relative).parent
    selected = (directory / "checkpoints" / observation["checkpoint"]).as_posix()
    _, selected_digest, selected_time = _read_saved_result(
        scan_dir, selected, scan_id, accepted_source_digests=accepted_source_digests
    )
    digest = _digest(observation)
    snapshot = (directory / "checkpoint-heads" / f"{digest}.json").as_posix()
    # Capture the selected file even if the worker created it after directory enumeration.
    if write and not (scan_dir / snapshot).exists():
        write_scan_local_bytes(scan_dir, snapshot, _encoded(observation))
    return {
        snapshot: (digest, int(observation["observedAtNs"])),
        selected: (selected_digest, selected_time),
    }


def _is_source_order_snapshot(relative: str) -> bool:
    path = Path(relative)
    return path.parent == Path("source-order") and bool(
        re.fullmatch(r"[0-9a-f]{64}\.json", path.name)
    )


def _read_saved_result(
    scan_dir: Path,
    relative: str,
    scan_id: str,
    *,
    kind: str | None = None,
    accepted_source_digests: dict[str, str] | None = None,
) -> tuple[dict[str, Any], str, int]:
    draft, contents, metadata = _read_scan_local_json_with_metadata(
        scan_dir, relative, "Saved scan checkpoint"
    )
    expected = (accepted_source_digests or {}).get(str(scan_dir / relative))
    if expected is not None and hashlib.sha256(contents).hexdigest() != expected:
        raise ContractError("checkpoint changed after acceptance")
    directory = _checkpoint_head_directory(relative)
    if directory is not None:
        checkpoint = draft.get("checkpoint")
        if not isinstance(checkpoint, str) or not re.fullmatch(r"[0-9a-f]{64}\.json", checkpoint):
            raise ContractError("checkpoint head does not name a saved checkpoint")
        _read_saved_result(
            scan_dir,
            (directory / "checkpoints" / checkpoint).as_posix(),
            scan_id,
            accepted_source_digests=accepted_source_digests,
        )
        if Path(relative).name == "checkpoint-head.json":
            return draft, _digest([draft, metadata.st_mtime_ns]), metadata.st_mtime_ns
        observed = draft.get("observedAtNs")
        if not isinstance(observed, str) or not re.fullmatch(r"-?[0-9]+", observed):
            raise ContractError("checkpoint head has no observation time")
        return draft, _digest(draft), int(observed)
    if draft.get("scanId") != scan_id:
        raise ContractError("checkpoint belongs to a different scan")
    if not _is_source_order_snapshot(relative) and (
        not isinstance(draft.get("findings"), list)
        or not isinstance(
            draft.get("sourceCoverage", draft.get("coverage", {}))
            if kind == "dedup"
            else draft.get("coverage"),
            dict,
        )
    ):
        raise ContractError("checkpoint has no semantic findings or coverage")
    return draft, _digest(draft), metadata.st_mtime_ns


def _frozen_source_times(scan_dir: Path, scan_id: str, sources: dict[str, str]) -> dict[str, int]:
    times: dict[str, int] = {}
    snapshots = [path for path in sources if _is_source_order_snapshot(path)]
    for path in snapshots:
        record, digest, _ = _read_saved_result(scan_dir, path, scan_id)
        if digest != sources[path] or not isinstance(record.get("sources"), dict):
            raise ContractError("saved source ordering changed after the scan stopped")
        for relative, observation in record["sources"].items():
            if (
                not isinstance(observation, dict)
                or relative not in sources
                or observation.get("digest") != sources[relative]
                or not isinstance(observation.get("observedAtNs"), str)
                or not re.fullmatch(r"-?[0-9]+", observation["observedAtNs"])
            ):
                raise ContractError("saved source ordering does not match its frozen sources")
            observed = int(observation["observedAtNs"])
            if relative in times and times[relative] != observed:
                raise ContractError("saved source ordering has conflicting observations")
            times[relative] = observed
    if snapshots and sources.keys() - set(snapshots) - times.keys():
        raise ContractError("saved source ordering is incomplete")
    return times


def _freeze_source_times(
    scan_dir: Path, scan_id: str, sources: dict[str, str], times: dict[str, int]
) -> None:
    # Identical result rewrites must not change the order of frozen review evidence.
    observations = {
        path: {"digest": digest, "observedAtNs": str(times[path])}
        for path, digest in sources.items()
        if not _is_source_order_snapshot(path)
    }
    if not observations:
        return
    record = {"scanId": scan_id, "sources": observations}
    digest = _digest(record)
    path = f"source-order/{digest}.json"
    if not (scan_dir / path).exists():
        write_scan_local_bytes(scan_dir, path, _encoded(record))
    if _read_saved_result(scan_dir, path, scan_id)[1] != digest:
        raise ContractError("saved source ordering does not match its digest")
    sources[path] = digest


def _parent_scan_draft(
    scan_id: str,
    parent_scan: dict[str, Any],
    findings: dict[str, Any],
    coverage: dict[str, Any],
) -> dict[str, Any]:
    parent = {
        "scanId": scan_id,
        "findings": findings.get("findings"),
        "coverage": coverage,
        **{
            key: parent_scan[key]
            for key in ("scope", "threatModel", "complete")
            if key in parent_scan
        },
    }
    if not isinstance(parent["findings"], list):
        raise ContractError("Saved parent draft has no findings array")
    return parent


def _worker_checkpoint_head(
    scan_dir: Path,
    directory: str,
    scan_id: str,
    accepted_source_digests: dict[str, str] | None = None,
) -> str | None:
    relative = f"{directory}/checkpoint-head.json"
    try:
        (scan_dir / relative).lstat()
    except FileNotFoundError:
        return None
    head = _read_scan_local_json(scan_dir, relative, "Saved worker checkpoint head")
    name = head.get("checkpoint")
    if not isinstance(name, str) or not re.fullmatch(r"[0-9a-f]{64}\.json", name):
        raise ContractError("Saved worker checkpoint head is invalid.")
    checkpoint = f"{directory}/checkpoints/{name}"
    # A committed head precedes replacement of result.json. Do not fall back to
    # that older result if the selected checkpoint cannot be read.
    _read_saved_result(
        scan_dir, checkpoint, scan_id, accepted_source_digests=accepted_source_digests
    )
    return checkpoint


def _worker_checkpoint_heads(
    scan_dir: Path,
    workers: list[Any],
    scan_id: str,
    accepted_source_digests: dict[str, str] | None = None,
) -> dict[str, str]:
    heads: dict[str, str] = {}
    for worker in workers:
        if worker["kind"] != "discovery":
            continue
        try:
            output = Path(worker["artifact_dir"]).relative_to(scan_dir)
        except (TypeError, ValueError):
            continue
        attempts = (output.parent if output.name == "output" else output) / "attempts"
        directories = [output] + [
            attempts / name
            for name in _children(scan_dir, attempts.as_posix())
            if re.fullmatch(r"attempt-\d+", name)
        ]
        for directory in directories:
            relative = directory.as_posix()
            head = _worker_checkpoint_head(scan_dir, relative, scan_id, accepted_source_digests)
            if head is not None:
                heads[relative] = head
    return heads


def _read_saved_parent_result(
    scan_dir: Path, scan_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = _read_scan_local_json(scan_dir, "scan-manifest.json", "Saved parent manifest")
    findings = _read_scan_local_json(scan_dir, "findings.json", "Saved parent findings")
    coverage = _read_scan_local_json(scan_dir, "coverage.json", "Saved parent coverage")
    parent_scan = manifest.get("scan")
    if not isinstance(parent_scan, dict):
        raise ContractError("Saved parent manifest has no scan object")
    if (parent_scan.get("sealedAt") or parent_scan.get("artifacts")) and (
        parent_scan.get("id", scan_id) != scan_id
        or findings.get("scanId", scan_id) != scan_id
        or coverage.get("scanId", scan_id) != scan_id
    ):
        raise ContractError("Saved parent documents belong to a different scan")
    return manifest, _parent_scan_draft(scan_id, parent_scan, findings, coverage)


def _source_digests(value: Any, error: str) -> dict[str, str]:
    if not isinstance(value, dict) or not all(
        isinstance(relative, str) and isinstance(digest, str) for relative, digest in value.items()
    ):
        raise ContractError(error)
    return value


def _retained_source_state(value: Any) -> tuple[dict[str, str], str | None]:
    if isinstance(value, dict) and isinstance(value.get("sources"), dict):
        sources = _source_digests(
            value["sources"], "Saved stopped-scan source digests are malformed."
        )
        model_source = value.get("threatModelSource")
        if not isinstance(model_source, str) or model_source not in sources:
            raise ContractError("Saved stopped-scan model source is outside its checkpoint set.")
        return sources, model_source
    return _source_digests(value, "Saved stopped-scan source digests are malformed."), None


def _encode_retained_sources(sources: dict[str, str], model_source: list[str]) -> str:
    state = {"sources": sources, "threatModelSource": model_source[0]} if model_source else sources
    return json.dumps(state, sort_keys=True)


def _saved_results_changed(db: Any, connection: Any, scan: Any) -> bool:
    try:
        scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
        manifest_path = db.artifact_path(scan_dir, db.ARTIFACTS["manifest"], required=False)
        workers = _saved_workers(connection, scan["id"])
        accepted_digests = _accepted_source_digests(connection, scan["id"])
        paths = dict(_saved_result_paths(scan_dir, workers))
        frozen_sources = scan["retained_source_digests_json"]

        def has_saved_source() -> bool:
            for path in paths:
                try:
                    _read_saved_result(
                        scan_dir,
                        path,
                        scan["id"],
                        kind=paths[path],
                        accepted_source_digests=accepted_digests,
                    )
                    return True
                except (ContractError, OSError, ValueError):
                    continue
            return False

        if manifest_path is None:
            if frozen_sources is not None:
                return bool(_retained_source_state(json.loads(frozen_sources))[0])
            return has_saved_source()
        if scan["seal_manifest_digest"] is None:
            try:
                _read_saved_parent_result(scan_dir, scan["id"])
                return True
            except (ContractError, OSError, ValueError):
                pass
            return has_saved_source()
        manifest = _read_scan_local_json(
            scan_dir,
            manifest_path.relative_to(scan_dir).as_posix(),
            "Saved scan manifest",
        )
        manifest_scan = manifest.get("scan")
        if not isinstance(manifest_scan, dict):
            return True
        published_sources = _source_digests(
            manifest_scan.get("preservedSources", {}),
            "Published scan source digests are malformed.",
        )
        if _worker_checkpoint_heads(
            scan_dir, workers, scan["id"], accepted_digests
        ) != manifest_scan.get("preservedCheckpointHeads", {}):
            return True
        current_sources = dict(published_sources)
        paths.update({path: None for path in published_sources if _is_source_order_snapshot(path)})
        for path in paths:
            try:
                captured = _capture_saved_source(
                    scan_dir,
                    path,
                    scan["id"],
                    kind=paths[path],
                    accepted_source_digests=accepted_digests,
                    snapshot_head=path not in published_sources,
                    write=False,
                )
                current_sources.update({path: value[0] for path, value in captured.items()})
            except (ContractError, OSError, ValueError):
                continue
        return current_sources != published_sources
    except (ContractError, OSError, SystemExit, ValueError):
        return False


def _recovery_source_digests(
    db: Any, connection: Any, scan: Any
) -> tuple[dict[str, str], bool, dict[str, str]]:
    scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
    frozen_sources: dict[str, str] | None = None
    include_parent = True
    raw_frozen_sources = scan["retained_source_digests_json"]
    if raw_frozen_sources is not None:
        frozen_sources, _ = _retained_source_state(json.loads(raw_frozen_sources))
        include_parent = False

    manifest_path = db.artifact_path(scan_dir, db.ARTIFACTS["manifest"], required=False)
    if manifest_path is not None:
        manifest = _read_scan_local_json(
            scan_dir,
            manifest_path.relative_to(scan_dir).as_posix(),
            "Saved scan manifest",
        )
        manifest_scan = manifest.get("scan")
        if not isinstance(manifest_scan, dict):
            raise ContractError("Saved scan manifest has no scan object")
        if scan["seal_manifest_digest"] is not None or (
            manifest_scan.get("sealedAt") is not None or manifest_scan.get("artifacts") is not None
        ):
            if "preservedSources" in manifest_scan:
                published_sources = _source_digests(
                    manifest_scan["preservedSources"],
                    "Published scan source digests are malformed.",
                )
                include_parent = not published_sources
                if published_sources:
                    if frozen_sources is not None and frozen_sources != published_sources:
                        raise ContractError(
                            "Stopped scan sources changed after terminal publication."
                        )
                    frozen_sources = published_sources
                elif frozen_sources is None:
                    frozen_sources = {}
            else:
                include_parent = True

    workers = _saved_workers(connection, scan["id"])
    accepted_digests = _accepted_source_digests(connection, scan["id"])
    checkpoint_heads = _worker_checkpoint_heads(scan_dir, workers, scan["id"], accepted_digests)
    paths = dict(_saved_result_paths(scan_dir, workers))
    recovery_sources = dict(frozen_sources or {})
    source_times = _frozen_source_times(scan_dir, scan["id"], recovery_sources)
    for relative, expected_digest in recovery_sources.items():
        try:
            _, digest, observed = _read_saved_result(
                scan_dir,
                relative,
                scan["id"],
                kind=paths.get(relative),
                accepted_source_digests=accepted_digests,
            )
        except (ContractError, OSError, ValueError) as exc:
            raise ContractError("Frozen stopped-scan checkpoint set is incomplete.") from exc
        if digest != expected_digest:
            raise ContractError("checkpoint changed after the scan stopped")
        if not _is_source_order_snapshot(relative):
            source_times.setdefault(relative, observed)

    for relative in paths.keys() - recovery_sources.keys():
        try:
            captured = _capture_saved_source(
                scan_dir,
                relative,
                scan["id"],
                kind=paths[relative],
                accepted_source_digests=accepted_digests,
            )
        except (ContractError, OSError, ValueError):
            continue
        for path, (digest, observed) in captured.items():
            if path in recovery_sources and recovery_sources[path] != digest:
                raise ContractError("checkpoint changed after the scan stopped")
            recovery_sources[path] = digest
            source_times.setdefault(path, observed)
    _freeze_source_times(scan_dir, scan["id"], recovery_sources, source_times)
    return recovery_sources, include_parent, checkpoint_heads
