"""Read and freeze saved scan checkpoint observations."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections.abc import Iterator
from functools import partial
from pathlib import Path
from typing import Any

from finalize_scan_contract import (
    ContractError,
    _read_scan_local_json,
    _read_scan_local_json_with_metadata,
    manifest_is_sealed,
    write_scan_local_bytes,
)
from workbench_coverage_receipts import capture_receipt_checkpoints


class _CheckpointSnapshotError(ContractError):
    """A captured source observation could not be persisted for publication replay."""

    def __init__(self, message: str, captured: dict[str, tuple[str, int]]) -> None:
        super().__init__(message)
        self.captured = captured
        self.records: dict[str, tuple[dict[str, Any], str, int]] = {}
        self.heads: dict[str, str | None] = {}
        self.model_source: list[str] = []
        self.parent_context: dict[str, str] = {}
        self.include_parent = False
        self.documents: tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None = None


def _encoded(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_encoded(value)).hexdigest()


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
        if "threatModelSource" in value and (
            not isinstance(model_source, str) or model_source not in sources
        ):
            raise ContractError("Saved stopped-scan model source is outside its checkpoint set.")
        return sources, model_source
    return _source_digests(value, "Saved stopped-scan source digests are malformed."), None


def _retained_checkpoint_state(
    scan: Any,
) -> tuple[dict[str, str | None] | None, dict[str, Any] | None]:
    raw = scan["retained_checkpoint_heads_json"]
    if raw is None:
        return None, None
    saved = json.loads(raw)
    if not isinstance(saved.get("heads"), dict):
        return saved, None
    if saved["recoveryBaseDigest"] != scan["seal_manifest_digest"]:
        raise ContractError("Stopped scan recovery publication changed after selection.")
    return saved["heads"], saved


def _encode_retained_sources(
    sources: dict[str, str],
    model_source: list[str],
    source_times: dict[str, int] | None = None,
    parent_context: dict[str, str] | None = None,
) -> str:
    state: dict[str, Any] = sources
    if model_source or source_times is not None:
        state = {"sources": sources}
        if model_source:
            state["threatModelSource"] = model_source[0]
        if source_times is not None:
            state["sourceTimes"] = source_times
            if parent_context:
                state["parentContext"] = parent_context
    return json.dumps(state, sort_keys=True)


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


def _checkpoint_paths(scan_dir: Path, directory: str) -> list[str]:
    return [
        f"{directory}/{name}"
        for name in _children(scan_dir, directory)
        if re.fullmatch(r"[0-9a-f]{64}\.json", name)
    ]


def _checkpoint_head_directory(relative: str) -> Path | None:
    path = Path(relative)
    if path.name == "checkpoint-head.json":
        return path.parent
    if path.parent.name == "checkpoint-heads":
        return path.parent.parent
    return None


def _unselected_root_order(
    saved_heads: dict[str, str],
    checkpoint_heads: dict[str, str | None],
    source_order: dict[str, tuple[int, int]],
) -> tuple[int, int]:
    # One payload can have several accepted observations; retain their order.
    return max(
        (
            source_order[head]
            for head, checkpoint in saved_heads.items()
            if _checkpoint_head_directory(head) == Path(".")
            and checkpoint_heads.get(".") not in (None, head, f"checkpoints/{checkpoint}")
        ),
        default=(-1, 0),
    )


def _capture_saved_source(
    scan_dir: Path,
    relative: str,
    scan_id: str,
    *,
    kind: str | None = None,
    snapshot_head: bool = True,
    write: bool = True,
    created_paths: set[str] | None = None,
    checkpoint_heads: dict[str, str | None] | None = None,
    expected_digest: str | None = None,
) -> dict[str, tuple[str, int]]:
    if not snapshot_head or Path(relative).name != "checkpoint-head.json":
        _, digest, observed = _read_saved_result(scan_dir, relative, scan_id, kind=kind)
        return capture_receipt_checkpoints(
            relative,
            kind,
            {relative: (digest, observed)},
            partial(_checkpoint_paths, scan_dir),
            partial(_read_saved_result, scan_dir, scan_id=scan_id),
        )
    head, head_digest, observed = _read_saved_result(scan_dir, relative, scan_id)
    if expected_digest is not None and head_digest != expected_digest:
        raise ContractError("checkpoint changed after the scan stopped")
    observation = {
        **{key: head[key] for key in ("checkpoint", "inputCheckpoint") if key in head},
        "observedAtNs": str(observed),
    }
    directory = Path(relative).parent
    selected_records = {}
    for key in ("checkpoint", "inputCheckpoint"):
        if key in head:
            selected = (directory / "checkpoints" / head[key]).as_posix()
            selected_records[selected] = _read_saved_result(scan_dir, selected, scan_id)
    selected_sources = {
        path: (digest, seen) for path, (_, digest, seen) in selected_records.items()
    }
    digest = _digest(observation)
    snapshot = (directory / "checkpoint-heads" / f"{digest}.json").as_posix()
    # Capture the selected file even if the worker created it after directory enumeration.
    if checkpoint_heads is not None:
        checkpoint_heads[directory.as_posix()] = snapshot
    if write and not (scan_dir / snapshot).exists():
        if created_paths is not None and not os.path.lexists(scan_dir / snapshot):
            created_paths.add(snapshot)
        try:
            write_scan_local_bytes(scan_dir, snapshot, _encoded(observation))
        except (ContractError, OSError) as exc:
            if checkpoint_heads is not None:
                checkpoint_heads[directory.as_posix()] = relative
            failure = _CheckpointSnapshotError(
                str(exc), {relative: (head_digest, observed), **selected_sources}
            )
            failure.records = {relative: (head, head_digest, observed), **selected_records}
            raise failure from exc
    return {
        snapshot: (digest, observed),
        **selected_sources,
    }


def _read_saved_result(
    scan_dir: Path, relative: str, scan_id: str, *, kind: str | None = None
) -> tuple[dict[str, Any], str, int]:
    draft, _, metadata = _read_scan_local_json_with_metadata(
        scan_dir, relative, "Saved scan checkpoint"
    )
    directory = _checkpoint_head_directory(relative)
    if directory is not None:
        checkpoint = draft.get("checkpoint")
        if not isinstance(checkpoint, str) or not re.fullmatch(r"[0-9a-f]{64}\.json", checkpoint):
            raise ContractError("checkpoint head does not name a saved checkpoint")
        _read_saved_result(scan_dir, (directory / "checkpoints" / checkpoint).as_posix(), scan_id)
        if "inputCheckpoint" in draft:
            raw = draft["inputCheckpoint"]
            if not isinstance(raw, str) or not re.fullmatch(r"[0-9a-f]{64}\.json", raw):
                raise ContractError("checkpoint head does not name a saved input checkpoint")
            _read_saved_result(scan_dir, (directory / "checkpoints" / raw).as_posix(), scan_id)
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
        or not isinstance(draft.get("coverage", {} if kind == "dedup" else None), dict)
    ):
        raise ContractError("checkpoint has no semantic findings or coverage")
    return draft, _digest(draft), metadata.st_mtime_ns


def _is_source_order_snapshot(relative: str) -> bool:
    path = Path(relative)
    return path.parent == Path("source-order") and bool(
        re.fullmatch(r"[0-9a-f]{64}\.json", path.name)
    )


def _frozen_source_times(
    scan_dir: Path,
    scan_id: str,
    sources: dict[str, str],
    parent_context: dict[str, str] | None = None,
) -> dict[str, int]:
    times: dict[str, int] = {}
    snapshots = [path for path in sources if _is_source_order_snapshot(path)]
    for path in snapshots:
        record, digest, _ = _read_saved_result(scan_dir, path, scan_id)
        if digest != sources[path] or not isinstance(record.get("sources"), dict):
            raise ContractError("saved source ordering changed after the scan stopped")
        context = record.get("parentContext")
        if parent_context is not None and context is not None:
            if not isinstance(context, dict) or any(
                (
                    "canonical" not in context
                    or not isinstance(relative, str)
                    or not re.fullmatch(r"-?[0-9]+", relative)
                )
                if role == "canonicalObservedAtNs"
                else (
                    role not in ("canonical", "head")
                    or not isinstance(relative, str)
                    or relative not in sources
                    or (role == "canonical" and Path(relative).parent != Path("checkpoints"))
                    or (role == "head" and _checkpoint_head_directory(relative) != Path("."))
                )
                for role, relative in context.items()
            ):
                raise ContractError("saved parent context is outside the frozen sources")
            if any(
                role in parent_context and parent_context[role] != relative
                for role, relative in context.items()
            ):
                raise ContractError("saved parent context has conflicting observations")
            parent_context.update(context)
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


def _frozen_checkpoint_heads(
    scan_dir: Path, scan_id: str, sources: dict[str, str], *, skip_unreadable: bool = False
) -> dict[str, str]:
    parent_context: dict[str, str] = {}
    try:
        times = _frozen_source_times(scan_dir, scan_id, sources, parent_context)
    except (ContractError, OSError, ValueError):
        if not skip_unreadable:
            raise
        times = {}
        parent_context.clear()
    # A frozen parent can identify its accepted head even when observation times tie.
    accepted_root = None
    heads: dict[str, tuple[int, str]] = {}
    ambiguous: set[str] = set()
    for relative, expected_digest in sources.items():
        directory = _checkpoint_head_directory(relative)
        if directory is None:
            continue
        try:
            head, digest, observed = _read_saved_result(scan_dir, relative, scan_id)
            if digest != expected_digest:
                raise ContractError("checkpoint changed after the scan stopped")
        except (ContractError, OSError, ValueError):
            if skip_unreadable:
                continue
            raise
        selected = (directory / "checkpoints" / head["checkpoint"]).as_posix()
        observation = (times.get(relative, observed), selected)
        key = directory.as_posix()
        if relative == parent_context.get("head"):
            accepted_root = relative
        if key not in heads or observation[0] > heads[key][0]:
            heads[key] = observation
            ambiguous.discard(key)
        elif observation[0] == heads[key][0] and selected != heads[key][1]:
            ambiguous.add(key)
    # A legacy tie retains both observations until recovery selects a head.
    frozen = {
        directory: selected
        for directory, (_, selected) in heads.items()
        if directory not in ambiguous
    }
    if accepted_root is not None:
        frozen["."] = accepted_root
    return frozen


def _legacy_checkpoint_observed_at(
    scan_dir: Path, scan_id: str, sources: dict[str, str], selected: str
) -> int | None:
    times = _frozen_source_times(scan_dir, scan_id, sources)
    checkpoint = Path(selected)
    observations = []
    for relative, expected_digest in sources.items():
        if _checkpoint_head_directory(relative) != checkpoint.parent.parent:
            continue
        head, digest, observed = _read_saved_result(scan_dir, relative, scan_id)
        if digest != expected_digest:
            raise ContractError("checkpoint changed after the scan stopped")
        if head["checkpoint"] == checkpoint.name:
            observations.append(times.get(relative, observed))
    # Payload-only selections used the newest retained observation for that payload.
    return max(observations, default=None)


def _restore_checkpoint_head(
    heads: dict[str, str | None],
    previous_heads: dict[str, str | None],
    sources: dict[str, str],
    relative: str,
) -> None:
    path = Path(relative)
    if path.name != "checkpoint-head.json":
        return
    directory = path.parent.as_posix()
    if directory in previous_heads:
        heads[directory] = previous_heads[directory]
        return
    directories = {path.parent, path.parent / "checkpoints", path.parent / "checkpoint-heads"}
    if any(Path(source).parent in directories for source in sources):
        # Legacy evidence can remain accepted without one selected head.
        heads.pop(directory, None)


def _freeze_source_times(
    scan_dir: Path,
    scan_id: str,
    sources: dict[str, str],
    times: dict[str, int],
    parent_context: dict[str, str] | None = None,
    *,
    created_paths: set[str] | None = None,
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
    if parent_context:
        record["parentContext"] = parent_context
    digest = _digest(record)
    path = f"source-order/{digest}.json"
    if not (scan_dir / path).exists():
        if created_paths is not None and not os.path.lexists(scan_dir / path):
            created_paths.add(path)
        write_scan_local_bytes(scan_dir, path, _encoded(record))
    if _read_saved_result(scan_dir, path, scan_id)[1] != digest:
        raise ContractError("saved source ordering does not match its digest")
    if parent_context:
        for previous in [relative for relative in sources if _is_source_order_snapshot(relative)]:
            previous_record, _, _ = _read_saved_result(scan_dir, previous, scan_id)
            if previous_record.get("parentContext"):
                del sources[previous]
    sources[path] = digest


def _parent_publication_ancestors(
    input_checkpoint: str | None, drafts: dict[str, dict[str, Any]]
) -> set[str]:
    """Find stale canonical projections without relying on publication clocks."""
    ancestors = set()
    inputs = set()
    # Input hashes distinguish repeated publication of the same projected result.
    while isinstance(input_checkpoint, str) and input_checkpoint not in inputs:
        inputs.add(input_checkpoint)
        publication = drafts.get(f"checkpoints/{input_checkpoint}", {}).get("publication")
        if not isinstance(publication, dict):
            break
        previous = publication.get("previousCheckpoint")
        if isinstance(previous, str):
            ancestors.add(f"checkpoints/{previous}")
        input_checkpoint = publication.get("previousInputCheckpoint")
    return ancestors


def _admit_parent_checkpoint(
    scan_dir: Path, scan_id: str, checkpoint: dict[str, Any], projected: dict[str, Any]
) -> bytes:
    """Bind a Deep input to the accepted head under the host's publication lock."""
    previous = {}
    try:
        previous, _, _ = _read_saved_result(scan_dir, "checkpoint-head.json", scan_id)
        if (
            previous.get("checkpoint") == f"{_digest(projected)}.json"
            and "inputCheckpoint" in previous
        ):
            accepted, _, _ = _read_saved_result(
                scan_dir, f"checkpoints/{previous['inputCheckpoint']}", scan_id
            )
            if {key: value for key, value in accepted.items() if key != "publication"} == {
                key: value for key, value in checkpoint.items() if key != "publication"
            }:
                for relative in _checkpoint_paths(scan_dir, "checkpoints"):
                    pending, _, _ = _read_saved_result(scan_dir, relative, scan_id)
                    publication = pending.get("publication")
                    if (
                        isinstance(publication, dict)
                        and publication.get("previousInputCheckpoint")
                        == previous["inputCheckpoint"]
                    ):
                        break
                else:
                    return _encoded(accepted)
    except (ContractError, OSError, ValueError):
        pass  # An absent or unreadable previous head contributes no predecessor.
    return _encoded(
        {
            **checkpoint,
            "publication": {
                "previousCheckpoint": previous.get("checkpoint"),
                "previousInputCheckpoint": previous.get("inputCheckpoint"),
            },
        }
    )


def _capture_parent_observation(
    scan_dir: Path,
    scan_id: str,
    checkpoint: str,
    observed: int,
    legacy_head: bool = False,
    *,
    created_paths: set[str] | None = None,
) -> dict[str, tuple[str, int]]:
    """Freeze canonical input, preserving the legacy sealed-parent migration."""
    if legacy_head:
        write_scan_local_bytes(
            scan_dir, "checkpoint-head.json", _encoded({"checkpoint": checkpoint})
        )
        os.utime(scan_dir / "checkpoint-head.json", ns=(observed, observed))
        return _capture_saved_source(
            scan_dir, "checkpoint-head.json", scan_id, created_paths=created_paths
        )
    observation = {"checkpoint": checkpoint, "observedAtNs": str(observed)}
    digest = _digest(observation)
    snapshot = f"checkpoint-heads/{digest}.json"
    if not (scan_dir / snapshot).exists():
        if created_paths is not None and not os.path.lexists(scan_dir / snapshot):
            created_paths.add(snapshot)
        try:
            write_scan_local_bytes(scan_dir, snapshot, _encoded(observation))
        except (ContractError, OSError) as exc:
            # The canonical checkpoint carries this observation without a live head.
            raise _CheckpointSnapshotError(str(exc), {}) from exc
    return {snapshot: (digest, observed)}


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


def _model_capture(scan_id: str, model: dict[str, Any]) -> dict[str, Any]:
    return _parent_scan_draft(scan_id, {"threatModel": model}, {"findings": []}, {})


def _restore_frozen_model_capture(
    scan_dir: Path,
    scan_id: str,
    sources: dict[str, str],
    times: dict[str, int] | None,
    model_source: str | None,
) -> None:
    if model_source not in (times or {}) or (scan_dir / model_source).exists():
        return
    manifest = _read_scan_local_json(scan_dir, "scan-manifest.json", "Saved scan manifest")
    scan = manifest.get("scan")
    if not isinstance(scan, dict) or not isinstance(scan.get("threatModel"), dict):
        return
    draft = _model_capture(scan_id, scan["threatModel"])
    digest = _digest(draft)
    if model_source != f"checkpoints/{digest}.json" or sources.get(model_source) != digest:
        return
    # A failed first capture can retry only the model and time bound by that stop.
    write_scan_local_bytes(scan_dir, model_source, _encoded(draft))
    observed = times[model_source]
    os.utime(scan_dir / model_source, ns=(observed, observed))


def _read_saved_parent_result(
    scan_dir: Path, scan_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = _read_scan_local_json(scan_dir, "scan-manifest.json", "Saved parent manifest")
    findings = _read_scan_local_json(scan_dir, "findings.json", "Saved parent findings")
    coverage = _read_scan_local_json(scan_dir, "coverage.json", "Saved parent coverage")
    parent_scan = manifest.get("scan")
    if not isinstance(parent_scan, dict):
        raise ContractError("Saved parent manifest has no scan object")
    if manifest_is_sealed(parent_scan) and (
        parent_scan.get("id", scan_id) != scan_id
        or findings.get("scanId", scan_id) != scan_id
        or coverage.get("scanId", scan_id) != scan_id
    ):
        raise ContractError("Saved parent documents belong to a different scan")
    return manifest, _parent_scan_draft(scan_id, parent_scan, findings, coverage)


def _require_current_deep_publication(
    db: Any, connection: Any, scan: Any, draft: dict[str, Any]
) -> None:
    scan_id = scan["id"]
    run = connection.execute(
        "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    publication = draft.get("deepScanPublication")
    if (
        publication is None
        and draft["manifest"]["scan"].get("complete") is False
        and (run is None or run["status"] == "running")
    ):
        return
    if run is None:
        run = db.deep_scan.require_deep_scan_run(connection, scan_id)
    # Finished discovery-only runs hand remaining publication back to the parent.
    if (
        publication is None
        and run["status"] != "running"
        and run["manifest_path"] != str(Path(scan["scan_dir"]) / "scan-manifest.json")
    ):
        return
    db.deep_scan.require_current_coordinator(
        run,
        argparse.Namespace(
            coordinator_generation=publication.get("coordinatorGeneration") if publication else None
        ),
    )
    # Once finish selects the canonical parent, only completion may replay it.
    if publication is None:
        if run["status"] != "running" and run["manifest_path"] == str(
            Path(scan["scan_dir"]) / "scan-manifest.json"
        ):
            raise SystemExit("Deep Scan is terminal; drafts cannot replace its publication.")
        return

    # Match the durable reducer sequence used by coordinator recovery.
    def reducer_order(worker: Any) -> tuple[int, str]:
        match = re.fullmatch(r"dedup-([0-9]+)", Path(worker["prompt_path"]).parent.name)
        return (int(match[1]) if match else 0, worker["id"])

    reducer = max(
        (
            worker
            for worker in connection.execute(
                "SELECT * FROM deep_scan_workers WHERE scan_id = ?", (scan_id,)
            )
            if worker["kind"] == "dedup"
            and worker["status"] == "succeeded"
            and worker["result_manifest_path"]
        ),
        key=reducer_order,
        default=None,
    )
    selected_result = reducer["result_manifest_path"] if reducer is not None else None
    if publication["resultPath"] != selected_result:
        raise SystemExit("Deep Scan aggregate belongs to a superseded publication selection.")


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()


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
