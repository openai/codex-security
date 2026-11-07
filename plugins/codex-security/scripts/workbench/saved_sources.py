"""Read and freeze saved scan checkpoint observations."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import stat
from collections.abc import Iterable, Iterator
from functools import partial
from pathlib import Path
from typing import Any

from finalize_scan_contract import (
    ContractError,
    PreparedScanFinalization,
    RecoverableContractError,
    _contract_json_bytes,
    _prepare_scan_finalization,
    _read_scan_local_json,
    _read_scan_local_json_with_metadata,
    manifest_is_sealed,
    warnings_for_seal,
    write_scan_local_bytes,
)
from review_state import checkpoint_review_state, review_state, uses_legacy_review
from workbench.storage import archived_deep_path, archived_worker_paths
from workbench_coverage_receipts import capture_receipt_checkpoints, clear_scan_receipt_refs
from workbench_validation import has_verified_selected_result, latest_publication_reference


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
    """Return the saved source digests and the optional path supplying the threat model.

    Accept both a legacy path-to-digest map and an envelope containing sources.
    Raise ContractError if the model points outside that envelope's source set.
    """
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
    """Return selected checkpoint heads and any pending recovery record.

    Older scans can store the head map directly. Recovery records also bind
    the selection to a sealed manifest digest. A conflicting digest raises ContractError.
    """
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
    """Return the owner directory of a current or archived checkpoint head path, or None for another file."""
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
    accepted_source_digests: dict[str, str] | None = None,
    checkpoint_heads: dict[str, str | None] | None = None,
    expected_digest: str | None = None,
) -> dict[str, tuple[str, int]]:
    """Capture digests and observation times for a saved source and its selected checkpoint or receipt inputs."""
    read = partial(
        _read_saved_result,
        scan_dir,
        scan_id=scan_id,
        accepted_source_digests=accepted_source_digests,
    )
    if not snapshot_head or Path(relative).name != "checkpoint-head.json":
        _, digest, observed = read(relative, kind=kind)
        return capture_receipt_checkpoints(
            relative,
            kind,
            {relative: (digest, observed)},
            partial(_checkpoint_paths, scan_dir),
            read,
        )
    head, head_digest, observed = read(relative)
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
            selected_records[selected] = read(selected)
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
    scan_dir: Path,
    relative: str,
    scan_id: str,
    *,
    kind: str | None = None,
    accepted_source_digests: dict[str, str] | None = None,
    normalize_review: bool = True,
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
        if "inputCheckpoint" in draft:
            raw = draft["inputCheckpoint"]
            if not isinstance(raw, str) or not re.fullmatch(r"[0-9a-f]{64}\.json", raw):
                raise ContractError("checkpoint head does not name a saved input checkpoint")
            _read_saved_result(
                scan_dir,
                (directory / "checkpoints" / raw).as_posix(),
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
    if _is_source_order_snapshot(relative):
        return draft, _digest(draft), metadata.st_mtime_ns
    coverage = (
        draft.get("sourceCoverage", draft.get("coverage", {}))
        if kind == "dedup"
        else draft.get("coverage")
    )
    if not isinstance(draft.get("findings"), list) or not isinstance(
        draft.get("reviewState", coverage), dict
    ):
        raise ContractError("checkpoint has no semantic findings or coverage")
    frozen_digest = _digest(draft)
    path = Path(relative)
    if expected is not None and (
        (path.parent.name == "checkpoints" and path.name == f"{expected}.json")
        or path.name == f"accepted-{expected}.json"
    ):
        # Direct snapshots retain their accepted bytes, but supply no host receipt ownership.
        clear_scan_receipt_refs(draft)
    if kind == "dedup" and normalize_review:
        # The host keeps grouping state in iteration checkpoints for resume only.
        for finding in draft["findings"]:
            if isinstance(finding, dict) and isinstance(finding.get("provenance"), dict):
                finding["provenance"].pop("deepScanRepairGroups", None)
    if normalize_review and "coverage" in draft and "reviewState" not in draft:
        draft["reviewState"] = draft.pop("coverage")
    return draft, frozen_digest, metadata.st_mtime_ns


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
    """Restore the prior selection for a checkpoint directory, allowing legacy evidence with no selected head."""
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
                scan_dir,
                f"checkpoints/{previous['inputCheckpoint']}",
                scan_id,
                normalize_review=False,
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
        "reviewState": coverage,
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
    *,
    unreadable_warnings: list[str] | None = None,
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
            try:
                head = _worker_checkpoint_head(scan_dir, relative, scan_id, accepted_source_digests)
            except (ContractError, OSError) as exc:
                if unreadable_warnings is None or worker["status"] != "canceled":
                    raise
                unreadable_warnings.append(
                    f"Preserved unreadable checkpoint {relative}/checkpoint-head.json: {exc}"
                )
                continue
            if head is not None:
                heads[relative] = head
    return heads


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
    parent_scan = manifest.get("scan")
    if not isinstance(parent_scan, dict):
        raise ContractError("Saved parent manifest has no scan object")
    coverage = (
        _read_scan_local_json(scan_dir, "coverage.json", "Saved parent coverage")
        if uses_legacy_review(parent_scan)
        else review_state(parent_scan)
    )
    if manifest_is_sealed(parent_scan) and (
        parent_scan.get("id", scan_id) != scan_id
        or findings.get("scanId", scan_id) != scan_id
        or coverage.get("scanId", scan_id) != scan_id
    ):
        raise ContractError("Saved parent documents belong to a different scan")
    return manifest, _parent_scan_draft(scan_id, parent_scan, findings, coverage)


def _selected_publication_digest(
    prepared: PreparedScanFinalization, legacy_completeness: str | None = None
) -> str:
    # Completion time is chosen at sealing, after publication. Everything else
    # must remain the host projection of the same accepted aggregate.
    manifest = copy.deepcopy(prepared.manifest)
    for field in ("completedAt", "sealedAt"):
        manifest["scan"].pop(field, None)
    coverage = prepared.coverage
    if prepared.was_sealed and not uses_legacy_review(manifest["scan"]):
        scan_id = manifest["scan"]["id"]
        head = _worker_checkpoint_head(prepared.scan_dir, ".", scan_id)
        if head is not None:
            # The compact seal stores only the review summary. Bind its original
            # detailed projection through the scan-local retained checkpoint.
            draft, _, _ = _read_saved_result(prepared.scan_dir, head, scan_id)
            coverage = review_state(
                {**manifest["scan"], "reviewState": checkpoint_review_state(draft["reviewState"])}
            )
    if legacy_completeness is not None:
        # Reconstruct the historical projection and its coverage artifact binding.
        coverage = {**coverage, "completeness": legacy_completeness}
        coverage_digest = hashlib.sha256(
            _contract_json_bytes("coverage.json", coverage)
        ).hexdigest()
        for artifact in manifest["scan"]["artifacts"]:
            if artifact["path"] == manifest["scan"]["coverageRef"]:
                artifact["sha256"] = coverage_digest
    return _digest([manifest, prepared.findings, coverage])


def _require_selected_result(scan: Any, selection: dict[str, Any]) -> None:
    relative = selection["resultPath"]
    if relative is not None:
        _read_saved_result(
            Path(scan["scan_dir"]),
            relative,
            scan["id"],
            kind="dedup",
            accepted_source_digests={
                str(Path(scan["scan_dir"]) / relative): selection["resultSha256"]
            },
        )


def bind_selected_publication(
    selection: dict[str, Any], prepared: PreparedScanFinalization
) -> None:
    digest = _selected_publication_digest(prepared)
    if selection.get("publicationSha256") != digest:
        selection.pop("sealedPublicationSha256", None)
        selection["publicationSha256"] = digest


def record_selected_publication(
    db: Any, connection: Any, scan: Any, prepared: PreparedScanFinalization
) -> None:
    run = db.deep_scan.require_deep_scan_run(connection, scan["id"])
    selection = db.deep_scan.deep_scan_finalization_input(run)
    if selection is None:
        return
    _require_selected_result(scan, selection)
    bind_selected_publication(selection, prepared)
    with connection:
        connection.execute(
            "UPDATE deep_scan_runs SET finalization_input_json = ? WHERE scan_id = ?",
            (json.dumps(selection), scan["id"]),
        )


def require_selected_publication(
    db: Any,
    connection: Any,
    scan: Any,
    prepared: PreparedScanFinalization,
    *,
    sealing_warnings: list[str] | None = None,
) -> None:
    if scan["mode"] != "deep":
        return
    run = db.deep_scan.require_deep_scan_run(connection, scan["id"])
    selection = db.deep_scan.deep_scan_finalization_input(run)
    if selection is None or "publicationSha256" not in selection:
        return
    try:
        _require_selected_result(scan, selection)
    except ContractError as exc:
        raise RecoverableContractError(str(exc)) from exc
    digest = selection["publicationSha256"]
    sealed_digest = selection.get("sealedPublicationSha256")
    if prepared.was_sealed and sealed_digest is not None:
        matches = sealed_digest == _selected_publication_digest(prepared)
    else:
        matches = digest == _selected_publication_digest(prepared)
        if (
            not matches
            and uses_legacy_review(prepared.manifest["scan"])
            and "completeness" not in prepared.coverage
        ):
            # Historical receipts include coverage completeness and its artifact digest.
            matches = any(
                digest == _selected_publication_digest(prepared, completeness)
                for completeness in ("complete", "partial", "unknown")
            )
    if not matches:
        raise RecoverableContractError(
            "The selected Deep Scan publication changed or is missing; "
            "republish its accepted result before completing the scan."
        )
    if prepared.was_sealed or sealing_warnings is None:
        return
    # Bind the host's exact warning projection before the seal can reach disk.
    # The original receipt still verifies an unsealed retry after process loss.
    warnings = warnings_for_seal(prepared, sealing_warnings)
    manifest_scan = prepared.manifest["scan"]
    if warnings and warnings != manifest_scan.get("warnings"):
        manifest = {**prepared.manifest, "scan": {**manifest_scan, "warnings": warnings}}
        selection["sealedPublicationSha256"] = _selected_publication_digest(
            prepared._replace(manifest=manifest)
        )
    else:
        selection.pop("sealedPublicationSha256", None)
    if selection.get("sealedPublicationSha256") != sealed_digest:
        with connection:
            connection.execute(
                "UPDATE deep_scan_runs SET finalization_input_json = ? WHERE scan_id = ?",
                (json.dumps(selection), scan["id"]),
            )


def _require_current_deep_publication(
    db: Any, connection: Any, scan: Any, draft: dict[str, Any]
) -> bool:
    scan_id = scan["id"]
    run = connection.execute(
        "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    publication = draft.get("deepScanPublication")
    selection = db.deep_scan.deep_scan_finalization_input(run) if run is not None else None
    if (
        selection is None
        and publication is None
        and draft["manifest"]["scan"].get("complete") is False
        and (run is None or run["status"] == "running")
    ):
        return False
    if run is None:
        run = db.deep_scan.require_deep_scan_run(connection, scan_id)
    # Finished discovery-only runs hand remaining publication back to the parent.
    if (
        selection is None
        and publication is None
        and run["status"] != "running"
        and run["manifest_path"] != str(Path(scan["scan_dir"]) / "scan-manifest.json")
    ):
        return False
    db.deep_scan.require_current_coordinator(
        run,
        argparse.Namespace(
            coordinator_generation=publication.get("coordinatorGeneration") if publication else None
        ),
    )
    accepted_findings = False
    if selection is not None:
        if publication is None:
            raise SystemExit("Deep Scan publication requires its committed selection.")
        scan = db.require_scan(connection, scan_id)
        accepted_findings = has_verified_selected_result(db, connection, scan)
        if "publicationSha256" in selection:
            manifest = draft["manifest"]
            if "reviewState" in draft:
                manifest_scan = {
                    **manifest["scan"],
                    "reviewState": checkpoint_review_state(draft["reviewState"]),
                }
                manifest_scan.pop("coverageRef", None)
                manifest = {**manifest, "scan": manifest_scan}
            elif (
                uses_legacy_review(manifest["scan"])
                and (Path(scan["scan_dir"]) / "coverage.json").is_file()
            ):
                # Historical workbenches inferred this reference from the sidecar
                # when reading a staged manifest that did not name it explicitly.
                manifest = {
                    **manifest,
                    "scan": {"coverageRef": "coverage.json", **manifest["scan"]},
                }
            prepared = _prepare_scan_finalization(
                Path(scan["scan_dir"]),
                expected_coverage_mode=db.expected_coverage_mode(scan),
                completion_binding=db.workbench_completion_binding(scan, db.now()),
                draft_documents=(
                    manifest,
                    draft["findings"],
                    draft["reviewState"] if "reviewState" in draft else draft["coverage"],
                ),
                accepted_findings=accepted_findings,
            )
            require_selected_publication(db, connection, scan, prepared)
        selected_result = (
            str(Path(scan["scan_dir"]) / selection["resultPath"])
            if selection["resultPath"] is not None
            else None
        )
    else:
        # Generation-one runs predate host publication metadata. Keep their existing
        # draft path; adopted coordinators must carry their generation and selection.
        if publication is None:
            if run["status"] != "running" and run["manifest_path"] == str(
                Path(scan["scan_dir"]) / "scan-manifest.json"
            ):
                raise SystemExit("Deep Scan is terminal; drafts cannot replace its publication.")
            return False

        reference = latest_publication_reference(db, connection, scan)
        selected_result = reference[0]
    if publication["resultPath"] != selected_result:
        raise SystemExit("Deep Scan aggregate belongs to a superseded publication selection.")
    if selection is None:
        accepted_findings = has_verified_selected_result(db, connection, scan, reference=reference)
    return accepted_findings


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()


def _saved_workers(connection: Any, scan: Any) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT worker.*, attempt.accepted_result_path, attempt.accepted_result_sha256 "
        "FROM deep_scan_workers AS worker "
        "LEFT JOIN deep_scan_attempts AS attempt "
        "ON attempt.worker_id = worker.id AND attempt.attempt = worker.attempt "
        "WHERE worker.scan_id = ? ORDER BY worker.created_at, worker.id",
        (scan["id"],),
    ).fetchall()
    scan_dir = Path(scan["scan_dir"])
    workers = [
        {
            **dict(row),
            "accepted_result_path": archived_deep_path(scan_dir, row["accepted_result_path"]),
            "result_manifest_path": row["accepted_result_path"] or row["result_manifest_path"],
        }
        for row in rows
    ]
    return archived_worker_paths(workers, scan_dir)


def _accepted_source_digests(connection: Any, scan: Any) -> dict[str, str]:
    scan_dir = Path(scan["scan_dir"])
    return {
        archived_deep_path(scan_dir, row["accepted_result_path"]): row["accepted_result_sha256"]
        for row in connection.execute(
            "SELECT accepted_result_path, accepted_result_sha256 FROM deep_scan_attempts "
            "WHERE scan_id = ? AND accepted_result_path IS NOT NULL "
            "AND accepted_result_sha256 IS NOT NULL",
            (scan["id"],),
        )
    }


def _iteration_order(worker: Any) -> tuple[int, str, str]:
    result = worker["result_manifest_path"]
    output = Path(result).parent if result else Path(worker["artifact_dir"])
    label = output.parent.name if output.name == "output" else output.name
    match = re.fullmatch(r"dedup-([0-9]+)", label)
    return (int(match[1]) if match else 0, worker["completed_at"] or "", worker["id"])


def _latest_iteration(workers: Iterable[Any]) -> Any | None:
    return max(
        (
            worker
            for worker in workers
            if worker["kind"] == "dedup"
            and worker["status"] == "succeeded"
            and worker["result_manifest_path"]
        ),
        key=_iteration_order,
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


def _reducer_output_paths(
    scan_dir: Path, worker: Any, directory: str, attempt: int
) -> tuple[str | None, list[str]]:
    # A durable acceptance replaces the mutable output for exactly this attempt.
    if (
        attempt == worker["attempt"]
        and "accepted_result_path" in worker.keys()
        and worker["accepted_result_path"]
    ):
        try:
            return Path(worker["accepted_result_path"]).relative_to(scan_dir).as_posix(), []
        except ValueError:
            return None, []
    checkpoints = _checkpoint_paths(scan_dir, f"{directory}/checkpoints")
    return (f"{directory}/result.json" if checkpoints else None), checkpoints


def _saved_result_paths(scan_dir: Path, workers: list[Any]) -> Iterator[tuple[str, str | None]]:
    iteration = _latest_iteration(workers)
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
        for directory, attempt in outputs:
            if worker["kind"] == "dedup":
                result, checkpoints = _reducer_output_paths(scan_dir, worker, directory, attempt)
                if result is not None:
                    yield result, worker["kind"]
            else:
                yield f"{directory}/checkpoint-head.json", worker["kind"]
                yield from (
                    (path, worker["kind"])
                    for path in _checkpoint_paths(scan_dir, f"{directory}/checkpoint-heads")
                )
                yield f"{directory}/result.json", worker["kind"]
                checkpoints = _checkpoint_paths(scan_dir, f"{directory}/checkpoints")
            yield from ((path, worker["kind"]) for path in checkpoints)
        if worker["result_manifest_path"] and (
            worker["kind"] == "discovery"
            or (iteration is not None and worker["id"] == iteration["id"])
        ):
            try:
                yield (
                    Path(worker["result_manifest_path"]).relative_to(scan_dir).as_posix(),
                    worker["kind"],
                )
            except ValueError:
                continue
