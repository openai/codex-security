"""Shared finding and coverage reconciliation for saved scan results."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from finalize_scan_contract import (
    ContractError,
    MissingScanLocalFileError,
    _prepare_scan_finalization,
    _read_scan_local_json,
    _read_scan_local_json_with_metadata,
    _validate_resolved_deferred,
    _validate_schema_node,
    finding_candidate_id,
    open_scan_local_file_descriptor,
    write_scan_local_bytes,
)


def _checkpoint_head_directory(relative: str) -> Path | None:
    path = Path(relative)
    if path.name == "checkpoint-head.json":
        return path.parent
    if path.parent.name == "checkpoint-heads":
        return path.parent.parent
    return None


def _is_source_order_snapshot(relative: str) -> bool:
    path = Path(relative)
    return path.parent == Path("source-order") and bool(
        re.fullmatch(r"[0-9a-f]{64}\.json", path.name)
    )


def _legacy_read_saved_result(
    scan_dir: Path,
    relative: str,
    scan_id: str,
    *,
    kind: str | None = None,
    materialize: bool = False,
) -> tuple[dict[str, Any], str, int]:
    staged_contents = None
    try:
        draft, _, metadata = _read_scan_local_json_with_metadata(
            scan_dir, relative, "Saved scan checkpoint"
        )
    except ContractError as error:
        if not isinstance(error, MissingScanLocalFileError) or not re.fullmatch(
            r"checkpoints/[0-9a-f]{64}\.json", relative
        ):
            raise
        name = Path(relative).name
        with os.fdopen(
            open_scan_local_file_descriptor(
                scan_dir, f"checkpoints/pending/{name}", "Pending checkpoint"
            ),
            "rb",
        ) as handle:
            staged = handle.read().decode("utf-8")
            metadata = os.fstat(handle.fileno())
        if not re.fullmatch(r"drafts/[0-9a-fA-F-]+\.checkpoint\.json", staged):
            raise ContractError("pending checkpoint has no valid staged source") from None
        draft, contents, _ = _read_scan_local_json_with_metadata(
            scan_dir, staged, "Staged scan checkpoint"
        )
        if hashlib.sha256(contents).hexdigest() != name.removesuffix(".json"):
            raise ContractError("staged checkpoint changed after publication failed") from None
        staged_contents = contents
    directory = _checkpoint_head_directory(relative)
    if directory is not None:
        checkpoint = draft.get("checkpoint")
        if not isinstance(checkpoint, str) or not re.fullmatch(r"[0-9a-f]{64}\.json", checkpoint):
            raise ContractError("checkpoint head does not name a saved checkpoint")
        _legacy_read_saved_result(
            scan_dir, (directory / "checkpoints" / checkpoint).as_posix(), scan_id
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
        or not isinstance(draft.get("coverage", {} if kind == "dedup" else None), dict)
    ):
        raise ContractError("checkpoint has no semantic findings or coverage")
    if materialize and staged_contents is not None:
        write_scan_local_bytes(scan_dir, relative, staged_contents)
        os.utime(scan_dir / relative, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    return draft, _digest(draft), metadata.st_mtime_ns


def _frozen_source_times(
    scan_dir: Path,
    scan_id: str,
    sources: dict[str, str],
    terminal_assessments: list[dict[str, str]] | None = None,
) -> dict[str, int]:
    times: dict[str, int] = {}
    snapshots = [path for path in sources if _is_source_order_snapshot(path)]
    for path in snapshots:
        record, digest, _ = _legacy_read_saved_result(scan_dir, path, scan_id)
        if digest != sources[path] or not isinstance(record.get("sources"), dict):
            raise ContractError("saved source ordering changed after the scan stopped")
        if terminal_assessments is not None and "terminalAssessments" in record:
            assessments = record["terminalAssessments"]
            if not isinstance(assessments, dict) or not all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in assessments.items()
            ):
                raise ContractError("saved terminal assessments are malformed")
            terminal_assessments.append(assessments)
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
    scan_dir: Path,
    scan_id: str,
    sources: dict[str, str],
    times: dict[str, int],
    terminal_assessments: dict[str, str] | None = None,
    selected_parent_checkpoint: str | None = None,
    committed_draft_digest: str | None = None,
    selected_parent_observed_at: int | None = None,
) -> None:
    # Identical result rewrites must not change the order of frozen review evidence.
    observations = {
        path: {"digest": digest, "observedAtNs": str(times[path])}
        for path, digest in sources.items()
        if not _is_source_order_snapshot(path)
    }
    if not observations:
        return
    if selected_parent_checkpoint is None or committed_draft_digest is None:
        for relative in sources:
            if _is_source_order_snapshot(relative):
                retained, digest, _ = _legacy_read_saved_result(scan_dir, relative, scan_id)
                if digest != sources[relative]:
                    raise ContractError("saved source ordering changed after the scan stopped")
                selected = retained.get("selectedParentCheckpoint")
                if (
                    selected_parent_checkpoint is None
                    and isinstance(selected, str)
                    and selected in sources
                ):
                    selected_parent_checkpoint = selected
                if selected == selected_parent_checkpoint and selected_parent_observed_at is None:
                    observed = retained.get("selectedParentObservedAtNs")
                    if isinstance(observed, str) and re.fullmatch(r"-?[0-9]+", observed):
                        selected_parent_observed_at = int(observed)
                if committed_draft_digest is None and isinstance(
                    retained.get("committedDraftDigest"), str
                ):
                    committed_draft_digest = retained["committedDraftDigest"]
    if terminal_assessments is None:
        for relative in sources:
            if not _is_source_order_snapshot(relative):
                continue
            retained, digest, _ = _legacy_read_saved_result(scan_dir, relative, scan_id)
            if digest != sources[relative]:
                raise ContractError("saved source ordering changed after the scan stopped")
            if (
                retained.get("sources") == observations
                and retained.get("selectedParentCheckpoint") == selected_parent_checkpoint
                and retained.get("committedDraftDigest") == committed_draft_digest
                and retained.get("selectedParentObservedAtNs")
                == (
                    str(selected_parent_observed_at)
                    if selected_parent_observed_at is not None
                    else None
                )
            ):
                return
    record = {"scanId": scan_id, "sources": observations}
    if terminal_assessments is not None:
        record["terminalAssessments"] = terminal_assessments
    if selected_parent_checkpoint is not None:
        record["selectedParentCheckpoint"] = selected_parent_checkpoint
    if committed_draft_digest is not None:
        record["committedDraftDigest"] = committed_draft_digest
    if selected_parent_observed_at is not None:
        record["selectedParentObservedAtNs"] = str(selected_parent_observed_at)
    digest = _digest(record)
    path = f"source-order/{digest}.json"
    if not (scan_dir / path).exists():
        write_scan_local_bytes(scan_dir, path, _encoded(record))
    if _legacy_read_saved_result(scan_dir, path, scan_id)[1] != digest:
        raise ContractError("saved source ordering does not match its digest")
    for relative in list(sources):
        if _is_source_order_snapshot(relative):
            del sources[relative]
    sources[path] = digest


def _encoded(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_encoded(value)).hexdigest()


def _finding_key(finding: dict[str, Any]) -> str:
    # Wording and evidence may improve between checkpoints; distinct source locations
    # must not collide merely because two workers chose the same semantic identity.
    provenance = finding.get("provenance")
    identity = (
        provenance.get("preservedIdentity", finding.get("identity"))
        if isinstance(provenance, dict)
        else finding.get("identity")
    )
    if not isinstance(identity, dict):
        normalized = dict(finding)
        normalized.pop("identity", None)
        _ensure_finding_identity(normalized)
        identity = normalized["identity"]
    locations = finding.get("locations", [])
    if not isinstance(locations, list):
        locations = []
    return _digest(
        [
            finding.get("ruleId"),
            identity,
            sorted(
                (
                    (
                        location.get("path"),
                        location.get("startLine"),
                        location.get("endLine", location.get("startLine")),
                    )
                    for location in locations
                    if isinstance(location, dict)
                ),
                key=_encoded,
            ),
        ]
    )


def _finding_content(finding: dict[str, Any]) -> dict[str, Any]:
    """Return substantive finding content without generated identity or provenance."""
    return {
        key: value
        for key, value in finding.items()
        if key not in {"findingId", "occurrenceId", "fingerprints", "identity", "provenance"}
    }


def _ensure_finding_identity(finding: Any, *, candidate_only: bool = False) -> None:
    if not isinstance(finding, dict) or "identity" in finding:
        return
    if candidate_only and not finding_candidate_id(finding):
        return
    extensions = finding.get("extensions")
    source = str(
        (extensions.get("candidateId") if isinstance(extensions, dict) else None)
        or finding.get("title")
        or "finding"
    )
    anchor = re.sub(r"[^a-z0-9._/-]+", "-", source.lower()).strip("._/-") or "finding"
    finding["identity"] = {"anchor": anchor}


def _terminal_parent_finding_keys(
    parent: dict[str, Any] | None,
    terminal_drafts: list[dict[str, Any]],
    frozen_assessments: list[dict[str, str]] | None,
) -> set[str]:
    if parent is None:
        return set()
    if frozen_assessments is not None:
        return {
            _finding_key(finding)
            for finding in parent["findings"]
            if isinstance(finding, dict)
            and any(
                assessments.get(_finding_key(finding)) == _digest(_finding_content(finding))
                for assessments in frozen_assessments
            )
        }
    return {
        _finding_key(finding)
        for finding in parent["findings"]
        if isinstance(finding, dict)
        and any(
            _finding_key(previous) == _finding_key(finding)
            and _finding_content(previous) == _finding_content(finding)
            for draft in terminal_drafts
            for previous in draft["findings"]
            if isinstance(previous, dict)
        )
    }


def coverage_for_comparison(db: Any, scan: Any) -> dict[str, Any]:
    if scan["seal_manifest_digest"] is None:
        raise SystemExit("Only sealed scans can be compared.")
    scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
    db.require_recorded_manifest_digest(scan, scan_dir)
    try:
        _, _, manifest, _, coverage, was_sealed, _, _ = _prepare_scan_finalization(scan_dir)
    except ContractError as exc:
        raise SystemExit(str(exc)) from exc
    if not was_sealed or manifest["scan"]["id"] != scan["id"]:
        raise SystemExit("Only sealed scans can be compared.")
    return coverage


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


def _saved_result_paths(scan_dir: Path) -> Iterator[str]:
    directory = (
        "checkpoints/pending" if (scan_dir / "checkpoints/pending").exists() else "checkpoints"
    )
    for name in _children(scan_dir, directory):
        if re.fullmatch(r"[0-9a-f]{64}\.json", name):
            yield f"checkpoints/{name}"


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


def _reconcile_child_coverage(
    coverage: dict[str, Any], child: dict[str, Any], child_id: str
) -> None:
    """Refresh only this unmerged child's namespaced, validated coverage state."""
    receipt_spellings = {
        ref.lower(): ref
        for surface in child.get("surfaces", [])
        for ref in surface.get("receiptRefs", [])
    }
    for field in ("surfaces", "explicitExclusions", "deferred", "openQuestions"):
        current = {row["id"]: row for row in child.get(field, []) if isinstance(row.get("id"), str)}
        retained = []
        for previous in coverage.get(field, []):
            identity = previous.get("id") if isinstance(previous, dict) else None
            if not isinstance(identity, str) or not identity.startswith(f"{child_id}/"):
                retained.append(previous)
                continue
            replacement = current.pop(identity, None)
            if replacement is None:
                continue
            for history_field in ("previousFindings", "receiptRefs"):
                if history_field == "receiptRefs" and field != "surfaces":
                    continue
                history = previous.get(history_field)
                if isinstance(history, list) and history:
                    values = replacement.get(history_field)
                    if values is None:
                        values = replacement[history_field] = []
                    if isinstance(values, list):
                        for value in history:
                            if (
                                history_field == "receiptRefs"
                                and isinstance(value, str)
                                and receipt_spellings.get(value.lower(), value) != value
                            ):
                                # The validated child already chose the current spelling.
                                continue
                            if value not in values:
                                values.append(copy.deepcopy(value))
            retained.append(replacement)
        coverage[field] = retained


def _retire_previous_child_coverage(
    sources: list[tuple[str, dict[str, Any], str | None]],
    source_order: dict[str, tuple[int, int]],
    child_ids: tuple[str, ...],
) -> None:
    """Do not replay older child state over a later full composed observation."""
    for child_id in child_ids:
        observations = [
            source_order[relative]
            for relative, draft, owner in sources
            if owner is None
            and isinstance(draft["coverage"].get("deferred"), list)
            and any(
                isinstance(row, dict)
                and row.get("id") == f"unmerged-{child_id}"
                and row.get("coverageObserved") is True
                for row in draft["coverage"].get("deferred", [])
            )
        ]
        if not observations:
            continue
        latest = max(observations)
        for relative, draft, owner in sources:
            if owner is not None or source_order[relative] >= latest:
                continue
            for field in ("surfaces", "explicitExclusions", "deferred", "openQuestions"):
                rows = draft["coverage"].get(field)
                if isinstance(rows, list):
                    draft["coverage"][field] = [
                        row
                        for row in rows
                        if not (
                            isinstance(row, dict)
                            and isinstance(row.get("id"), str)
                            and row["id"].startswith(f"{child_id}/")
                        )
                    ]


def _reconcile_child_withdrawals(aggregate: dict[str, Any], child: dict[str, Any]) -> None:
    """Move recovered child findings into their later terminal decision's history."""
    reported = {finding_candidate_id(finding) for finding in child["findings"]}
    for field in ("surfaces", "explicitExclusions"):
        for row in child["coverage"].get(field, []):
            candidate = row.get("candidateId")
            if not isinstance(candidate, str) or row.get("disposition") not in {
                "rejected",
                "not_applicable",
            }:
                continue
            history = row.get("previousFindings")
            history = list(history) if isinstance(history, list) else []
            observation = {key: value for key, value in row.items() if key != "previousFindings"}
            for previous in aggregate["coverage"].get(field, []):
                if {
                    key: value for key, value in previous.items() if key != "previousFindings"
                } == observation and isinstance(previous.get("previousFindings"), list):
                    for finding in previous["previousFindings"]:
                        if finding not in history:
                            history.append(finding)
            retained = []
            for finding in aggregate["findings"]:
                if candidate not in reported and finding_candidate_id(finding) == candidate:
                    if finding not in history:
                        history.append(finding)
                else:
                    retained.append(finding)
            aggregate["findings"] = retained
            if history:
                row["previousFindings"] = history


def _deferred_candidate_id(
    row: dict[str, Any],
    owner: str | None,
    ambiguous_deferred: set[tuple[str | None, str]],
) -> str | None:
    identity = row.get("candidateId") or row.get("id")
    if not isinstance(identity, str):
        return None
    if (owner, identity) in ambiguous_deferred and not any(
        key in row for key in ("candidateId", "candidate", "finding")
    ):
        return None
    return identity


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


def _legacy_source_digests(value: Any, error: str) -> dict[str, str]:
    if not isinstance(value, dict) or not all(
        isinstance(relative, str) and isinstance(digest, str) for relative, digest in value.items()
    ):
        raise ContractError(error)
    return value


def _deferred_rows(coverage: dict[str, Any]) -> list[Any]:
    rows = coverage.get("deferred", [])
    return rows if isinstance(rows, list) else []


def _resolved_deferred_rows(
    draft: dict[str, Any], schema: dict[str, Any], *, accepted: bool = False
) -> list[dict[str, Any]]:
    # Accepted progress can retain closures inherited from a terminal draft.
    if draft.get("complete") is False and not accepted:
        return []
    coverage = draft["coverage"]
    rows = coverage.get("resolvedDeferred", [])
    try:
        # Invalid closure metadata cannot discard the evidence it names.
        _validate_schema_node(rows, schema, "coverage.resolvedDeferred")
        _validate_resolved_deferred({**coverage, "deferred": _deferred_rows(coverage)})
    except ContractError:
        return []
    return rows


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
