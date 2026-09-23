"""Derive canonical scan artifacts from authenticated, persisted scan phases."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from finalize_scan_contract import (
    CONFIDENCES,
    ContractError,
    ScanDraftDocuments,
    _require_safe_json_value,
    _require_safe_relative_path,
    open_scan_local_file_descriptor,
)

_INVENTORY_PATH = "artifacts/02_discovery/in_scope_files.txt"
_LEDGER_PATH = "artifacts/02_discovery/candidate_ledger.jsonl"
_THREAT_MODEL_PATH = "artifacts/01_context/threat_model.md"
_HARDENING_PATH = "hardening/hardening.md"
_LEDGER_MAX_BYTES = 128 * 1024 * 1024
_INVENTORY_MAX_BYTES = 32 * 1024 * 1024
_THREAT_MODEL_MAX_BYTES = 8 * 1024 * 1024
_CWE_PATTERN = re.compile(r"^CWE-[1-9][0-9]*$")
_SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._/-]*$")
_WRITEUP_PATTERN = re.compile(r"^findings/([a-z0-9][a-z0-9._-]*)/\1\.md$")
_LOCATION_ROLES = {
    "entrypoint",
    "entrypoint/wrapper",
    "source",
    "root_control",
    "sink",
    "concrete_implementation",
    "evidence",
}
_VALIDATION_DISPOSITIONS = {"reportable", "suppressed", "not_applicable", "deferred"}
_ATTACK_DECISIONS = {"reportable", "ignore", "deferred"}
_IMPACT_LEVELS = {"high", "medium", "low", "ignore", "unknown"}
_REPORTABLE_SEVERITIES = {"critical", "high", "medium", "low"}
_DEPENDENCY_ARTIFACT_ENVIRONMENT = "CODEX_SECURITY_DEPENDENCY_ARTIFACT_SCAN"


class CompactCompletionNotReady(ValueError):
    """A native scan can resume after its incomplete persisted phase is repaired."""


def _required_text(payload: dict[str, Any], field: str, context: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise CompactCompletionNotReady(f"{context}.{field}: expected nonempty text")
    return value


def _optional_text(payload: dict[str, Any], field: str, context: str) -> str | None:
    if field not in payload:
        return None
    return _required_text(payload, field, context)


def _slug(value: str) -> str:
    result = re.sub(r"[^a-z0-9._/-]+", "-", value.lower()).strip("-._/")
    if not result or not _SLUG_PATTERN.fullmatch(result):
        return "item-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return result


def _read_scan_text(scan_dir: Path, relative_path: str, *, maximum: int) -> str:
    try:
        descriptor = open_scan_local_file_descriptor(scan_dir, relative_path, relative_path)
        with os.fdopen(descriptor, "rb") as handle:
            if os.fstat(handle.fileno()).st_size > maximum:
                raise CompactCompletionNotReady(
                    f"{relative_path}: artifact exceeds the {maximum}-byte limit"
                )
            contents = handle.read(maximum + 1)
            if len(contents) > maximum:
                raise CompactCompletionNotReady(
                    f"{relative_path}: artifact exceeds the {maximum}-byte limit"
                )
        return contents.decode("utf-8")
    except CompactCompletionNotReady:
        raise
    except (ContractError, OSError, UnicodeError) as error:
        raise CompactCompletionNotReady(f"{relative_path}: {error}") from error


def _optional_scan_text(scan_dir: Path, relative_path: str, *, maximum: int) -> str | None:
    try:
        (scan_dir / relative_path).lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise CompactCompletionNotReady(f"{relative_path}: {error}") from error
    return _read_scan_text(scan_dir, relative_path, maximum=maximum)


def _safe_relative_path(value: str, context: str) -> str:
    try:
        result = _require_safe_relative_path(value, context)
    except (ContractError, TypeError, ValueError) as error:
        raise CompactCompletionNotReady(str(error)) from error
    if (
        result != value
        or re.match(r"^[A-Za-z]:", value)
        or any(part in {"", "."} for part in value.split("/"))
    ):
        raise CompactCompletionNotReady(f"{context}: expected a normalized repository path")
    return result


def _inventory(scan_dir: Path) -> set[str]:
    result: set[str] = set()
    for line_number, line in enumerate(
        _read_scan_text(scan_dir, _INVENTORY_PATH, maximum=_INVENTORY_MAX_BYTES).splitlines(),
        start=1,
    ):
        if not line:
            continue
        # The shared inventory generator intentionally emits `./path` entries.
        # Remove only its documented prefix; traversal and repeated prefixes
        # still pass through the strict repository-path validation below.
        inventory_path = line[2:] if line.startswith("./") else line
        path = _safe_relative_path(inventory_path, f"{_INVENTORY_PATH}:{line_number}")
        if path in result:
            raise CompactCompletionNotReady(f"{_INVENTORY_PATH}: duplicate path {path}")
        result.add(path)
    return result


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r} is not supported")


def _candidate_rows(scan_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        _read_scan_text(scan_dir, _LEDGER_PATH, maximum=_LEDGER_MAX_BYTES).splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        context = f"{_LEDGER_PATH}:{line_number}"
        try:
            row = json.loads(line, parse_constant=_reject_nonfinite)
            _require_safe_json_value(row, context)
        except (ContractError, UnicodeError, ValueError) as error:
            raise CompactCompletionNotReady(f"{context}: invalid JSON: {error}") from error
        if not isinstance(row, dict):
            raise CompactCompletionNotReady(f"{context}: expected a candidate object")
        rows.append(row)
    return rows


def _candidate_locations(
    candidate: dict[str, Any], candidate_id: str, inventory: set[str]
) -> list[dict[str, Any]]:
    locations = candidate.get("locations")
    if not isinstance(locations, list) or not locations:
        raise CompactCompletionNotReady(f"candidate {candidate_id}.locations: expected locations")
    result: list[dict[str, Any]] = []
    for index, location in enumerate(locations):
        context = f"candidate {candidate_id}.locations[{index}]"
        if not isinstance(location, dict):
            raise CompactCompletionNotReady(f"{context}: expected a location object")
        path = _safe_relative_path(_required_text(location, "path", context), f"{context}.path")
        start_line = location.get("start_line")
        end_line = location.get("end_line")
        if (
            isinstance(start_line, bool)
            or not isinstance(start_line, int)
            or start_line < 1
            or isinstance(end_line, bool)
            or not isinstance(end_line, int)
            or end_line < start_line
        ):
            raise CompactCompletionNotReady(f"{context}: expected a valid source-line range")
        role = _required_text(location, "role", context)
        if role not in _LOCATION_ROLES:
            raise CompactCompletionNotReady(f"{context}.role: unsupported discovery role")
        result.append({"path": path, "startLine": start_line, "endLine": end_line, "role": role})
    if not any(location["path"] in inventory for location in result):
        raise CompactCompletionNotReady(
            f"candidate {candidate_id}.locations: no location is in the review inventory"
        )
    return result


def _text_list(value: Any, context: str) -> list[str]:
    if isinstance(value, str) and value.strip():
        return [value]
    if not isinstance(value, list) or not value:
        raise CompactCompletionNotReady(f"{context}: expected nonempty text or a text array")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise CompactCompletionNotReady(f"{context}: expected nonempty text entries")
    return value.copy()


def _validate_candidate(
    candidate: dict[str, Any], inventory: set[str], seen: set[str]
) -> tuple[str, list[dict[str, Any]], dict[str, Any], dict[str, Any] | None]:
    candidate_id = _required_text(candidate, "candidate_id", "candidate")
    if candidate_id in {".", ".."} or any(value in candidate_id for value in ("/", "\\", "\0")):
        raise CompactCompletionNotReady(f"candidate {candidate_id!r}: unsafe candidate identity")
    if candidate_id in seen:
        raise CompactCompletionNotReady(f"candidate ledger repeats candidate {candidate_id}")
    seen.add(candidate_id)
    _required_text(candidate, "summary", f"candidate {candidate_id}")
    _required_text(candidate, "evidence", f"candidate {candidate_id}")
    for field in ("context", "instance"):
        _optional_text(candidate, field, f"candidate {candidate_id}")
    cwes = candidate.get("cwe_ids")
    if not isinstance(cwes, list) or any(
        not isinstance(cwe, str) or not _CWE_PATTERN.fullmatch(cwe) for cwe in cwes
    ):
        raise CompactCompletionNotReady(f"candidate {candidate_id}.cwe_ids: expected CWE IDs")
    locations = _candidate_locations(candidate, candidate_id, inventory)
    validation = candidate.get("validation")
    if not isinstance(validation, dict):
        raise CompactCompletionNotReady(f"candidate {candidate_id}: missing validation")
    disposition = validation.get("disposition")
    if disposition not in _VALIDATION_DISPOSITIONS:
        raise CompactCompletionNotReady(f"candidate {candidate_id}: invalid validation disposition")
    for field in ("method", "confidence_rationale"):
        _required_text(validation, field, f"candidate {candidate_id}.validation")
    if validation.get("confidence") not in CONFIDENCES:
        raise CompactCompletionNotReady(f"candidate {candidate_id}.validation.confidence: invalid")
    _text_list(validation.get("evidence"), f"candidate {candidate_id}.validation.evidence")
    if "rubric" not in validation or not isinstance(validation["rubric"], (str, dict, list)):
        raise CompactCompletionNotReady(f"candidate {candidate_id}.validation.rubric: invalid")
    for field in ("counterevidence_or_proof_gap", "remaining_uncertainty"):
        if not isinstance(validation.get(field), str):
            raise CompactCompletionNotReady(f"candidate {candidate_id}.validation.{field}: invalid")
    attack = candidate.get("attack_path")
    if disposition in {"reportable", "deferred"}:
        if not isinstance(attack, dict):
            raise CompactCompletionNotReady(
                f"candidate {candidate_id}: missing attack-path analysis"
            )
        _validate_attack_path(candidate_id, attack)
    elif attack is not None:
        raise CompactCompletionNotReady(
            f"candidate {candidate_id}: attack-path analysis is not eligible for {disposition}"
        )
    return candidate_id, locations, validation, attack if isinstance(attack, dict) else None


def _validate_attack_path(candidate_id: str, attack: dict[str, Any]) -> None:
    context = f"candidate {candidate_id}.attack_path"
    decision = attack.get("decision")
    if decision not in _ATTACK_DECISIONS:
        raise CompactCompletionNotReady(f"{context}.decision: unsupported attack-path decision")
    for field in (
        "dataflow",
        "reachability",
        "counterevidence",
        "severity_rationale",
        "change_conditions",
    ):
        _required_text(attack, field, context)
    for field in ("impact", "likelihood"):
        if attack.get(field) not in _IMPACT_LEVELS:
            raise CompactCompletionNotReady(f"{context}.{field}: unsupported level")
    severity = attack.get("severity")
    if decision == "reportable" and severity not in _REPORTABLE_SEVERITIES:
        raise CompactCompletionNotReady(f"{context}.severity: expected a reportable severity")
    if decision == "ignore" and severity != "ignore":
        raise CompactCompletionNotReady(
            f"{context}.severity: ignored paths require ignore severity"
        )
    if decision == "deferred":
        if severity not in (_REPORTABLE_SEVERITIES | {"unknown"}):
            raise CompactCompletionNotReady(f"{context}.severity: invalid deferred severity")
        _required_text(attack, "proof_gap", context)
    if decision == "reportable":
        reports = attack.get("reports")
        if not isinstance(reports, list) or not reports:
            raise CompactCompletionNotReady(
                f"candidate {candidate_id} requires at least one finding report"
            )


def _selected_locations(
    candidate_id: str, report: dict[str, Any], locations: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[int] | None]:
    indexes = report.get("locationIndexes")
    if indexes is None:
        return copy.deepcopy(locations), None
    if (
        not isinstance(indexes, list)
        or not indexes
        or any(isinstance(index, bool) or not isinstance(index, int) for index in indexes)
        or any(index < 0 or index >= len(locations) for index in indexes)
        or len(set(indexes)) != len(indexes)
    ):
        raise CompactCompletionNotReady(
            f"candidate {candidate_id}.reports.locationIndexes: invalid discovery locations"
        )
    return [copy.deepcopy(locations[index]) for index in indexes], indexes.copy()


def _finding_instance(
    candidate: dict[str, Any], report: dict[str, Any], indexes: list[int] | None, count: int
) -> str | None:
    instance = _optional_text(report, "instance", "finding report")
    if instance is None and count > 1:
        if indexes is None:
            raise CompactCompletionNotReady(
                "Multiple finding reports require an instance or distinct locationIndexes"
            )
        instance = "locations-" + "-".join(str(index) for index in sorted(indexes))
    if instance is None:
        instance = _optional_text(candidate, "instance", "candidate")
    elif candidate.get("instance"):
        instance = f"{candidate['instance']}-{instance}"
    return _slug(instance) if instance else None


def _dependency_finding_identity(
    metadata: dict[str, Any],
    *,
    rule_id: str,
    anchor: str,
    instance: str | None,
    context: str,
) -> tuple[str, str, str | None]:
    if "ruleId" in metadata:
        rule_id = _required_text(metadata, "ruleId", context)
    if not _SLUG_PATTERN.fullmatch(rule_id):
        raise CompactCompletionNotReady(f"{context}.ruleId: expected a safe rule slug")
    if "identity" not in metadata:
        return rule_id, anchor, instance
    identity = metadata["identity"]
    if not isinstance(identity, dict):
        raise CompactCompletionNotReady(f"{context}.identity: expected an object")
    anchor = _required_text(identity, "anchor", f"{context}.identity")
    if not _SLUG_PATTERN.fullmatch(anchor):
        raise CompactCompletionNotReady(f"{context}.identity.anchor: expected a safe slug")
    instance = _optional_text(identity, "instance", f"{context}.identity")
    if instance is not None and not _SLUG_PATTERN.fullmatch(instance):
        raise CompactCompletionNotReady(f"{context}.identity.instance: expected a safe slug")
    return rule_id, anchor, instance


def _dependency_finding_metadata(
    finding: dict[str, Any],
    metadata: dict[str, Any],
    *,
    candidate_id: str,
    inventory: set[str],
) -> None:
    context = f"candidate {candidate_id}.validation.dependencyFinding"
    for field in ("title", "summary", "remediation"):
        if field in metadata:
            finding[field] = _required_text(metadata, field, context)

    for field in ("severity", "confidence", "taxonomy"):
        if field not in metadata:
            continue
        value = metadata[field]
        if not isinstance(value, dict):
            raise CompactCompletionNotReady(f"{context}.{field}: expected an object")
        finding[field].update(copy.deepcopy(value))

    if "locations" in metadata:
        locations = metadata["locations"]
        if not isinstance(locations, list) or not locations:
            raise CompactCompletionNotReady(f"{context}.locations: expected locations")
        normalized_locations: list[dict[str, Any]] = []
        for index, location in enumerate(locations):
            location_context = f"{context}.locations[{index}]"
            if not isinstance(location, dict):
                raise CompactCompletionNotReady(f"{location_context}: expected an object")
            normalized_location = copy.deepcopy(location)
            normalized_location["path"] = _safe_relative_path(
                _required_text(location, "path", location_context), f"{location_context}.path"
            )
            if normalized_location["path"] not in inventory:
                raise CompactCompletionNotReady(f"{location_context}.path: not in review inventory")
            normalized_locations.append(normalized_location)
        finding["locations"] = normalized_locations

    if "codeEvidence" in metadata:
        code_evidence = metadata["codeEvidence"]
        if not isinstance(code_evidence, list):
            raise CompactCompletionNotReady(f"{context}.codeEvidence: expected an array")
        normalized_evidence: list[dict[str, Any]] = []
        for index, evidence in enumerate(code_evidence):
            evidence_context = f"{context}.codeEvidence[{index}]"
            if not isinstance(evidence, dict):
                raise CompactCompletionNotReady(f"{evidence_context}: expected an object")
            normalized_entry = copy.deepcopy(evidence)
            normalized_entry["path"] = _safe_relative_path(
                _required_text(evidence, "path", evidence_context), f"{evidence_context}.path"
            )
            if normalized_entry["path"] not in inventory:
                raise CompactCompletionNotReady(f"{evidence_context}.path: not in review inventory")
            normalized_evidence.append(normalized_entry)
        finding["codeEvidence"] = normalized_evidence

    if "rootCause" in metadata:
        root_cause = metadata["rootCause"]
        if isinstance(root_cause, str):
            if not root_cause.strip():
                raise CompactCompletionNotReady(f"{context}.rootCause: expected nonempty text")
        elif isinstance(root_cause, dict):
            _required_text(root_cause, "summary", f"{context}.rootCause")
        else:
            raise CompactCompletionNotReady(f"{context}.rootCause: expected text or an object")
        finding["rootCause"] = copy.deepcopy(root_cause)

    for field in ("remediationTests", "preventiveControls"):
        if field not in metadata:
            continue
        values = metadata[field]
        if not isinstance(values, list) or any(
            not isinstance(value, str) or not value.strip() for value in values
        ):
            raise CompactCompletionNotReady(f"{context}.{field}: expected text entries")
        finding[field] = values.copy()


def _finding(
    *,
    candidate: dict[str, Any],
    candidate_id: str,
    validation: dict[str, Any],
    attack: dict[str, Any],
    locations: list[dict[str, Any]],
    report: dict[str, Any],
    report_count: int,
    scan_mode: str,
    scan_dir: Path,
    inventory: set[str],
    dependency_artifact: bool,
    identities: set[tuple[str, str, str | None]],
) -> dict[str, Any]:
    context = f"candidate {candidate_id}.report"
    category = _required_text(report, "category", context)
    remediation = _required_text(report, "remediation", context)
    selected_locations, indexes = _selected_locations(candidate_id, report, locations)
    instance = _finding_instance(candidate, report, indexes, report_count)
    rule_id = _optional_text(report, "ruleId", context) or _slug(category)
    if not _SLUG_PATTERN.fullmatch(rule_id):
        raise CompactCompletionNotReady(f"{context}.ruleId: expected a safe rule slug")
    anchor = _slug(candidate_id)
    metadata = validation.get("dependencyFinding") if dependency_artifact else None
    if metadata is not None:
        if not isinstance(metadata, dict):
            raise CompactCompletionNotReady(f"{context}.dependencyFinding: expected an object")
        rule_id, anchor, instance = _dependency_finding_identity(
            metadata,
            rule_id=rule_id,
            anchor=anchor,
            instance=instance,
            context=f"candidate {candidate_id}.validation.dependencyFinding",
        )
    identity = (rule_id, anchor, instance)
    if identity in identities and indexes is not None:
        location_instance = "locations-" + "-".join(str(index) for index in sorted(indexes))
        instance = _slug(f"{instance}-{location_instance}" if instance else location_instance)
        identity = (rule_id, anchor, instance)
    if identity in identities:
        raise CompactCompletionNotReady(f"{context}: duplicate finding identity")
    identities.add(identity)
    evidence = _text_list(validation["evidence"], f"{context}.validation.evidence")
    if candidate["evidence"] not in evidence:
        evidence.append(candidate["evidence"])
    counterevidence = list(
        dict.fromkeys(
            value
            for value in (
                validation["counterevidence_or_proof_gap"],
                validation["remaining_uncertainty"],
                attack["counterevidence"],
            )
            if value.strip()
        )
    )
    dataflow: dict[str, Any] = {"summary": attack["dataflow"]}
    for source, destination in (("source", "source"), ("sink", "sink"), ("control", "control")):
        value = _optional_text(validation, source, f"{context}.validation")
        if value is not None:
            dataflow[destination] = value
    reachability: dict[str, Any] = {"summary": attack["reachability"]}
    if "preconditions" in validation:
        reachability["preconditions"] = _text_list(
            validation["preconditions"], f"{context}.validation.preconditions"
        )
    extensions = (
        {
            "candidateId": candidate_id,
            "reportId": f"{candidate_id}-{instance}" if instance else candidate_id,
        }
        if scan_mode == "deep"
        else {"ledgerRowId": candidate_id}
    )
    finding: dict[str, Any] = {
        "ruleId": rule_id,
        "identity": {"anchor": anchor, **({"instance": instance} if instance else {})},
        "title": _optional_text(report, "title", context) or candidate["summary"],
        "summary": _optional_text(report, "summary", context) or candidate["summary"],
        "severity": {
            "level": attack["severity"],
            "rationale": attack["severity_rationale"],
            "changeConditions": attack["change_conditions"],
        },
        "confidence": {
            "level": validation["confidence"],
            "rationale": validation["confidence_rationale"],
        },
        "taxonomy": {"category": category, "cwe": copy.deepcopy(candidate["cwe_ids"])},
        "locations": selected_locations,
        "validation": {
            "method": validation["method"],
            "summary": validation["confidence_rationale"],
            "evidence": evidence,
            "counterEvidence": counterevidence,
            "rubric": copy.deepcopy(validation["rubric"]),
        },
        "attackPath": {
            "dataflow": dataflow,
            "reachability": reachability,
            "impact": {"level": attack["impact"], "why": attack["severity_rationale"]},
            "likelihood": {"level": attack["likelihood"], "why": attack["reachability"]},
        },
        "remediation": remediation,
        "provenance": {"source": "local_plugin"},
        "extensions": extensions,
    }
    root_cause = _optional_text(report, "rootCause", context)
    if root_cause:
        finding["rootCause"] = {"summary": root_cause}
    for field in ("remediationTests", "preventiveControls"):
        if field in report:
            values = report[field]
            if not isinstance(values, list) or any(
                not isinstance(value, str) or not value.strip() for value in values
            ):
                raise CompactCompletionNotReady(f"{context}.{field}: expected text entries")
            finding[field] = values.copy()
    if "writeup" in report:
        writeup = report["writeup"]
        if not isinstance(writeup, dict):
            raise CompactCompletionNotReady(f"{context}.writeup: expected an object")
        report_path = _required_text(writeup, "reportPath", f"{context}.writeup")
        if not _WRITEUP_PATTERN.fullmatch(report_path):
            raise CompactCompletionNotReady(f"{context}.writeup.reportPath: unsafe finding path")
        _read_scan_text(scan_dir, report_path, maximum=_LEDGER_MAX_BYTES)
        finding["writeup"] = {"reportPath": report_path}
    if metadata is not None:
        _dependency_finding_metadata(
            finding, metadata, candidate_id=candidate_id, inventory=inventory
        )
    return finding


def _surface(
    candidate: dict[str, Any],
    candidate_id: str,
    validation: dict[str, Any],
    attack: dict[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    validation_disposition = validation["disposition"]
    decision = attack["decision"] if attack else None
    if validation_disposition == "reportable" and decision == "reportable":
        disposition = "reported"
    elif validation_disposition == "deferred" or decision == "deferred":
        disposition = "needs_follow_up"
    elif validation_disposition == "not_applicable":
        disposition = "not_applicable"
    elif validation_disposition == "suppressed" or decision == "ignore":
        disposition = "rejected"
    else:
        raise CompactCompletionNotReady(f"candidate {candidate_id}: inconsistent phase decisions")
    surface_id = "surface_" + _slug(candidate_id)
    surface: dict[str, Any] = {
        "id": surface_id,
        "label": candidate["summary"],
        "disposition": disposition,
        "receiptRefs": [],
    }
    if candidate.get("context"):
        surface["notes"] = candidate["context"]
    if disposition != "needs_follow_up":
        return surface, None
    reason = next(
        (
            value
            for value in (
                attack.get("proof_gap") if attack else None,
                validation.get("counterevidence_or_proof_gap"),
                validation.get("remaining_uncertainty"),
            )
            if isinstance(value, str) and value.strip()
        ),
        None,
    )
    if reason is None:
        raise CompactCompletionNotReady(f"candidate {candidate_id}: deferred proof gap is missing")
    paths = list(dict.fromkeys(location["path"] for location in candidate["locations"]))
    return surface, {
        "id": candidate_id,
        "reason": reason,
        "paths": paths,
        "surfaceIds": [surface_id],
    }


def _inventory_strategy(scan: sqlite3.Row, completion_binding: dict[str, Any]) -> str:
    if scan["mode"] in {"diff", "dependency_update"}:
        return "diff"
    if completion_binding["coverageMode"] == "scoped_path":
        return "scoped_path"
    if scan["mode"] == "deep":
        return "repository"
    if scan["target_revision"] == "unversioned":
        return "directory"
    return "repository"


def _target_kind(completion_binding: dict[str, Any]) -> str:
    allowed = completion_binding["allowedTargetKinds"]
    target = completion_binding["target"]
    if "snapshotDigest" not in target and "git_revision" in allowed:
        return "git_revision"
    return allowed[0]


def prepare_compact_completion_draft(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    scan_dir: Path,
    completion_binding: dict[str, Any],
) -> ScanDraftDocuments | None:
    """Select host-derived completion without changing historical authored scans."""

    if (
        os.environ.get(_DEPENDENCY_ARTIFACT_ENVIRONMENT) != "1"
        or scan["recipe_json"] is None
        or scan["mode"] not in {"standard", "diff"}
    ):
        return None

    try:
        (scan_dir / "scan-manifest.json").lstat()
    except FileNotFoundError:
        progress = connection.execute(
            "SELECT * FROM scan_progress WHERE scan_id = ?", (scan["id"],)
        ).fetchone()
        try:
            return build_compact_completion_draft(
                scan=scan,
                scan_dir=scan_dir,
                completion_binding=completion_binding,
                progress=progress,
            )
        except CompactCompletionNotReady as error:
            raise SystemExit(str(error)) from error
    except OSError as error:
        raise SystemExit(f"scan-manifest.json: {error}") from error

    if scan["recipe_json"] is not None and scan["phase"] != "reporting":
        for compact_artifact in (_INVENTORY_PATH, _LEDGER_PATH):
            try:
                (scan_dir / compact_artifact).lstat()
            except FileNotFoundError:
                continue
            except OSError as error:
                raise SystemExit(f"{compact_artifact}: {error}") from error
            raise SystemExit("Scan completion requires the reporting phase.")
    return None


def build_compact_completion_draft(
    *,
    scan: sqlite3.Row,
    scan_dir: Path,
    completion_binding: dict[str, Any],
    progress: sqlite3.Row | None,
) -> ScanDraftDocuments:
    """Build unsealed documents only from host-owned scan state and recorded decisions."""

    if scan["phase"] != "reporting":
        raise CompactCompletionNotReady("Scan completion requires the reporting phase.")
    if progress is None:
        raise CompactCompletionNotReady("Scan completion is missing its recorded progress.")
    if (
        scan["mode"] == "standard"
        and progress["review_items_total"] > 0
        and progress["review_items_completed"] != progress["review_items_total"]
    ):
        raise CompactCompletionNotReady("The Standard review inventory is incomplete.")

    inventory = _inventory(scan_dir)
    rows = _candidate_rows(scan_dir)
    candidate_ids: set[str] = set()
    finding_identities: set[tuple[str, str, str | None]] = set()
    findings: list[dict[str, Any]] = []
    surfaces: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    for candidate in rows:
        candidate_id, locations, validation, attack = _validate_candidate(
            candidate, inventory, candidate_ids
        )
        surface, follow_up = _surface(candidate, candidate_id, validation, attack)
        surfaces.append(surface)
        if follow_up is not None:
            deferred.append(follow_up)
        if validation["disposition"] != "reportable" or attack is None:
            continue
        if attack["decision"] != "reportable":
            continue
        reports = attack["reports"]
        for report in reports:
            if not isinstance(report, dict):
                raise CompactCompletionNotReady(
                    f"candidate {candidate_id}.reports: expected objects"
                )
            findings.append(
                _finding(
                    candidate=candidate,
                    candidate_id=candidate_id,
                    validation=validation,
                    attack=attack,
                    locations=locations,
                    report=report,
                    report_count=len(reports),
                    scan_mode=scan["mode"],
                    scan_dir=scan_dir,
                    inventory=inventory,
                    dependency_artifact=scan["recipe_json"] is not None,
                    identities=finding_identities,
                )
            )

    if not surfaces:
        surfaces.append(
            {
                "id": "surface_reviewed_repository",
                "label": "Reviewed repository",
                "disposition": "no_issue_found",
                "receiptRefs": [],
            }
        )
    scope = copy.deepcopy(completion_binding["scope"])
    if "target_summary" in scan.keys() and scan["target_summary"]:
        scope["summary"] = scan["target_summary"]
    if scan["user_context"]:
        scope["context"] = scan["user_context"]

    scan_document: dict[str, Any] = {
        "id": completion_binding["scanId"],
        "producer": copy.deepcopy(completion_binding["producer"]),
        "status": "completed",
        "startedAt": completion_binding["startedAt"],
        "completedAt": completion_binding["completedAt"],
        "target": {
            "kind": _target_kind(completion_binding),
            **copy.deepcopy(completion_binding["target"]),
        },
        "scope": scope,
        "coverageRef": "coverage.json",
        "findingsRef": "findings.json",
    }
    threat_model = _optional_scan_text(
        scan_dir, _THREAT_MODEL_PATH, maximum=_THREAT_MODEL_MAX_BYTES
    )
    if threat_model is not None and threat_model.strip():
        scan_document["threatModel"] = {"summary": threat_model.strip()}
    if _optional_scan_text(scan_dir, _HARDENING_PATH, maximum=_LEDGER_MAX_BYTES) is not None:
        scan_document["hardening"] = {"portfolioPath": _HARDENING_PATH}

    manifest = {
        "documentType": "codex-security.scan-manifest",
        "schemaVersion": "1.0",
        "scan": scan_document,
    }
    findings_document = {
        "documentType": "codex-security.findings",
        "schemaVersion": "1.0",
        "scanId": completion_binding["scanId"],
        "findings": findings,
    }
    coverage_document = {
        "documentType": "codex-security.coverage",
        "schemaVersion": "1.0",
        "scanId": completion_binding["scanId"],
        "mode": completion_binding["coverageMode"],
        "completeness": "partial" if deferred else "complete",
        "inventoryStrategy": _inventory_strategy(scan, completion_binding),
        "includePaths": copy.deepcopy(completion_binding["scope"]["includePaths"]),
        "excludePaths": copy.deepcopy(completion_binding["scope"]["excludePaths"]),
        "surfaces": surfaces,
        "explicitExclusions": [
            {"pattern": pattern, "reason": "Excluded by the selected scan scope."}
            for pattern in completion_binding["scope"]["excludePaths"]
        ],
        "deferred": deferred,
    }
    return manifest, findings_document, coverage_document


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
