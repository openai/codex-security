"""Validate required fields in Codex Security scan artifacts."""

from __future__ import annotations

from typing import Any


class ContractError(ValueError):
    """Raised when a completed scan does not satisfy the additive contract."""


def _require_dict(payload: dict[str, Any], key: str, context: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise ContractError(f"{context}.{key}: expected an object")
    return value


def _require_list(payload: dict[str, Any], key: str, context: str) -> list[Any]:
    value = payload.get(key)
    if not isinstance(value, list):
        raise ContractError(f"{context}.{key}: expected an array")
    return value


def _require_str(payload: dict[str, Any], key: str, context: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{context}.{key}: expected a non-empty string")
    return value


def _validate_finding_evidence(
    finding: dict[str, Any], index: int = 0, *, source_only: bool = False
) -> None:
    context = f"findings.findings[{index}]"
    if not _require_list(finding, "codeEvidence", context):
        raise ContractError(f"{context}.codeEvidence: include the source snippets used as proof")
    root_cause = finding.get("rootCause")
    if isinstance(root_cause, dict):
        _require_str(root_cause, "summary", f"{context}.rootCause")
    else:
        _require_str(finding, "rootCause", context)
    attack_path = _require_dict(finding, "attackPath", context)
    dataflow = attack_path.get("dataflow")
    if isinstance(dataflow, dict):
        if not dataflow.get("summary"):
            _require_str(dataflow, "source", f"{context}.attackPath.dataflow")
            _require_str(dataflow, "sink", f"{context}.attackPath.dataflow")
    else:
        _require_str(attack_path, "dataflow", f"{context}.attackPath")
    if source_only:
        return
    validation = _require_dict(finding, "validation", context)
    _require_str(validation, "method", f"{context}.validation")
    if not validation.get("result"):
        _require_str(validation, "summary", f"{context}.validation")
    if not any(validation.get(key) for key in ("evidence", "evidenceRefs")):
        raise ContractError(
            f"{context}.validation: include observed evidence or evidenceRefs to the source proof"
        )
