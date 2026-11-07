"""Exercise numeric types and constraints on referenced nodes in the finalizer's schema checker."""

from __future__ import annotations

from pathlib import Path

import pytest
from workbench_test_support import load_script

FINALIZER = load_script("finalize_scan_contract")


@pytest.mark.parametrize(("expected", "value"), [("integer", 1), ("number", 1.5)])
def test_schema_numeric_types_do_not_accept_booleans(expected, value) -> None:
    schema = {"type": expected}
    FINALIZER._validate_schema_node(value, schema, "value")
    with pytest.raises(FINALIZER.ContractError, match="expected schema type"):
        FINALIZER._validate_schema_node(True, schema, "value")


def test_schema_references_preserve_constraints_siblings_and_cycle_errors() -> None:
    root = {"$defs": {"text": {"type": "string", "minLength": 1}}}
    reference = {"$ref": "#/$defs/text"}
    FINALIZER._validate_schema_node("yes", reference, "value", root)
    with pytest.raises(FINALIZER.ContractError, match="string is too short"):
        FINALIZER._validate_schema_node("", reference, "value", root)
    with pytest.raises(FINALIZER.ContractError, match="string does not match schema pattern"):
        FINALIZER._validate_schema_node("no", {**reference, "pattern": "^yes$"}, "value", root)
    with pytest.raises(RecursionError):
        FINALIZER._validate_schema_node("yes", {"$ref": "#"}, "value")


@pytest.mark.parametrize(
    "digests",
    [
        [],
        ["sha256:" + "0" * 64] * 2,
        [{}],
        ["sha256:" + "A" * 64],
        ["sha256:" + "0" * 64 + "\n"],
    ],
)
def test_invalid_manifest_instruction_digests(digests) -> None:
    root = Path(__file__).resolve().parents[1]
    manifest = FINALIZER._read_json(root / "examples" / "completed-scan" / "scan-manifest.json")
    manifest["scan"]["producer"]["instructionDigests"] = digests
    with pytest.raises(FINALIZER.ContractError, match="producer.instructionDigests"):
        FINALIZER.validate_against_schema(manifest, root / "schemas" / "scan-manifest.schema.json")
