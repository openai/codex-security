from __future__ import annotations

import json
from pathlib import Path

import pytest
from workbench_test_support import load_script

FINALIZER = load_script("finalize_scan_contract")


def test_accepts_custom_schema_beyond_previous_complexity_limits(tmp_path: Path) -> None:
    schema = {
        "type": "object",
        "allOf": [{"type": "object"}] * 129,
        "properties": {
            **{f"property_{index}": {} for index in range(4097)},
            "name": {"type": "string", "pattern": "^a+$"},
        },
    }
    path = tmp_path / "custom.schema.json"
    path.write_text(json.dumps(schema), encoding="utf-8")

    FINALIZER.validate_against_schema({"name": "aaa"}, path)


def test_allows_schema_properties_named_like_validation_keywords(tmp_path: Path) -> None:
    schema = {
        "type": "object",
        "properties": {
            "$ref": {"type": "string"},
            "pattern": {"type": "string"},
            "uniqueItems": {"type": "boolean"},
        },
    }
    path = tmp_path / "custom.schema.json"
    path.write_text(json.dumps(schema), encoding="utf-8")

    FINALIZER.validate_against_schema(
        {"$ref": "value", "pattern": "^(a+)+$", "uniqueItems": True},
        path,
    )


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
