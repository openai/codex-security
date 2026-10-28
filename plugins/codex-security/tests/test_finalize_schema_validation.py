from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from workbench_test_support import load_script

FINALIZER = load_script("finalize_scan_contract")


def test_sparse_sealed_report_remains_readable_and_exportable(tmp_path: Path) -> None:
    example = Path(__file__).resolve().parent.parent / "examples" / "legacy-completed-scan"
    shutil.copytree(example, tmp_path, dirs_exist_ok=True)
    before = {path.name: path.read_bytes() for path in tmp_path.glob("*.json")}
    original = json.loads(before["findings.json"])
    assert "codeEvidence" not in original["findings"][0]

    _, restored, _ = FINALIZER.finalize_scan(tmp_path)
    csv_export = FINALIZER.build_findings_export(tmp_path, "csv")
    sarif_export = FINALIZER.build_sarif_projection(tmp_path)

    assert restored == original
    assert original["findings"][0]["title"] in csv_export.decode()
    assert len(sarif_export["runs"][0]["results"]) == 1
    assert {name: (tmp_path / name).read_bytes() for name in before} == before


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
