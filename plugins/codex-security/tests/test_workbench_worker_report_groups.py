from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from test_workbench_standard_deep_results import deep_scan_fixture
from workbench_test_support import checkpoint, register, run_workbench, write_completed_contract


@pytest.mark.parametrize("candidate_field", ["provenance", "extensions"])
def test_stopped_child_reports_group_candidates_within_their_own_scan(
    tmp_path: Path, candidate_field: str
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    original = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    children = []
    expected_titles = set()
    for index, instances in enumerate((2, 1), start=1):
        directory = scan_dir / f"artifacts/deep-scan/passes/pass-{index}"
        child = register(state_dir, target, directory, parent=scan_id, role="deep_pass")
        write_completed_contract(directory, child["scanId"], target, relative_path="app.py")
        document = {"findings": []}
        for instance in range(instances):
            finding = copy.deepcopy(original)
            finding["title"] = f"Pass {index} finding {instance}"
            finding["identity"] = {"anchor": f"pass-{index}", "instance": str(instance)}
            finding.setdefault(candidate_field, {})["candidateId"] = "candidate-1"
            document["findings"].append(finding)
            expected_titles.add(finding["title"])
        (directory / "findings.json").write_text(json.dumps(document))
        run_workbench(state_dir, "complete-scan", "--scan-id", child["scanId"])
        children.append(
            {"directory": directory.relative_to(scan_dir).as_posix(), "scanId": child["scanId"]}
        )
    checkpoint(state_dir, {"scanId": scan_id, "scanDir": str(scan_dir)}, passes=children)
    run_workbench(
        state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped before reduction."
    )

    retained = json.loads((scan_dir / "findings.json").read_text())["findings"]
    assert {finding["title"] for finding in retained} == expected_titles
    assert {
        finding["provenance"]["sourceFindings"][0]["finding"][candidate_field]["candidateId"]
        for finding in retained
    } == {"candidate-1"}
    report = (scan_dir / "report.md").read_text()
    assert "| Reportable DSS findings | 2 |" in report
    assert "| Report instances | 3 |" in report
