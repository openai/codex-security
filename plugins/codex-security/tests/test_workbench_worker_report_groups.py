from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from test_workbench_standard_deep_results import accepted_standard_worker, deep_scan_fixture
from workbench_test_support import fail_deep_scan, write_completed_contract


@pytest.mark.parametrize("candidate_field", ["provenance", "extensions"])
def test_stopped_worker_reports_group_candidates_within_their_own_worker(
    tmp_path: Path, candidate_field: str
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path, workers=2)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    original = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    workers = set()
    expected_titles = set()
    for index, instances in enumerate((2, 1), start=1):
        worker_id, result_path = accepted_standard_worker(
            state_dir, codex_home, scan_dir, scan_id, name=f"worker-{index}"
        )
        workers.add(worker_id)
        draft = json.loads(result_path.read_text())
        for instance in range(instances):
            finding = copy.deepcopy(original)
            finding["title"] = f"Worker {index} finding {instance}"
            finding["identity"] = {"anchor": f"worker-{index}", "instance": str(instance)}
            finding.setdefault(candidate_field, {})["candidateId"] = "candidate-1"
            draft["findings"].append(finding)
            expected_titles.add(finding["title"])
        result_path.write_text(json.dumps(draft))

    fail_deep_scan(state_dir, codex_home, scan_id, message="Stopped before reduction.")

    retained = json.loads((scan_dir / "findings.json").read_text())["findings"]
    assert {finding["title"] for finding in retained} == expected_titles
    assert {finding["provenance"]["workerId"] for finding in retained} == workers
    assert all("sourceFindingIds" not in finding["provenance"] for finding in retained)
    report = (scan_dir / "report.md").read_text()
    assert "| Reportable DSS findings | 2 |" in report
    assert "| Report instances | 3 |" in report
