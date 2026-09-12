from __future__ import annotations

import copy
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parents[1]


def run_finalizer(scan_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(PLUGIN_DIR / "scripts" / "finalize_scan_contract.py"),
            "--scan-dir",
            str(scan_dir),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize("mode", ["repository", "scoped_path", "diff"])
@pytest.mark.parametrize("has_findings", [True, False])
def test_file_authored_assembly_seals_without_completion_binding(
    tmp_path: Path, mode: str, has_findings: bool
) -> None:
    def example(name: str) -> dict:
        return json.loads((PLUGIN_DIR / "examples" / "completed-scan" / name).read_text())

    scan = example("scan-manifest.json")["scan"]
    scan.pop("sealedAt")
    scan.pop("artifacts")
    scan["id"] = "scan_fresh_terminal"
    findings = example("findings.json")["findings"] if has_findings else []
    coverage = example("coverage.json")
    for key in ("documentType", "schemaVersion", "scanId"):
        coverage.pop(key)
    coverage["mode"] = mode
    coverage["inventoryStrategy"] = mode
    if mode == "diff":
        scan["target"]["kind"] = "git_diff"
    if not has_findings:
        coverage["surfaces"][0]["disposition"] = "no_issue_found"
    before = copy.deepcopy((scan, findings, coverage))

    # Reproduce the reported terminal state before exercising fresh assembly.
    incomplete_dir = tmp_path / "incomplete"
    incomplete_dir.mkdir()
    incomplete = {
        "scan-manifest.json": {
            "documentType": "codex-security.scan-manifest",
            "schemaVersion": "1.0",
            "scan": {**scan, "id": "scan_incomplete_terminal"},
        },
        "findings.json": {
            "documentType": "codex-security.findings",
            "schemaVersion": "1.0",
            "findings": findings,
        },
        "coverage.json": {
            "documentType": "codex-security.coverage",
            "schemaVersion": "1.0",
            **coverage,
        },
    }
    for name, document in incomplete.items():
        (incomplete_dir / name).write_text(json.dumps(document), encoding="utf-8")
    retained = {path.name: path.read_bytes() for path in incomplete_dir.iterdir()}
    failed = run_finalizer(incomplete_dir)
    assert failed.returncode == 2
    assert "findings.scanId: must match manifest scan id" in failed.stderr
    assert {path.name: path.read_bytes() for path in incomplete_dir.iterdir()} == retained

    # Exercise the producer recipe shipped to file-authoring scan skills.
    reference = (PLUGIN_DIR / "references" / "final-report.md").read_text(encoding="utf-8")
    recipe = re.search(r"```python\n(.*?)\n```", reference, re.DOTALL)
    assert recipe is not None
    namespace = {
        "plugin_dir": str(PLUGIN_DIR),
        "scan": scan,
        "findings": findings,
        "coverage": coverage,
    }
    exec(recipe[1], namespace)
    documents = namespace["documents"]
    assert (scan, findings, coverage) == before
    assert documents["scan-manifest.json"]["scan"]["id"] == scan["id"]
    assert documents["findings.json"]["scanId"] == scan["id"]
    assert documents["coverage.json"]["scanId"] == scan["id"]
    assert documents["findings.json"]["findings"] == findings
    assert all(documents["coverage.json"][key] == value for key, value in coverage.items())
    fresh_dir = tmp_path / "fresh"
    fresh_dir.mkdir()
    for name, document in documents.items():
        (fresh_dir / name).write_text(json.dumps(document), encoding="utf-8")

    result = run_finalizer(fresh_dir)

    assert result.returncode == 0, result.stderr
    manifest = json.loads((fresh_dir / "scan-manifest.json").read_text(encoding="utf-8"))
    assert manifest["scan"]["sealedAt"]
    assert manifest["scan"]["id"] == scan["id"]
    assert (fresh_dir / "report.md").is_file()
    completed_findings = json.loads((fresh_dir / "findings.json").read_text(encoding="utf-8"))
    assert completed_findings["scanId"] == scan["id"]
    assert len(completed_findings["findings"]) == len(findings)
    completed_coverage = json.loads((fresh_dir / "coverage.json").read_text(encoding="utf-8"))
    assert completed_coverage["scanId"] == scan["id"]
    assert completed_coverage["mode"] == mode
    assert {path.name: path.read_bytes() for path in incomplete_dir.iterdir()} == retained
