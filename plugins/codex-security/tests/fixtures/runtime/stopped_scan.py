"""Inert TypeScript-to-selected-Python publication boundary fixture."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from workbench_test_support import (
    register,
    run_workbench,
    write_checkpoint,
    write_completed_contract,
)


def stopped_scan(root: Path) -> dict:
    target = root / "target"
    target.mkdir()
    (target / "app.py").write_text("pass\n" * 50)
    state = root / "state"
    scan = register(state, target, root / "scan")
    directory = Path(scan["scanDir"])
    write_completed_contract(directory, scan["scanId"], target, relative_path="app.py")
    write_checkpoint(
        directory / "checkpoints",
        {
            "scanId": scan["scanId"],
            "complete": False,
            "findings": json.loads((directory / "findings.json").read_text())["findings"],
            "coverage": json.loads((directory / "coverage.json").read_text()),
        },
    )
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        (directory / name).unlink()
    saved = run_workbench(
        state, "fail-scan", "--scan-id", scan["scanId"], "--message", "Synthetic stop"
    )["scan"]
    findings = json.loads((directory / "findings.json").read_text())["findings"]
    return {
        "findingCount": saved["findingCount"],
        "progressStatus": saved["progress"]["status"],
        "artifactFindingCount": len(findings),
    }


if __name__ == "__main__":
    print(json.dumps(stopped_scan(Path(sys.argv[1]).resolve())))
