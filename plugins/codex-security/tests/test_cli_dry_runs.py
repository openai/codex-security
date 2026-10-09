from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = PLUGIN_ROOT / "scripts"


def run_script(name: str, *args: str, isolated: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *(["-I"] if isolated else []), str(SCRIPT_DIR / name), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def test_all_scripts_support_help() -> None:
    for script in sorted(SCRIPT_DIR.glob("*.py")):
        result = run_script(script.name, "--help")
        assert result.returncode == 0, f"{script.name}: {result.stderr}"
        assert "usage:" in result.stdout.lower(), script.name


@pytest.mark.parametrize(
    "name",
    (
        "workbench_publication.py",
        "workbench_severity.py",
        "finalize_scan_contract.py",
        "validate_scan_contract.py",
        "validate_tracking_source.py",
        "threat_model_projection.py",
    ),
)
def test_helpers_support_help_with_safe_path(name: str) -> None:
    result = run_script(name, "--help", isolated=True)

    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout.lower()


def test_recover_scan_results_help_describes_its_contract() -> None:
    result = run_script("workbench_db.py", "recover-scan-results", "--help")

    assert result.returncode == 0, result.stderr
    assert "failed, non-canceled scan" in result.stdout
    assert "retained checkpoints" in result.stdout


@pytest.mark.parametrize("isolated", (False, True))
def test_finalizer_cli_completes_checked_in_scan_bundle(tmp_path: Path, isolated: bool) -> None:
    scan_dir = tmp_path / "completed-scan"
    shutil.copytree(PLUGIN_ROOT / "examples" / "completed-scan", scan_dir)

    result = run_script(
        "finalize_scan_contract.py",
        "--scan-dir",
        str(scan_dir),
        "--schema-dir",
        str(PLUGIN_ROOT / "schemas"),
        isolated=isolated,
    )

    assert result.returncode == 0, result.stderr
    assert (scan_dir / "exports" / "results.sarif").is_file()
