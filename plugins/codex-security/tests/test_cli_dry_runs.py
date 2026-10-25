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


@pytest.mark.parametrize(
    "name",
    (
        "deep_scan_config.py",
        "finalize_scan_contract.py",
        "generate_in_scope_files.py",
        "generate_rank_input.py",
        "snapshot_sqlite.py",
        "threat_model_projection.py",
        "validate_scan_contract.py",
        "validate_tracking_source.py",
        "workbench_db.py",
    ),
)
def test_commands_support_help(name: str) -> None:
    result = run_script(name, "--help")
    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout.lower()


def test_script_modules_import_in_a_fresh_interpreter() -> None:
    modules = sorted(path.stem for path in SCRIPT_DIR.glob("*.py"))
    program = (
        "import importlib, sys\n"
        "sys.path.insert(0, sys.argv[1])\n"
        "for name in sys.argv[2:]:\n"
        "    importlib.import_module(name)\n"
    )
    subprocess.run(
        [sys.executable, "-I", "-c", program, str(SCRIPT_DIR), *modules],
        check=True,
    )


@pytest.mark.parametrize(
    "name",
    (
        "workbench_publication.py",
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
