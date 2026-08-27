from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = PLUGIN_ROOT / "scripts"


def run_script(name: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT_DIR / name), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def test_all_scripts_support_help() -> None:
    for script in sorted(SCRIPT_DIR.glob("*.py")):
        result = run_script(script.name, "--help")
        assert result.returncode == 0, f"{script.name}: {result.stderr}"
        assert "usage:" in result.stdout.lower(), script.name


def test_finalizer_cli_completes_checked_in_scan_bundle(tmp_path: Path) -> None:
    scan_dir = tmp_path / "completed-scan"
    shutil.copytree(PLUGIN_ROOT / "examples" / "completed-scan", scan_dir)

    result = run_script(
        "finalize_scan_contract.py",
        "--scan-dir",
        str(scan_dir),
        "--schema-dir",
        str(PLUGIN_ROOT / "schemas"),
    )

    assert result.returncode == 0, result.stderr
    assert (scan_dir / "exports" / "results.sarif").is_file()
