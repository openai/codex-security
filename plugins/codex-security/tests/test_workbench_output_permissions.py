from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from workbench_test_support import create_saved_workspace, run_workbench

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX directory permissions")


@pytest.fixture(
    params=[
        ("start-scan", "results"),
        ("start-prompt-only-scan", "scan"),
        ("start-headless-standard-scan", "scan"),
        ("begin-deep-scan", "deepScan"),
    ],
    ids=lambda entry: entry[0],
)
def scan_entrypoint(request) -> tuple[str, str]:
    return request.param


def start_scan_with_permissive_umask(
    tmp_path: Path, scan_root: Path | None, entrypoint: tuple[str, str]
) -> Path:
    command, result_key = entrypoint
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "fixture.py").write_text("print('fixture')\n")
    if command == "start-scan":
        workspace = create_saved_workspace(state_dir, target)
        args = ["--workspace-id", str(workspace["id"])]
    else:
        args = ["--thread-id", "permissions-test", "--target-path", str(target), "--scope", "."]
        if command == "start-prompt-only-scan":
            args.extend(["--mode", "standard"])
    if scan_root is not None:
        args.extend(["--scan-root", str(scan_root)])
    started = run_workbench(
        state_dir,
        command,
        *args,
        environment={"CODEX_HOME": str(tmp_path / "codex-home")},
        umask=0o002,
    )
    return Path(str(started[result_key]["scanDir"]))


def test_scan_start_creates_private_output_parents_under_permissive_umask(
    tmp_path: Path, scan_entrypoint: tuple[str, str], workbench_api
) -> None:
    existing_root = tmp_path / "output"
    existing_root.mkdir()
    existing_root.chmod(0o755)
    scan_root = existing_root / "nested" / "scans"

    scan_dir = start_scan_with_permissive_umask(tmp_path, scan_root, scan_entrypoint)

    assert stat.S_IMODE(existing_root.stat().st_mode) == 0o755
    for directory in (scan_root.parent, scan_root, scan_dir.parent, scan_dir):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert workbench_api["require_canonical_scan_directory"](scan_dir) == scan_dir


def test_scan_start_creates_private_default_output_parents_under_permissive_umask(
    tmp_path: Path, scan_entrypoint: tuple[str, str], workbench_api
) -> None:
    scan_dir = start_scan_with_permissive_umask(tmp_path, None, scan_entrypoint)

    state_dir = tmp_path / "state"
    assert scan_dir.parent.parent == state_dir / "scans"
    for directory in (state_dir, state_dir / "scans", scan_dir.parent, scan_dir):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert workbench_api["require_canonical_scan_directory"](scan_dir) == scan_dir


@pytest.mark.parametrize("existing_mode", [0o755, 0o775, 0o777, 0o1777])
def test_scan_start_preserves_existing_output_permissions_and_validation(
    tmp_path: Path, scan_entrypoint: tuple[str, str], existing_mode: int, workbench_api
) -> None:
    scan_root = tmp_path / "scans"
    target_root = scan_root / "target"
    target_root.mkdir(parents=True)
    scan_root.chmod(0o755)
    target_root.chmod(existing_mode)

    scan_dir = start_scan_with_permissive_umask(tmp_path, scan_root, scan_entrypoint)

    assert stat.S_IMODE(scan_root.stat().st_mode) == 0o755
    assert stat.S_IMODE(target_root.stat().st_mode) == existing_mode
    assert stat.S_IMODE(scan_dir.stat().st_mode) == 0o700
    validate_directory = workbench_api["require_canonical_scan_directory"]
    if existing_mode in (0o775, 0o777):
        with pytest.raises(SystemExit, match="group- or world-writable without the sticky bit"):
            validate_directory(scan_dir)
    else:
        assert validate_directory(scan_dir) == scan_dir
