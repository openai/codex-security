from __future__ import annotations

from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "layout",
    [
        "empty",
        "no-leaf",
        "missing-root",
        "linked-parent",
        "dangling-parent",
        "linked-root",
        "parent-file",
        "malformed",
    ],
)
def test_optional_checkpoint_preserves_path_errors(
    tmp_path: Path, monkeypatch, workbench_api, layout
):
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(tmp_path / "state"))
    scan_dir = tmp_path / "scan"
    if layout != "missing-root":
        scan_dir.mkdir(mode=0o700)
    if layout == "linked-root":
        target = tmp_path / "target"
        target.mkdir(mode=0o700)
        scan_dir.rmdir()
        scan_dir.symlink_to(target, target_is_directory=True)
    elif layout not in {"empty", "missing-root"}:
        (scan_dir / "artifacts").mkdir(mode=0o700)
        parent = scan_dir / "artifacts/deep-scan"
        if layout in {"linked-parent", "dangling-parent"}:
            target = tmp_path / "target"
            if layout == "linked-parent":
                target.mkdir(mode=0o700)
            parent.symlink_to(target, target_is_directory=True)
        elif layout == "parent-file":
            parent.write_text("synthetic file")
        else:
            parent.mkdir(mode=0o700)
            if layout == "malformed":
                (parent / "checkpoint.json").write_text("{")
    read = workbench_api["load_composition"].__globals__["read_composition_checkpoint"]
    scan = {"id": "00000000-0000-4000-8000-000000000001", "scan_dir": str(scan_dir)}
    if layout in {"empty", "no-leaf"}:
        assert read(scan) is None
    else:
        with pytest.raises(workbench_api["ContractError"]):
            read(scan)
