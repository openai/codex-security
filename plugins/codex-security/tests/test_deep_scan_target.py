"""Exercise filesystem failures encountered below a selected Deep Scan directory."""

from __future__ import annotations

import errno
import os
import runpy
from pathlib import Path

import pytest


@pytest.fixture
def check_targets():
    script = Path(__file__).resolve().parents[1] / "scripts" / "check_deep_scan_target.py"
    return runpy.run_path(str(script))["check_selected_targets"]


@pytest.mark.cross_platform
def test_nested_read_failure_is_preserved_unless_another_selection_has_content(
    tmp_path, monkeypatch, check_targets
):
    root = tmp_path / "target"
    denied = root / "empty" / "nested"
    denied.mkdir(parents=True)
    failure = PermissionError(errno.EACCES, "Synthetic denied directory", str(denied))
    original = os.scandir

    def scandir(path):
        if Path(path) == denied:
            raise failure
        return original(path)

    monkeypatch.setattr(os, "scandir", scandir)
    with pytest.raises(PermissionError) as caught:
        check_targets(root, ["empty"], [])
    assert caught.value is failure
    (root / "sibling.py").write_text("")
    check_targets(root, ["empty", "sibling.py"], ["sibling.py"])


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory symlink fixture")
def test_nested_directory_links_are_not_followed(tmp_path, monkeypatch, check_targets):
    root = tmp_path / "target"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)
    original = os.scandir

    def scandir(path):
        assert Path(path) != outside
        return original(path)

    monkeypatch.setattr(os, "scandir", scandir)
    check_targets(root, ["."], [])
