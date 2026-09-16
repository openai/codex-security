from __future__ import annotations

import runpy
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

import pytest


class WindowsScopePath(PureWindowsPath):
    def expanduser(self):
        return self


@pytest.mark.parametrize("script", ["generate_in_scope_files.py", "generate_rank_input.py"])
def test_scope_rejects_ntfs_streams_before_resolving_paths(monkeypatch, script: str) -> None:
    path = Path(__file__).resolve().parents[1] / "scripts" / script
    namespace = runpy.run_path(str(path), run_name="scope_stream_test")
    resolve_scope = namespace["resolve_scope"]
    monkeypatch.setitem(resolve_scope.__globals__, "os", SimpleNamespace(name="nt"))
    monkeypatch.setitem(resolve_scope.__globals__, "Path", WindowsScopePath)
    root = PureWindowsPath(r"C:\Repository")
    error = namespace.get("InventoryError", SystemExit)
    with pytest.raises(error, match="alternate data stream"):
        resolve_scope(root, "src/app.py:stream")
    assert namespace["windows_stream_component"](root / "src/app.py") is None
    monkeypatch.setitem(resolve_scope.__globals__, "os", SimpleNamespace(name="posix"))
    assert namespace["windows_stream_component"](Path("src/app.py:fixture")) is None
