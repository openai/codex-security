"""Exercise native Windows direct-plugin output creation races."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from workbench import storage  # noqa: E402

pytestmark = pytest.mark.skipif(os.name != "nt", reason="requires native Windows junctions")


def test_private_temporary_directory_rejects_post_creation_junction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "shared"
    parent.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    substituted: list[Path] = []
    create_directory = storage._create_private_windows_directory

    def replace_with_junction(path: Path, *, exist_ok: bool) -> None:
        create_directory(path, exist_ok=exist_ok)
        path.rmdir()
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(path), str(external)],
            check=True,
            capture_output=True,
            text=True,
        )
        substituted.append(path)

    monkeypatch.setattr(storage, "_create_private_windows_directory", replace_with_junction)
    try:
        with pytest.raises(OSError, match="canonical and non-reparse"):
            storage.create_private_temporary_directory(parent, prefix="scan_")
    finally:
        for path in substituted:
            path.rmdir()

    assert list(external.iterdir()) == []
