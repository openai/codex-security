from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from workbench_test_support import SNAPSHOT_SCRIPT


def test_sqlite_snapshot_rejects_source_identity_as_destination(tmp_path: Path) -> None:
    source = tmp_path / "source.sqlite3"
    alias = tmp_path / "source-alias.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE records (value TEXT NOT NULL)")
        connection.execute("INSERT INTO records VALUES ('sealed')")
        connection.commit()
    os.link(source, alias)

    for destination in (source, alias):
        completed = subprocess.run(
            [sys.executable, str(SNAPSHOT_SCRIPT), str(source), str(destination)],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        assert completed.returncode == 2
        assert "source and destination must refer to different database files" in completed.stderr
