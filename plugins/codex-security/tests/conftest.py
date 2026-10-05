from __future__ import annotations

import runpy
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def workbench_api():
    script = Path(__file__).resolve().parents[1] / "scripts" / "workbench_db.py"
    return runpy.run_path(str(script), run_name="codex_security_test_workbench")


@pytest.fixture(scope="session")
def workbench_schema(workbench_api):
    # Only the schema is shared. Each test receives its own database below.
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        workbench_api["apply_migrations"](connection)
        yield connection


@pytest.fixture
def workbench_db(workbench_schema):
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        workbench_schema.backup(connection)
        yield connection
