"""SQLite schema history for the Codex Security workbench."""

import argparse
import json
import sqlite3
from collections.abc import Callable
from pathlib import Path

_SHARED = Path(__file__).resolve().parents[1] / "shared"
_HISTORY = json.loads((_SHARED / "workbench-migrations.json").read_text(encoding="utf-8"))
_REPAIR_HISTORY = json.dumps(_HISTORY)
_REPAIR_PLAN = json.loads((_SHARED / "workbench-history-repairs.json").read_text(encoding="utf-8"))
MIGRATIONS = tuple(
    (migration["version"], migration["name"], "\n".join(migration["statements"]))
    for migration in _HISTORY
)


def migration_json_extract(document: str, path: str) -> str | int | float | None:
    # The fixed scalar paths in migrations 38/39 must retain embedded NULs on older SQLite.
    value = json.loads(document)
    for key in path[2:].split("."):
        value = value.get(key) if isinstance(value, dict) else None
    return value


def migrate_finding_workflow_results(connection: sqlite3.Connection) -> None:
    for row in connection.execute("SELECT id, results_json FROM finding_workflows").fetchall():
        stages = json.loads(row["results_json"])["stages"]
        results = {stage: value["result"] for stage, value in stages.items() if "result" in value}
        if "pendingWrite" in stages["dedupe"]:
            results["dedupePendingWrite"] = stages["dedupe"]["pendingWrite"]
        # SQLite JSON extraction on older runtimes truncates embedded NULs in diagnostics.
        connection.execute(
            "UPDATE finding_workflows SET scan_error = ?, publish_error = ?, dedupe_error = ?, "
            "results_json = ? WHERE id = ?",
            (
                stages["scan"].get("error"),
                stages["publish"].get("error"),
                stages["dedupe"].get("error"),
                json.dumps(results, allow_nan=False),
                row["id"],
            ),
        )


def apply_migrations(
    connection: sqlite3.Connection,
    migrations: tuple[tuple[int, str, str], ...],
    now: Callable[[], str],
    backfill_security_targets: Callable[[sqlite3.Connection], None],
    *,
    immediate: bool = False,
) -> None:
    connection.commit()
    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    with connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
        normalize_pre_release_migrations(connection, now())
        applied = {
            row["version"] for row in connection.execute("SELECT version FROM schema_migrations")
        }
        should_backfill_targets = False
        for version, name, sql in migrations:
            if version == 6:
                repair_thread_scoped_workspaces_migration(connection)
            elif version == 16:
                should_backfill_targets = repair_stable_targets_migration(connection)
            elif version in applied:
                if version in (2, 12, 13, 26, 28, 31, 32, 42, 47, 48):
                    repair_additive_migration(connection, version)
                elif version == 11:
                    repair_deep_scan_migration(connection)
            else:
                if version in (38, 39):
                    connection.create_function("migration_json_extract", 2, migration_json_extract)
                    sql = sql.replace("json_extract(", "migration_json_extract(")
                for statement in sql_statements(sql):
                    connection.execute(statement)
                if version == 38:
                    migrate_finding_workflow_results(connection)
            if version not in applied:
                connection.execute(
                    "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                    (version, name, now()),
                )
        if 27 in applied:
            repair_deep_scan_failure_counter_migration(connection)
        if should_backfill_targets:
            backfill_security_targets(connection)


def normalize_pre_release_migrations(connection: sqlite3.Connection, timestamp: str) -> None:
    for query in _REPAIR_PLAN:
        actions = connection.execute("\n".join(query), {"history": _REPAIR_HISTORY}).fetchall()
        for action in actions:
            operation, value = action["operation"], action["value"]
            if operation == "error":
                raise SystemExit(value)
            if operation == "additive":
                repair_additive_migration(connection, value)
            elif operation == "column":
                add_migration_column(connection, value)
            else:
                connection.execute(value, (timestamp,) if operation == "timestamp" else ())


def repair_deep_scan_migration(connection: sqlite3.Connection) -> None:
    scan_columns = {row["name"] for row in connection.execute("PRAGMA table_info(scans)")}
    owner_column_missing = "deep_scan_owner_thread_id" not in scan_columns
    expected_objects = {
        "scans_one_running_deep_per_owner_target",
        "deep_scan_runs",
        "deep_scan_workers",
        "deep_scan_workers_completion_sequence",
        "deep_scan_workers_by_scan_status",
        "deep_scan_dedup_inputs",
    }
    existing_objects = {
        row["name"]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE name LIKE 'deep_scan_%' "
            "OR name = 'scans_one_running_deep_per_owner_target'"
        )
    }
    if not owner_column_missing and expected_objects <= existing_objects:
        return

    if owner_column_missing:
        add_column_if_missing(connection, "scans", "deep_scan_owner_thread_id", "TEXT")
    migration_sql = next(sql for version, _, sql in MIGRATIONS if version == 11)
    for statement in sql_statements(migration_sql):
        if statement.startswith("ALTER TABLE scans"):
            continue
        if statement.startswith("UPDATE scans") and not owner_column_missing:
            continue
        for prefix in ("CREATE UNIQUE INDEX ", "CREATE INDEX ", "CREATE TABLE "):
            if statement.startswith(prefix):
                statement = statement.replace(prefix, f"{prefix}IF NOT EXISTS ", 1)
                break
        connection.execute(statement)
        if statement.startswith("UPDATE scans") and "continuation_thread_id" in scan_columns:
            connection.execute(
                "UPDATE scans SET deep_scan_owner_thread_id = continuation_thread_id "
                "WHERE mode = 'deep' AND status = 'running' "
                "AND continuation_thread_id IS NOT NULL"
            )


def repair_deep_scan_failure_counter_migration(connection: sqlite3.Connection) -> None:
    threshold_column, count_column, _backfill = sql_statements(
        next(sql for version, _, sql in MIGRATIONS if version == 27)
    )
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(deep_scan_runs)")}
    threshold_missing = "stop_after_consecutive_errors" not in columns
    add_migration_column(connection, threshold_column)
    if threshold_missing:
        connection.execute(
            "UPDATE deep_scan_runs SET stop_after_consecutive_errors = stop_after_no_new"
        )
    add_migration_column(connection, count_column)


def repair_thread_scoped_workspaces_migration(connection: sqlite3.Connection) -> None:
    add_column_if_missing(connection, "workspaces", "thread_id", "TEXT")
    connection.execute(
        "CREATE INDEX IF NOT EXISTS workspaces_by_thread_and_updated_at "
        "ON workspaces(thread_id, updated_at DESC)"
    )


def repair_stable_targets_migration(connection: sqlite3.Connection) -> bool:
    workspace_columns = {row["name"] for row in connection.execute("PRAGMA table_info(workspaces)")}
    scan_columns = {row["name"] for row in connection.execute("PRAGMA table_info(scans)")}
    existing_objects = {
        row["name"]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE name IN ('security_targets', 'scans_by_target')"
        )
    }
    if (
        "target_id" in workspace_columns
        and "target_id" in scan_columns
        and existing_objects == {"security_targets", "scans_by_target"}
    ):
        return False

    migration_sql = next(sql for version, _, sql in MIGRATIONS if version == 16)
    for statement in sql_statements(migration_sql):
        if statement.startswith(("ALTER TABLE workspaces", "ALTER TABLE scans")):
            add_migration_column(connection, statement)
            continue
        statement = statement.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1)
        statement = statement.replace("CREATE INDEX ", "CREATE INDEX IF NOT EXISTS ", 1)
        connection.execute(statement)
    connection.execute(
        """
        UPDATE scans
        SET target_id = NULL
        WHERE target_id IS NOT NULL
            AND NOT EXISTS (
                SELECT 1 FROM security_targets WHERE security_targets.id = scans.target_id
            )
        """
    )
    return True


def repair_additive_migration(connection: sqlite3.Connection, version: int) -> None:
    sql = next(sql for migration_version, _, sql in MIGRATIONS if migration_version == version)
    for statement in sql_statements(sql):
        add_migration_column(connection, statement)


def add_migration_column(connection: sqlite3.Connection, statement: str) -> None:
    _, _, table, _, _, column, definition = statement.removesuffix(";").split(None, 6)
    # Preserve the compact declarations used by historical repairs, including CHECK errors.
    definition = " ".join(definition.split()).replace("( ", "(").replace(" )", ")")
    add_column_if_missing(connection, table, column, definition)


def add_column_if_missing(
    connection: sqlite3.Connection, table: str, column: str, definition: str
) -> None:
    columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def sql_statements(script: str) -> list[str]:
    statements: list[str] = []
    buffer = ""
    for line in script.splitlines():
        buffer = f"{buffer}\n{line}".strip()
        if sqlite3.complete_statement(buffer):
            statements.append(buffer)
            buffer = ""
    if buffer:
        raise ValueError("Incomplete SQLite migration statement.")
    return statements


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
