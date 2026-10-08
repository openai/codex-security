"""SQLite schema history for the Codex Security workbench."""

import argparse
import json
import sqlite3
from collections.abc import Callable
from pathlib import Path

MIGRATIONS = tuple(
    (migration["version"], migration["name"], "\n".join(migration["statements"]))
    for migration in json.loads(
        (Path(__file__).resolve().parents[1] / "shared" / "workbench-migrations.json").read_text(
            encoding="utf-8"
        )
    )
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
                if version in (2, 12, 13, 26, 28, 31, 32, 47):
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


def normalize_pre_release_execution_profile_migrations(
    connection: sqlite3.Connection, timestamp: str
) -> None:
    scan_columns = {row["name"] for row in connection.execute("PRAGMA table_info(scans)")}
    workspace_columns = {row["name"] for row in connection.execute("PRAGMA table_info(workspaces)")}
    legacy_columns = {"execution_model", "reasoning_effort"}
    renamed_columns = {
        "legacy_execution_model",
        "legacy_reasoning_effort",
    }
    execution_migrations = {
        row["version"]: row["name"]
        for row in connection.execute(
            "SELECT version, name FROM schema_migrations WHERE version IN (11, 12, 25)"
        )
    }
    supported_execution_migrations = {
        11: {"deep scan orchestration state", "scan execution profiles"},
        12: {
            "scan continuation threads",
            "scan execution profiles",
            "dynamic scan execution profiles",
        },
    }
    model_migration_name = "persist scan model settings"
    if execution_migrations.get(25) == "dynamic scan execution profiles":
        connection.execute(
            "UPDATE schema_migrations SET name = ? WHERE version = 25 AND name = ?",
            (model_migration_name, "dynamic scan execution profiles"),
        )
        execution_migrations[25] = model_migration_name
    has_legacy_profile_history = any(
        execution_migrations.get(version) in legacy_names
        for version, legacy_names in (
            (11, {"scan execution profiles"}),
            (12, {"scan execution profiles", "dynamic scan execution profiles"}),
        )
    )
    has_legacy_profile_columns = any(
        column in columns
        for column, columns in (
            ("execution_model", scan_columns),
            ("execution_model", workspace_columns),
            ("reasoning_effort", workspace_columns),
        )
    )
    if not (has_legacy_profile_history or has_legacy_profile_columns):
        return

    if any(
        execution_migrations.get(version) not in ({None} | supported_names)
        for version, supported_names in supported_execution_migrations.items()
    ):
        raise SystemExit(
            "The Codex Security database has an unsupported execution-profile migration history."
        )

    if has_legacy_profile_columns and not (
        legacy_columns <= scan_columns
        and legacy_columns <= workspace_columns
        and not renamed_columns.intersection(scan_columns | workspace_columns)
    ):
        raise SystemExit(
            "The Codex Security database has an unsupported execution-profile migration history."
        )
    if has_legacy_profile_history and not has_legacy_profile_columns:
        raise SystemExit(
            "The Codex Security database has an unsupported execution-profile migration history."
        )

    if execution_migrations.get(25) not in (None, model_migration_name):
        raise SystemExit(
            "The Codex Security database has an unsupported execution-profile migration history."
        )

    # Keep the historical values and constraints for recovery while moving
    # them out of the namespace used by the current independent scan settings.
    for table in ("workspaces", "scans"):
        connection.execute(
            f"ALTER TABLE {table} RENAME COLUMN execution_model TO legacy_execution_model"
        )
        connection.execute(
            f"ALTER TABLE {table} RENAME COLUMN reasoning_effort TO legacy_reasoning_effort"
        )
    repair_additive_migration(connection, 25)
    connection.execute(
        """
        UPDATE scans
        SET model = COALESCE(model, legacy_execution_model),
            reasoning_effort = COALESCE(reasoning_effort, legacy_reasoning_effort)
        """
    )
    for version, name in (
        (11, "scan execution profiles"),
        (12, "scan execution profiles"),
        (12, "dynamic scan execution profiles"),
    ):
        connection.execute(
            "DELETE FROM schema_migrations WHERE version = ? AND name = ?",
            (version, name),
        )
    if execution_migrations.get(25) is None:
        connection.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
            (25, model_migration_name, timestamp),
        )


def move_pre_release_migration(
    connection: sqlite3.Connection, old_version: int, new_version: int, name: str
) -> None:
    if (
        connection.execute(
            "SELECT 1 FROM schema_migrations WHERE version = ? AND name = ?", (old_version, name)
        ).fetchone()
        is None
    ):
        return
    connection.execute(
        "UPDATE schema_migrations SET version = ? WHERE version = ? AND name = ?",
        (new_version, old_version, name),
    )


def normalize_pre_release_migrations(connection: sqlite3.Connection, timestamp: str) -> None:
    normalize_mirror_lineage_migrations(connection)
    move_pre_release_migration(connection, 33, 40, "index finding identity and comparison history")

    move_pre_release_migration(connection, 25, 26, "persist scan completion warnings")
    move_pre_release_migration(connection, 12, 20, "phase-specific scan progress")

    normalize_pre_release_execution_profile_migrations(connection, timestamp)

    move_pre_release_migration(connection, 13, 21, "current scan preflight state")

    for version, legacy_names in (
        (18, {"scan target summaries"}),
        (19, {"structured scan guidance context", "idempotent scan lifecycle requests"}),
        (20, {"retain superseded scan lifecycle requests", "threat model publication receipts"}),
        (21, {"scan progress projection and activity", "deep coordinator manifest receipts"}),
        (22, {"dynamic scan execution profiles"}),
    ):
        migration = connection.execute(
            "SELECT name FROM schema_migrations WHERE version = ?", (version,)
        ).fetchone()
        if migration is None or migration["name"] not in legacy_names:
            continue
        _, name, sql = next(migration for migration in MIGRATIONS if migration[0] == version)
        if version == 18:
            connection.execute(
                "UPDATE scans SET handoff_claimed_at = NULL, handoff_claim_token = NULL "
                "WHERE handoff_status = 'delivered'"
            )
        elif version == 19:
            for statement in sql_statements(sql):
                connection.execute(
                    statement.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1)
                )
        else:
            repair_additive_migration(connection, version)
        connection.execute(
            "UPDATE schema_migrations SET name = ? WHERE version = ? AND name = ?",
            (name, version, migration["name"]),
        )

    migration = connection.execute(
        "SELECT name FROM schema_migrations WHERE version = 2"
    ).fetchone()
    if migration is None or migration["name"] != "finding management schema":
        return

    legacy_versions = {
        row["version"]: row["name"]
        for row in connection.execute(
            "SELECT version, name FROM schema_migrations WHERE version BETWEEN 2 AND 5"
        )
    }
    expected = {
        2: "finding management schema",
        3: "scan handoff delivery claims",
        4: "finding remediation action claims",
        5: "scan target snapshot digests",
    }
    for version, name in legacy_versions.items():
        if expected.get(version) != name:
            raise SystemExit(
                "The Codex Security database has an unsupported pre-release migration history."
            )

    connection.execute(
        "DELETE FROM schema_migrations WHERE version = 5 AND name = ?",
        (expected[5],),
    )
    for old_version, new_version in ((4, 5), (3, 4), (2, 3)):
        connection.execute(
            "UPDATE schema_migrations SET version = ? WHERE version = ? AND name = ?",
            (new_version, old_version, expected[old_version]),
        )
    repair_additive_migration(connection, 2)
    add_column_if_missing(connection, "scans", "target_snapshot_digest", "TEXT")
    connection.execute(
        "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
        (2, "persist capability preflight summaries", timestamp),
    )


def normalize_mirror_lineage_migrations(connection: sqlite3.Connection) -> None:
    mirror_names = {
        29: "freeze stopped scan source digests",
        30: "separate deep scan publication failures",
    }
    migrations = {
        row["version"]: row["name"]
        for row in connection.execute(
            "SELECT version, name FROM schema_migrations WHERE version BETWEEN 29 AND 32"
        )
    }
    if not any(migrations.get(version) == name for version, name in mirror_names.items()):
        return
    if migrations != mirror_names:
        raise SystemExit("The Codex Security database has an unsupported mirror migration history.")
    for old_version, new_version in ((30, 32), (29, 31)):
        connection.execute(
            "UPDATE schema_migrations SET version = ? WHERE version = ? AND name = ?",
            (new_version, old_version, mirror_names[old_version]),
        )


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
