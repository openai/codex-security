"""SQLite schema history for the Codex Security workbench."""

import argparse
import json
import sqlite3
from collections.abc import Callable
from pathlib import Path

_SHARED = Path(__file__).resolve().parents[1] / "shared"
_HISTORY = json.loads((_SHARED / "workbench-migrations.json").read_text(encoding="utf-8"))
_STATEMENTS = {migration["version"]: migration["statements"] for migration in _HISTORY}
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
    discovery_roots: tuple[Path, ...] = (),
) -> None:
    """Apply missing schema versions and repair supported historical migrations.

    Commit pending work on the connection before starting the migration transaction.
    Set immediate to acquire the SQLite write lock up front. The backfill callback
    links older scans and workspaces to stable targets when required.
    """
    from workbench_target import scoped_git_discovery

    connection.commit()
    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    with (
        connection,
        scoped_git_discovery(
            lambda: [*migration_target_paths(connection), *discovery_roots],
            recorded_git_roots=lambda: recorded_git_checkout_roots(connection),
        ),
    ):
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
                # Preserve the original one-line index declaration in sqlite_schema.
                for statement in _STATEMENTS[6]:
                    apply_repair_statement(connection, statement.replace("\n", " "))
            elif version == 16:
                should_backfill_targets = repair_stable_targets_migration(connection)
            elif version == 67:
                should_backfill_targets = (
                    repair_repository_identity_migration(connection)
                    or version not in applied
                    or should_backfill_targets
                )
            elif version in applied:
                if version in (
                    2,
                    12,
                    13,
                    26,
                    28,
                    31,
                    32,
                    42,
                    47,
                    50,
                    54,
                    55,
                    58,
                    59,
                    60,
                    61,
                    69,
                    70,
                    76,
                ):
                    repair_schema(connection, version)
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
                elif version == 68:
                    from workbench_target_state import upgrade_linux_repository_generations

                    upgrade_linux_repository_generations(connection)
            if version not in applied:
                connection.execute(
                    "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                    (version, name, now()),
                )
        if 27 in applied:
            repair_deep_scan_failure_counter_migration(connection)
        if should_backfill_targets:
            backfill_security_targets(connection)


def migration_target_paths(connection: sqlite3.Connection) -> list[Path]:
    paths: set[Path] = set()
    for table, column in (
        ("security_targets", "current_path"),
        ("workspaces", "target_path"),
        ("scans", "target_path"),
    ):
        columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
        if column in columns:
            condition = (
                " AND (target_path_unvalidated = 0 OR target_id IS NOT NULL)"
                if table == "workspaces" and "target_path_unvalidated" in columns
                else ""
            )
            paths.update(
                Path(row[0])
                for row in connection.execute(
                    f"SELECT DISTINCT {column} FROM {table} WHERE {column} IS NOT NULL{condition}"
                )
            )
    return list(paths)


def recorded_git_checkout_roots(connection: sqlite3.Connection) -> set[Path] | None:
    """Return saved boundaries, or None if any historical target lacks one."""
    target_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(security_targets)")
    }
    boundaries = (
        {
            Path(target): Path(root)
            for target, root in connection.execute(
                "SELECT current_path, git_checkout_root FROM security_targets "
                "WHERE git_checkout_root IS NOT NULL"
            )
        }
        if "git_checkout_root" in target_columns
        else {}
    )
    # Even an unversioned scan may have come from an unborn Git checkout.
    if any(path not in boundaries for path in migration_target_paths(connection)):
        return None
    roots = set(boundaries.values())
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(workspaces)")}
    if "target_path_unvalidated" in columns:
        saved = (
            "rejected_checkout_roots_json" if "rejected_checkout_roots_json" in columns else "NULL"
        )
        for (root,) in connection.execute(
            f"SELECT DISTINCT value FROM workspaces LEFT JOIN json_each({saved}) "
            f"WHERE {saved} IS NOT NULL OR "
            "(target_path IS NOT NULL AND target_path_unvalidated = 1 AND target_id IS NULL)"
        ):
            if root is None:
                return None
            roots.add(Path(root))
    return roots


def normalize_pre_release_migrations(connection: sqlite3.Connection, timestamp: str) -> None:
    for query in _REPAIR_PLAN:
        actions = connection.execute("\n".join(query), {"history": _REPAIR_HISTORY}).fetchall()
        for action in actions:
            operation, value = action["operation"], action["value"]
            if operation == "error":
                raise SystemExit(value)
            if operation == "additive":
                repair_schema(connection, value)
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

    for statement in _STATEMENTS[11]:
        if statement.startswith("UPDATE scans") and not owner_column_missing:
            continue
        apply_repair_statement(connection, statement)
        if statement.startswith("UPDATE scans") and "continuation_thread_id" in scan_columns:
            connection.execute(
                "UPDATE scans SET deep_scan_owner_thread_id = continuation_thread_id "
                "WHERE mode = 'deep' AND status = 'running' "
                "AND continuation_thread_id IS NOT NULL"
            )


def repair_deep_scan_failure_counter_migration(connection: sqlite3.Connection) -> None:
    threshold, count, backfill = _STATEMENTS[27]
    if add_migration_column(connection, threshold):
        connection.execute(backfill)
    add_migration_column(connection, count)


def repair_stable_targets_migration(connection: sqlite3.Connection) -> bool:
    """Repair a partial target-ID migration and return whether the schema required repair.

    Create missing target tables, columns, and indexes. Clear scan references
    to missing target records so they can be backfilled.
    """
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
        validated_workspace = (
            "workspace.target_path_unvalidated = 0 AND "
            if "target_path_unvalidated" in workspace_columns
            else ""
        )
        needs_backfill = bool(
            connection.execute(
                f"""
                SELECT EXISTS (
                    SELECT 1 FROM workspaces AS workspace
                    WHERE ({validated_workspace}workspace.target_id IS NULL
                           AND workspace.target_path IS NOT NULL)
                        OR (
                            workspace.target_id IS NOT NULL
                            AND NOT EXISTS (
                                SELECT 1 FROM security_targets
                                WHERE security_targets.id = workspace.target_id
                            )
                        )
                ) OR EXISTS (
                    SELECT 1 FROM scans AS scan
                    WHERE scan.target_id IS NULL
                        OR NOT EXISTS (
                            SELECT 1 FROM security_targets
                            WHERE security_targets.id = scan.target_id
                        )
                )
                """
            ).fetchone()[0]
        )
        if not needs_backfill:
            return False
    else:
        repair_schema(connection, 16)

    for table in ("workspaces", "scans"):
        connection.execute(
            f"""
            UPDATE {table}
            SET target_id = NULL
            WHERE target_id IS NOT NULL
                AND NOT EXISTS (
                    SELECT 1 FROM security_targets
                    WHERE security_targets.id = {table}.target_id
                )
            """
        )
    return True


def repair_repository_identity_migration(connection: sqlite3.Connection) -> bool:
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(security_targets)")}
    index_exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'index' "
        "AND name = 'security_targets_by_repository_identity'"
    ).fetchone()
    identity_changed = "repository_identity" not in columns or index_exists is None
    if (
        "repository_identity" in columns
        and connection.execute(
            "SELECT 1 FROM schema_migrations WHERE version = 67 AND name = ?",
            ("persist repository identities",),
        ).fetchone()
        is not None
        and not any(
            row["name"] == "repository_generation"
            for row in connection.execute("PRAGMA table_info(scans)")
        )
    ):
        from workbench_target_state import normalize_pre_release_repository_identities

        normalize_pre_release_repository_identities(connection)
    migration_sql = next(sql for version, _, sql in MIGRATIONS if version == 67)
    for statement in sql_statements(migration_sql):
        if statement.startswith(("ALTER TABLE security_targets", "ALTER TABLE scans")):
            add_migration_column(connection, statement)
            continue
        for prefix in ("CREATE UNIQUE INDEX ", "CREATE INDEX ", "CREATE TRIGGER "):
            if statement.startswith(prefix):
                statement = statement.replace(prefix, f"{prefix}IF NOT EXISTS ", 1)
                break
        connection.execute(statement)

    from workbench_scan_history import _scan_completion_order

    if connection.execute(
        "SELECT 1 FROM scans WHERE status = 'complete' AND completion_sequence IS NULL LIMIT 1"
    ).fetchone():
        # SQL preserves the recorded sequence. Both projections omit it so the merge
        # compares each pending row with the timestamp of the next recorded completion.
        recorded = connection.execute(
            "SELECT id, started_at, completed_at FROM scans "
            "WHERE status = 'complete' AND completion_sequence IS NOT NULL "
            "ORDER BY completion_sequence"
        ).fetchall()
        unsequenced = connection.execute(
            "SELECT id, started_at, completed_at FROM scans "
            "WHERE status = 'complete' AND completion_sequence IS NULL"
        ).fetchall()
        pending = iter(sorted(unsequenced, key=_scan_completion_order))
        candidate = next(pending, None)
        completed = []
        for scan in recorded:
            while candidate is not None and _scan_completion_order(
                candidate
            ) <= _scan_completion_order(scan):
                completed.append(candidate)
                candidate = next(pending, None)
            completed.append(scan)
        if candidate is not None:
            completed.append(candidate)
            completed.extend(pending)
        connection.execute("UPDATE scans SET completion_sequence = NULL WHERE status = 'complete'")
        sequence = connection.execute(
            "SELECT COALESCE(MAX(completion_sequence), 0) FROM scans"
        ).fetchone()[0]
        for scan in completed:
            sequence += 1
            connection.execute(
                "UPDATE scans SET completion_sequence = ? WHERE id = ?",
                (sequence, scan["id"]),
            )
    return identity_changed


def repair_schema(connection: sqlite3.Connection, version: int) -> None:
    for statement in _STATEMENTS[version]:
        apply_repair_statement(connection, statement)


def apply_repair_statement(connection: sqlite3.Connection, statement: str) -> None:
    if statement.startswith("ALTER TABLE "):
        add_migration_column(connection, statement)
        return
    for prefix in ("CREATE UNIQUE INDEX ", "CREATE INDEX ", "CREATE TABLE "):
        if statement.startswith(prefix):
            statement = statement.replace(prefix, f"{prefix}IF NOT EXISTS ", 1)
            break
    connection.execute(statement)


def add_migration_column(connection: sqlite3.Connection, statement: str) -> bool:
    _, _, table, _, _, column, definition = statement.removesuffix(";").split(None, 6)
    columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
    if column in columns:
        return False
    # Preserve the compact declarations used by historical repairs, including CHECK errors.
    definition = " ".join(definition.split()).replace("( ", "(").replace(" )", ")")
    connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
    return True


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
