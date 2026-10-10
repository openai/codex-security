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


def backfill_unindexed_severity_assessments(connection: sqlite3.Connection) -> None:
    from finalize_scan_contract import _stable_id

    rows = connection.execute(
        """SELECT classification.scan_id, assessment.finding_id,
            assessment.occurrence_id, finding.fingerprint
        FROM scan_severity_classifications AS classification
        JOIN json_each(classification.finding_ids_json) AS selected
        JOIN finding_severity_assessments AS assessment ON assessment.finding_id = selected.value
        JOIN findings AS finding ON finding.id = assessment.finding_id"""
    ).fetchall()
    for row in rows:
        # Classification does not require indexing the scan's occurrences first.
        if row["occurrence_id"] == _stable_id("occ", row["scan_id"], row["fingerprint"]):
            connection.execute(
                "INSERT OR IGNORE INTO scan_severity_assessments "
                "SELECT ?, assessment.* FROM finding_severity_assessments AS assessment "
                "WHERE assessment.finding_id = ?",
                (row["scan_id"], row["finding_id"]),
            )


def backfill_composition_children(connection: sqlite3.Connection) -> None:
    # Preserve the previous membership rule using stored paths, including archived
    # scans and scans whose outputs no longer exist. Do not consult checkpoints.
    rows = connection.execute(
        "SELECT children.id, children.scan_dir, parents.scan_dir AS parent_scan_dir "
        "FROM scans AS children JOIN scans AS parents ON parents.id = children.parent_scan_id "
        "WHERE parents.mode = 'deep' AND children.mode = 'standard'"
    ).fetchall()
    for child in rows:
        child_dir = Path(child["scan_dir"])
        parent_dir = Path(child["parent_scan_dir"])
        previous_parent = child_dir.parent.parent.parent.parent
        if (
            child_dir.parent == previous_parent / "artifacts/deep-scan/passes"
            and parent_dir.parent == previous_parent.parent
            and parent_dir.name.startswith(f"{previous_parent.name}.previous-")
        ):
            # Older archival moved only the parent row while retaining nested files.
            archived_child = parent_dir / child_dir.relative_to(previous_parent)
            for artifact in connection.execute(
                "SELECT kind, path FROM scan_artifacts WHERE scan_id = ?", (child["id"],)
            ).fetchall():
                path = Path(artifact["path"])
                if path.is_relative_to(child_dir):
                    connection.execute(
                        "UPDATE scan_artifacts SET path = ? WHERE scan_id = ? AND kind = ?",
                        (
                            str(archived_child / path.relative_to(child_dir)),
                            child["id"],
                            artifact["kind"],
                        ),
                    )
            connection.execute(
                "UPDATE scans SET scan_dir = ? WHERE id = ?", (str(archived_child), child["id"])
            )
            child_dir = archived_child
        if child_dir.parent == parent_dir / "artifacts/deep-scan/passes":
            connection.execute(
                "UPDATE scans SET parent_scan_role = 'deep_pass' WHERE id = ?", (child["id"],)
            )

    # Older indexers published pass findings before membership was persisted.
    # Repair only records created with a retained occurrence. Earlier imports
    # can lose their embedding when a pass later replaces the indexed document.
    findings = connection.execute(
        """SELECT DISTINCT findings.id FROM findings
        JOIN finding_occurrences AS occurrence ON occurrence.finding_id = findings.id
        JOIN scans ON scans.id = occurrence.scan_id
        WHERE scans.parent_scan_role = 'deep_pass'
            AND findings.details_json = occurrence.details_json
            AND EXISTS (
                SELECT 1 FROM finding_occurrences AS original
                WHERE original.finding_id = findings.id
                    AND original.created_at = findings.created_at
            )
            AND NOT EXISTS (SELECT 1 FROM finding_embeddings WHERE finding_id = findings.id)"""
    ).fetchall()
    for finding in findings:
        finding_id = finding["id"]
        connection.execute(
            """DELETE FROM finding_repositories WHERE finding_id = ?
            AND repository_id IN (
                SELECT scans.target_id FROM finding_occurrences AS occurrence
                JOIN scans ON scans.id = occurrence.scan_id
                WHERE occurrence.finding_id = ? AND scans.parent_scan_role = 'deep_pass'
            ) AND repository_id NOT IN (
                SELECT scans.target_id FROM finding_occurrences AS occurrence
                JOIN scans ON scans.id = occurrence.scan_id
                WHERE occurrence.finding_id = ? AND scans.parent_scan_role IS NOT 'deep_pass'
                    AND scans.target_id IS NOT NULL
            )""",
            (finding_id, finding_id, finding_id),
        )
        public = connection.execute(
            """SELECT occurrence.details_json, occurrence.created_at
            FROM finding_occurrences AS occurrence JOIN scans ON scans.id = occurrence.scan_id
            WHERE occurrence.finding_id = ? AND scans.parent_scan_role IS NOT 'deep_pass'
                AND occurrence.details_json != '{}'
            ORDER BY occurrence.created_at DESC, occurrence.id DESC LIMIT 1""",
            (finding_id,),
        ).fetchone()
        if public is not None:
            connection.execute(
                "UPDATE findings SET details_json = ?, updated_at = ? WHERE id = ?",
                (public["details_json"], public["created_at"], finding_id),
            )
        elif (
            connection.execute(
                "SELECT 1 FROM finding_repositories WHERE finding_id = ?", (finding_id,)
            ).fetchone()
            is None
        ):
            connection.execute(
                "UPDATE findings SET details_json = NULL WHERE id = ?", (finding_id,)
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
                elif version in (51, 55, 56):
                    backfill_composition_children(connection)
                elif version == 54:
                    backfill_unindexed_severity_assessments(connection)
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
