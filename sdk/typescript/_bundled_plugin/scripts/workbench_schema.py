"""SQLite schema history for the Codex Security workbench."""

import argparse
import sqlite3

MIGRATIONS = (
    (
        1,
        "initial workbench schema",
        """
        CREATE TABLE workspaces (
            id TEXT PRIMARY KEY,
            target_path TEXT,
            target_title TEXT,
            target_summary TEXT,
            default_scope TEXT NOT NULL DEFAULT '.',
            default_mode TEXT NOT NULL DEFAULT 'standard'
                CHECK (default_mode IN ('diff', 'standard', 'deep')),
            user_context TEXT,
            diff_target_kind TEXT
                CHECK (diff_target_kind IN ('working_tree', 'commit', 'range')),
            diff_base_revision TEXT,
            diff_head_revision TEXT,
            diff_content_digest TEXT,
            diff_resolution_id TEXT,
            submitted INTEGER NOT NULL DEFAULT 0 CHECK (submitted IN (0, 1)),
            active_scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE scans (
            id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
            target_path TEXT NOT NULL,
            target_revision TEXT NOT NULL,
            target_snapshot_digest TEXT,
            scope TEXT NOT NULL,
            mode TEXT NOT NULL CHECK (mode IN ('diff', 'standard', 'deep')),
            user_context TEXT,
            diff_target_kind TEXT
                CHECK (diff_target_kind IN ('working_tree', 'commit', 'range')),
            diff_base_revision TEXT,
            diff_head_revision TEXT,
            diff_content_digest TEXT,
            scan_dir TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL CHECK (status IN ('running', 'complete', 'failed')),
            phase TEXT NOT NULL CHECK (
                phase IN ('preflight', 'threat_model', 'discovery', 'validation', 'attack_path', 'reporting')
            ),
            handoff_status TEXT NOT NULL DEFAULT 'pending'
                CHECK (handoff_status IN ('pending', 'delivered')),
            failure_message TEXT,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE scan_progress (
            scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
            review_items_total INTEGER NOT NULL DEFAULT 0 CHECK (review_items_total >= 0),
            review_items_completed INTEGER NOT NULL DEFAULT 0
                CHECK (review_items_completed >= 0 AND review_items_completed <= review_items_total),
            reportable_findings_count INTEGER NOT NULL DEFAULT 0
                CHECK (reportable_findings_count >= 0),
            deep_review_pass INTEGER CHECK (deep_review_pass IS NULL OR deep_review_pass >= 1),
            updated_at TEXT NOT NULL
        );

        CREATE TABLE scan_artifacts (
            scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            kind TEXT NOT NULL CHECK (
                kind IN ('coverage', 'findings', 'manifest', 'markdownReport')
            ),
            path TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (scan_id, kind)
        );

        CREATE TABLE findings (
            id TEXT PRIMARY KEY,
            fingerprint TEXT NOT NULL UNIQUE,
            rule_id TEXT NOT NULL,
            identity_anchor TEXT NOT NULL,
            identity_instance TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE finding_occurrences (
            id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL REFERENCES findings(id),
            scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL,
            remediation TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE (scan_id, finding_id)
        );

        CREATE TABLE finding_locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            occurrence_id TEXT NOT NULL REFERENCES finding_occurrences(id) ON DELETE CASCADE,
            relative_path TEXT NOT NULL,
            start_line INTEGER NOT NULL CHECK (start_line >= 1),
            end_line INTEGER NOT NULL CHECK (end_line >= start_line),
            role TEXT,
            sort_order INTEGER NOT NULL CHECK (sort_order >= 0),
            UNIQUE (occurrence_id, sort_order)
        );

        CREATE UNIQUE INDEX scans_one_running_per_workspace
        ON scans(workspace_id)
        WHERE status = 'running';
        """,
    ),
    (
        2,
        "persist capability preflight summaries",
        """
        ALTER TABLE workspaces ADD COLUMN capability_preflight_json TEXT;
        """,
    ),
    (
        3,
        "finding management schema",
        """
        CREATE TABLE finding_triage (
            occurrence_id TEXT PRIMARY KEY REFERENCES finding_occurrences(id) ON DELETE CASCADE,
            status TEXT NOT NULL CHECK (status IN ('open', 'closed')),
            close_reason TEXT CHECK (
                close_reason IS NULL OR close_reason IN ('already_fixed', 'wont_fix', 'false_positive')
            ),
            note TEXT,
            updated_at TEXT NOT NULL,
            CHECK (
                (status = 'open' AND close_reason IS NULL)
                OR (status = 'closed' AND close_reason IS NOT NULL)
            )
        );

        CREATE TABLE finding_remediation_attempts (
            request_id TEXT PRIMARY KEY,
            occurrence_id TEXT NOT NULL REFERENCES finding_occurrences(id) ON DELETE CASCADE,
            state TEXT NOT NULL CHECK (
                state IN ('idle', 'requested', 'generated', 'applied', 'verifying', 'verified', 'failed', 'superseded')
            ),
            version INTEGER NOT NULL CHECK (version >= 1),
            base_revision TEXT NOT NULL,
            base_content_digest TEXT,
            applied_content_digest TEXT,
            pending_action TEXT CHECK (
                pending_action IS NULL OR pending_action IN ('generate', 'apply', 'verify')
            ),
            patch_path TEXT,
            patch_digest TEXT,
            summary TEXT,
            verification_summary TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX finding_remediation_attempts_by_occurrence
        ON finding_remediation_attempts(occurrence_id, created_at DESC);

        ALTER TABLE finding_occurrences
        ADD COLUMN details_json TEXT NOT NULL DEFAULT '{}';

        """,
    ),
    (
        4,
        "scan handoff delivery claims",
        """
        ALTER TABLE scans
        ADD COLUMN handoff_claimed_at TEXT;

        ALTER TABLE scans
        ADD COLUMN handoff_claim_token TEXT;
        """,
    ),
    (
        5,
        "finding remediation action claims",
        """
        ALTER TABLE finding_remediation_attempts
        ADD COLUMN pending_action_claimed_at TEXT;

        ALTER TABLE finding_remediation_attempts
        ADD COLUMN pending_action_claim_token TEXT;
        """,
    ),
    (
        6,
        "thread-scoped workspaces",
        """
        ALTER TABLE workspaces
        ADD COLUMN thread_id TEXT;

        CREATE INDEX workspaces_by_thread_and_updated_at
        ON workspaces(thread_id, updated_at DESC);
        """,
    ),
    (
        7,
        "remediation host delivery state",
        """
        ALTER TABLE finding_remediation_attempts
        ADD COLUMN pending_action_delivered_at TEXT;
        """,
    ),
    (
        8,
        "sealed manifest digests",
        """
        ALTER TABLE scans
        ADD COLUMN seal_manifest_digest TEXT;
        """,
    ),
    (
        9,
        "scan target filesystem identity",
        """
        ALTER TABLE scans
        ADD COLUMN target_device INTEGER;

        ALTER TABLE scans
        ADD COLUMN target_inode INTEGER;
        """,
    ),
    (
        10,
        "scan cancellation state",
        """
        ALTER TABLE scans
        ADD COLUMN canceled_at TEXT;
        """,
    ),
    (
        11,
        "deep scan orchestration state",
        """
        ALTER TABLE scans
        ADD COLUMN deep_scan_owner_thread_id TEXT;

        UPDATE scans
        SET deep_scan_owner_thread_id = (
            SELECT workspaces.thread_id
            FROM workspaces
            WHERE workspaces.id = scans.workspace_id
        )
        WHERE mode = 'deep'
            AND status = 'running'
            AND id IN (
                SELECT MIN(active_scans.id)
                FROM scans AS active_scans
                JOIN workspaces AS active_workspaces
                    ON active_workspaces.id = active_scans.workspace_id
                WHERE active_scans.mode = 'deep'
                    AND active_scans.status = 'running'
                    AND active_workspaces.thread_id IS NOT NULL
                GROUP BY active_workspaces.thread_id,
                    active_scans.target_path,
                    active_scans.scope
            );

        CREATE UNIQUE INDEX scans_one_running_deep_per_owner_target
        ON scans(deep_scan_owner_thread_id, target_path, scope)
        WHERE mode = 'deep'
            AND status = 'running'
            AND deep_scan_owner_thread_id IS NOT NULL;

        CREATE TABLE deep_scan_runs (
            scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
            schema_version INTEGER NOT NULL CHECK (schema_version = 1),
            workflow_version TEXT NOT NULL,
            coordinator_generation INTEGER NOT NULL DEFAULT 1
                CHECK (coordinator_generation >= 1),
            status TEXT NOT NULL CHECK (
                status IN ('running', 'succeeded', 'failed', 'canceled', 'interrupted')
            ),
            phase TEXT NOT NULL CHECK (
                phase IN ('setup', 'discovery', 'reducing', 'terminal')
            ),
            workers INTEGER NOT NULL CHECK (workers >= 1),
            subagents INTEGER NOT NULL CHECK (subagents >= 0),
            stop_after_no_new INTEGER NOT NULL CHECK (stop_after_no_new >= 1),
            max_discovery_runs INTEGER NOT NULL CHECK (max_discovery_runs >= 1),
            discovery_runs_dispatched INTEGER NOT NULL DEFAULT 0
                CHECK (discovery_runs_dispatched >= 0),
            completion_sequence INTEGER NOT NULL DEFAULT 0
                CHECK (completion_sequence >= 0),
            consecutive_no_new INTEGER NOT NULL DEFAULT 0
                CHECK (consecutive_no_new >= 0),
            cancel_requested INTEGER NOT NULL DEFAULT 0
                CHECK (cancel_requested IN (0, 1)),
            canonical_inventory_path TEXT,
            canonical_finding_report_path TEXT,
            canonical_candidates_path TEXT,
            dedupe_report_path TEXT,
            seed_research_path TEXT,
            work_ledger_path TEXT,
            raw_candidates_path TEXT,
            coverage_ledger_path TEXT,
            findings_dir TEXT,
            manifest_path TEXT,
            terminal_reason TEXT CHECK (
                terminal_reason IS NULL OR terminal_reason IN ('saturated', 'capped')
            ),
            error_message TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            completed_at TEXT,
            CHECK (
                (
                    canonical_inventory_path IS NULL
                    AND canonical_finding_report_path IS NULL
                    AND canonical_candidates_path IS NULL
                    AND dedupe_report_path IS NULL
                    AND seed_research_path IS NULL
                    AND work_ledger_path IS NULL
                    AND raw_candidates_path IS NULL
                    AND coverage_ledger_path IS NULL
                    AND findings_dir IS NULL
                ) OR (
                    canonical_inventory_path IS NOT NULL
                    AND canonical_finding_report_path IS NOT NULL
                    AND canonical_candidates_path IS NOT NULL
                    AND dedupe_report_path IS NOT NULL
                    AND seed_research_path IS NOT NULL
                    AND work_ledger_path IS NOT NULL
                    AND raw_candidates_path IS NOT NULL
                    AND coverage_ledger_path IS NOT NULL
                    AND findings_dir IS NOT NULL
                )
            )
        );

        CREATE TABLE deep_scan_workers (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL REFERENCES deep_scan_runs(scan_id) ON DELETE CASCADE,
            kind TEXT NOT NULL CHECK (kind IN ('setup', 'discovery', 'dedup')),
            status TEXT NOT NULL CHECK (
                status IN ('queued', 'running', 'succeeded', 'failed', 'canceled')
            ),
            merge_state TEXT NOT NULL DEFAULT 'none' CHECK (
                merge_state IN ('none', 'buffered', 'merging', 'merged')
            ),
            prompt_path TEXT NOT NULL,
            artifact_dir TEXT NOT NULL,
            result_manifest_path TEXT,
            attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
            sdk_thread_id TEXT,
            completion_sequence INTEGER CHECK (completion_sequence >= 1),
            error_message TEXT,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            updated_at TEXT NOT NULL,
            UNIQUE (scan_id, id),
            CHECK (kind = 'discovery' OR merge_state = 'none'),
            CHECK (kind = 'discovery' OR completion_sequence IS NULL)
        );

        CREATE UNIQUE INDEX deep_scan_workers_completion_sequence
        ON deep_scan_workers(scan_id, completion_sequence)
        WHERE completion_sequence IS NOT NULL;

        CREATE INDEX deep_scan_workers_by_scan_status
        ON deep_scan_workers(scan_id, status, kind, created_at);

        CREATE TABLE deep_scan_dedup_inputs (
            scan_id TEXT NOT NULL,
            dedup_worker_id TEXT NOT NULL,
            discovery_worker_id TEXT NOT NULL,
            input_order INTEGER NOT NULL CHECK (input_order >= 0),
            PRIMARY KEY (dedup_worker_id, discovery_worker_id),
            UNIQUE (dedup_worker_id, input_order),
            FOREIGN KEY (scan_id, dedup_worker_id)
                REFERENCES deep_scan_workers(scan_id, id) ON DELETE CASCADE,
            FOREIGN KEY (scan_id, discovery_worker_id)
                REFERENCES deep_scan_workers(scan_id, id) ON DELETE CASCADE
        );
        """,
    ),
    (
        12,
        "scan continuation threads",
        """
        ALTER TABLE scans
        ADD COLUMN continuation_thread_id TEXT;
        """,
    ),
    (
        13,
        "scan scope file counts",
        """
        ALTER TABLE scan_progress
        ADD COLUMN scope_file_count INTEGER
            CHECK (scope_file_count >= 0);
        """,
    ),
    (
        14,
        "imported triage results",
        """
        CREATE TABLE triage_results (
            id TEXT PRIMARY KEY,
            repository_path TEXT NOT NULL,
            repository_revision TEXT,
            finding_count INTEGER NOT NULL CHECK (finding_count >= 0),
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX triage_results_by_updated_at
        ON triage_results(updated_at DESC, id);
        """,
    ),
    (
        15,
        "append-only finding decisions",
        """
        CREATE TABLE finding_decisions (
            id TEXT PRIMARY KEY,
            occurrence_id TEXT NOT NULL REFERENCES finding_occurrences(id) ON DELETE CASCADE,
            status TEXT NOT NULL CHECK (status IN ('open', 'closed')),
            close_reason TEXT CHECK (
                close_reason IS NULL OR close_reason IN ('already_fixed', 'wont_fix', 'false_positive')
            ),
            note TEXT,
            created_at TEXT NOT NULL,
            CHECK (
                (status = 'open' AND close_reason IS NULL)
                OR (status = 'closed' AND close_reason IS NOT NULL)
            )
        );

        CREATE INDEX finding_decisions_by_occurrence
        ON finding_decisions(occurrence_id, created_at DESC, id DESC);

        INSERT INTO finding_decisions (
            id, occurrence_id, status, close_reason, note, created_at
        )
        SELECT
            'legacy_' || occurrence_id,
            occurrence_id,
            status,
            close_reason,
            note,
            updated_at
        FROM finding_triage;
        """,
    ),
    (
        16,
        "stable repository targets",
        """
        CREATE TABLE security_targets (
            id TEXT PRIMARY KEY,
            current_path TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        ALTER TABLE workspaces
        ADD COLUMN target_id TEXT REFERENCES security_targets(id);

        ALTER TABLE scans
        ADD COLUMN target_id TEXT REFERENCES security_targets(id);

        CREATE INDEX scans_by_target
        ON scans(target_id, started_at DESC, id);
        """,
    ),
    (
        17,
        "scan target summaries",
        """
        ALTER TABLE scans
        ADD COLUMN target_summary TEXT;
        """,
    ),
    (
        18,
        "clear legacy delivered handoff claims",
        """
        UPDATE scans
        SET handoff_claimed_at = NULL, handoff_claim_token = NULL
        WHERE handoff_status = 'delivered';
        """,
    ),
    (
        19,
        "persist setup workspace preference",
        """
        CREATE TABLE setup_preferences (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            skip_setup_ui INTEGER NOT NULL CHECK (skip_setup_ui IN (0, 1)),
            updated_at TEXT NOT NULL
        );
        """,
    ),
    (
        20,
        "phase-specific scan progress",
        """
        ALTER TABLE scan_progress
        ADD COLUMN phase_items_total INTEGER NOT NULL DEFAULT 0
            CHECK (phase_items_total >= 0);

        ALTER TABLE scan_progress
        ADD COLUMN phase_items_completed INTEGER NOT NULL DEFAULT 0
            CHECK (phase_items_completed >= 0 AND phase_items_completed <= phase_items_total);

        ALTER TABLE scan_progress
        ADD COLUMN phase_progress_unit TEXT CHECK (
            phase_progress_unit IS NULL OR phase_progress_unit IN (
                'checks',
                'threat_surfaces',
                'review_receipts',
                'candidate_findings',
                'validated_findings',
                'report_artifacts'
            )
        );
        """,
    ),
    (
        21,
        "current scan preflight state",
        """
        ALTER TABLE scan_progress
        ADD COLUMN preflight_issues_json TEXT NOT NULL DEFAULT '[]';

        ALTER TABLE scan_progress
        ADD COLUMN preflight_checks_total INTEGER NOT NULL DEFAULT 0
            CHECK (preflight_checks_total >= 0);

        ALTER TABLE scan_progress
        ADD COLUMN preflight_checks_completed INTEGER NOT NULL DEFAULT 0
            CHECK (
                preflight_checks_completed >= 0
                AND preflight_checks_completed <= preflight_checks_total
            );

        """,
    ),
    (
        22,
        "replayable scan launch recipes",
        """
        ALTER TABLE scans ADD COLUMN recipe_json TEXT;
        ALTER TABLE scans ADD COLUMN parent_scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL;
        """,
    ),
    (
        23,
        "semantic scan comparison matches",
        """
        CREATE TABLE scan_comparisons (
            before_scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            after_scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (before_scan_id, after_scan_id),
            CHECK (before_scan_id != after_scan_id)
        );

        CREATE TABLE scan_comparison_matches (
            before_scan_id TEXT NOT NULL,
            after_scan_id TEXT NOT NULL,
            before_occurrence_id TEXT NOT NULL
                REFERENCES finding_occurrences(id) ON DELETE CASCADE,
            after_occurrence_id TEXT NOT NULL
                REFERENCES finding_occurrences(id) ON DELETE CASCADE,
            reason TEXT NOT NULL,
            PRIMARY KEY (
                before_scan_id, after_scan_id, before_occurrence_id, after_occurrence_id
            ),
            FOREIGN KEY (before_scan_id, after_scan_id)
                REFERENCES scan_comparisons(before_scan_id, after_scan_id) ON DELETE CASCADE
        );

        CREATE INDEX scan_comparison_matches_by_before_occurrence
        ON scan_comparison_matches(before_occurrence_id);

        CREATE INDEX scan_comparison_matches_by_after_occurrence
        ON scan_comparison_matches(after_occurrence_id);
        """,
    ),
    (
        24,
        "persist scan cost estimates",
        """
        ALTER TABLE scans ADD COLUMN cost_json TEXT;
        """,
    ),
    (
        25,
        "persist scan model settings",
        """
        ALTER TABLE scans ADD COLUMN model TEXT;
        ALTER TABLE scans ADD COLUMN reasoning_effort TEXT;
        """,
    ),
    (
        26,
        "persist scan completion warnings",
        """
        ALTER TABLE scans
        ADD COLUMN completion_warnings_json TEXT NOT NULL DEFAULT '[]';
        """,
    ),
)


def normalize_pre_release_migrations(
    connection: sqlite3.Connection, timestamp: str
) -> None:
    execution_migrations = {
        row["version"]: row["name"]
        for row in connection.execute(
            "SELECT version, name FROM schema_migrations WHERE version IN (11, 12)"
        )
    }
    supported_execution_migrations = {
        11: {"deep scan orchestration state", "scan execution profiles"},
        12: {
            "scan continuation threads",
            "dynamic scan execution profiles",
            "phase-specific scan progress",
        },
    }
    if any(
        name not in supported_execution_migrations[version]
        for version, name in execution_migrations.items()
    ):
        raise SystemExit(
            "The Codex Security database has an unsupported execution-profile migration history."
        )

    phase_progress_migration = connection.execute(
        "SELECT name FROM schema_migrations WHERE version = 12"
    ).fetchone()
    if (
        phase_progress_migration is not None
        and phase_progress_migration["name"] == "phase-specific scan progress"
    ):
        target_migration = connection.execute(
            "SELECT name FROM schema_migrations WHERE version = 20"
        ).fetchone()
        if target_migration is not None:
            raise SystemExit(
                "The Codex Security database has an unsupported pre-release migration history."
            )
        connection.execute(
            "UPDATE schema_migrations SET version = 20 WHERE version = 12 AND name = ?",
            ("phase-specific scan progress",),
        )

    normalize_pre_release_execution_profile_migrations(connection, timestamp)

    preflight_progress_migration = connection.execute(
        "SELECT name FROM schema_migrations WHERE version = 13"
    ).fetchone()
    if (
        preflight_progress_migration is not None
        and preflight_progress_migration["name"] == "current scan preflight state"
    ):
        target_migration = connection.execute(
            "SELECT name FROM schema_migrations WHERE version = 21"
        ).fetchone()
        if target_migration is not None:
            raise SystemExit(
                "The Codex Security database has an unsupported pre-release migration history."
            )
        connection.execute(
            "UPDATE schema_migrations SET version = 21 WHERE version = 13 AND name = ?",
            ("current scan preflight state",),
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
    add_column_if_missing(connection, "workspaces", "capability_preflight_json", "TEXT")
    add_column_if_missing(connection, "scans", "target_snapshot_digest", "TEXT")
    connection.execute(
        "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
        (2, "persist capability preflight summaries", timestamp),
    )


def normalize_pre_release_execution_profile_migrations(
    connection: sqlite3.Connection, timestamp: str
) -> None:
    execution_migrations = {
        row["version"]: row["name"]
        for row in connection.execute(
            "SELECT version, name FROM schema_migrations WHERE version IN (11, 12, 25, 26)"
        )
    }
    legacy_names = {
        11: "scan execution profiles",
        12: "dynamic scan execution profiles",
    }
    released_names = {
        11: "deep scan orchestration state",
        12: "scan continuation threads",
    }
    model_migration_name = "persist scan model settings"
    warnings_migration_name = "persist scan completion warnings"
    has_legacy_profile_history = execution_migrations.get(11) == legacy_names[11]
    has_public_warnings_history = (
        execution_migrations.get(25) == warnings_migration_name
    )

    scan_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(scans)")
    }
    workspace_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(workspaces)")
    }
    has_legacy_profile_columns = (
        "execution_model" in scan_columns or "execution_model" in workspace_columns
    )
    if not (
        has_legacy_profile_history
        or has_public_warnings_history
        or has_legacy_profile_columns
    ):
        return

    if (
        any(
            execution_migrations.get(version)
            not in (None, released_names[version], legacy_names[version])
            for version in (11, 12)
        )
        or (
            has_legacy_profile_history
            and execution_migrations.get(12)
            not in (None, legacy_names[12], released_names[12])
        )
        or (
            not has_legacy_profile_history
            and execution_migrations.get(12) == legacy_names[12]
        )
    ):
        raise SystemExit(
            "The Codex Security database has an unsupported execution-profile migration history."
        )

    expected_legacy_columns = {"execution_model", "reasoning_effort"}
    renamed_legacy_columns = {
        "legacy_execution_model",
        "legacy_reasoning_effort",
    }
    if has_legacy_profile_columns and (
        not expected_legacy_columns.issubset(scan_columns)
        or not expected_legacy_columns.issubset(workspace_columns)
        or renamed_legacy_columns.intersection(scan_columns)
        or renamed_legacy_columns.intersection(workspace_columns)
    ):
        raise SystemExit(
            "The Codex Security database has an unsupported execution-profile migration history."
        )
    if has_legacy_profile_history and not has_legacy_profile_columns:
        raise SystemExit(
            "The Codex Security database has an unsupported execution-profile migration history."
        )

    if has_public_warnings_history:
        if execution_migrations.get(26) is not None:
            raise SystemExit(
                "The Codex Security database has an unsupported pre-release migration history."
            )
        connection.execute(
            "UPDATE schema_migrations SET version = 26 WHERE version = 25 AND name = ?",
            (warnings_migration_name,),
        )
        execution_migrations.pop(25)

    if execution_migrations.get(25) not in (None, model_migration_name):
        raise SystemExit(
            "The Codex Security database has an unsupported execution-profile migration history."
        )

    # Keep the historical values and constraints for recovery while moving
    # them out of the namespace used by the current independent scan settings.
    for table in ("workspaces", "scans") if has_legacy_profile_columns else ():
        connection.execute(
            f"ALTER TABLE {table} RENAME COLUMN execution_model TO legacy_execution_model"
        )
        connection.execute(
            f"ALTER TABLE {table} RENAME COLUMN reasoning_effort TO legacy_reasoning_effort"
        )
    add_column_if_missing(connection, "scans", "model", "TEXT")
    add_column_if_missing(connection, "scans", "reasoning_effort", "TEXT")
    if has_legacy_profile_columns:
        connection.execute(
            """
            UPDATE scans
            SET model = COALESCE(model, legacy_execution_model),
                reasoning_effort = legacy_reasoning_effort
            WHERE legacy_execution_model IS NOT NULL
                OR legacy_reasoning_effort IS NOT NULL
            """
        )
    if has_legacy_profile_history:
        for version, name in legacy_names.items():
            connection.execute(
                "DELETE FROM schema_migrations WHERE version = ? AND name = ?",
                (version, name),
            )
    if execution_migrations.get(25) is None:
        connection.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
            (25, model_migration_name, timestamp),
        )


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


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()
