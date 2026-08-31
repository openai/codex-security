"""SQLite schema history for the Codex Security workbench."""

import argparse
import json
import sqlite3
from collections.abc import Callable

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
    (
        27,
        "persist deep scan consecutive discovery failures",
        """
        ALTER TABLE deep_scan_runs
        ADD COLUMN stop_after_consecutive_errors INTEGER NOT NULL DEFAULT 1
            CHECK (stop_after_consecutive_errors >= 1);

        ALTER TABLE deep_scan_runs
        ADD COLUMN consecutive_errors INTEGER NOT NULL DEFAULT 0
            CHECK (consecutive_errors >= 0);

        UPDATE deep_scan_runs
        SET stop_after_consecutive_errors = stop_after_no_new;
        """,
    ),
    (
        28,
        "persist deep scan discovery time limit",
        """
        ALTER TABLE deep_scan_runs
        ADD COLUMN max_time_hours REAL NOT NULL DEFAULT 96;
        """,
    ),
    (
        29,
        "persist finding publication associations",
        """
        CREATE TABLE finding_publications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            finding_id TEXT NOT NULL REFERENCES findings(id),
            occurrence_id TEXT NOT NULL
                REFERENCES finding_occurrences(id) ON DELETE CASCADE,
            destination_type TEXT NOT NULL,
            team_id TEXT,
            project_id TEXT,
            external_id TEXT NOT NULL,
            external_url TEXT,
            created_at TEXT NOT NULL,
            UNIQUE (occurrence_id, destination_type, team_id, project_id, external_id),
            UNIQUE (destination_type, team_id, project_id, external_id)
        );

        CREATE INDEX finding_publications_by_scan
        ON finding_publications(scan_id, occurrence_id, id);

        CREATE INDEX finding_publications_by_finding
        ON finding_publications(finding_id, id);
        """,
    ),
    (
        30,
        "preserve team-only finding publication associations",
        """
        CREATE UNIQUE INDEX finding_publications_team_only_occurrence
        ON finding_publications(occurrence_id, destination_type, team_id, external_id)
        WHERE project_id IS NULL;

        CREATE UNIQUE INDEX finding_publications_team_only_external_issue
        ON finding_publications(destination_type, team_id, external_id)
        WHERE project_id IS NULL;
        """,
    ),
    (
        31,
        "freeze stopped scan source digests",
        """
        ALTER TABLE scans ADD COLUMN retained_source_digests_json TEXT;
        """,
    ),
    (
        32,
        "separate deep scan publication failures",
        """
        ALTER TABLE deep_scan_runs ADD COLUMN publication_error_message TEXT;
        """,
    ),
    (
        33,
        "store complete findings and embeddings without a scan",
        """
        ALTER TABLE findings ADD COLUMN details_json TEXT;

        UPDATE findings SET details_json = (
            SELECT details_json FROM finding_occurrences
            WHERE finding_id = findings.id AND details_json != '{}'
            ORDER BY created_at DESC, id DESC LIMIT 1
        );

        CREATE TABLE finding_embeddings (
            finding_id TEXT PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
            model TEXT NOT NULL,
            vector_json TEXT NOT NULL
        );

        CREATE TRIGGER invalidate_finding_embedding
        AFTER UPDATE OF details_json ON findings
        WHEN OLD.details_json IS NOT NEW.details_json
        BEGIN
            DELETE FROM finding_embeddings WHERE finding_id = NEW.id;
        END;
        """,
    ),
    (
        34,
        "associate findings with repositories",
        """
        CREATE TABLE finding_repositories (
            repository_id TEXT NOT NULL,
            finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            PRIMARY KEY (repository_id, finding_id)
        );

        INSERT OR IGNORE INTO finding_repositories (repository_id, finding_id)
        SELECT scans.target_id, finding_occurrences.finding_id
        FROM finding_occurrences JOIN scans ON scans.id = finding_occurrences.scan_id
        WHERE scans.target_id IS NOT NULL;
        """,
    ),
    (
        35,
        "persist finding dedupe groups",
        """
        CREATE TABLE finding_dedupe_groups (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL
        );

        CREATE TABLE finding_dedupe_group_members (
            group_id TEXT NOT NULL REFERENCES finding_dedupe_groups(id) ON DELETE CASCADE,
            finding_id TEXT NOT NULL REFERENCES findings(id),
            PRIMARY KEY (group_id, finding_id)
        );

        CREATE INDEX finding_dedupe_groups_by_finding
        ON finding_dedupe_group_members(finding_id, group_id);
        """,
    ),
    (
        36,
        "persist local findings workflows",
        """
        CREATE TABLE finding_workflows (
            id TEXT PRIMARY KEY,
            state_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """,
    ),
    (
        37,
        "checkpoint validated dedupe reviews",
        """
        CREATE TABLE finding_workflow_reviews (
            workflow_id TEXT NOT NULL REFERENCES finding_workflows(id) ON DELETE CASCADE,
            review_key TEXT NOT NULL,
            binding_json TEXT NOT NULL,
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (workflow_id, review_key)
        );
        """,
    ),
    (
        38,
        "store findings workflow metadata in columns",
        """
        ALTER TABLE finding_workflows RENAME COLUMN state_json TO results_json;
        ALTER TABLE finding_workflows ADD COLUMN repository_path TEXT;
        ALTER TABLE finding_workflows ADD COLUMN scan_request_digest TEXT;
        ALTER TABLE finding_workflows ADD COLUMN scan_id TEXT;
        ALTER TABLE finding_workflows ADD COLUMN scan_dir TEXT;
        ALTER TABLE finding_workflows ADD COLUMN artifact_digest TEXT;
        ALTER TABLE finding_workflows ADD COLUMN destination TEXT;
        ALTER TABLE finding_workflows ADD COLUMN scope_repository_id TEXT;
        ALTER TABLE finding_workflows ADD COLUMN scope_all_repositories INTEGER;
        ALTER TABLE finding_workflows ADD COLUMN scan_status TEXT NOT NULL DEFAULT 'pending';
        ALTER TABLE finding_workflows ADD COLUMN scan_error TEXT;
        ALTER TABLE finding_workflows ADD COLUMN publish_status TEXT NOT NULL DEFAULT 'pending';
        ALTER TABLE finding_workflows ADD COLUMN publish_error TEXT;
        ALTER TABLE finding_workflows ADD COLUMN dedupe_status TEXT NOT NULL DEFAULT 'pending';
        ALTER TABLE finding_workflows ADD COLUMN dedupe_error TEXT;
        """,
    ),
    (
        39,
        "store dedupe checkpoint bindings in columns",
        """
        ALTER TABLE finding_workflow_reviews RENAME COLUMN binding_json TO prompt_digest;
        ALTER TABLE finding_workflow_reviews ADD COLUMN review_contract_version INTEGER;
        ALTER TABLE finding_workflow_reviews ADD COLUMN codex_version TEXT;
        ALTER TABLE finding_workflow_reviews ADD COLUMN source_repository_path TEXT;
        ALTER TABLE finding_workflow_reviews ADD COLUMN source_revision TEXT;
        ALTER TABLE finding_workflow_reviews ADD COLUMN source_refs_digest TEXT;
        ALTER TABLE finding_workflow_reviews ADD COLUMN source_content_digest TEXT;
        ALTER TABLE finding_workflow_reviews ADD COLUMN scope_repository_id TEXT;
        ALTER TABLE finding_workflow_reviews ADD COLUMN scope_all_repositories INTEGER;
        ALTER TABLE finding_workflow_reviews ADD COLUMN model TEXT;
        ALTER TABLE finding_workflow_reviews ADD COLUMN effort TEXT;
        ALTER TABLE finding_workflow_reviews ADD COLUMN settings_digest TEXT;
        ALTER TABLE finding_workflow_reviews ADD COLUMN contract_digest TEXT;
        """,
    ),
    (
        40,
        "index finding identity and comparison history",
        """
        CREATE INDEX finding_occurrences_by_finding
        ON finding_occurrences(finding_id, id);

        CREATE INDEX scan_comparisons_by_after_scan
        ON scan_comparisons(after_scan_id, before_scan_id);
        """,
    ),
)


def migrate_finding_workflow_review_columns(connection: sqlite3.Connection) -> None:
    for row in connection.execute(
        "SELECT workflow_id, review_key, prompt_digest FROM finding_workflow_reviews"
    ).fetchall():
        binding = json.loads(row["prompt_digest"])
        source = binding["source"]
        scope = binding["scope"]
        connection.execute(
            """UPDATE finding_workflow_reviews SET review_contract_version = ?, codex_version = ?,
            source_repository_path = ?, source_revision = ?, source_refs_digest = ?,
            source_content_digest = ?, scope_repository_id = ?, scope_all_repositories = ?,
            model = ?, effort = ?, settings_digest = ?, prompt_digest = ?, contract_digest = ?
            WHERE workflow_id = ? AND review_key = ?""",
            (
                binding["version"],
                binding["codexVersion"],
                source["repository"],
                source["revision"],
                source["refsDigest"],
                source["content"],
                scope.get("repositoryId"),
                scope.get("allRepositories"),
                binding["model"],
                binding["effort"],
                binding.get("settingsDigest"),
                binding["promptDigest"],
                binding["contractDigest"],
                row["workflow_id"],
                row["review_key"],
            ),
        )


def migrate_finding_workflow_columns(connection: sqlite3.Connection) -> None:
    # Rename/backfill in place so existing checkpoint foreign keys and rows survive.
    for row in connection.execute("SELECT id, results_json FROM finding_workflows").fetchall():
        state = json.loads(row["results_json"])
        scope = state.get("scope", {})
        stages = state["stages"]
        results = {stage: value["result"] for stage, value in stages.items() if "result" in value}
        if "pendingWrite" in stages["dedupe"]:
            results["dedupePendingWrite"] = stages["dedupe"]["pendingWrite"]
        connection.execute(
            """UPDATE finding_workflows SET
            repository_path = ?, scan_request_digest = ?, scan_id = ?, scan_dir = ?,
            artifact_digest = ?, destination = ?, scope_repository_id = ?, scope_all_repositories = ?,
            scan_status = ?, scan_error = ?, publish_status = ?, publish_error = ?,
            dedupe_status = ?, dedupe_error = ?, results_json = ? WHERE id = ?""",
            (
                state.get("repositoryPath"),
                state.get("scanRequestDigest"),
                state.get("scanId"),
                state.get("scanDir"),
                state.get("artifactDigest"),
                state.get("destination"),
                scope.get("repositoryId"),
                scope.get("allRepositories"),
                stages["scan"]["status"],
                stages["scan"].get("error"),
                stages["publish"]["status"],
                stages["publish"].get("error"),
                stages["dedupe"]["status"],
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
) -> None:
    connection.commit()
    connection.execute("BEGIN IMMEDIATE")
    try:
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
            if version in applied:
                if version == 2:
                    add_column_if_missing(
                        connection, "workspaces", "capability_preflight_json", "TEXT"
                    )
                elif version == 6:
                    repair_thread_scoped_workspaces_migration(connection)
                elif version == 11:
                    repair_deep_scan_migration(connection)
                elif version == 12:
                    add_column_if_missing(connection, "scans", "continuation_thread_id", "TEXT")
                elif version == 13:
                    add_column_if_missing(
                        connection,
                        "scan_progress",
                        "scope_file_count",
                        "INTEGER CHECK (scope_file_count >= 0)",
                    )
                elif version == 16:
                    should_backfill_targets = repair_stable_targets_migration(connection)
                elif version == 26:
                    add_column_if_missing(
                        connection,
                        "scans",
                        "completion_warnings_json",
                        "TEXT NOT NULL DEFAULT '[]'",
                    )
                elif version == 28:
                    add_column_if_missing(
                        connection,
                        "deep_scan_runs",
                        "max_time_hours",
                        "REAL NOT NULL DEFAULT 96",
                    )
                elif version == 31:
                    add_column_if_missing(
                        connection,
                        "scans",
                        "retained_source_digests_json",
                        "TEXT",
                    )
                elif version == 32:
                    add_column_if_missing(
                        connection,
                        "deep_scan_runs",
                        "publication_error_message",
                        "TEXT",
                    )
                continue
            if version == 6:
                repair_thread_scoped_workspaces_migration(connection)
            elif version == 16:
                should_backfill_targets = repair_stable_targets_migration(connection)
            else:
                for statement in sql_statements(sql):
                    connection.execute(statement)
                if version == 38:
                    migrate_finding_workflow_columns(connection)
                elif version == 39:
                    migrate_finding_workflow_review_columns(connection)
            connection.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                (version, name, now()),
            )
        if 27 in applied:
            repair_deep_scan_failure_counter_migration(connection)
        if should_backfill_targets:
            backfill_security_targets(connection)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise


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
    add_column_if_missing(connection, "scans", "model", "TEXT")
    add_column_if_missing(connection, "scans", "reasoning_effort", "TEXT")
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


def normalize_pre_release_migrations(connection: sqlite3.Connection, timestamp: str) -> None:
    normalize_mirror_lineage_migrations(connection)
    connection.execute(
        "UPDATE schema_migrations SET version = 40 WHERE version = 33 AND name = ?",
        ("index finding identity and comparison history",),
    )

    completion_warning_migration = connection.execute(
        "SELECT name FROM schema_migrations WHERE version = 25"
    ).fetchone()
    if (
        completion_warning_migration is not None
        and completion_warning_migration["name"] == "persist scan completion warnings"
    ):
        if (
            connection.execute("SELECT 1 FROM schema_migrations WHERE version = 26").fetchone()
            is not None
        ):
            raise SystemExit(
                "The Codex Security database has an unsupported pre-release migration history."
            )
        connection.execute(
            "UPDATE schema_migrations SET version = 26 WHERE version = 25 AND name = ?",
            ("persist scan completion warnings",),
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

    delivered_claim_migration = connection.execute(
        "SELECT name FROM schema_migrations WHERE version = 18"
    ).fetchone()
    if (
        delivered_claim_migration is not None
        and delivered_claim_migration["name"] == "scan target summaries"
    ):
        connection.execute(
            "UPDATE scans SET handoff_claimed_at = NULL, handoff_claim_token = NULL "
            "WHERE handoff_status = 'delivered'"
        )
        connection.execute(
            "UPDATE schema_migrations SET name = ? WHERE version = 18 AND name = ?",
            ("clear legacy delivered handoff claims", "scan target summaries"),
        )

    setup_preferences_migration = connection.execute(
        "SELECT name FROM schema_migrations WHERE version = 19"
    ).fetchone()
    legacy_setup_preferences_migrations = {
        "structured scan guidance context",
        "idempotent scan lifecycle requests",
    }
    if (
        setup_preferences_migration is not None
        and setup_preferences_migration["name"] in legacy_setup_preferences_migrations
    ):
        migration_sql = next(sql for version, _, sql in MIGRATIONS if version == 19)
        for statement in sql_statements(migration_sql):
            connection.execute(statement.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1))
        connection.execute(
            "UPDATE schema_migrations SET name = ? WHERE version = 19 AND name = ?",
            ("persist setup workspace preference", setup_preferences_migration["name"]),
        )

    phase_progress_migration = connection.execute(
        "SELECT name FROM schema_migrations WHERE version = 20"
    ).fetchone()
    legacy_phase_progress_migrations = {
        "retain superseded scan lifecycle requests",
        "threat model publication receipts",
    }
    if (
        phase_progress_migration is not None
        and phase_progress_migration["name"] in legacy_phase_progress_migrations
    ):
        add_column_if_missing(
            connection,
            "scan_progress",
            "phase_items_total",
            "INTEGER NOT NULL DEFAULT 0 CHECK (phase_items_total >= 0)",
        )
        add_column_if_missing(
            connection,
            "scan_progress",
            "phase_items_completed",
            "INTEGER NOT NULL DEFAULT 0 "
            "CHECK (phase_items_completed >= 0 AND phase_items_completed <= phase_items_total)",
        )
        add_column_if_missing(
            connection,
            "scan_progress",
            "phase_progress_unit",
            "TEXT CHECK (phase_progress_unit IS NULL OR phase_progress_unit IN ("
            "'checks', 'threat_surfaces', 'review_receipts', 'candidate_findings', "
            "'validated_findings', 'report_artifacts'))",
        )
        connection.execute(
            "UPDATE schema_migrations SET name = ? WHERE version = 20 AND name = ?",
            ("phase-specific scan progress", phase_progress_migration["name"]),
        )

    preflight_progress_migration = connection.execute(
        "SELECT name FROM schema_migrations WHERE version = 21"
    ).fetchone()
    legacy_preflight_progress_migrations = {
        "scan progress projection and activity",
        "deep coordinator manifest receipts",
    }
    if (
        preflight_progress_migration is not None
        and preflight_progress_migration["name"] in legacy_preflight_progress_migrations
    ):
        add_column_if_missing(
            connection,
            "scan_progress",
            "preflight_issues_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )
        add_column_if_missing(
            connection,
            "scan_progress",
            "preflight_checks_total",
            "INTEGER NOT NULL DEFAULT 0 CHECK (preflight_checks_total >= 0)",
        )
        add_column_if_missing(
            connection,
            "scan_progress",
            "preflight_checks_completed",
            "INTEGER NOT NULL DEFAULT 0 CHECK (preflight_checks_completed >= 0 "
            "AND preflight_checks_completed <= preflight_checks_total)",
        )
        connection.execute(
            "UPDATE schema_migrations SET name = ? WHERE version = 21 AND name = ?",
            ("current scan preflight state", preflight_progress_migration["name"]),
        )

    scan_recipe_migration = connection.execute(
        "SELECT name FROM schema_migrations WHERE version = 22"
    ).fetchone()
    if (
        scan_recipe_migration is not None
        and scan_recipe_migration["name"] == "dynamic scan execution profiles"
    ):
        add_column_if_missing(connection, "scans", "recipe_json", "TEXT")
        add_column_if_missing(
            connection,
            "scans",
            "parent_scan_id",
            "TEXT REFERENCES scans(id) ON DELETE SET NULL",
        )
        connection.execute(
            "UPDATE schema_migrations SET name = ? WHERE version = 22 AND name = ?",
            ("replayable scan launch recipes", "dynamic scan execution profiles"),
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
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(deep_scan_runs)")}
    threshold_missing = "stop_after_consecutive_errors" not in columns
    add_column_if_missing(
        connection,
        "deep_scan_runs",
        "stop_after_consecutive_errors",
        "INTEGER NOT NULL DEFAULT 1 CHECK (stop_after_consecutive_errors >= 1)",
    )
    if threshold_missing:
        connection.execute(
            "UPDATE deep_scan_runs SET stop_after_consecutive_errors = stop_after_no_new"
        )
    add_column_if_missing(
        connection,
        "deep_scan_runs",
        "consecutive_errors",
        "INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_errors >= 0)",
    )


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
        if statement.startswith("ALTER TABLE workspaces"):
            add_column_if_missing(
                connection,
                "workspaces",
                "target_id",
                "TEXT REFERENCES security_targets(id)",
            )
            continue
        if statement.startswith("ALTER TABLE scans"):
            add_column_if_missing(
                connection,
                "scans",
                "target_id",
                "TEXT REFERENCES security_targets(id)",
            )
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
