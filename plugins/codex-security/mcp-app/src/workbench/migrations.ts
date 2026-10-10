import { createHash } from "node:crypto";
import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import history from "../../../shared/workbench-migrations.json";
import repairPlan from "../../../shared/workbench-history-repairs.json";
import { parseJson, stringifyJson } from "../helpers/json";
import { transaction } from "./transaction";

const repairHistory = JSON.stringify(history);

export interface Migration {
  version: number;
  name: string;
  statements: readonly string[];
}

export const migrations: readonly Migration[] = history;
const migration = (version: number) =>
  migrations.find((item) => item.version === version)!;

function columns(database: DatabaseSync, table: string): Set<string> {
  return new Set(
    database
      .prepare(`PRAGMA table_info(${table})`)
      .all()
      .map((row) => String(row.name)),
  );
}

function addColumn(database: DatabaseSync, statement: string): void {
  const [, table, column] = /^ALTER TABLE\s+(\w+)\s+ADD COLUMN\s+(\w+)/u.exec(
    statement,
  )!;
  if (!columns(database, table).has(column)) database.exec(statement);
}

function repairAdditive(database: DatabaseSync, version: number): void {
  for (const statement of migration(version).statements)
    addColumn(database, statement);
}

function normalizeHistory(database: DatabaseSync): void {
  for (const query of repairPlan) {
    for (const { operation, value } of database
      .prepare(query.join("\n"))
      .all({ ":history": repairHistory })) {
      if (operation === "error") throw new Error(String(value));
      if (operation === "additive") repairAdditive(database, Number(value));
      else if (operation === "column") addColumn(database, String(value));
      else if (operation === "timestamp")
        database.prepare(String(value)).run(new Date().toISOString());
      else database.exec(String(value));
    }
  }
}

function repairDeepScan(database: DatabaseSync): void {
  const scanColumns = columns(database, "scans");
  const missingOwner = !scanColumns.has("deep_scan_owner_thread_id");
  const existing = new Set(
    database
      .prepare(
        "SELECT name FROM sqlite_master WHERE name LIKE 'deep_scan_%' OR name = 'scans_one_running_deep_per_owner_target'",
      )
      .all()
      .map((row) => row.name),
  );
  const expected = [
    "scans_one_running_deep_per_owner_target",
    "deep_scan_runs",
    "deep_scan_workers",
    "deep_scan_workers_completion_sequence",
    "deep_scan_workers_by_scan_status",
    "deep_scan_dedup_inputs",
  ];
  if (!missingOwner && expected.every((name) => existing.has(name))) return;
  addColumn(
    database,
    "ALTER TABLE scans ADD COLUMN deep_scan_owner_thread_id TEXT;",
  );
  for (const statement of migration(11).statements) {
    if (
      statement.startsWith("ALTER TABLE scans") ||
      (statement.startsWith("UPDATE scans") && !missingOwner)
    )
      continue;
    database.exec(
      statement.replace(
        /^CREATE (UNIQUE INDEX|INDEX|TABLE) /u,
        "CREATE $1 IF NOT EXISTS ",
      ),
    );
    if (
      statement.startsWith("UPDATE scans") &&
      scanColumns.has("continuation_thread_id")
    ) {
      database.exec(
        "UPDATE scans SET deep_scan_owner_thread_id = continuation_thread_id WHERE mode = 'deep' AND status = 'running' AND continuation_thread_id IS NOT NULL",
      );
    }
  }
}

function repairStableTargets(database: DatabaseSync): boolean {
  const existing = database
    .prepare(
      "SELECT name FROM sqlite_master WHERE name IN ('security_targets', 'scans_by_target')",
    )
    .all();
  if (
    columns(database, "workspaces").has("target_id") &&
    columns(database, "scans").has("target_id") &&
    existing.length === 2
  )
    return false;
  for (const statement of migration(16).statements) {
    if (statement.startsWith("ALTER TABLE")) addColumn(database, statement);
    else
      database.exec(
        statement.replace(
          /^CREATE (TABLE|INDEX) /u,
          "CREATE $1 IF NOT EXISTS ",
        ),
      );
  }
  database.exec(
    "UPDATE scans SET target_id = NULL WHERE target_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM security_targets WHERE security_targets.id = scans.target_id)",
  );
  return true;
}

function backfillTargets(database: DatabaseSync): void {
  const targets = database
    .prepare(
      "SELECT target_path FROM workspaces WHERE target_path IS NOT NULL UNION SELECT target_path FROM scans",
    )
    .all();
  const lookup = database.prepare(
    "SELECT id FROM security_targets WHERE current_path = ?",
  );
  const insert = database.prepare(
    "INSERT OR IGNORE INTO security_targets (id, current_path, display_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
  );
  for (const row of targets) {
    const path = String(row.target_path);
    let id = lookup.get(path)?.id;
    if (id === undefined) {
      id =
        "target_sha256_" +
        createHash("sha256")
          .update("local-workspace\0" + path)
          .digest("hex");
      const timestamp = new Date().toISOString();
      insert.run(id, path, basename(path), timestamp, timestamp);
    }
    for (const table of ["workspaces", "scans"]) {
      database
        .prepare(
          `UPDATE ${table} SET target_id = ? WHERE target_path = ? AND target_id IS NULL`,
        )
        .run(id, path);
    }
  }
}

function migrateWorkflowResults(database: DatabaseSync): void {
  const update = database.prepare(
    `UPDATE finding_workflows SET scan_error = ?, publish_error = ?, dedupe_error = ?,
    results_json = ? WHERE rowid = ?`,
  );
  const rows = database.prepare(
    "SELECT rowid, results_json FROM finding_workflows",
  );
  rows.setReadBigInts(true);
  for (const row of rows.all()) {
    const { stages } = parseJson(String(row.results_json)) as {
      stages: Record<
        string,
        { error?: string; result?: unknown; pendingWrite?: unknown }
      >;
    };
    const results: Record<string, unknown> = {};
    for (const [stage, value] of Object.entries(stages)) {
      if ("result" in value) results[stage] = value.result;
    }
    if ("pendingWrite" in stages.dedupe)
      results.dedupePendingWrite = stages.dedupe.pendingWrite;
    // Keep diagnostic strings intact on older SQLite runtimes.
    update.run(
      stages.scan.error ?? null,
      stages.publish.error ?? null,
      stages.dedupe.error ?? null,
      stringifyJson(results),
      row.rowid,
    );
  }
}

function backfillUnindexedSeverityAssessments(database: DatabaseSync): void {
  const rows = database
    .prepare(
      `SELECT classification.scan_id, assessment.finding_id,
    assessment.occurrence_id, finding.fingerprint
    FROM scan_severity_classifications AS classification
    JOIN json_each(classification.finding_ids_json) AS selected
    JOIN finding_severity_assessments AS assessment ON assessment.finding_id = selected.value
    JOIN findings AS finding ON finding.id = assessment.finding_id`,
    )
    .all();
  const insert =
    database.prepare(`INSERT OR IGNORE INTO scan_severity_assessments
    SELECT ?, assessment.* FROM finding_severity_assessments AS assessment
    WHERE assessment.finding_id = ?`);
  for (const row of rows) {
    // Classification may precede indexing the scan's occurrences.
    const occurrence = `occ_${createHash("sha256").update(`${row.scan_id}\0${row.fingerprint}`).digest("hex").slice(0, 24)}`;
    if (row.occurrence_id === occurrence)
      insert.run(row.scan_id, row.finding_id);
  }
}

function backfillCompositionChildren(database: DatabaseSync): void {
  // Stored paths also cover archived scans and outputs that no longer exist.
  const children = database
    .prepare(
      `SELECT children.id, children.scan_dir, parents.scan_dir AS parent_scan_dir
    FROM scans AS children JOIN scans AS parents ON parents.id = children.parent_scan_id
    WHERE parents.mode = 'deep' AND children.mode = 'standard'`,
    )
    .all();
  for (const child of children) {
    let childDirectory = String(child.scan_dir);
    const parentDirectory = String(child.parent_scan_dir);
    const previousParent = dirname(dirname(dirname(dirname(childDirectory))));
    if (
      dirname(childDirectory) ===
        join(previousParent, "artifacts", "deep-scan", "passes") &&
      dirname(parentDirectory) === dirname(previousParent) &&
      basename(parentDirectory).startsWith(
        `${basename(previousParent)}.previous-`,
      )
    ) {
      const archivedChild = join(
        parentDirectory,
        relative(previousParent, childDirectory),
      );
      for (const artifact of database
        .prepare("SELECT kind, path FROM scan_artifacts WHERE scan_id = ?")
        .all(child.id)) {
        const suffix = relative(childDirectory, String(artifact.path));
        if (
          !isAbsolute(suffix) &&
          suffix !== ".." &&
          !suffix.startsWith(`..${sep}`)
        )
          database
            .prepare(
              "UPDATE scan_artifacts SET path = ? WHERE scan_id = ? AND kind = ?",
            )
            .run(join(archivedChild, suffix), child.id, artifact.kind);
      }
      database
        .prepare("UPDATE scans SET scan_dir = ? WHERE id = ?")
        .run(archivedChild, child.id);
      childDirectory = archivedChild;
    }
    if (
      dirname(childDirectory) ===
      join(parentDirectory, "artifacts", "deep-scan", "passes")
    )
      database
        .prepare("UPDATE scans SET parent_scan_role = 'deep_pass' WHERE id = ?")
        .run(child.id);
  }
  // Repair pass findings published by older indexers, preserving earlier imports.
  const findings = database
    .prepare(
      `SELECT DISTINCT findings.id FROM findings
    JOIN finding_occurrences AS occurrence ON occurrence.finding_id = findings.id
    JOIN scans ON scans.id = occurrence.scan_id
    WHERE scans.parent_scan_role = 'deep_pass'
      AND findings.details_json = occurrence.details_json
      AND EXISTS (SELECT 1 FROM finding_occurrences AS original
        WHERE original.finding_id = findings.id AND original.created_at = findings.created_at)
      AND NOT EXISTS (SELECT 1 FROM finding_embeddings WHERE finding_id = findings.id)`,
    )
    .all();
  for (const finding of findings) {
    database
      .prepare(
        `DELETE FROM finding_repositories WHERE finding_id = ?
      AND repository_id IN (
        SELECT scans.target_id FROM finding_occurrences AS occurrence
        JOIN scans ON scans.id = occurrence.scan_id
        WHERE occurrence.finding_id = ? AND scans.parent_scan_role = 'deep_pass')
      AND repository_id NOT IN (
        SELECT scans.target_id FROM finding_occurrences AS occurrence
        JOIN scans ON scans.id = occurrence.scan_id
        WHERE occurrence.finding_id = ? AND scans.parent_scan_role IS NOT 'deep_pass'
          AND scans.target_id IS NOT NULL)`,
      )
      .run(finding.id, finding.id, finding.id);
    const publicOccurrence = database
      .prepare(
        `SELECT occurrence.details_json, occurrence.created_at
      FROM finding_occurrences AS occurrence JOIN scans ON scans.id = occurrence.scan_id
      WHERE occurrence.finding_id = ? AND scans.parent_scan_role IS NOT 'deep_pass'
        AND occurrence.details_json != '{}'
      ORDER BY occurrence.created_at DESC, occurrence.id DESC LIMIT 1`,
      )
      .get(finding.id);
    if (publicOccurrence)
      database
        .prepare(
          "UPDATE findings SET details_json = ?, updated_at = ? WHERE id = ?",
        )
        .run(
          publicOccurrence.details_json,
          publicOccurrence.created_at,
          finding.id,
        );
    else if (
      !database
        .prepare("SELECT 1 FROM finding_repositories WHERE finding_id = ?")
        .get(finding.id)
    )
      database
        .prepare("UPDATE findings SET details_json = NULL WHERE id = ?")
        .run(finding.id);
  }
}

export function applyMigrations(
  database: DatabaseSync,
  selected: readonly Migration[] = migrations,
  immediate = false,
): void {
  transaction(database, immediate ? "BEGIN IMMEDIATE" : "BEGIN", () => {
    database.exec(
      "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)",
    );
    normalizeHistory(database);
    const applied = new Set(
      database
        .prepare("SELECT version FROM schema_migrations")
        .all()
        .map((row) => Number(row.version)),
    );
    let backfill = false;
    for (const item of selected) {
      if (item.version === 6) {
        addColumn(
          database,
          "ALTER TABLE workspaces ADD COLUMN thread_id TEXT;",
        );
        database.exec(
          "CREATE INDEX IF NOT EXISTS workspaces_by_thread_and_updated_at ON workspaces(thread_id, updated_at DESC)",
        );
      } else if (item.version === 16) backfill = repairStableTargets(database);
      else if (applied.has(item.version)) {
        if ([2, 12, 13, 26, 28, 31, 32, 47].includes(item.version))
          repairAdditive(database, item.version);
        else if (item.version === 11) repairDeepScan(database);
      } else {
        database.exec(item.statements.join("\n"));
        if (item.version === 38) migrateWorkflowResults(database);
        else if ([51, 55, 56].includes(item.version))
          backfillCompositionChildren(database);
        else if (item.version === 54)
          backfillUnindexedSeverityAssessments(database);
      }
      if (!applied.has(item.version)) {
        database
          .prepare(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
          )
          .run(item.version, item.name, new Date().toISOString());
      }
    }
    if (applied.has(27)) {
      const [threshold, count] = migration(27).statements;
      const missing = !columns(database, "deep_scan_runs").has(
        "stop_after_consecutive_errors",
      );
      addColumn(database, threshold);
      if (missing)
        database.exec(
          "UPDATE deep_scan_runs SET stop_after_consecutive_errors = stop_after_no_new",
        );
      addColumn(database, count);
    }
    if (backfill) backfillTargets(database);
  });
}
