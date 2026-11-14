import { createHash } from "node:crypto";
import { basename } from "node:path";
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

// Python owns the repository-dependent migrations 67–71. Migration 72 only uses
// the external source tables that both workbench runtimes already maintain.
export const migrations: readonly Migration[] = history.filter(
  (item) => item.version <= 66 || item.version === 72,
);
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

function addColumn(database: DatabaseSync, statement: string): boolean {
  const [, table, column] = /^ALTER TABLE\s+(\w+)\s+ADD COLUMN\s+(\w+)/u.exec(
    statement,
  )!;
  if (columns(database, table).has(column)) return false;
  database.exec(statement);
  return true;
}

function applyRepairStatement(database: DatabaseSync, statement: string): void {
  if (statement.startsWith("ALTER TABLE ")) addColumn(database, statement);
  else
    database.exec(
      statement.replace(
        /^CREATE (UNIQUE INDEX|INDEX|TABLE) /u,
        "CREATE $1 IF NOT EXISTS ",
      ),
    );
}

function repairSchema(database: DatabaseSync, version: number): void {
  for (const statement of migration(version).statements)
    applyRepairStatement(database, statement);
}

function normalizeHistory(database: DatabaseSync): void {
  for (const query of repairPlan) {
    for (const { operation, value } of database
      .prepare(query.join("\n"))
      .all({ ":history": repairHistory })) {
      if (operation === "error") throw new Error(String(value));
      if (operation === "additive") repairSchema(database, Number(value));
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
  for (const statement of migration(11).statements) {
    if (statement.startsWith("UPDATE scans") && !missingOwner) continue;
    applyRepairStatement(database, statement);
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
  repairSchema(database, 16);
  database.exec(
    "UPDATE scans SET target_id = NULL WHERE target_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM security_targets WHERE security_targets.id = scans.target_id)",
  );
  return true;
}

export function stableTargetId(path: string): string {
  return (
    "target_sha256_" +
    createHash("sha256")
      .update("local-workspace\0" + path)
      .digest("hex")
  );
}

function backfillTargets(database: DatabaseSync): void {
  const validatedWorkspace = columns(database, "workspaces").has(
    "target_path_unvalidated",
  )
    ? " AND target_path_unvalidated = 0"
    : "";
  const targets = database
    .prepare(
      "SELECT target_path FROM workspaces WHERE target_path IS NOT NULL" +
        validatedWorkspace +
        " UNION SELECT target_path FROM scans",
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
      id = stableTargetId(path);
      const timestamp = new Date().toISOString();
      insert.run(id, path, basename(path), timestamp, timestamp);
    }
    for (const table of ["workspaces", "scans"]) {
      database
        .prepare(
          `UPDATE ${table} SET target_id = ? WHERE target_path = ? AND target_id IS NULL` +
            (table === "workspaces" ? validatedWorkspace : ""),
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
  // run() also returns the connection's last inserted row ID after an UPDATE.
  update.setReadBigInts(true);
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
        // Preserve the original one-line index declaration in sqlite_schema.
        for (const statement of migration(6).statements)
          applyRepairStatement(database, statement.replaceAll("\n", " "));
      } else if (item.version === 16) backfill = repairStableTargets(database);
      else if (applied.has(item.version)) {
        if (
          [
            2, 12, 13, 26, 28, 31, 32, 42, 47, 50, 54, 55, 58, 59, 60, 61, 76,
          ].includes(item.version)
        )
          repairSchema(database, item.version);
        else if (item.version === 11) repairDeepScan(database);
      } else {
        database.exec(item.statements.join("\n"));
        if (item.version === 38) migrateWorkflowResults(database);
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
      const [threshold, count, backfillThreshold] = migration(27).statements;
      if (addColumn(database, threshold)) database.exec(backfillThreshold);
      addColumn(database, count);
    }
    if (backfill) backfillTargets(database);
  });
}
