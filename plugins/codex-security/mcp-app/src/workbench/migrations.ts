import { createHash } from "node:crypto";
import { basename } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import history from "../../../shared/workbench-migrations.json";
import { parseJson, stringifyJson } from "../helpers/json";
import { transaction } from "./transaction";

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

function moveMigration(
  database: DatabaseSync,
  from: number,
  to: number,
  name: string,
): void {
  if (
    !database
      .prepare("SELECT 1 FROM schema_migrations WHERE version = ? AND name = ?")
      .get(from, name)
  )
    return;
  database
    .prepare(
      "UPDATE schema_migrations SET version = ? WHERE version = ? AND name = ?",
    )
    .run(to, from, name);
}

function normalizeExecutionProfiles(database: DatabaseSync): void {
  const scanColumns = columns(database, "scans");
  const workspaceColumns = columns(database, "workspaces");
  const recorded = new Map(
    database
      .prepare(
        "SELECT version, name FROM schema_migrations WHERE version IN (11, 12, 25)",
      )
      .all()
      .map((row) => [Number(row.version), String(row.name)]),
  );
  const modelName = migration(25).name;
  if (recorded.get(25) === "dynamic scan execution profiles") {
    database
      .prepare("UPDATE schema_migrations SET name = ? WHERE version = 25")
      .run(modelName);
    recorded.set(25, modelName);
  }
  const legacyNames = new Map([
    [11, ["scan execution profiles"]],
    [12, ["scan execution profiles", "dynamic scan execution profiles"]],
  ]);
  const legacyHistory = [...legacyNames].some(([version, names]) =>
    names.includes(recorded.get(version) ?? ""),
  );
  const legacyColumns =
    scanColumns.has("execution_model") ||
    workspaceColumns.has("execution_model") ||
    workspaceColumns.has("reasoning_effort");
  if (!legacyHistory && !legacyColumns) return;
  const supported = new Map([
    [11, ["deep scan orchestration state", "scan execution profiles"]],
    [
      12,
      [
        "scan continuation threads",
        "scan execution profiles",
        "dynamic scan execution profiles",
      ],
    ],
    [25, [modelName]],
  ]);
  const invalidHistory = [...supported].some(
    ([version, names]) =>
      recorded.has(version) && !names.includes(recorded.get(version)!),
  );
  const validColumns = [scanColumns, workspaceColumns].every(
    (names) =>
      names.has("execution_model") &&
      names.has("reasoning_effort") &&
      !names.has("legacy_execution_model") &&
      !names.has("legacy_reasoning_effort"),
  );
  if (
    invalidHistory ||
    (legacyColumns && !validColumns) ||
    (legacyHistory && !legacyColumns)
  ) {
    throw new Error(
      "The Codex Security database has an unsupported execution-profile migration history.",
    );
  }
  for (const table of ["workspaces", "scans"]) {
    database.exec(`ALTER TABLE ${table} RENAME COLUMN execution_model TO legacy_execution_model;
      ALTER TABLE ${table} RENAME COLUMN reasoning_effort TO legacy_reasoning_effort;`);
  }
  repairAdditive(database, 25);
  database.exec(`UPDATE scans SET model = COALESCE(model, legacy_execution_model),
    reasoning_effort = COALESCE(reasoning_effort, legacy_reasoning_effort)`);
  const remove = database.prepare(
    "DELETE FROM schema_migrations WHERE version = ? AND name = ?",
  );
  for (const [version, names] of legacyNames)
    for (const name of names) remove.run(version, name);
  if (!recorded.has(25)) {
    database
      .prepare(
        "INSERT INTO schema_migrations (version, name, applied_at) VALUES (25, ?, ?)",
      )
      .run(modelName, new Date().toISOString());
  }
}

function normalizeHistory(database: DatabaseSync): void {
  const mirror = database
    .prepare(
      "SELECT version, name FROM schema_migrations WHERE version BETWEEN 29 AND 32 ORDER BY version",
    )
    .all();
  const mirrorNames = new Map([
    [29, "freeze stopped scan source digests"],
    [30, "separate deep scan publication failures"],
  ]);
  if (mirror.some((row) => mirrorNames.get(Number(row.version)) === row.name)) {
    if (
      mirror.length !== 2 ||
      mirror.some((row) => mirrorNames.get(Number(row.version)) !== row.name)
    ) {
      throw new Error(
        "The Codex Security database has an unsupported mirror migration history.",
      );
    }
    for (const [from, to] of [
      [30, 32],
      [29, 31],
    ])
      moveMigration(database, from, to, mirrorNames.get(from)!);
  }
  moveMigration(
    database,
    33,
    40,
    "index finding identity and comparison history",
  );
  moveMigration(database, 25, 26, "persist scan completion warnings");
  moveMigration(database, 12, 20, "phase-specific scan progress");
  normalizeExecutionProfiles(database);
  moveMigration(database, 13, 21, "current scan preflight state");
  const shadowed = new Map([
    [18, ["scan target summaries"]],
    [
      19,
      [
        "structured scan guidance context",
        "idempotent scan lifecycle requests",
      ],
    ],
    [
      20,
      [
        "retain superseded scan lifecycle requests",
        "threat model publication receipts",
      ],
    ],
    [
      21,
      [
        "scan progress projection and activity",
        "deep coordinator manifest receipts",
      ],
    ],
    [22, ["dynamic scan execution profiles"]],
  ]);
  const lookup = database.prepare(
    "SELECT name FROM schema_migrations WHERE version = ?",
  );
  for (const [version, names] of shadowed) {
    const name = lookup.get(version)?.name;
    if (typeof name !== "string" || !names.includes(name)) continue;
    if (version === 18) database.exec(migration(version).statements.join("\n"));
    else if (version === 19) {
      for (const sql of migration(version).statements)
        database.exec(
          sql.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS "),
        );
    } else repairAdditive(database, version);
    database
      .prepare("UPDATE schema_migrations SET name = ? WHERE version = ?")
      .run(migration(version).name, version);
  }
  if (lookup.get(2)?.name !== "finding management schema") return;
  const expected = new Map([
    [2, "finding management schema"],
    [3, "scan handoff delivery claims"],
    [4, "finding remediation action claims"],
    [5, "scan target snapshot digests"],
  ]);
  const legacy = database
    .prepare(
      "SELECT version, name FROM schema_migrations WHERE version BETWEEN 2 AND 5",
    )
    .all();
  if (legacy.some((row) => expected.get(Number(row.version)) !== row.name)) {
    throw new Error(
      "The Codex Security database has an unsupported pre-release migration history.",
    );
  }
  database.exec("DELETE FROM schema_migrations WHERE version = 5");
  for (const [from, to] of [
    [4, 5],
    [3, 4],
    [2, 3],
  ])
    moveMigration(database, from, to, expected.get(from)!);
  repairAdditive(database, 2);
  addColumn(
    database,
    "ALTER TABLE scans ADD COLUMN target_snapshot_digest TEXT;",
  );
  database
    .prepare(
      "INSERT INTO schema_migrations (version, name, applied_at) VALUES (2, ?, ?)",
    )
    .run(migration(2).name, new Date().toISOString());
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
