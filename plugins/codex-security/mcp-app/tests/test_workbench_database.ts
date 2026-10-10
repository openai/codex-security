import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { copyFile, mkdir, readFile, stat, symlink } from "node:fs/promises";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { after, test, type TestContext } from "node:test";
import { Worker } from "node:worker_threads";
import { importSource } from "./import-module.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";
import type * as Database from "../src/workbench/database.ts";
import type * as Migrations from "../src/workbench/migrations.ts";

const { openWorkbenchDatabase, databaseInfo } = (await importSource(
  "src/workbench/database.ts",
  {
    define: {
      // Native bindings are installed beside the generated server bundle.
      "import.meta.url": JSON.stringify(
        new URL(
          "../../../../sdk/typescript/_bundled_plugin/mcp/server.mjs",
          import.meta.url,
        ).href,
      ),
    },
  },
)) as typeof Database;
const { applyMigrations, migrations } = (await importSource(
  "src/workbench/migrations.ts",
)) as typeof Migrations;
// Frozen from 7fa0980411d89d7d1f2aafd5b2cbae941f539724, before severity migration 43.
const historicalRepositoryMigrations: readonly Migrations.Migration[] =
  JSON.parse(
    await readFile(
      new URL(
        "./fixtures/pre-severity-repository-migrations.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
const temporary = createTemporaryDirectories(true);
after(() => temporary.cleanup());

function memory(t: TestContext, version?: number) {
  const database = new DatabaseSync(":memory:");
  t.after(() => database.close());
  database.exec("PRAGMA foreign_keys = ON");
  if (version !== undefined)
    applyMigrations(
      database,
      migrations.filter((item) => item.version <= version),
    );
  return database;
}

function schema(database: DatabaseSync) {
  return database
    .prepare("SELECT name, sql FROM sqlite_master ORDER BY name")
    .all();
}

function assertMigrationNames(database: DatabaseSync, ...versions: number[]) {
  for (const version of versions)
    assert.equal(
      database
        .prepare("SELECT name FROM schema_migrations WHERE version = ?")
        .get(version)?.name,
      migrations[version - 1].name,
    );
}

function insertScan(database: DatabaseSync, target = "/synthetic/repository") {
  database
    .prepare(
      "INSERT INTO workspaces (id, target_path, created_at, updated_at) VALUES ('workspace', ?, 'created', 'updated')",
    )
    .run(target);
  database
    .prepare(
      `INSERT INTO scans (id, workspace_id, target_path, target_revision,
    scope, mode, scan_dir, status, phase, started_at, created_at, updated_at)
    VALUES ('scan', 'workspace', ?, 'revision', '.', 'deep', '/synthetic/scan',
      'running', 'discovery', 'started', 'created', 'updated')`,
    )
    .run(target);
}

test("retains SQLite open errors and recovery guidance", async () => {
  const directory = await temporary.create("workbench-database-error-");
  const databasePath = join(directory, "workbench.sqlite3");
  await mkdir(databasePath);
  await assert.rejects(
    openWorkbenchDatabase(databasePath),
    (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.equal((error as Error & { errcode: number }).errcode, 14);
      assert.equal(
        (error as Error & { code: string }).code,
        "ERR_SQLITE_ERROR",
      );
      assert.ok(error.message.includes("unable to open database file"));
      assert.ok(error.message.includes(databasePath));
      assert.ok(error.message.includes("CODEX_SECURITY_STATE_DIR"));
      return true;
    },
  );
});

test("opens a private WAL database at the configured state path", async () => {
  const directory = await temporary.create("workbench-database-");
  const home = join(directory, "codex-home");
  const { databasePath } = await databaseInfo(
    join(home, "state/plugins/codex-security"),
  );
  assert.equal(
    databasePath,
    join(home, "state/plugins/codex-security/workbench.sqlite3"),
  );
  const database = await openWorkbenchDatabase(databasePath);
  try {
    assert.equal(
      database.prepare("PRAGMA foreign_keys").get()?.foreign_keys,
      1,
    );
    assert.equal(database.prepare("PRAGMA busy_timeout").get()?.timeout, 5000);
    assert.equal(
      database.prepare("PRAGMA journal_mode").get()?.journal_mode,
      "wal",
    );
    assertMigrationNames(database, ...migrations.map(({ version }) => version));
    assert.deepEqual(database.prepare("PRAGMA foreign_key_check").all(), []);
    if (process.platform !== "win32") {
      assert.equal((await stat(databasePath)).mode & 0o777, 0o600);
      for (const part of [
        "",
        "state",
        "state/plugins",
        "state/plugins/codex-security",
      ])
        assert.equal((await stat(join(home, part))).mode & 0o777, 0o700);
    }
  } finally {
    database.close();
  }
  const override = join(directory, "existing-state");
  await mkdir(override, { mode: 0o755 });
  assert.equal(
    (await databaseInfo(override)).databasePath,
    join(override, "workbench.sqlite3"),
  );
  if (process.platform !== "win32")
    assert.equal((await stat(override)).mode & 0o777, 0o755);
});

test("every released schema upgrades to the same current schema and remains idempotent", (t) => {
  const current = memory(t);
  applyMigrations(current);
  const expected = schema(current);
  for (const version of [0, ...migrations.map((item) => item.version)]) {
    const database = memory(t, version);
    applyMigrations(database);
    assert.deepEqual(
      schema(database),
      expected,
      `upgrade from version ${version}`,
    );
    const history = database
      .prepare("SELECT * FROM schema_migrations ORDER BY version")
      .all();
    applyMigrations(database);
    assert.deepEqual(
      database
        .prepare("SELECT * FROM schema_migrations ORDER BY version")
        .all(),
      history,
    );
    assert.deepEqual(database.prepare("PRAGMA foreign_key_check").all(), []);
  }
});

test("configured state paths use native parent traversal semantics", async () => {
  const directory = await temporary.create("workbench-symlink-");
  const actual = join(directory, "actual");
  const child = join(actual, "child");
  await mkdir(child, { recursive: true });
  const alias = join(directory, "alias");
  await symlink(
    child,
    alias,
    process.platform === "win32" ? "junction" : "dir",
  );
  const parent = process.platform === "win32" ? directory : actual;
  assert.equal(
    (await databaseInfo(alias + "/../state")).databasePath,
    join(parent, "state", "workbench.sqlite3"),
  );
  assert.equal(
    (await databaseInfo(alias + "/../state/plugins/codex-security"))
      .databasePath,
    join(parent, "state/plugins/codex-security/workbench.sqlite3"),
  );
});

test("configured directory links create missing destinations privately", async () => {
  const directory = await temporary.create("workbench-dangling-");
  for (const nested of [false, true]) {
    const destination = join(directory, `destination-${nested}`, "state");
    const alias = join(directory, `alias-${nested}`);
    await symlink(
      destination,
      alias,
      process.platform === "win32" ? "junction" : "dir",
    );
    const result = await databaseInfo(nested ? join(alias, "nested") : alias);
    assert.equal(
      result.databasePath,
      join(destination, ...(nested ? ["nested"] : []), "workbench.sqlite3"),
    );
    assert.equal((await stat(result.databasePath)).isFile(), true);
    if (process.platform !== "win32")
      assert.equal((await stat(destination)).mode & 0o777, 0o700);
  }
  if (process.platform !== "win32") {
    const state = join(directory, "trailing-state");
    const alias = join(directory, "trailing-alias");
    const destination = join(directory, "trailing-destination");
    await symlink("trailing-alias/", state);
    await symlink("trailing-destination", alias);
    const result = await databaseInfo(state);
    assert.equal(result.databasePath, join(destination, "workbench.sqlite3"));
    assert.equal((await stat(result.databasePath)).isFile(), true);
    assert.equal((await stat(destination)).mode & 0o777, 0o700);
    const cycle = join(directory, "cycle");
    await symlink(cycle, cycle);
    await assert.rejects(databaseInfo(cycle), { code: "ELOOP" });
  }
});

test(
  "an ASCII state alias opens its raw-byte POSIX target without changing a sibling database",
  { skip: process.platform === "win32" },
  async () => {
    const directory = await temporary.create("workbench-raw-target-");
    const target = Buffer.concat([
      Buffer.from(directory + "/state-"),
      Buffer.from([0xff]),
    ]);
    await mkdir(target);
    const alias = join(directory, "alias");
    await symlink(target, alias);
    const sibling = join(directory, "state-\ufffd");
    await mkdir(sibling);
    const existing = new DatabaseSync(join(alias, "workbench.sqlite3"));
    existing.exec(
      "CREATE TABLE retained (value TEXT); INSERT INTO retained VALUES ('original')",
    );
    existing.close();
    const result = await databaseInfo(alias);
    assert.equal(
      result.databasePath,
      directory + "/state-\udcff/workbench.sqlite3",
    );
    const database = new DatabaseSync(join(alias, "workbench.sqlite3"));
    try {
      assert.equal(
        database.prepare("SELECT value FROM retained").get()?.value,
        "original",
      );
      assertMigrationNames(
        database,
        ...migrations.map(({ version }) => version),
      );
    } finally {
      database.close();
    }
    await assert.rejects(stat(join(sibling, "workbench.sqlite3")), {
      code: "ENOENT",
    });
  },
);

test("preview index history does not skip findings, embedding or checkpoint migrations", (t) => {
  const database = memory(t);
  applyMigrations(database, [
    ...migrations.filter((item) => item.version <= 32),
    { ...migrations.find((item) => item.version === 40)!, version: 33 },
  ]);
  database.exec(
    "INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, created_at, updated_at) VALUES ('finding', 'fingerprint', 'rule', 'anchor', 'created', 'updated')",
  );
  const indexes = database
    .prepare(
      "SELECT name, rootpage FROM sqlite_master WHERE name IN ('finding_occurrences_by_finding', 'scan_comparisons_by_after_scan') ORDER BY name",
    )
    .all();
  applyMigrations(database);
  assert.equal(
    database
      .prepare("SELECT details_json FROM findings WHERE id = 'finding'")
      .get()?.details_json,
    null,
  );
  assert.equal(
    database.prepare("SELECT COUNT(*) AS count FROM finding_embeddings").get()
      ?.count,
    0,
  );
  assert.equal(
    database
      .prepare("SELECT COUNT(*) AS count FROM finding_workflow_reviews")
      .get()?.count,
    0,
  );
  assert.deepEqual(
    database
      .prepare(
        "SELECT name, rootpage FROM sqlite_master WHERE name IN ('finding_occurrences_by_finding', 'scan_comparisons_by_after_scan') ORDER BY name",
      )
      .all(),
    indexes,
  );
  assertMigrationNames(database, 33);
});

test("repairs mirror migration numbers without losing publication fields", (t) => {
  const database = memory(t, 28);
  for (const [version, from] of [
    [29, 31],
    [30, 32],
  ]) {
    const item = migrations.find((item) => item.version === from)!;
    database.exec(item.statements.join("\n"));
    database
      .prepare("INSERT INTO schema_migrations VALUES (?, ?, 'original')")
      .run(version, item.name);
  }
  applyMigrations(database);
  assertMigrationNames(database, 29, 30, 31, 32);
  assert.equal(
    database
      .prepare("SELECT applied_at FROM schema_migrations WHERE version = 31")
      .get()?.applied_at,
    "original",
  );
});

test("legacy execution profiles retain values while allowing independent model settings", (t) => {
  for (const version of [11, 12]) {
    const database = memory(t);
    applyMigrations(
      database,
      migrations.filter(
        (item) => item.version < 25 && item.version !== version,
      ),
    );
    for (const table of ["workspaces", "scans"]) {
      database.exec(`ALTER TABLE ${table} ADD COLUMN execution_model TEXT;
        ALTER TABLE ${table} ADD COLUMN reasoning_effort TEXT;`);
    }
    database
      .prepare(
        "INSERT INTO schema_migrations VALUES (?, 'scan execution profiles', 'original')",
      )
      .run(version);
    insertScan(database);
    database.exec(
      "UPDATE scans SET execution_model = 'synthetic-model', reasoning_effort = 'future-effort'",
    );
    applyMigrations(database, []);
    const row = database
      .prepare(
        "SELECT model, reasoning_effort, legacy_execution_model, legacy_reasoning_effort FROM scans",
      )
      .get()!;
    assert.deepEqual(
      { ...row },
      {
        model: "synthetic-model",
        reasoning_effort: "future-effort",
        legacy_execution_model: "synthetic-model",
        legacy_reasoning_effort: "future-effort",
      },
    );
    database.exec("UPDATE scans SET model = NULL, reasoning_effort = 'high'");
    applyMigrations(database);
    assertMigrationNames(database, version);
  }
});

test("rejects unsupported history without partially changing its schema or rows", (t) => {
  const database = memory(t, 24);
  database.exec(
    "UPDATE schema_migrations SET name = 'scan execution profiles' WHERE version = 11",
  );
  const before = schema(database);
  const history = database
    .prepare("SELECT * FROM schema_migrations ORDER BY version")
    .all();
  assert.throws(
    () => applyMigrations(database),
    /unsupported execution-profile migration history/u,
  );
  assert.deepEqual(schema(database), before);
  assert.deepEqual(
    database.prepare("SELECT * FROM schema_migrations ORDER BY version").all(),
    history,
  );
});

test("repairs pre-release numbering and shadowed migrations without repeating data cleanup", (t) => {
  const database = memory(t);
  applyMigrations(
    database,
    migrations.filter((item) => item.version <= 5 && item.version !== 2),
  );
  database.exec(
    "UPDATE schema_migrations SET version = version - 1 WHERE version BETWEEN 3 AND 5",
  );
  database.exec(
    "INSERT INTO schema_migrations VALUES (5, 'scan target snapshot digests', 'original')",
  );
  applyMigrations(database);
  insertScan(database);
  database.exec(`UPDATE scans SET handoff_status = 'delivered', handoff_claimed_at = 'old', handoff_claim_token = 'old';
    UPDATE schema_migrations SET name = 'scan target summaries' WHERE version = 18;
    UPDATE schema_migrations SET name = 'idempotent scan lifecycle requests' WHERE version = 19;
    UPDATE schema_migrations SET name = 'threat model publication receipts' WHERE version = 20;
    UPDATE schema_migrations SET name = 'deep coordinator manifest receipts' WHERE version = 21;
    UPDATE schema_migrations SET name = 'dynamic scan execution profiles' WHERE version = 22;
    DROP TABLE setup_preferences;
    ALTER TABLE scan_progress DROP COLUMN phase_items_completed;
    ALTER TABLE scan_progress DROP COLUMN phase_items_total;
    ALTER TABLE scan_progress DROP COLUMN phase_progress_unit;
    ALTER TABLE scan_progress DROP COLUMN preflight_issues_json;
    ALTER TABLE scans DROP COLUMN recipe_json;`);
  applyMigrations(database);
  assert.equal(
    database.prepare("SELECT handoff_claim_token FROM scans").get()
      ?.handoff_claim_token,
    null,
  );
  assert.equal(
    database.prepare("SELECT COUNT(*) AS count FROM setup_preferences").get()
      ?.count,
    0,
  );
  assertMigrationNames(database, 2, 3, 4, 5, 18, 19, 20, 21, 22);
  database.exec("UPDATE scans SET handoff_claim_token = 'current'");
  applyMigrations(database);
  assert.equal(
    database.prepare("SELECT handoff_claim_token FROM scans").get()
      ?.handoff_claim_token,
    "current",
  );
});

test("relocates released warning and progress histories while retaining their data", (t) => {
  const database = memory(t);
  applyMigrations(database);
  insertScan(database);
  database.exec(`UPDATE scans SET completion_warnings_json = '["retained warning"]';
    DELETE FROM schema_migrations WHERE version IN (12, 13, 25);
    ALTER TABLE scans DROP COLUMN continuation_thread_id;
    ALTER TABLE scan_progress DROP COLUMN scope_file_count;
    ALTER TABLE scans DROP COLUMN model;
    ALTER TABLE scans DROP COLUMN reasoning_effort;
    UPDATE schema_migrations SET version = 12 WHERE version = 20;
    UPDATE schema_migrations SET version = 13 WHERE version = 21;
    UPDATE schema_migrations SET version = 25 WHERE version = 26;`);
  applyMigrations(database);
  assert.equal(
    database.prepare("SELECT completion_warnings_json FROM scans").get()
      ?.completion_warnings_json,
    '["retained warning"]',
  );
  assertMigrationNames(database, 12, 13, 20, 21, 25, 26);
});

test("repairs recorded Deep Scan and target migrations and backfills stable identities once", (t) => {
  const database = memory(t);
  applyMigrations(
    database,
    migrations.filter((item) => item.version < 16 && item.version !== 11),
  );
  database.exec(
    "ALTER TABLE scans ADD COLUMN target_id TEXT; INSERT INTO schema_migrations VALUES (11, 'stable scan target identities', 'original')",
  );
  insertScan(database);
  database.exec(
    "UPDATE workspaces SET thread_id = 'owner'; UPDATE scans SET continuation_thread_id = 'continuation', target_id = 'obsolete-id'",
  );
  applyMigrations(database);
  const targetId =
    "target_sha256_" +
    createHash("sha256")
      .update("local-workspace\0/synthetic/repository")
      .digest("hex");
  assert.equal(
    database.prepare("SELECT target_id FROM workspaces").get()?.target_id,
    targetId,
  );
  const scan = database
    .prepare("SELECT target_id, deep_scan_owner_thread_id FROM scans")
    .get()!;
  assert.equal(scan.target_id, targetId);
  assert.equal(scan.deep_scan_owner_thread_id, "continuation");
  assert.deepEqual(database.prepare("PRAGMA foreign_key_check").all(), []);
  database.exec(
    "UPDATE workspaces SET target_id = NULL; UPDATE scans SET target_id = NULL",
  );
  applyMigrations(database);
  assert.equal(
    database.prepare("SELECT target_id FROM scans").get()?.target_id,
    null,
  );
});

test("recorded additive migrations restore missing columns and configured error thresholds", (t) => {
  const database = memory(t, 26);
  insertScan(database);
  database.exec(`INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, status, phase,
    workers, subagents, stop_after_no_new, max_discovery_runs, created_at, updated_at)
    VALUES ('scan', 1, 'v1', 'running', 'discovery', 1, 0, 7, 10, 'created', 'updated')`);
  for (const version of [27, 28, 31, 32, 47])
    database
      .prepare("INSERT INTO schema_migrations VALUES (?, ?, 'original')")
      .run(version, migrations[version - 1].name);
  applyMigrations(database);
  assert.equal(
    database
      .prepare("SELECT stop_after_consecutive_errors FROM deep_scan_runs")
      .get()?.stop_after_consecutive_errors,
    7,
  );
  assert.equal(
    database
      .prepare("SELECT discovery_user_context_json FROM deep_scan_runs")
      .get()?.discovery_user_context_json,
    null,
  );
  database.exec(`UPDATE deep_scan_runs SET stop_after_consecutive_errors = 2,
    discovery_user_context_json = '"Original discovery context"'`);
  applyMigrations(database);
  assert.equal(
    database
      .prepare("SELECT stop_after_consecutive_errors FROM deep_scan_runs")
      .get()?.stop_after_consecutive_errors,
    2,
  );
  assert.equal(
    database
      .prepare("SELECT discovery_user_context_json FROM deep_scan_runs")
      .get()?.discovery_user_context_json,
    '"Original discovery context"',
  );
});

test("workflow and review checkpoints upgrade atomically with their preserved result data", (t) => {
  const database = memory(t, 37);
  const state = {
    repositoryPath: "/synthetic/repository",
    scanRequestDigest: "request",
    scanId: "scan",
    scanDir: "/synthetic/scan",
    artifactDigest: "artifact",
    destination: "local",
    scope: { allRepositories: true },
    stages: {
      scan: { status: "complete", result: { findings: 2 } },
      publish: { status: "failed", error: "diagnostic\0retained tail" },
      dedupe: { status: "running", pendingWrite: { digest: "pending" } },
    },
  };
  const binding = {
    version: 1,
    codexVersion: "1.0.0",
    source: {
      repository: "/synthetic/repository",
      revision: "revision",
      refsDigest: "refs",
      content: "content",
    },
    scope: { repositoryId: "repository", allRepositories: false },
    model: "synthetic-model",
    effort: "high",
    settingsDigest: "settings",
    promptDigest: "prompt",
    contractDigest: "contract",
  };
  const workflowIds = ["workflow", "workflow\0one", "workflow\0two"];
  const reviewKeys = ["review", "review\0one", "review\0two"];
  const states = workflowIds.map((_, index) =>
    JSON.stringify({
      ...state,
      repositoryPath: `${state.repositoryPath}/${index}`,
      stages: {
        ...state.stages,
        scan: { ...state.stages.scan, result: { findings: index } },
      },
    }).replace(
      `"findings":${index}`,
      `"findings":${index},"opaqueId":9007199254740993`,
    ),
  );
  for (const [index, id] of workflowIds.entries()) {
    database
      .prepare(
        "INSERT INTO finding_workflows (rowid, id, state_json, created_at, updated_at) VALUES (?, ?, ?, 'created', 'updated')",
      )
      .run(9007199254740993n + BigInt(index), id, states[index]);
    for (const [keyIndex, key] of reviewKeys.entries()) {
      database
        .prepare(
          "INSERT INTO finding_workflow_reviews (rowid, workflow_id, review_key, binding_json, result_json, created_at) VALUES (?, ?, ?, ?, ?, 'created')",
        )
        .run(
          9007199254740993n + BigInt(index * reviewKeys.length + keyIndex),
          id,
          key,
          JSON.stringify({
            ...binding,
            promptDigest: `prompt-${index}-${keyIndex}`,
          }),
          JSON.stringify({ retained: `${index}-${keyIndex}` }),
        );
    }
  }
  const before = schema(database);
  assert.throws(
    () =>
      applyMigrations(database, [
        ...migrations,
        {
          version: 999,
          name: "failing migration",
          statements: ["SELECT * FROM missing_table;"],
        },
      ]),
    /missing_table/u,
  );
  assert.deepEqual(schema(database), before);
  for (const [index, id] of workflowIds.entries()) {
    assert.equal(
      database
        .prepare("SELECT state_json FROM finding_workflows WHERE id = ?")
        .get(id)?.state_json,
      states[index],
    );
  }
  applyMigrations(database);
  for (const [index, id] of workflowIds.entries()) {
    const workflow = database
      .prepare(
        "SELECT *, json_quote(publish_error) AS publish_error_json FROM finding_workflows WHERE id = ?",
      )
      .get(id)!;
    assert.equal(workflow.repository_path, `${state.repositoryPath}/${index}`);
    assert.equal(workflow.scope_all_repositories, 1);
    assert.equal(
      JSON.parse(String(workflow.publish_error_json)),
      state.stages.publish.error,
    );
    const resultsJson = String(workflow.results_json);
    assert.match(resultsJson, /"opaqueId":\s*9007199254740993/u);
    assert.deepEqual(
      JSON.parse(
        resultsJson.replace(/,\s*"opaqueId":\s*9007199254740993/u, ""),
      ),
      {
        scan: { findings: index },
        dedupePendingWrite: { digest: "pending" },
      },
    );
    for (const [keyIndex, key] of reviewKeys.entries()) {
      const review = database
        .prepare(
          "SELECT * FROM finding_workflow_reviews WHERE workflow_id = ? AND review_key = ?",
        )
        .get(id, key)!;
      assert.equal(review.settings_digest, "settings");
      assert.equal(review.prompt_digest, `prompt-${index}-${keyIndex}`);
      assert.equal(review.source_revision, "revision");
      assert.equal(review.scope_all_repositories, 0);
      assert.equal(
        review.result_json,
        JSON.stringify({ retained: `${index}-${keyIndex}` }),
      );
    }
  }
  assert.deepEqual(database.prepare("PRAGMA foreign_key_check").all(), []);
});

test("a storage failure preserves its error and the original migration state", (t) => {
  const database = memory(t, 37);
  const state = JSON.stringify({
    stages: {
      scan: { status: "completed", result: { data: Array(3000).fill("x") } },
      publish: { status: "pending" },
      dedupe: { status: "pending" },
    },
  });
  database
    .prepare(
      "INSERT INTO finding_workflows (id, state_json, created_at, updated_at) VALUES ('workflow', ?, 'created', 'updated')",
    )
    .run(state);
  const pages = Number(database.prepare("PRAGMA page_count").get()!.page_count);
  database.exec(`PRAGMA max_page_count = ${pages + 5}`);
  assert.throws(() => applyMigrations(database), { errcode: 13 });
  assert.equal(
    database
      .prepare("SELECT MAX(version) AS version FROM schema_migrations")
      .get()!.version,
    37,
  );
  assert.equal(
    database
      .prepare("SELECT state_json FROM finding_workflows WHERE id = 'workflow'")
      .get()!.state_json,
    state,
  );
});

test("an up-to-date database-info reader does not wait for a writer", async () => {
  const directory = await temporary.create("workbench-reader-");
  const first = await databaseInfo(directory);
  const writer = new DatabaseSync(first.databasePath);
  try {
    writer.exec("BEGIN IMMEDIATE; UPDATE workspaces SET updated_at = 'writer'");
    assert.deepEqual(await databaseInfo(directory), first);
  } finally {
    writer.exec("ROLLBACK");
    writer.close();
  }
});

test("retries an upgrade when another process holds the write lock beyond the busy timeout", async () => {
  const directory = await temporary.create("workbench-retry-");
  const databasePath = join(directory, "workbench.sqlite3");
  const old = new DatabaseSync(databasePath);
  applyMigrations(
    old,
    migrations.filter((item) => item.version < 16),
  );
  insertScan(old);
  old.close();
  const writer = new Worker(
    `const { DatabaseSync } = require('node:sqlite');
    const { parentPort, workerData } = require('node:worker_threads');
    const db = new DatabaseSync(workerData);
    db.exec('BEGIN IMMEDIATE'); parentPort.postMessage('locked');
    setTimeout(() => { db.exec('COMMIT'); db.close(); }, 6000);`,
    { eval: true, workerData: databasePath },
  );
  try {
    await once(writer, "message");
    const database = await openWorkbenchDatabase(databasePath);
    try {
      assertMigrationNames(
        database,
        ...migrations.map(({ version }) => version),
      );
      assert.equal(
        database.prepare("SELECT COUNT(*) AS count FROM security_targets").get()
          ?.count,
        1,
      );
    } finally {
      database.close();
    }
  } finally {
    await writer.terminate();
  }
});

function pythonMigrations(databasePath: string, through?: number): void {
  const result = spawnSync(
    process.env.PYTHON?.trim() || "python3",
    [
      "-I",
      "-B",
      "-c",
      `import sqlite3, sys
sys.path.insert(0, sys.argv[1])
import workbench_db, workbench_schema
with sqlite3.connect(sys.argv[2]) as database:
    database.row_factory = sqlite3.Row
    database.execute("PRAGMA foreign_keys = ON")
    workbench_schema.apply_migrations(database,
        tuple(item for item in workbench_db.MIGRATIONS if item[0] <= int(sys.argv[3])),
        workbench_db.now, workbench_db.backfill_security_targets)
`,
      fileURLToPath(new URL("../../scripts", import.meta.url)),
      databasePath,
      String(through ?? 49),
    ],
    { encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr || String(result.error));
}

function storedRows(database: DatabaseSync) {
  return database
    .prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
    )
    .all()
    .map(({ name }) => [
      name,
      database
        .prepare(`SELECT * FROM "${name}"`)
        .all()
        .map((row) => {
          // Independently run initializers use different migration application times.
          if (name === "schema_migrations") delete row.applied_at;
          return row;
        }),
    ]);
}

test("Node initialization leaves repository migration semantics to the Python consumer", async (t) => {
  for (const fixture of [
    "main42",
    "main43",
    "legacy30",
    "legacy31",
    "partial43",
    "current43",
    "current44",
  ] as const) {
    await t.test(fixture, async () => {
      const directory = await temporary.create("workbench-repository-upgrade-");
      const databasePath = join(directory, "workbench.sqlite3");
      const database = new DatabaseSync(databasePath);
      applyMigrations(
        database,
        migrations.filter(
          (item) =>
            item.version <=
            (fixture === "legacy30"
              ? 29
              : fixture === "legacy31"
                ? 30
                : fixture === "main43"
                  ? 43
                  : 42),
        ),
      );
      insertScan(database);
      database.exec(`INSERT INTO security_targets (id,current_path,display_name,created_at,updated_at)
        VALUES ('target','/synthetic/repository','Synthetic repository','created','updated');
        UPDATE workspaces SET target_id='target'; UPDATE scans SET target_id='target';
        UPDATE scans SET status='complete', started_at='2026-01-01T00:00:00Z',
          completed_at='2026-01-01T00:00:01.123456789123z';`);
      if (["legacy30", "legacy31", "partial43"].includes(fixture)) {
        database.exec(
          "ALTER TABLE security_targets ADD COLUMN repository_identity TEXT",
        );
        database.exec(
          "UPDATE security_targets SET repository_identity='unestablished-legacy-identity'",
        );
      }
      if (fixture === "legacy30" || fixture === "legacy31")
        database
          .prepare(
            "INSERT INTO schema_migrations VALUES(?,'persist repository identities','original')",
          )
          .run(fixture === "legacy30" ? 30 : 31);
      database.close();
      if (fixture === "current43" || fixture === "current44") {
        const current = new DatabaseSync(databasePath);
        applyMigrations(
          current,
          historicalRepositoryMigrations.filter(
            (item) => item.version <= (fixture === "current43" ? 43 : 44),
          ),
        );
        assert.equal(
          current
            .prepare("SELECT MAX(version) AS version FROM schema_migrations")
            .get()?.version,
          fixture === "current43" ? 43 : 44,
        );
        current.exec(
          "UPDATE scans SET completion_sequence=77,repository_generation='synthetic-generation'; UPDATE security_targets SET repository_identity='synthetic-generation'",
        );
        current.close();
      }
      const saved = new DatabaseSync(databasePath);
      const originalHistory = saved
        .prepare(
          "SELECT name, applied_at FROM schema_migrations WHERE name IN ('persist repository identities', 'stabilize Linux repository generations') ORDER BY name",
        )
        .all();
      saved.close();
      const controlPath = join(directory, "python.sqlite3");
      await copyFile(databasePath, controlPath);
      pythonMigrations(controlPath);
      await databaseInfo(directory);
      const initialized = new DatabaseSync(databasePath);
      const identity = initialized
        .prepare("SELECT * FROM security_targets")
        .get()?.repository_identity;
      assert.equal(
        identity,
        fixture === "current43" || fixture === "current44"
          ? "synthetic-generation"
          : fixture === "main42" || fixture === "main43"
            ? undefined
            : "unestablished-legacy-identity",
      );
      assert.equal(
        initialized
          .prepare("PRAGMA table_info(scans)")
          .all()
          .some((row) => row.name === "repository_generation"),
        fixture === "current43" || fixture === "current44",
      );
      const beforeRepeat = storedRows(initialized);
      initialized.close();
      await databaseInfo(directory);
      const repeated = new DatabaseSync(databasePath);
      assert.deepEqual(storedRows(repeated), beforeRepeat);
      repeated.close();
      pythonMigrations(databasePath);
      const actual = new DatabaseSync(databasePath);
      const expected = new DatabaseSync(controlPath);
      try {
        assert.deepEqual(storedRows(actual), storedRows(expected));
        for (const row of originalHistory)
          assert.equal(
            actual
              .prepare("SELECT applied_at FROM schema_migrations WHERE name=?")
              .get(row.name!)?.applied_at,
            row.applied_at,
          );
        assert.equal(
          actual
            .prepare("SELECT MAX(version) AS version FROM schema_migrations")
            .get()?.version,
          49,
        );
        assert.equal(
          actual.prepare("SELECT completion_sequence FROM scans").get()
            ?.completion_sequence,
          fixture === "current43" || fixture === "current44" ? 77 : 1,
        );
        assert.deepEqual(actual.prepare("PRAGMA foreign_key_check").all(), []);
      } finally {
        actual.close();
        expected.close();
      }
    });
  }
});

test("Node repository migration-label collisions roll back without changing stored rows", async (t) => {
  for (const [name, setup] of [
    [
      "identity destination",
      "UPDATE schema_migrations SET name='persist repository identities' WHERE version=31; INSERT INTO schema_migrations VALUES(48,'persist repository identities','original')",
    ],
    [
      "generation destination",
      "UPDATE schema_migrations SET name='stabilize Linux repository generations' WHERE version=44; INSERT INTO schema_migrations VALUES(49,'occupied destination','retained')",
    ],
    [
      "identity collision after generation relocation",
      "UPDATE schema_migrations SET name='persist repository identities' WHERE version IN (31,43); UPDATE schema_migrations SET name='stabilize Linux repository generations' WHERE version=44",
    ],
  ] as const)
    await t.test(name, async () => {
      const directory = await temporary.create(
        "workbench-repository-collision-",
      );
      const databasePath = join(directory, "workbench.sqlite3");
      const database = new DatabaseSync(databasePath);
      applyMigrations(database);
      database.exec(setup);
      const beforeSchema = schema(database);
      const beforeRows = storedRows(database);
      const beforeHistory = database
        .prepare("SELECT * FROM schema_migrations ORDER BY version")
        .all();
      database.close();
      await assert.rejects(
        databaseInfo(directory),
        /UNIQUE constraint failed/u,
      );
      const after = new DatabaseSync(databasePath);
      try {
        assert.deepEqual(schema(after), beforeSchema);
        assert.deepEqual(storedRows(after), beforeRows);
        assert.deepEqual(
          after
            .prepare("SELECT * FROM schema_migrations ORDER BY version")
            .all(),
          beforeHistory,
        );
      } finally {
        after.close();
      }
    });
});

test("Node database-info preserves a linked repository's stored43 history for Python", async () => {
  const directory = await temporary.create("workbench-linked-upgrade-");
  const databasePath = join(directory, "workbench.sqlite3");
  const repository = join(directory, "repository");
  const linked = join(directory, "linked");
  const database = new DatabaseSync(databasePath);
  applyMigrations(
    database,
    migrations.filter((item) => item.version <= 42),
  );
  insertScan(database, repository);
  database.exec(
    "INSERT INTO scan_progress (scan_id,updated_at) VALUES ('scan','updated')",
  );
  database.close();
  const scripts = fileURLToPath(new URL("../../scripts", import.meta.url));
  const seeded = spawnSync(
    process.env.PYTHON?.trim() || "python3",
    [
      "-I",
      "-B",
      "-c",
      `
import json, pathlib, sqlite3, subprocess, sys
from datetime import datetime, timezone
sys.path.insert(0, sys.argv[1])
import workbench_db as workbench, workbench_schema as schema, workbench_target_state as state
repository, linked = map(pathlib.Path, sys.argv[3:5])
subprocess.run(['git', 'init', '-q', str(repository)], check=True)
subprocess.run(['git', '-C', str(repository), '-c', 'user.name=Fixture', '-c',
    'user.email=fixture@example.invalid', 'commit', '-q', '--allow-empty', '-m', 'fixture'], check=True)
subprocess.run(['git', '-C', str(repository), 'worktree', 'add', '-q', '--detach', str(linked)], check=True)
with sqlite3.connect(sys.argv[2]) as connection:
    connection.row_factory = sqlite3.Row
    timestamp = datetime.now(timezone.utc).isoformat()
    connection.execute('UPDATE scans SET started_at=?, created_at=?, updated_at=?', (timestamp, timestamp, timestamp))
    connection.execute('UPDATE scan_progress SET updated_at=?', (timestamp,))
    metadata = repository.stat()
    connection.execute('UPDATE scans SET target_device=?, target_inode=?', (str(metadata.st_dev), str(metadata.st_ino)))
    migration = json.loads(pathlib.Path(sys.argv[5]).read_text())[0]
    assert migration['version'] == 43 and migration['name'] == 'persist repository identities'
    for statement in migration['statements']:
        connection.execute(statement)
    connection.execute('INSERT INTO schema_migrations VALUES (?, ?, ?)',
        (migration['version'], migration['name'], 'original'))
    workbench.backfill_security_targets(connection)
    identity = state._repository_identity_details(repository)
    generation = identity.previous_value or identity.value
    connection.execute('UPDATE security_targets SET repository_identity=?', (generation,))
    connection.execute('UPDATE scans SET repository_generation=?', (generation,))
`,
      scripts,
      databasePath,
      repository,
      linked,
      fileURLToPath(
        new URL(
          "./fixtures/pre-severity-repository-migrations.json",
          import.meta.url,
        ),
      ),
    ],
    { encoding: "utf8" },
  );
  assert.equal(seeded.status, 0, seeded.stderr || String(seeded.error));
  const before = new DatabaseSync(databasePath);
  const savedRows = storedRows(before);
  assert.equal(
    before
      .prepare("SELECT MAX(version) AS version FROM schema_migrations")
      .get()?.version,
    43,
  );
  before.close();
  assert.equal((await databaseInfo(directory)).databasePath, databasePath);
  const initialized = new DatabaseSync(databasePath);
  assert.deepEqual(
    storedRows(initialized).filter(
      ([name]) =>
        name !== "schema_migrations" &&
        name !== "scan_severity_assessments" &&
        name !== "local_finding_embeddings",
    ),
    savedRows.filter(([name]) => name !== "schema_migrations"),
  );
  assert.equal(
    initialized
      .prepare("SELECT COUNT(*) AS count FROM local_finding_embeddings")
      .get()?.count,
    0,
  );
  assert.equal(
    initialized
      .prepare("SELECT COUNT(*) AS count FROM scan_severity_assessments")
      .get()?.count,
    0,
  );
  assert.equal(
    initialized
      .prepare("SELECT name FROM schema_migrations WHERE version=48")
      .get()?.name,
    "persist repository identities",
  );
  assert.equal(
    initialized
      .prepare("SELECT name FROM schema_migrations WHERE version=49")
      .get(),
    undefined,
  );
  initialized.close();
  const queried = spawnSync(
    process.env.PYTHON?.trim() || "python3",
    [
      "-I",
      "-B",
      "-c",
      `
import argparse, sqlite3, sys
sys.path.insert(0, sys.argv[1])
import workbench_db as workbench, workbench_scan_history as history
with sqlite3.connect(sys.argv[2]) as connection:
    connection.row_factory = sqlite3.Row
    workbench.apply_migrations(connection)
    for repository in sys.argv[3:5]:
        args = argparse.Namespace(repository=repository, scan_root=None, target_id=None,
            mode=None, status=None, query=None, limit=None, offset=0)
        scans = history.list_scans(connection, args)['scans']
        assert [scan['scanId'] for scan in scans] == ['scan'], (repository, scans)
    assert connection.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0] == 49
`,
      scripts,
      databasePath,
      repository,
      linked,
    ],
    { encoding: "utf8" },
  );
  assert.equal(queried.status, 0, queried.stderr || String(queried.error));
});
