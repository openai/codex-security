import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { after, test, type TestContext } from "node:test";
import { fileURLToPath } from "node:url";
import { importSource } from "./import-module.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";
import type * as External from "../src/workbench/external-findings.ts";
import type * as Migrations from "../src/workbench/migrations.ts";

const { storeExternalFindings, listExternalFindings } = (await importSource(
  "src/workbench/external-findings.ts",
)) as typeof External;
const { applyMigrations, migrations } = (await importSource(
  "src/workbench/migrations.ts",
)) as typeof Migrations;
const temporary = createTemporaryDirectories(true);
after(() => temporary.cleanup());
const repository = join(process.cwd(), "synthetic-repository");
const created = "2026-01-01T00:00:00.000Z";
const updated = "2026-01-02T00:00:00.000Z";

function open(t: TestContext) {
  const database = new DatabaseSync(":memory:");
  t.after(() => database.close());
  applyMigrations(database);
  return database;
}

function batch(): External.ExternalFindingsImport {
  return {
    repository,
    provider: "synthetic-scanner",
    sourceKey: "project-one",
    findings: [
      {
        source_finding_id: "finding-one",
        evidence: {
          title: "Dependency finding",
          source_data: { retained: { fields: [null, "value"] } },
          commit_sha: "a".repeat(40),
        },
      },
      { source_finding_id: "finding-two", evidence: {} },
    ],
  };
}

test("external imports preserve incomplete evidence without creating assessed findings or scans", (t) => {
  const database = open(t);
  const input = batch();
  const result = storeExternalFindings(database, input, created);
  assert.deepEqual(result.counts, { created: 2, updated: 0, unchanged: 0 });
  for (const [index, finding] of result.findings.entries()) {
    assert.match(finding.id, /^ext_[0-9a-f]{64}$/u);
    assert.deepEqual(finding, {
      id: finding.id,
      repository,
      provider: input.provider,
      sourceKey: input.sourceKey,
      sourceFindingId: input.findings[index].source_finding_id,
      evidence: input.findings[index].evidence,
      assessment: { state: "not_assessed" },
      version: 1,
      createdAt: created,
      updatedAt: created,
    });
  }
  for (const table of ["scans", "findings", "finding_occurrences"])
    assert.equal(
      database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get()!.count,
      0,
    );
});

test("repeat imports keep identities and unchanged timestamps; changed evidence increments once", (t) => {
  const database = open(t);
  const input = batch();
  const first = storeExternalFindings(database, input, created);
  const originalJson = database
    .prepare("SELECT evidence_json FROM external_source_reports WHERE id = ?")
    .get(first.findings[0].id)!.evidence_json;
  const reordered = {
    ...input,
    findings: [
      {
        source_finding_id: "finding-one",
        evidence: {
          commit_sha: "a".repeat(40),
          source_data: { retained: { fields: [null, "value"] } },
          title: "Dependency finding",
        },
      },
    ],
  };
  assert.deepEqual(storeExternalFindings(database, reordered, updated), {
    findings: [first.findings[0]],
    counts: { created: 0, updated: 0, unchanged: 1 },
  });
  assert.equal(
    database
      .prepare("SELECT evidence_json FROM external_source_reports WHERE id = ?")
      .get(first.findings[0].id)!.evidence_json,
    originalJson,
  );
  reordered.findings[0].evidence.title = "Updated source finding";
  const changed = storeExternalFindings(database, reordered, updated);
  assert.deepEqual(changed.counts, { created: 0, updated: 1, unchanged: 0 });
  assert.deepEqual(changed.findings[0], {
    ...first.findings[0],
    evidence: reordered.findings[0].evidence,
    version: 2,
    updatedAt: updated,
  });
  const all = listExternalFindings(database, { repository }).findings;
  assert.equal(all.length, 2);
  assert.deepEqual(
    all.find(({ id }) => id === first.findings[1].id),
    first.findings[1],
  );
});

test("repository, provider and source namespaces keep distinct finding identities", (t) => {
  const database = open(t);
  const input = batch();
  input.findings = input.findings.slice(0, 1);
  const inputs = [
    input,
    { ...input, repository: join(repository, "another") },
    { ...input, provider: "another-scanner" },
    { ...input, sourceKey: "project-two" },
  ];
  const stored = inputs.map(
    (item) => storeExternalFindings(database, item, created).findings[0],
  );
  assert.equal(new Set(stored.map(({ id }) => id)).size, 4);
  assert.equal(
    listExternalFindings(database, { repository }).findings.length,
    3,
  );
  assert.deepEqual(
    listExternalFindings(database, { repository, id: stored[0].id }).findings,
    [stored[0]],
  );
  assert.deepEqual(
    listExternalFindings(database, { repository, id: stored[1].id }).findings,
    [],
  );
});

test("invalid batches and failed writes preserve all previously stored evidence", (t) => {
  const database = open(t);
  const input = batch();
  storeExternalFindings(database, input, created);
  const before = listExternalFindings(database, { repository });
  const duplicate = {
    ...input,
    findings: [
      input.findings[0],
      { ...input.findings[0], evidence: { changed: true } },
    ],
  };
  assert.throws(
    () => storeExternalFindings(database, duplicate, updated),
    /duplicate source_finding_id/u,
  );
  assert.deepEqual(listExternalFindings(database, { repository }), before);
  database.exec(`CREATE TRIGGER fail_external_insert BEFORE INSERT ON external_source_reports
    WHEN NEW.source_finding_id = 'fail'
    BEGIN SELECT RAISE(ABORT, 'synthetic write failure'); END;`);
  assert.throws(
    () =>
      storeExternalFindings(
        database,
        {
          ...input,
          findings: [
            { ...input.findings[0], evidence: { changed: true } },
            { source_finding_id: "inserted-before-failure", evidence: {} },
            { source_finding_id: "fail", evidence: {} },
          ],
        },
        updated,
      ),
    /synthetic write failure/u,
  );
  assert.deepEqual(listExternalFindings(database, { repository }), before);
});

test("a Python database at the preceding schema upgrades in Node and remains readable in Python", async () => {
  const directory = await temporary.create("external-migration-");
  const path = join(directory, "workbench.sqlite3");
  execFileSync(process.env.PYTHON ?? "python", [
    "-I",
    "-B",
    "-X",
    "utf8",
    "-c",
    `import sqlite3, sys
sys.path.insert(0, sys.argv[1])
import workbench_db
workbench_db.MIGRATIONS = tuple(item for item in workbench_db.MIGRATIONS if item[0] < 53)
with sqlite3.connect(sys.argv[2]) as db:
    db.row_factory = sqlite3.Row
    workbench_db.apply_migrations(db)`,
    fileURLToPath(new URL("../../scripts/", import.meta.url)),
    path,
  ]);
  const database = new DatabaseSync(path);
  try {
    assert.equal(
      database
        .prepare("SELECT MAX(version) AS version FROM schema_migrations")
        .get()!.version,
      52,
    );
    applyMigrations(database);
    assert.equal(
      database
        .prepare("SELECT MAX(version) AS version FROM schema_migrations")
        .get()!.version,
      migrations.at(-1)!.version,
    );
    storeExternalFindings(database, batch(), created);
    applyMigrations(database);
    assert.equal(
      listExternalFindings(database, { repository }).findings.length,
      2,
    );
  } finally {
    database.close();
  }
  const evidence = execFileSync(
    process.env.PYTHON ?? "python",
    [
      "-I",
      "-B",
      "-X",
      "utf8",
      "-c",
      `import json, sqlite3, sys
sys.path.insert(0, sys.argv[1])
from workbench_db import apply_migrations
with sqlite3.connect(sys.argv[2]) as db:
    db.row_factory = sqlite3.Row
    apply_migrations(db)
    print(json.dumps([[row["source_finding_id"], json.loads(row["evidence_json"])]
        for row in db.execute("SELECT source_finding_id, evidence_json FROM external_source_reports ORDER BY source_finding_id")]))`,
      fileURLToPath(new URL("../../scripts/", import.meta.url)),
      path,
    ],
    { encoding: "utf8" },
  );
  assert.deepEqual(
    JSON.parse(evidence),
    batch().findings.map(({ source_finding_id, evidence }) => [
      source_finding_id,
      evidence,
    ]),
  );
});
