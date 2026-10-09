import assert from "node:assert/strict";
import { execFile, execFileSync, spawnSync } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { after, test, type TestContext } from "node:test";
import { importSource } from "./import-module.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";
import type * as Findings from "../src/workbench/findings.ts";
import type * as Migrations from "../src/workbench/migrations.ts";

const { storeFindings, listStoredFindings } = (await importSource(
  "src/workbench/findings.ts",
)) as typeof Findings;
const { applyMigrations } = (await importSource(
  "src/workbench/migrations.ts",
)) as typeof Migrations;
const { parseJson, stringifyJson } = await importSource("src/helpers/json.ts");
const temporary = createTemporaryDirectories(true);
after(() => temporary.cleanup());

function open(t: TestContext, path = ":memory:") {
  const database = new DatabaseSync(path);
  t.after(() => database.close());
  database.exec("PRAGMA foreign_keys = ON");
  applyMigrations(database);
  return database;
}

function entry(id: string): Findings.EmbeddedFinding {
  return {
    finding: {
      findingId: id,
      fingerprints: { primary: `fingerprint-${id}` },
      ruleId: "synthetic-rule",
      identity: { anchor: "synthetic-anchor" },
      title: "Synthetic finding λ",
      evidence: { message: "complete\0diagnostic", lines: [1, 2] },
    },
    embedding: { model: "synthetic-model", vector: [1, 0] },
  };
}

for (const formatting of ["spaced", "reordered", "escaped"]) {
  test(`unchanged service upserts retain local cache and document serialization: ${formatting}`, (t) => {
    const database = open(t);
    const original = entry("shared-finding");
    storeFindings(database, [original], "created");
    const body =
      formatting === "reordered"
        ? Object.fromEntries(Object.entries(original.finding).reverse())
        : original.finding;
    const stored = stringifyJson(body, 2).replaceAll(
      "λ",
      formatting === "escaped" ? "\\u03bb" : "λ",
    );
    database
      .prepare("UPDATE findings SET details_json = ? WHERE id = ?")
      .run(stored, original.finding.findingId);
    database
      .prepare(
        "INSERT INTO local_finding_embeddings VALUES (?, 'local-model', '[1,0]', 'local-cache-key')",
      )
      .run(original.finding.findingId);
    const updated = {
      ...original,
      embedding: { model: "service-model", vector: [0, 1] },
    };
    assert.deepEqual(storeFindings(database, [updated], "updated"), {
      findingIds: [original.finding.findingId],
    });
    assert.equal(
      database
        .prepare("SELECT details_json FROM findings WHERE id = ?")
        .get(original.finding.findingId)?.details_json,
      stored,
    );
    assert.equal(
      database
        .prepare(
          "SELECT cache_key FROM local_finding_embeddings WHERE finding_id = ?",
        )
        .get(original.finding.findingId)?.cache_key,
      "local-cache-key",
    );
    assert.equal(
      database
        .prepare("SELECT model FROM finding_embeddings WHERE finding_id = ?")
        .get(original.finding.findingId)?.model,
      "service-model",
    );
    storeFindings(
      database,
      [
        {
          ...updated,
          finding: { ...original.finding, title: "Changed finding body" },
        },
      ],
      "changed",
    );
    assert.equal(
      database
        .prepare(
          "SELECT cache_key FROM local_finding_embeddings WHERE finding_id = ?",
        )
        .get(original.finding.findingId),
      undefined,
    );
  });
}

test("finding helper help exits without reading stdin", async () => {
  const helper = fileURLToPath(
    new URL(
      "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
      import.meta.url,
    ),
  );
  const commands = [
    "store-findings",
    "list-stored-findings",
    "find-potential-duplicates",
    "store-dedupe-groups",
    "list-dedupe-groups",
    "dashboard",
  ];
  for (const command of commands) {
    // execFile leaves stdin open; help must exit without waiting for JSON.
    const { stdout } = await promisify(execFile)(
      process.execPath,
      [helper, command, "--help"],
      { timeout: 30_000 },
    );
    assert.ok(stdout.startsWith(`Usage: ${command}`));
    assert.ok(stdout.includes("stateDirectory"));
  }
  const usage = spawnSync(process.execPath, [helper], { encoding: "utf8" });
  assert.equal(usage.status, 2);
  for (const command of commands) assert.ok(usage.stderr.includes(command));
});

test("import batches preserve identity, repository memberships and stable pages", (t) => {
  const database = open(t);
  const [a, b, c] = ["a", "b", "c"].map(entry);
  a.finding.identity = {
    anchor: "anchor\0suffix",
    instance: "instance\0suffix",
  };
  assert.deepEqual(storeFindings(database, [b, a], "created", "repository-a"), {
    findingIds: ["b", "a"],
  });
  assert.deepEqual(storeFindings(database, [a], "updated", "repository-b"), {
    findingIds: ["a"],
  });
  assert.deepEqual(listStoredFindings(database, { limit: 1, offset: 0 }), {
    findings: [a.finding],
    limit: 1,
    offset: 0,
    total: 2,
    nextOffset: 1,
  });
  assert.deepEqual(listStoredFindings(database, { limit: 1, offset: 1 }), {
    findings: [b.finding],
    limit: 1,
    offset: 1,
    total: 2,
    nextOffset: null,
  });
  const conflict = structuredClone(a);
  conflict.finding.identity.anchor = "anchor";
  assert.deepEqual(
    storeFindings(database, [c, conflict], "later", "repository-c"),
    {
      error: "finding_conflict",
    },
  );
  assert.deepEqual(
    listStoredFindings(database, { limit: 10, offset: 0 }).findings,
    [a.finding, b.finding],
  );
  assert.deepEqual(
    database
      .prepare(
        "SELECT repository_id FROM finding_repositories WHERE finding_id = 'a' ORDER BY repository_id",
      )
      .all()
      .map((row) => row.repository_id),
    ["repository-a", "repository-b"],
  );
  assert.equal(
    database.prepare("SELECT COUNT(*) AS total FROM finding_embeddings").get()!
      .total,
    2,
  );
  const duplicate = entry("duplicate");
  duplicate.finding.fingerprints = a.finding.fingerprints;
  assert.deepEqual(storeFindings(database, [c, duplicate], "later"), {
    error: "finding_conflict",
  });
  assert.equal(listStoredFindings(database, { limit: 10, offset: 0 }).total, 2);
});

test("mixed writers retain unchanged Python embeddings and replace supplied Node embeddings", async (t) => {
  const directory = await temporary.create("workbench-findings-");
  const path = join(directory, "workbench.sqlite3");
  const database = open(t, path);
  const item = entry("finding");
  item.finding.extensions = { opaqueId: 9007199254740993n };
  item.finding.severity = { score: 10 };
  storeFindings(database, [item], "initial");
  const details = () =>
    database
      .prepare("SELECT details_json FROM findings WHERE id = 'finding'")
      .get()!.details_json;
  const embedding = () =>
    database.prepare("SELECT model, vector_json FROM finding_embeddings").get();
  const scripts = fileURLToPath(new URL("../../scripts/", import.meta.url));
  const pythonUpsert = (finding: Findings.Finding | string) =>
    execFileSync(
      process.env.PYTHON ?? "python",
      [
        "-I",
        "-X",
        "utf8",
        "-c",
        `import json, sqlite3, sys
sys.path.insert(0, sys.argv[1])
from workbench_finding_index import upsert_finding
with sqlite3.connect(sys.argv[2]) as db:
    db.row_factory = sqlite3.Row
    upsert_finding(db, json.load(sys.stdin), "python")`,
        scripts,
        path,
      ],
      {
        input: typeof finding === "string" ? finding : stringifyJson(finding),
        encoding: "utf8",
      },
    );
  const original = details();
  assert.match(String(original), /9007199254740993/u);
  pythonUpsert(
    stringifyJson(
      Object.fromEntries(Object.entries(item.finding).reverse()),
    ).replace('"score": 10', '"score": 10.0'),
  );
  assert.equal(details(), original);
  assert.ok(embedding());
  const changed = { ...item.finding, title: "Updated finding" };
  pythonUpsert(changed);
  assert.equal(embedding(), undefined);
  item.embedding = { model: "replacement-model", vector: [0, 1] };
  storeFindings(database, [{ ...item, finding: changed }], "node");
  const stored = embedding()!;
  assert.equal(stored.model, item.embedding.model);
  assert.deepEqual(parseJson(String(stored.vector_json)), [0, 1]);
  assert.deepEqual(
    listStoredFindings(database, { limit: 10, offset: 0 }).findings,
    [changed],
  );
  for (const [before, after] of [
    [true, 1],
    [1, true],
  ]) {
    storeFindings(
      database,
      [{ ...item, finding: { ...changed, extensions: { foo: before } } }],
      "node",
    );
    pythonUpsert({ ...changed, extensions: { foo: after } });
    assert.equal(JSON.parse(String(details())).extensions.foo, after);
    assert.equal(embedding(), undefined);
  }
});

test("imports reject lossy SQLite keys and non-finite JSON atomically", (t) => {
  const database = open(t);
  const original = entry("existing");
  original.finding.identity = { anchor: "identity�", instance: "identity�" };
  original.finding.extensions = {
    opaqueId: 9007199254740993n,
    opaqueText: "preserve\ud800",
  };
  storeFindings(database, [original], "initial", "scope�");
  assert.deepEqual(
    listStoredFindings(database, { limit: 10, offset: 0 }).findings,
    [original.finding],
  );
  const snapshot = () =>
    ["findings", "finding_embeddings", "finding_repositories"].map((table) =>
      database.prepare(`SELECT * FROM ${table}`).all(),
    );
  const before = snapshot();
  for (const location of [
    "extension",
    "vector",
    "repository",
    "anchor",
    "instance",
  ] as const) {
    const updated = structuredClone(original);
    updated.finding.title = "Updated title";
    updated.embedding.vector = [0, 1];
    const invalid = entry("invalid");
    const overflow = parseJson("1e400") as number;
    if (location === "extension")
      invalid.finding.extensions = { evidence: [overflow] };
    else if (location === "vector") invalid.embedding.vector = [overflow, 0];
    else if (location !== "repository") {
      invalid.finding = structuredClone(original.finding);
      invalid.finding.identity[location] = "identity\ud800";
    }
    assert.throws(
      () =>
        storeFindings(
          database,
          [updated, entry("new"), invalid],
          "later",
          location === "repository" ? "scope\ud800" : "new-repository",
        ),
      /non-finite|Unicode/u,
    );
    assert.deepEqual(snapshot(), before);
  }
});
