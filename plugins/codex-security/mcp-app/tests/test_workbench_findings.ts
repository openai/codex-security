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
const { findPotentialDuplicates, listDedupeGroups } = (await importSource(
  "src/workbench/duplicates.ts",
)) as typeof import("../src/workbench/duplicates.ts");
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

function pythonUpsert(path: string, finding: Findings.Finding | string): void {
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
      fileURLToPath(new URL("../../scripts/", import.meta.url)),
      path,
    ],
    {
      input: typeof finding === "string" ? finding : stringifyJson(finding),
      encoding: "utf8",
    },
  );
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
    "severity-classification",
    "read-severity-classification",
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

test("timestamp ordering keeps time zones, page boundaries, and stable ties", (t) => {
  const database = open(t);
  const timestamps = [
    ["middle-b", "2026-10-08t01:00:01.123z"],
    ["first", "2026-10-08T03:00:00+02:00"],
    ["last", "2026-10-08T01:00:02.000001Z"],
    ["middle-a", "2026-10-08T03:00:01.123000+02:00"],
  ];
  const expected = ["first", "middle-a", "middle-b", "last"];
  for (const [id, timestamp] of timestamps) {
    storeFindings(database, [entry(id)], timestamp, "repository");
  }
  for (const [id, timestamp] of timestamps) {
    database
      .prepare("INSERT INTO finding_dedupe_groups VALUES (?, ?)")
      .run(id, timestamp);
    database
      .prepare("INSERT INTO finding_dedupe_group_members VALUES (?, 'first')")
      .run(id);
  }
  assert.deepEqual(
    expected.flatMap((_, offset) =>
      listStoredFindings(database, { limit: 1, offset }).findings.map(
        (finding) => finding.findingId,
      ),
    ),
    expected,
  );
  assert.deepEqual(
    listDedupeGroups(database, "first").groups.map((group) => group.groupId),
    expected,
  );
  for (const repository of [undefined, "repository"]) {
    const result = findPotentialDuplicates(database, "first", repository);
    assert.ok(result.potentialDuplicates);
    assert.deepEqual(
      result.potentialDuplicates.map(
        (finding) => (finding as Findings.Finding).findingId,
      ),
      expected.slice(1),
    );
  }
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
  const original = details();
  assert.match(String(original), /9007199254740993/u);
  pythonUpsert(
    path,
    stringifyJson(
      Object.fromEntries(Object.entries(item.finding).reverse()),
    ).replace('"score": 10', '"score": 10.0'),
  );
  assert.equal(details(), original);
  assert.ok(embedding());
  const changed = { ...item.finding, title: "Updated finding" };
  pythonUpsert(path, changed);
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
    pythonUpsert(path, { ...changed, extensions: { foo: after } });
    assert.equal(JSON.parse(String(details())).extensions.foo, after);
    assert.equal(embedding(), undefined);
  }
});

for (const [name, previousValue, value, unchanged] of [
  ["negative zero", "-0.0", 0, true],
  ["exact exponent spelling", "1e+20", 1e20, true],
  ["rounded exponent spelling", "1e+23", 1e23, true],
  ["exact BigInt readback", "1e+23", 100000000000000000000000n, false],
] as const) {
  test(`stored finding numeric equality preserves Python ${name}`, async (t) => {
    const directory = await temporary.create("workbench-numeric-finding-");
    const path = join(directory, "workbench.sqlite3");
    const database = open(t, path);
    const item = entry("finding");
    item.finding.extensions = { measurement: "numeric-placeholder" };
    pythonUpsert(
      path,
      stringifyJson(item.finding).replace(
        '"numeric-placeholder"',
        previousValue,
      ),
    );
    const previous = database
      .prepare("SELECT details_json FROM findings")
      .get()!.details_json;
    assert.ok(String(previous).includes(previousValue));
    database
      .prepare(
        "INSERT INTO local_finding_embeddings VALUES ('finding', 'local-model', '[1,0]', 'prepared-key')",
      )
      .run();
    item.finding.extensions = { measurement: value };
    storeFindings(database, [item], "native-import");
    assert.equal(
      database.prepare("SELECT details_json FROM findings").get()!.details_json,
      unchanged ? previous : stringifyJson(item.finding, 0),
    );
    const readback = listStoredFindings(database, { limit: 10, offset: 0 })
      .findings[0].extensions as { measurement: number | bigint };
    assert.equal(BigInt(readback.measurement), BigInt(value));
    assert.equal(
      database.prepare("SELECT cache_key FROM local_finding_embeddings").get()
        ?.cache_key,
      unchanged ? "prepared-key" : undefined,
    );
    if (unchanged)
      assert.deepEqual(
        findPotentialDuplicates(database, "finding", undefined, {
          finding: "prepared-key",
        }).potentialDuplicates,
        [],
      );
    assert.equal(
      database.prepare("SELECT model FROM finding_embeddings").get()!.model,
      item.embedding.model,
    );
  });
}

const numericCases: readonly [string, string, unknown, boolean][] = [
  ["fractional integer", "10.000", 10, true],
  ["negative zero exponent", "1e-0", 1, true],
  ["positive zero exponent", "1e+000", 1, true],
  ["cancelled integer scale", "10e-1", 1, true],
  ["cancelled fractional scale", "0.10e1", 1, true],
  ["shifted coefficient", "1000e-3", 1, true],
  ["negative coefficient", "-1200e-3", -1.2, true],
  ["large finite exponent", "1e308", 1e308, true],
  ["smallest positive Number", "5e-324", Number.MIN_VALUE, true],
  ["rounded subnormal neighbor", "4e-324", Number.MIN_VALUE, false],
  [
    "exact huge integer",
    "123456789012345678901234567890",
    123456789012345678901234567890n,
    true,
  ],
  ["unsafe integer exponent", "9007199254740993e0", 9007199254740993n, false],
  ["rounded unsafe integer", "1000000000000000000001e0", 1e21, false],
  ["precise fraction", "1.00000000000000001", 1, false],
  ["positive underflow", "1e-400", 0, false],
  ["negative underflow", "-1e-400", 0, false],
  ["adjacent huge integer", "9007199254740993", 9007199254740992n, false],
  ["boolean", "true", 1, false],
  ["string", '"1"', 1, false],
  ["array", "[1]", 1, false],
  ["duplicate members", '{"value":2,"value":1.000}', { value: 1 }, true],
  ["empty member", '{"":-0.0}', { "": 0 }, true],
  [
    "nested objects and prototype member",
    '{"z":[-0.0,10e-1],"a":{"__proto__":{"value":1}}}',
    JSON.parse('{"a":{"__proto__":{"value":1}},"z":[0,1]}'),
    true,
  ],
  ["huge zero exponent", `-0.0e${"9".repeat(65_536)}`, 0, true],
  ["huge positive exponent", `1e${"9".repeat(65_536)}`, 1, false],
  ["huge negative exponent", `1e-${"9".repeat(65_536)}`, 0, false],
  ["exponent leading zeros", `1e+${"0".repeat(65_536)}1`, 10, true],
  ["long precise fraction", `1.${"0".repeat(65_536)}1`, 1, false],
  [
    "long fractional scale cancellation",
    `0.${"0".repeat(4096)}1e4097`,
    1,
    true,
  ],
  ["long integer scale cancellation", `1${"0".repeat(4096)}e-4096`, 1, true],
];

for (const [name, previousValue, value, equal] of numericCases) {
  test(`stored finding numeric equality handles ${name}`, (t) => {
    const database = open(t);
    const item = entry("finding");
    item.finding.extensions = { measurement: value };
    storeFindings(database, [item], "initial");
    const fresh = stringifyJson(item.finding, 0);
    const previous = stringifyJson(
      {
        ...item.finding,
        extensions: { measurement: "numeric-placeholder" },
      },
      0,
    ).replace('"numeric-placeholder"', previousValue);
    database.prepare("UPDATE findings SET details_json = ?").run(previous);
    database
      .prepare(
        "INSERT INTO local_finding_embeddings VALUES ('finding', 'local-model', '[1,0]', 'prepared-key')",
      )
      .run();
    storeFindings(database, [item], "updated");
    assert.ok(
      database.prepare("SELECT details_json FROM findings").get()!
        .details_json === (equal ? previous : fresh),
      `${name}: ${equal ? "retain the exact stored body" : "replace the changed numeric body"}`,
    );
    assert.equal(
      database.prepare("SELECT cache_key FROM local_finding_embeddings").get()
        ?.cache_key,
      equal ? "prepared-key" : undefined,
    );
  });
}

test("stored finding numeric equality preserves malformed-row errors and batch rollback", (t) => {
  const database = open(t);
  const first = entry("first");
  const corrupt = entry("corrupt");
  storeFindings(database, [first, corrupt], "initial", "original-repository");
  const malformed = '{"value":1e999999,"broken":"line\u001btail"}';
  database
    .prepare("UPDATE findings SET details_json = ? WHERE id = 'corrupt'")
    .run(malformed);
  database
    .prepare(
      "INSERT INTO local_finding_embeddings VALUES ('first', 'local-model', '[1,0]', 'prepared-key')",
    )
    .run();
  const snapshot = () =>
    [
      "findings",
      "finding_embeddings",
      "finding_repositories",
      "local_finding_embeddings",
    ].map((table) =>
      database.prepare(`SELECT * FROM ${table} ORDER BY 1`).all(),
    );
  const before = snapshot();
  let expected: unknown;
  try {
    parseJson(malformed);
  } catch (error) {
    expected = error;
  }
  assert.ok(expected instanceof SyntaxError);
  const expectedMessage = expected.message;
  first.finding.title = "Changed before malformed later entry";
  first.embedding = { model: "replacement-model", vector: [0, 1] };
  assert.throws(
    () => storeFindings(database, [first, corrupt], "later", "new-repository"),
    (error: unknown) =>
      error instanceof SyntaxError && error.message === expectedMessage,
  );
  assert.deepEqual(snapshot(), before);
  assert.deepEqual(storeFindings(database, [first], "recovered"), {
    findingIds: ["first"],
  });
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
