import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { after, test, type TestContext } from "node:test";
import { importSource } from "./import-module.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";
import type * as Local from "../src/workbench/local-dedupe.ts";
import type * as Migrations from "../src/workbench/migrations.ts";
import type { Finding } from "../src/workbench/findings.ts";

const { localDedupe } = (await importSource("src/workbench/local-dedupe.ts", {
  define: {
    // Native bindings are installed beside the generated server bundle.
    "import.meta.url": JSON.stringify(
      new URL(
        "../../../../sdk/typescript/_bundled_plugin/mcp/server.mjs",
        import.meta.url,
      ).href,
    ),
  },
})) as typeof Local;
const { applyMigrations } = (await importSource(
  "src/workbench/migrations.ts",
)) as typeof Migrations;
const temporary = createTemporaryDirectories(true);
after(() => temporary.cleanup());
const timestamp = "2026-01-01T00:00:00Z";
const space = "synthetic-space";

async function fixture(t: TestContext) {
  const root = await temporary.create("local-dedupe-");
  const database = new DatabaseSync(":memory:");
  t.after(() => database.close());
  database.exec("PRAGMA foreign_keys = ON");
  applyMigrations(database);
  const targetId = `target_sha256_${createHash("sha256").update(`local-workspace\0${root}`).digest("hex")}`;
  const prepare = (
    findings: Finding[],
    overrides: Partial<
      Extract<Local.LocalDedupeRequest, { action: "prepare" }>
    > = {},
  ) =>
    localDedupe(
      database,
      {
        action: "prepare",
        space,
        repositoryPath: root,
        anchorRepositoryId: targetId,
        repositoryId: targetId,
        findings,
        ...overrides,
      },
      timestamp,
    );
  const embed = (
    entries: Extract<Local.LocalDedupeRequest, { action: "embed" }>["entries"],
  ) =>
    localDedupe(
      database,
      { action: "embed", space, model: "synthetic", dimensions: 2, entries },
      timestamp,
    );
  return { root, database, targetId, prepare, embed };
}

function finding(id: string): Finding {
  return {
    findingId: id,
    fingerprints: { primary: `fingerprint-${id}` },
    ruleId: "synthetic-rule",
    identity: { anchor: `anchor-${id}` },
    title: `Finding ${id} λ`,
    evidence: { diagnostic: "complete\0message", count: 9007199254740993n },
  };
}

function prepared(result: ReturnType<typeof localDedupe>) {
  assert.ok("cacheKeys" in result && "findingsToEmbed" in result);
  return result as {
    cacheKeys: Record<string, string>;
    findingsToEmbed: Finding[];
  };
}

function entry(result: ReturnType<typeof prepared>, id: string) {
  return {
    findingId: id,
    cacheKey: result.cacheKeys[id]!,
    embedding: { model: "synthetic", vector: [1, 0] },
  };
}

function cacheKey(body: string) {
  return createHash("sha256").update(`${space}\0${body}`).digest("hex");
}

function snapshot(database: DatabaseSync) {
  return [
    "findings",
    "finding_repositories",
    "local_finding_embeddings",
    "finding_embeddings",
  ].map((table) => database.prepare(`SELECT * FROM ${table} ORDER BY 1`).all());
}

test("preparation retains current body bytes, large integers and independent service embeddings", async (t) => {
  const { database, prepare, embed } = await fixture(t);
  const original = finding("__proto__");
  prepared(prepare([original]));
  const body =
    '{ "evidence":{"count":9007199254740993,"diagnostic":"complete\\u0000message"},' +
    '"title":"Current \\u03bb evidence","identity":{"anchor":"anchor-__proto__"},' +
    '"ruleId":"synthetic-rule","fingerprints":{"primary":"fingerprint-__proto__"},"findingId":"__proto__" }';
  database
    .prepare("UPDATE findings SET details_json = ? WHERE id = ?")
    .run(body, original.findingId);
  const first = prepared(prepare([original]));
  assert.equal(first.cacheKeys[original.findingId], cacheKey(body));
  assert.deepEqual(first.findingsToEmbed, [
    { ...original, title: "Current λ evidence" },
  ]);
  assert.deepEqual(Object.keys(first.findingsToEmbed[0]!), [
    "evidence",
    "findingId",
    "fingerprints",
    "identity",
    "ruleId",
    "title",
  ]);
  assert.deepEqual(embed([entry(first, original.findingId)]), {});
  database
    .prepare(
      "INSERT INTO finding_embeddings VALUES (?, 'synthetic', '[0, 1]', NULL)",
    )
    .run(original.findingId);
  assert.deepEqual(prepare([original]), {
    cacheKeys: first.cacheKeys,
    findingsToEmbed: [],
  });
  assert.equal(
    database.prepare("SELECT details_json FROM findings").get()!.details_json,
    body,
  );
  assert.equal(
    database.prepare("SELECT vector_json FROM finding_embeddings").get()!
      .vector_json,
    "[0, 1]",
  );
  const changedSpace = prepared(
    prepare([original], { space: "another-space" }),
  );
  assert.notEqual(changedSpace.cacheKeys[original.findingId], cacheKey(body));
  assert.deepEqual(changedSpace.findingsToEmbed, first.findingsToEmbed);
});

for (const [encoding, expectedKey] of [
  ["UTF-8", "41841dc6a8e60f506e90d97fb9599f6cd6ddba109c24bd6ca2593ca72fb8f646"],
  [
    "UTF-16LE",
    "23ba87b2a052c2b711dc909ad478346d1e253701cecf6f4b82b62d4cab9597c1",
  ],
  [
    "UTF-32LE",
    "c4e623bd52874215c18d910e333ad041eaef16e11ca5b307c1a0a51cb061ab3e",
  ],
] as const) {
  test(`${encoding} BLOB bodies retain Python cache identity and stored bytes`, async (t) => {
    const { database, prepare, embed } = await fixture(t);
    prepared(prepare([finding("old")]));
    const text = '{"findingId":"old","title":"BLOB body"}';
    const body =
      encoding === "UTF-8"
        ? Buffer.from(text)
        : encoding === "UTF-16LE"
          ? Buffer.concat([
              Buffer.from([255, 254]),
              Buffer.from(text, "utf16le"),
            ])
          : Buffer.from([
              255,
              254,
              0,
              0,
              ...Array.from(Buffer.from(text)).flatMap((byte) => [
                byte,
                0,
                0,
                0,
              ]),
            ]);
    database
      .prepare("UPDATE findings SET details_json = ? WHERE id = 'old'")
      .run(body);
    const first = prepared(prepare([finding("old")]));
    // Frozen Python SHA256 values use its bytes representation, not decoded JSON.
    assert.equal(first.cacheKeys.old, expectedKey);
    assert.notEqual(first.cacheKeys.old, cacheKey(text));
    assert.deepEqual(first.findingsToEmbed, [JSON.parse(text)]);
    assert.deepEqual(embed([entry(first, "old")]), {});
    assert.deepEqual(prepare([finding("old")]), {
      cacheKeys: first.cacheKeys,
      findingsToEmbed: [],
    });
    const row = database
      .prepare(
        "SELECT typeof(details_json) AS storage, details_json FROM findings",
      )
      .get()!;
    assert.equal(row.storage, "blob");
    assert.deepEqual(Buffer.from(row.details_json as Uint8Array), body);
  });
}

test("a malformed cached BLOB body is reused without decoding and permits later inserts", async (t) => {
  const { database, prepare } = await fixture(t);
  prepared(prepare([finding("old")]));
  database
    .prepare("UPDATE findings SET details_json = ? WHERE id = 'old'")
    .run(Buffer.from("{"));
  const key = cacheKey("b'{'");
  database
    .prepare(
      "INSERT INTO local_finding_embeddings VALUES ('old', 'synthetic', '[1,0]', ?)",
    )
    .run(key);
  const result = prepared(prepare([finding("new")]));
  assert.equal(result.cacheKeys.old, key);
  assert.deepEqual(result.findingsToEmbed, [finding("new")]);
  assert.ok(database.prepare("SELECT id FROM findings WHERE id = 'new'").get());
});

test("malformed UTF-8 TEXT is rejected before committing new findings", async (t) => {
  const { database, prepare } = await fixture(t);
  prepared(prepare([finding("old")]));
  const body = Buffer.concat([
    Buffer.from('{"note":"'),
    Buffer.from([255]),
    Buffer.from('"}'),
  ]);
  database
    .prepare(
      "UPDATE findings SET details_json = CAST(? AS TEXT) WHERE id = 'old'",
    )
    .run(body);
  const before = snapshot(database);
  assert.throws(() => prepare([finding("new")]), /utf-8/iu);
  assert.deepEqual(snapshot(database), before);
  assert.equal(
    database.prepare("SELECT hex(details_json) AS bytes FROM findings").get()!
      .bytes,
    body.toString("hex").toUpperCase(),
  );
});

test("preparation indexes legacy missing bodies and invalidates changed local vectors", async (t) => {
  const { database, prepare, embed } = await fixture(t);
  const original = finding("legacy");
  database
    .prepare(
      `INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, created_at, updated_at)
       VALUES ('legacy', 'fingerprint-legacy', 'synthetic-rule', 'anchor-legacy', ?, ?)`,
    )
    .run(timestamp, timestamp);
  const first = prepared(prepare([original]));
  assert.deepEqual(first.findingsToEmbed, [original]);
  assert.deepEqual(embed([entry(first, "legacy")]), {});
  const body = String(
    database.prepare("SELECT details_json FROM findings").get()!.details_json,
  );
  assert.equal(first.cacheKeys.legacy, cacheKey(body));
  database
    .prepare("UPDATE findings SET details_json = ? WHERE id = 'legacy'")
    .run(body.replace("Finding legacy", "Updated legacy"));
  assert.equal(
    database
      .prepare("SELECT COUNT(*) AS total FROM local_finding_embeddings")
      .get()!.total,
    0,
  );
  assert.equal(
    prepared(prepare([original])).findingsToEmbed[0]!.title,
    "Updated legacy λ",
  );
});

test("repository scope preserves creation order, cached keys and empty-input behavior", async (t) => {
  const { database, targetId, prepare, embed } = await fixture(t);
  const other = prepared(prepare([finding("other")]));
  const first = prepared(prepare([finding("first")]));
  prepared(prepare([finding("second")]));
  database
    .prepare("DELETE FROM finding_repositories WHERE finding_id = 'other'")
    .run();
  database
    .prepare(
      "INSERT INTO finding_repositories VALUES ('other-target', 'other')",
    )
    .run();
  database
    .prepare("UPDATE findings SET created_at = '2025' WHERE id = 'second'")
    .run();
  assert.deepEqual(embed([entry(first, "first")]), {});
  const scoped = prepared(prepare([finding("first")]));
  assert.deepEqual(Object.keys(scoped.cacheKeys), ["second", "first"]);
  assert.deepEqual(scoped.findingsToEmbed, [finding("second")]);
  const all = prepared(
    prepare([finding("first")], { repositoryId: undefined }),
  );
  assert.deepEqual(Object.keys(all.cacheKeys), ["second", "first", "other"]);
  assert.equal(all.cacheKeys.other, other.cacheKeys.other);
  assert.equal(all.cacheKeys.first, first.cacheKeys.first);
  assert.deepEqual(prepare([], { repositoryId: undefined }), {
    cacheKeys: {},
    findingsToEmbed: [],
  });
  assert.deepEqual(prepare([], { anchorRepositoryId: `${targetId}-wrong` }), {
    error: "target_mismatch",
  });
});

test("registered target identity is authoritative and a later identity conflict rolls back the batch", async (t) => {
  const { root, database, prepare } = await fixture(t);
  database
    .prepare(
      "INSERT INTO security_targets (id, current_path, display_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
    )
    .run("registered-target", root, "Synthetic target", timestamp, timestamp);
  assert.deepEqual(prepare([finding("old")]), { error: "target_mismatch" });
  const scope = {
    anchorRepositoryId: "registered-target",
    repositoryId: "registered-target",
  };
  prepared(prepare([finding("old")], scope));
  database.prepare("DELETE FROM finding_repositories").run();
  const before = snapshot(database);
  const conflicting = finding("old");
  conflicting.identity.anchor = "different-anchor";
  assert.deepEqual(prepare([finding("new"), conflicting], scope), {
    error: "finding_conflict",
  });
  assert.deepEqual(snapshot(database), before);
});

for (const failure of [
  "stale",
  "model",
  "dimensions",
  "zero",
  "nonfinite",
  "overflow-norm",
] as const) {
  test(`a later ${failure} embedding rolls back earlier replacements`, async (t) => {
    const { database, prepare, embed } = await fixture(t);
    const first = prepared(prepare([finding("one"), finding("two")]));
    assert.deepEqual(embed([entry(first, "one")]), {});
    const before = snapshot(database);
    const replacement = entry(first, "one");
    replacement.embedding.vector = [0, 1];
    const invalid = entry(first, "two");
    if (failure === "stale") invalid.cacheKey = "previous-input";
    else if (failure === "model") invalid.embedding.model = "another-model";
    else
      invalid.embedding.vector = {
        dimensions: [1],
        zero: [0, 0],
        nonfinite: [Number.NaN, 0],
        "overflow-norm": [Number.MAX_VALUE, Number.MAX_VALUE],
      }[failure];
    assert.deepEqual(embed([replacement, invalid]), {
      error: failure === "stale" ? "finding_changed" : "embedding_failed",
    });
    assert.deepEqual(snapshot(database), before);
  });
}

test("a changed document rejects an in-flight embedding and retains the previous batch", async (t) => {
  const { database, prepare, embed } = await fixture(t);
  const first = prepared(prepare([finding("one"), finding("two")]));
  database
    .prepare("UPDATE findings SET details_json = ? WHERE id = 'two'")
    .run('{"findingId":"two","title":"Newer evidence"}');
  const before = snapshot(database);
  assert.deepEqual(embed([entry(first, "one"), entry(first, "two")]), {
    error: "finding_changed",
  });
  assert.deepEqual(snapshot(database), before);
});

test("finite integer, boolean and subnormal vector components keep their stored values", async (t) => {
  const { database, prepare, embed } = await fixture(t);
  const first = prepared(prepare([finding("one")]));
  const saved = entry(first, "one");
  for (const [vector, stored] of [
    [[true, 9007199254740993n], "[true,9007199254740993]"],
    [[Number.MIN_VALUE, 0], "[5e-324,0]"],
    [[Number.MAX_VALUE, 0], "[1.7976931348623157e+308,0]"],
  ] as const) {
    assert.deepEqual(
      embed([{ ...saved, embedding: { model: "synthetic", vector } }]),
      {},
    );
    assert.equal(
      database
        .prepare("SELECT vector_json FROM local_finding_embeddings")
        .get()!.vector_json,
      stored,
    );
  }
  const before = snapshot(database);
  assert.throws(
    () =>
      embed([
        {
          ...saved,
          embedding: { model: "synthetic", vector: [10n ** 400n, 0] },
        },
      ]),
    /int too large to convert to float/u,
  );
  assert.deepEqual(snapshot(database), before);
});

test("vector norm admits the largest finite result and rejects its overflowing neighbor", async (t) => {
  const { database, prepare, embed } = await fixture(t);
  const first = prepared(prepare([finding("one")]));
  const saved = entry(first, "one");
  const accepted = 1.2711610061536462e308;
  assert.deepEqual(
    embed([
      {
        ...saved,
        embedding: { model: "synthetic", vector: [accepted, accepted] },
      },
    ]),
    {},
  );
  const before = snapshot(database);
  const rejected = 1.2711610061536464e308;
  assert.deepEqual(
    embed([
      {
        ...saved,
        embedding: { model: "synthetic", vector: [rejected, rejected] },
      },
    ]),
    { error: "embedding_failed" },
  );
  assert.deepEqual(snapshot(database), before);
});

test("cache hits skip body parsing while malformed cache misses roll back inserted findings", async (t) => {
  const { database, prepare } = await fixture(t);
  prepared(prepare([finding("old")]));
  const body = '{"incomplete":';
  database
    .prepare("UPDATE findings SET details_json = ? WHERE id = 'old'")
    .run(body);
  database
    .prepare(
      "INSERT INTO local_finding_embeddings VALUES ('old', 'synthetic', '[1, 0]', ?)",
    )
    .run(cacheKey(body));
  assert.deepEqual(prepare([finding("old")]), {
    cacheKeys: { old: cacheKey(body) },
    findingsToEmbed: [],
  });
  database.prepare("DELETE FROM local_finding_embeddings").run();
  const before = snapshot(database);
  const failed = prepare([finding("new")]);
  assert.ok("error" in failed);
  assert.match(String(failed.error), /JSON|position|property|end/iu);
  assert.deepEqual(snapshot(database), before);
});

test("historical numeric overflow reaches the response after preparation commits", async (t) => {
  const { database, prepare } = await fixture(t);
  prepared(prepare([finding("old")]));
  database
    .prepare("UPDATE findings SET details_json = ? WHERE id = 'old'")
    .run('{"findingId":"old","evidence":{"count":1e400}}');
  const result = prepared(prepare([finding("new")]));
  assert.equal(
    (
      result.findingsToEmbed.find((item) => item.findingId === "old")!
        .evidence as { count: number }
    ).count,
    Infinity,
  );
  assert.ok(database.prepare("SELECT id FROM findings WHERE id = 'new'").get());
});

test("an incomplete corpus body rolls back newly indexed findings", async (t) => {
  const { database, prepare } = await fixture(t);
  prepared(prepare([finding("old")]));
  database.prepare("UPDATE findings SET details_json = NULL").run();
  const before = snapshot(database);
  assert.deepEqual(prepare([finding("new")]), {
    error: "finding_not_indexed",
  });
  assert.deepEqual(snapshot(database), before);
});
