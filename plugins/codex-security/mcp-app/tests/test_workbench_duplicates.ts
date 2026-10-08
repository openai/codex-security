import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { after, test, type TestContext } from "node:test";
import { importSource } from "./import-module.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";
import { stringifyJson } from "../src/helpers/json.ts";
import type * as Duplicates from "../src/workbench/duplicates.ts";
import type * as Migrations from "../src/workbench/migrations.ts";

const { findPotentialDuplicates, storeDedupeGroups, listDedupeGroups } =
  (await importSource("src/workbench/duplicates.ts")) as typeof Duplicates;
const { applyMigrations } = (await importSource(
  "src/workbench/migrations.ts",
)) as typeof Migrations;

const temporary = createTemporaryDirectories(true);
after(() => temporary.cleanup());

function open(t: TestContext, path = ":memory:") {
  const database = new DatabaseSync(path);
  t.after(() => database.close());
  database.exec("PRAGMA foreign_keys = ON");
  applyMigrations(database);
  return database;
}

function finding(
  database: DatabaseSync,
  index: number | string,
  vector = [1, 0],
  repository = "synthetic-repository",
  model = "synthetic-model",
) {
  const findingId =
    typeof index === "number"
      ? `csf_${String(index).padStart(24, "0")}`
      : index;
  const document = {
    findingId,
    extensions: { opaqueId: 9007199254740993n, score: 0 },
  };
  database
    .prepare(
      `
    INSERT INTO findings
      (id, fingerprint, rule_id, identity_anchor, details_json, created_at, updated_at)
    VALUES (?, ?, 'synthetic-rule', ?, ?, 'created', 'updated')
  `,
    )
    .run(findingId, findingId, findingId, stringifyJson(document));
  database
    .prepare(
      "INSERT INTO finding_embeddings (finding_id, model, vector_json) VALUES (?, ?, ?)",
    )
    .run(findingId, model, JSON.stringify(vector));
  database
    .prepare("INSERT INTO finding_repositories VALUES (?, ?)")
    .run(repository, findingId);
  return document;
}

test("local neighborhoods keep repository associations separate from finding bodies", (t) => {
  const database = open(t);
  const anchor = finding(
    database,
    "finding-a\0tail",
    [1, 0],
    "repository-a\0suffix",
  );
  const other = finding(database, 2, [1, 0], "repository-b\0suffix");
  database
    .prepare("INSERT INTO finding_repositories VALUES (?, ?)")
    .run("repository-alias", anchor.findingId);
  const keys = Object.fromEntries(
    [anchor, other].map((f) => [f.findingId, `cache-${f.findingId}`]),
  );
  for (const f of [anchor, other])
    database
      .prepare(
        "INSERT INTO local_finding_embeddings VALUES (?, 'local-model', '[1, 0]', ?)",
      )
      .run(f.findingId, keys[f.findingId]);
  const local = findPotentialDuplicates(
    database,
    anchor.findingId,
    undefined,
    keys,
  );
  assert.deepEqual(local.repositoryIds, {
    [anchor.findingId]: ["repository-a\0suffix", "repository-alias"],
    [other.findingId]: ["repository-b\0suffix"],
  });
  assert.deepEqual(local.finding, anchor);
  assert.deepEqual(local.potentialDuplicates, [other]);
  assert.deepEqual(local.sourceSnapshots, {});
  assert.equal(
    "repositoryIds" in findPotentialDuplicates(database, anchor.findingId),
    false,
  );
});

for (const scenario of [
  "matching",
  "empty",
  "missing",
  "deleted",
  "stale",
  "changed-body",
]) {
  test(`local search and group writes validate the whole cache map: ${scenario}`, (t) => {
    const database = open(t);
    const anchor = finding(database, 1);
    const neighbor = finding(database, 'finding-2-"-☃', [0, 1]);
    const keys: Record<string, string> = {};
    for (const item of [anchor, neighbor]) {
      keys[item.findingId] = `cache-${item.findingId}`;
      database
        .prepare(
          "INSERT INTO local_finding_embeddings VALUES (?, 'local-model', '[0, 1]', ?)",
        )
        .run(item.findingId, keys[item.findingId]);
    }
    // Local vectors must not change the service's orthogonal-vector search.
    assert.deepEqual(
      findPotentialDuplicates(database, anchor.findingId).potentialDuplicates,
      [],
    );
    if (scenario === "empty") {
      for (const key of Object.keys(keys)) delete keys[key];
    } else if (scenario === "missing") keys.missing = "missing-key";
    else if (scenario === "deleted")
      database
        .prepare("DELETE FROM local_finding_embeddings WHERE finding_id = ?")
        .run(neighbor.findingId);
    else if (scenario === "stale")
      database
        .prepare(
          "UPDATE local_finding_embeddings SET cache_key = 'stale' WHERE finding_id = ?",
        )
        .run(neighbor.findingId);
    else if (scenario === "changed-body")
      database
        .prepare("UPDATE findings SET details_json = '{}' WHERE id = ?")
        .run(neighbor.findingId);
    const neighbors = findPotentialDuplicates(
      database,
      anchor.findingId,
      undefined,
      keys,
    );
    const groups = storeDedupeGroups(
      database,
      [[anchor.findingId, neighbor.findingId]],
      "created",
      keys,
    );
    if (scenario === "matching" || scenario === "empty") {
      assert.deepEqual(
        neighbors.potentialDuplicates,
        scenario === "matching" ? [neighbor] : [],
      );
      assert.ok("groups" in groups);
      assert.equal(groups.groups.length, 1);
    } else {
      assert.deepEqual(neighbors, { error: "finding_changed" });
      assert.deepEqual(groups, { error: "finding_changed" });
      assert.equal(
        listDedupeGroups(database, anchor.findingId).groups.length,
        0,
      );
    }
  });
}

for (const body of [
  "identical",
  "reformatted",
  "changed",
  "prototype-id",
  "signed-zero",
  "rounded-exponent",
]) {
  test(`saved source context follows semantically matching occurrence bodies: ${body}`, (t) => {
    const database = open(t);
    const document = {
      ...finding(database, body === "prototype-id" ? "__proto__" : 1),
      occurrenceId: "occurrence-a",
    };
    if (body === "rounded-exponent")
      document.extensions.opaqueId = 9007199254740992n;
    database
      .prepare("UPDATE findings SET details_json = ? WHERE id = ?")
      .run(stringifyJson(document), document.findingId);
    database.exec(`
      INSERT INTO security_targets (id, current_path, display_name, created_at, updated_at)
        VALUES ('synthetic-repository', '/synthetic', 'Synthetic', 'now', 'now');
      INSERT INTO workspaces (id, created_at, updated_at) VALUES ('workspace-a', 'now', 'now');
      INSERT INTO scans (id, workspace_id, target_path, target_revision, target_snapshot_digest,
                         target_id, scope, mode, scan_dir, status, phase, started_at, created_at, updated_at)
        VALUES ('scan-a', 'workspace-a', '/synthetic', 'recorded-revision', 'recorded-snapshot',
                'synthetic-repository', '.', 'standard', '/synthetic-scan', 'complete', 'reporting', 'now', 'now', 'now');
    `);
    const occurrence =
      body === "identical"
        ? stringifyJson(document)
        : body === "signed-zero"
          ? stringifyJson(document).replace('"score": 0', '"score": -0.0')
          : body === "rounded-exponent"
            ? stringifyJson(document).replace(
                "9007199254740992",
                "9.007199254740993e15",
              )
            : body === "changed"
              ? stringifyJson({ ...document, title: "A different observation" })
              : `{\n  "extensions": ${stringifyJson(document.extensions)},\n  "occurrenceId": "occurrence-a",\n  "findingId": ${JSON.stringify(document.findingId)}\n}`;
    database
      .prepare(
        `INSERT INTO finding_occurrences
      (id, finding_id, scan_id, title, summary, severity, confidence, remediation, details_json, created_at)
      VALUES ('occurrence-a', ?, 'scan-a', 'Synthetic', 'Synthetic', 'high', 'high', 'Fix', ?, 'now')`,
      )
      .run(document.findingId, occurrence);
    database
      .prepare(
        "INSERT INTO local_finding_embeddings VALUES (?, 'local-model', '[1, 0]', 'cache')",
      )
      .run(document.findingId);
    for (const kind of [null, "working_tree", "commit", "range"]) {
      const snapshot = kind === null ? "recorded-snapshot" : null;
      const diffSnapshot =
        kind === "working_tree" ? "recorded-diff-snapshot" : null;
      database
        .prepare(
          "UPDATE scans SET target_snapshot_digest = ?, diff_target_kind = ?, diff_content_digest = ? WHERE id = 'scan-a'",
        )
        .run(snapshot, kind, diffSnapshot);
      assert.deepEqual(
        findPotentialDuplicates(database, document.findingId, undefined, {
          [document.findingId]: "cache",
        }).sourceSnapshots,
        body === "changed" || body === "rounded-exponent"
          ? {}
          : {
              [document.findingId]: {
                repositoryId: "synthetic-repository",
                revision: "recorded-revision",
                snapshotDigest: diffSnapshot ?? snapshot,
              },
            },
      );
    }
  });
}

test("duplicate helper requires an explicit JSON scope before accessing state", async () => {
  const stateDirectory = join(
    await temporary.create("duplicate-scope-"),
    "state",
  );
  const helper = fileURLToPath(
    new URL(
      "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
      import.meta.url,
    ),
  );
  const call = (scope: unknown) =>
    spawnSync(process.execPath, [helper, "find-potential-duplicates"], {
      input: JSON.stringify({
        stateDirectory,
        payload: { findingId: "missing", scope },
      }),
      encoding: "utf8",
    });
  for (const scope of [
    undefined,
    null,
    {},
    { allRepositories: false },
    { repositoryId: 7 },
    { repositoryId: "repository", allRepositories: true },
  ]) {
    const result = call(scope);
    assert.equal(result.status, 1);
    assert.ok(result.stderr.includes("scope must specify either"));
    assert.equal(existsSync(stateDirectory), false);
  }
  for (const scope of [
    { repositoryId: "repository" },
    { allRepositories: true },
  ]) {
    const result = call(scope);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), {
      error: "finding_not_indexed",
    });
  }
});

test("duplicate retrieval filters before scoring and loads only the stable top 50 documents", (t) => {
  const database = open(t);
  const entries = Array.from({ length: 62 }, (_, index) =>
    finding(database, index + 1),
  );
  // Out-of-scope vectors and documents beyond the top 50 need not be readable.
  const foreign = finding(database, 100, [0, 0], "another-repository");
  finding(database, 101, [0, 0], "synthetic-repository", "another-model");
  finding(database, 102, [1, 0, 0]);
  database.exec("DROP TRIGGER invalidate_finding_embedding");
  for (const entry of entries.slice(51))
    database
      .prepare("UPDATE findings SET details_json = 'invalid JSON' WHERE id = ?")
      .run(entry.findingId);
  assert.deepEqual(
    findPotentialDuplicates(
      database,
      entries[0].findingId,
      "synthetic-repository",
    ),
    {
      finding: entries[0],
      potentialDuplicates: entries.slice(1, 51),
    },
  );
  assert.deepEqual(
    findPotentialDuplicates(
      database,
      foreign.findingId,
      "synthetic-repository",
    ),
    {
      error: "finding_not_indexed",
    },
  );
  assert.deepEqual(findPotentialDuplicates(database, entries[0].findingId), {
    error: "embedding_failed",
  });
});

test("cosine scoring handles large and scaled vectors without argument spreading", (t) => {
  const database = open(t);
  const vector = Array<number>(150_000).fill(0);
  vector[0] = 1e-300;
  const anchor = finding(database, 1, vector);
  vector[0] = 1e300;
  const candidate = finding(database, 2, vector);
  assert.deepEqual(findPotentialDuplicates(database, anchor.findingId), {
    finding: anchor,
    potentialDuplicates: [candidate],
  });
  const update = database.prepare(
    "UPDATE finding_embeddings SET vector_json = ? WHERE finding_id = ?",
  );
  update.run(JSON.stringify([Number.MIN_VALUE, 0]), anchor.findingId);
  update.run(JSON.stringify([Number.MAX_VALUE, 0]), candidate.findingId);
  assert.deepEqual(findPotentialDuplicates(database, anchor.findingId), {
    finding: anchor,
    potentialDuplicates: [candidate],
  });
  update.run("[0,0]", anchor.findingId);
  assert.deepEqual(findPotentialDuplicates(database, anchor.findingId), {
    error: "embedding_failed",
  });
});

test("cosine scoring includes the threshold and excludes scores below it", (t) => {
  const database = open(t);
  const anchor = finding(database, 1, [7, 0]);
  const candidate = finding(database, 2, [0.55, Math.sqrt(1 - 0.55 ** 2)]);
  finding(database, 3, [0.54, Math.sqrt(1 - 0.54 ** 2)]);
  const strongest = finding(database, 4, [1, 0]);
  finding(database, 5, [0.549e-161, Math.sqrt(1 - 0.549 ** 2) * 1e-161]);
  for (const repository of [undefined, "synthetic-repository"])
    assert.deepEqual(
      findPotentialDuplicates(database, anchor.findingId, repository),
      { finding: anchor, potentialDuplicates: [strongest, candidate] },
    );
});

test("dedupe retries retain durable hashes, first timestamps, and overlapping groups", (t) => {
  const database = open(t);
  const a = finding(database, 1).findingId;
  const b = finding(database, 2).findingId;
  const c = finding(database, 3).findingId;
  const original = storeDedupeGroups(
    database,
    [
      [b, a],
      [b, c],
    ],
    "first",
  );
  assert.ok("groups" in original);
  assert.equal(
    original.groups[0].groupId,
    "fdg_e1bc8f7052a79c844323824d7f9e0707373dd9ed4391c477aa9694702baae619",
  );
  assert.deepEqual(
    storeDedupeGroups(
      database,
      [
        [a, b, a],
        [c, b],
      ],
      "later",
    ),
    original,
  );
  assert.deepEqual(
    listDedupeGroups(database, b).groups,
    [...original.groups].sort((left, right) =>
      left.groupId.localeCompare(right.groupId),
    ),
  );
  assert.equal(
    database.prepare("SELECT count(*) AS count FROM finding_embeddings").get()!
      .count,
    3,
  );
});

test("a missing member rolls back the entire dedupe batch and leaves the connection usable", (t) => {
  const database = open(t);
  const a = finding(database, 1).findingId;
  const b = finding(database, 2).findingId;
  assert.deepEqual(
    storeDedupeGroups(
      database,
      [
        [a, b],
        [b, "missing"],
      ],
      "created",
    ),
    {
      error: "finding_conflict",
    },
  );
  assert.deepEqual(listDedupeGroups(database, b), { groups: [] });
  assert.equal(
    database
      .prepare("SELECT count(*) AS count FROM finding_dedupe_groups")
      .get()!.count,
    0,
  );
  assert.ok("groups" in storeDedupeGroups(database, [[a, b]], "retry"));
});

test("retries preserve persisted legacy Unicode group identities and timestamps", (t) => {
  const database = open(t);
  // Captured from the retired Python writer, including its persisted member order.
  const group = {
    groupId:
      "fdg_6f25bc42f005cebe1de9d4efe6448acdb1d42b1882d58aed74476385dfaa9f3c",
    findingIds: [
      "finding-\u007f",
      "finding-λ",
      "finding-\ue000",
      "finding-\u{10000}",
    ],
    createdAt: "first",
  };
  for (const id of group.findingIds) finding(database, id);
  database
    .prepare("INSERT INTO finding_dedupe_groups (id, created_at) VALUES (?, ?)")
    .run(group.groupId, group.createdAt);
  const member = database.prepare(
    "INSERT INTO finding_dedupe_group_members (group_id, finding_id) VALUES (?, ?)",
  );
  for (const id of group.findingIds) member.run(group.groupId, id);
  const original = { groups: [group] };
  assert.deepEqual(
    storeDedupeGroups(database, [[...group.findingIds].reverse()], "later"),
    original,
  );
  assert.deepEqual(listDedupeGroups(database, group.findingIds[0]), original);
  assert.equal(
    database
      .prepare("SELECT count(*) AS count FROM finding_dedupe_groups")
      .get()!.count,
    1,
  );
});

test("duplicate retrieval and group listing preserve NUL-bearing IDs and model scope", (t) => {
  const database = open(t);
  const anchor = finding(
    database,
    "finding\0anchor",
    [1, 0],
    "repository",
    "model\0suffix",
  );
  const duplicate = finding(
    database,
    "finding\0duplicate",
    [1, 0],
    "repository",
    "model\0suffix",
  );
  finding(database, "different-model", [1, 0], "repository", "model");
  assert.deepEqual(
    findPotentialDuplicates(database, anchor.findingId, "repository"),
    {
      finding: anchor,
      potentialDuplicates: [duplicate],
    },
  );
  const stored = storeDedupeGroups(
    database,
    [[duplicate.findingId, anchor.findingId]],
    "created",
  );
  assert.deepEqual(listDedupeGroups(database, duplicate.findingId), stored);
});

test("unpaired surrogates cannot alias stored finding IDs or repository scopes", (t) => {
  const database = open(t);
  const replacement = finding(
    database,
    "finding-\ufffd",
    [1, 0],
    "repository-\ufffd",
  );
  const other = finding(database, "other", [1, 0], "repository-\ufffd");
  for (const surrogate of ["\ud800", "\udfff"]) {
    const malformedId = `finding-${surrogate}`;
    assert.throws(
      () => findPotentialDuplicates(database, malformedId),
      TypeError,
    );
    assert.throws(
      () =>
        findPotentialDuplicates(
          database,
          replacement.findingId,
          `repository-${surrogate}`,
        ),
      TypeError,
    );
    assert.throws(() => listDedupeGroups(database, malformedId), TypeError);
    assert.throws(
      () =>
        storeDedupeGroups(
          database,
          [
            [replacement.findingId, other.findingId],
            [other.findingId, malformedId],
          ],
          "created",
        ),
      TypeError,
    );
    assert.equal(
      database
        .prepare("SELECT count(*) AS count FROM finding_dedupe_groups")
        .get()!.count,
      0,
    );
  }
  assert.deepEqual(
    findPotentialDuplicates(
      database,
      replacement.findingId,
      "repository-\ufffd",
    ),
    {
      finding: replacement,
      potentialDuplicates: [other],
    },
  );
});
