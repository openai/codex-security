import assert from "node:assert/strict";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { after, test, type TestContext } from "node:test";
import { importSource } from "./import-module.ts";
import { stringifyJson } from "../src/helpers/json.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";
import type * as Dashboard from "../src/workbench/dashboard.ts";
import type * as Migrations from "../src/workbench/migrations.ts";

const { dashboard } = (await importSource(
  "src/workbench/dashboard.ts",
)) as typeof Dashboard;
const { applyMigrations } = (await importSource(
  "src/workbench/migrations.ts",
)) as typeof Migrations;
const temporary = createTemporaryDirectories(true);
after(() => temporary.cleanup());

function database(t: TestContext, path = ":memory:") {
  const db = new DatabaseSync(path);
  t.after(() => db.close());
  applyMigrations(db);
  return db;
}

function insert(
  db: DatabaseSync,
  id: string,
  repository: string,
  title = `Évaluation ${id}`,
) {
  const document = {
    title,
    severity: { level: "high" },
    extensions: { opaqueId: 9007199254740993n },
  };
  db.prepare(
    `INSERT INTO findings
    (id, fingerprint, rule_id, identity_anchor, created_at, updated_at, details_json)
    VALUES (?, ?, 'rule', ?, 'created', 'updated', ?)`,
  ).run(id, id, id, stringifyJson(document));
  db.prepare("INSERT INTO finding_repositories VALUES (?, ?)").run(
    repository,
    id,
  );
  return document;
}

test("dashboard selects details independently of filters and pagination", (t) => {
  const db = database(t);
  insert(db, "a", "Alpha");
  const selected = insert(db, "b", "beta", "ΟΣΑ");
  insert(db, "c", "Alpha");
  db.exec(`INSERT INTO finding_dedupe_groups VALUES ('group', 'created');
    INSERT INTO finding_dedupe_group_members VALUES ('group', 'a'), ('group', 'b');`);
  const before = db.prepare("SELECT total_changes() AS count").get();
  const result = dashboard(db, {
    view: "findings",
    sort: "title",
    direction: "asc",
    query: "ÉVALUATION",
    repository: "Alpha",
    limit: 1,
    offset: 1,
    id: "b",
  });
  assert.deepEqual(
    result.items.map((item) => item.id),
    ["c"],
  );
  assert.equal(result.total, 2);
  assert.equal(result.nextOffset, null);
  assert.deepEqual(result.overview, { findings: 3, groups: 1 });
  assert.deepEqual(result.repositories, [
    { id: "Alpha", label: "Alpha" },
    { id: "beta", label: "beta" },
  ]);
  assert.equal(result.detail?.item.id, "b");
  assert.deepEqual(result.detail?.finding, selected);
  assert.deepEqual(result.detail?.groups, [
    { groupId: "group", createdAt: "created", findingIds: ["a", "b"] },
  ]);
  const groups = dashboard(db, {
    view: "groups",
    sort: "members",
    repository: "Alpha",
    limit: 1,
    offset: 0,
    id: "group",
  });
  assert.deepEqual(groups.items[0].repositoryIds, ["Alpha", "beta"]);
  assert.equal(groups.items[0].memberCount, 2);
  assert.deepEqual(groups.detail?.group, result.detail?.groups?.[0]);
  for (const query of ["ΟΣ", "οσ", "ος"])
    assert.deepEqual(
      dashboard(db, {
        view: "findings",
        sort: "title",
        query,
        limit: 50,
        offset: 0,
      }).items.map((item) => item.id),
      ["b"],
    );
  assert.deepEqual(db.prepare("SELECT total_changes() AS count").get(), before);
});

test("dashboard preserves NUL text through display, filters, search, and sorting", (t) => {
  const db = database(t);
  const first = "first\0id";
  const second = "second\0id";
  const selected = insert(db, first, "repository\0Zulu", "Title\0Zulu");
  insert(db, second, "repository\0Alpha", "Title\0Alpha");
  const query = {
    view: "findings",
    sort: "title",
    direction: "asc",
    limit: 50,
    offset: 0,
  } as const;
  const result = dashboard(db, { ...query, id: first });
  assert.deepEqual(
    result.items.map((item) => item.id),
    [second, first],
  );
  assert.deepEqual(
    result.items.map((item) => item.title),
    ["Title\0Alpha", "Title\0Zulu"],
  );
  assert.deepEqual(result.repositories, [
    { id: "repository\0Alpha", label: "repository\0Alpha" },
    { id: "repository\0Zulu", label: "repository\0Zulu" },
  ]);
  assert.equal(result.detail?.item.id, first);
  assert.deepEqual(result.detail?.finding, selected);
  assert.deepEqual(
    dashboard(db, {
      ...query,
      repository: result.repositories[0].id,
    }).items.map((item) => item.id),
    [second],
  );
  assert.deepEqual(
    dashboard(db, { ...query, query: "\0ALPHA" }).items.map((item) => item.id),
    [second],
  );
  assert.deepEqual(
    dashboard(db, { ...query, sort: "repository" }).items.map(
      (item) => item.id,
    ),
    [second, first],
  );
  db.exec("INSERT INTO finding_dedupe_groups VALUES ('group', 'created')");
  const member = db.prepare(
    "INSERT INTO finding_dedupe_group_members VALUES ('group', ?)",
  );
  member.run(first);
  member.run(second);
  const groups = dashboard(db, {
    ...query,
    view: "groups",
    query: "ALPHA",
    id: "group",
  });
  assert.equal(groups.total, 1);
  assert.deepEqual(groups.detail?.group?.findingIds, [first, second]);
});

test("dashboard rejects malformed Unicode query keys without aliasing stored values", (t) => {
  const db = database(t);
  const stored = insert(db, "record-\ufffd", "scope-\ufffd", "Title\ufffd");
  const query = {
    view: "findings",
    sort: "title",
    limit: 50,
    offset: 0,
  } as const;
  assert.deepEqual(
    dashboard(db, { ...query, repository: "scope-\ufffd", id: "record-\ufffd" })
      .detail?.finding,
    stored,
  );
  for (const filter of [
    { query: "Title\ud800" },
    { repository: "scope-\ud800" },
    { id: "record-\ud800" },
  ]) {
    assert.throws(() => dashboard(db, { ...query, ...filter }));
  }
});

test("dashboard reads its counts and rows from one WAL snapshot", async (t) => {
  const path = join(
    await temporary.create("workbench-dashboard-"),
    "state.sqlite3",
  );
  const db = database(t, path);
  db.exec("PRAGMA journal_mode = WAL");
  insert(db, "before", "repository");
  const writer = new DatabaseSync(path);
  t.after(() => writer.close());
  const prepare = db.prepare.bind(db);
  let written = false;
  t.mock.method(db, "prepare", (sql: string) => {
    if (!written && sql.startsWith("SELECT COUNT(*) AS count FROM (")) {
      written = true;
      insert(writer, "after", "new-repository");
    }
    return prepare(sql);
  });
  const query = {
    view: "findings",
    sort: "newest",
    limit: 50,
    offset: 0,
  } as const;
  const snapshot = dashboard(db, query);
  assert.equal(written, true);
  assert.equal(snapshot.total, 1);
  assert.equal(snapshot.overview.findings, 1);
  assert.deepEqual(
    snapshot.items.map((item) => item.id),
    ["before"],
  );
  assert.deepEqual(snapshot.repositories, [
    { id: "repository", label: "repository" },
  ]);
  assert.equal(dashboard(db, query).total, 2);
});
