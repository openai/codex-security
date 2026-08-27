import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import type { Finding, FindingsDocument } from "../src/models.js";
import type { FindingDedupeGroup } from "../src/finding-dedupe-groups.js";
import { resolvePluginPython, runCodexCommand } from "../src/runtime.js";
import type { FindingEmbedder } from "../src/server/embeddings.js";
import { FindingsError } from "../src/server/errors.js";
import { startFindingsServer } from "../src/server/server.js";
import { SqliteFindingsStore } from "../src/server/sqlite-store.js";
import type { EmbeddedFinding, FindingsPage } from "../src/server/storage.js";
import type { DashboardSnapshot } from "../src/server/dashboard-types.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const servers: Server[] = [];
const directories: string[] = [];
const example = (
  JSON.parse(
    await readFile(
      join(PLUGIN_ROOT, "examples/completed-scan/findings.json"),
      "utf8",
    ),
  ) as FindingsDocument
).findings[0]!;

function finding(index = 1): Finding {
  return {
    ...structuredClone(example),
    findingId: `csf_${index.toString(16).padStart(24, "0")}`,
    occurrenceId: `occ_${index.toString(16).padStart(24, "0")}`,
    fingerprints: {
      algorithm: "codex-security/v1",
      primary: `codex-security/v1:sha256:${index.toString(16).padStart(64, "0")}`,
    },
    title: `Synthetic finding ${index}`,
    extensions: { evidence: { text: "complete evidence ✓", values: [1, 2] } },
  };
}

function embedded(
  index: number,
  vector = [1, 0],
  model = "synthetic",
): EmbeddedFinding {
  return { finding: finding(index), embedding: { model, vector } };
}

const embedder: FindingEmbedder = {
  async embed(findings) {
    return findings.map((_, index) => ({
      model: "synthetic-model",
      vector: [index, 0.5],
    }));
  },
};

afterEach(async () => {
  for (const server of servers.splice(0)) {
    await new Promise<void>((resolve, reject) => {
      server.close((error) =>
        error === undefined ? resolve() : reject(error),
      );
    });
  }
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true });
});

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), "findings-store-"));
  directories.push(directory);
  const environment = {
    ...process.env,
    CODEX_SECURITY_STATE_DIR: join(directory, "state with spaces"),
  };
  return { environment, store: new SqliteFindingsStore(environment) };
}

async function start(
  store: SqliteFindingsStore,
  embeddings = embedder,
): Promise<string> {
  const server = await startFindingsServer({
    store,
    embeddings,
    host: "127.0.0.1",
    port: 0,
  });
  servers.push(server);
  const address = server.address();
  if (address === null || typeof address === "string")
    throw new Error("No port");
  return `http://127.0.0.1:${address.port}`;
}

function insert(
  base: string,
  findings: Finding[],
  repositoryId = "repository-a",
) {
  return fetch(`${base}/v1/bulk/findings`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ findings, repositoryId }),
  });
}

function storeGroups(base: string, groups: unknown) {
  return fetch(`${base}/v1/dedupe-groups`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ groups }),
  });
}

async function dashboard(
  base: string,
  parameters: Record<string, string> = {},
) {
  const response = await fetch(
    `${base}/v1/dashboard?${new URLSearchParams(parameters)}`,
  );
  expect(response.status).toBe(200);
  expect(response.headers.get("cache-control")).toBe("no-store");
  return (await response.json()) as DashboardSnapshot;
}

test("dashboard serves only findings and groups, and never calls an embedding provider", async () => {
  const { store } = await fixture();
  const base = await start(store, {
    async embed() {
      throw new Error("Read-only dashboard called embeddings");
    },
  });
  const redirect = await fetch(`${base}/dashboard`, { redirect: "manual" });
  expect(redirect.status).toBe(308);
  for (const prefix of ["", "/service"]) {
    expect(
      new URL(redirect.headers.get("location")!, `${base}${prefix}/dashboard`)
        .pathname,
    ).toBe(`${prefix}/dashboard/`);
  }
  for (const view of ["findings", "groups"]) {
    const result = await dashboard(base, { view });
    expect(result).toMatchObject({
      items: [],
      total: 0,
      nextOffset: null,
      detail: null,
      overview: { findings: 0, groups: 0 },
    });
  }
  for (const parameters of [
    "view=unknown",
    "view=scans",
    "view=workflows",
    "sort=unknown",
    "offset=-1",
    "limit=0",
  ]) {
    expect((await fetch(`${base}/v1/dashboard?${parameters}`)).status).toBe(
      400,
    );
  }
  expect(
    (await fetch(`${base}/v1/dashboard`, { method: "POST", body: "{}" }))
      .status,
  ).toBe(404);
  expect((await fetch(`${base}/dashboard/not-a-bundled-asset`)).status).toBe(
    404,
  );
});

test("dashboard browses imported findings and overlapping groups without local runs", async () => {
  const { store, environment } = await fixture();
  const base = await start(store);
  const first = finding(1),
    second = finding(2),
    third = finding(3);
  first.title = "Évaluation synthétique";
  await store.insert(
    [{ ...embedded(1), finding: first }, embedded(2)],
    "repository-a",
  );
  await store.insert([embedded(3)], "repository-b");
  const groups = await store.storeDedupeGroups([
    [first.findingId, second.findingId],
    [second.findingId, third.findingId],
  ]);
  const before = await database(
    environment,
    "print(json.dumps(list(db.iterdump())))",
  );
  expect(
    await database(
      environment,
      `from workbench_dashboard import dashboard
allowed = {'findings', 'finding_repositories', 'finding_dedupe_groups', 'finding_dedupe_group_members'}
def authorize(action, table, column, database, source):
    if action == sqlite3.SQLITE_READ and table not in allowed:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK
db.set_authorizer(authorize)
queries = json.load(sys.stdin)
print(json.dumps([dashboard(db, query)['total'] for query in queries]))`,
      [
        {
          view: "findings",
          limit: 50,
          offset: 0,
          sort: "activity",
          id: first.findingId,
        },
        {
          view: "groups",
          limit: 50,
          offset: 0,
          sort: "newest",
          id: groups[0]!.groupId,
        },
      ],
    ),
  ).toEqual([3, 2]);

  const page = await dashboard(base, {
    limit: "1",
    repository: "repository-a",
    id: first.findingId,
  });
  expect(page.total).toBe(2);
  expect(page.repositories).toEqual([
    { id: "repository-a", label: "repository-a" },
    { id: "repository-b", label: "repository-b" },
  ]);
  expect(page.nextOffset).toBe(1);
  expect(page.overview).toEqual({
    findings: 3,
    groups: 2,
  });
  expect(page.detail).toMatchObject({
    finding: first,
    groups: [groups[0]],
  });
  const next = await dashboard(base, {
    view: "findings",
    limit: "1",
    offset: "1",
    repository: "repository-a",
  });
  expect(next.items[0]!.id).not.toBe(page.items[0]!.id);
  expect(next.nextOffset).toBeNull();
  expect(
    (await dashboard(base, { view: "findings", query: first.title })).items.map(
      (item) => item.id,
    ),
  ).toEqual([first.findingId]);
  for (const query of ["évaluation", "SYNTHÉTIQUE"]) {
    expect(
      (await dashboard(base, { view: "findings", query })).items.map(
        (item) => item.id,
      ),
    ).toEqual([first.findingId]);
  }
  expect(
    (
      await dashboard(base, { view: "groups", repository: "repository-b" })
    ).items.map((item) => item.id),
  ).toEqual([groups[1]!.groupId]);
  const group = await dashboard(base, {
    view: "groups",
    id: groups[0]!.groupId,
  });
  expect(group.detail!.group).toEqual(groups[0]!);
  expect(group.items).toHaveLength(2);
  expect(
    (await dashboard(base, { view: "findings", id: "not-stored" })).detail,
  ).toBeNull();
  expect(
    await database(environment, "print(json.dumps(list(db.iterdump())))"),
  ).toEqual(before);
});

async function getGroups(
  base: string,
  findingId: string,
): Promise<FindingDedupeGroup[]> {
  const response = await fetch(`${base}/v1/finding/${findingId}/dedupe-groups`);
  expect(response.status).toBe(200);
  return (await response.json()) as FindingDedupeGroup[];
}

async function database(
  environment: NodeJS.ProcessEnv,
  script: string,
  input?: unknown,
): Promise<unknown> {
  const python = await resolvePluginPython({ environment });
  const result = await runCodexCommand(
    { command: python },
    [
      "-I",
      "-B",
      "-X",
      "utf8",
      "-c",
      `import json, sqlite3, sys
from pathlib import Path
sys.path.insert(0, sys.argv[2])
path = Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
db = sqlite3.connect(path)
db.row_factory = sqlite3.Row
${script}
`,
      join(environment["CODEX_SECURITY_STATE_DIR"]!, "workbench.sqlite3"),
      join(PLUGIN_ROOT, "scripts"),
    ],
    environment,
    input === undefined ? undefined : JSON.stringify(input),
  );
  expect(result.success, result.stderr).toBe(true);
  return JSON.parse(result.stdout);
}

test("bulk insert preserves complete findings and embeddings without creating scans", async () => {
  const { store, environment } = await fixture();
  const base = await start(store);
  const findings = [finding(1), finding(2)];
  const log = spyOn(console, "log").mockImplementation(() => undefined);
  try {
    const response = await insert(base, findings);
    expect(response.status).toBe(201);
    expect(await response.json()).toEqual(
      findings.map((finding) => finding.findingId),
    );
    expect(log.mock.calls).toEqual([["POST /v1/bulk/findings"]]);
  } finally {
    log.mockRestore();
  }
  const response = await fetch(`${base}/v1/findings`);
  expect(await response.json()).toEqual({
    findings,
    limit: 50,
    offset: 0,
    total: 2,
    nextOffset: null,
  });
  expect(
    await database(
      environment,
      `print(json.dumps({
    "vectors": [{"findingId": row[0], "model": row[1], "vector": json.loads(row[2])} for row in db.execute("SELECT finding_id, model, vector_json FROM finding_embeddings ORDER BY finding_id")],
    "scans": db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
}))`,
    ),
  ).toEqual({
    vectors: findings.map((finding, index) => ({
      findingId: finding.findingId,
      model: "synthetic-model",
      vector: [index, 0.5],
    })),
    scans: 0,
  });

  const reopened = new SqliteFindingsStore(environment);
  await reopened.initialize();
  expect(
    await reopened.findPotentialDuplicates(findings[0]!.findingId, {
      repositoryId: "repository-a",
    }),
  ).toEqual({ finding: findings[0]!, potentialDuplicates: [] });
  expect((await reopened.list({ limit: 50, offset: 0 })).findings).toEqual(
    findings,
  );
});

test("persists overlapping dedupe groups idempotently without changing findings or embeddings", async () => {
  const { store, environment } = await fixture();
  const base = await start(store);
  const entries = [embedded(1), embedded(2), embedded(3)];
  await store.insert(entries);
  const [a, b, c] = entries.map((entry) => entry.finding.findingId) as [
    string,
    string,
    string,
  ];
  const groups = [
    [a, b],
    [b, c],
    [c, a],
  ];
  const response = await storeGroups(base, groups);
  expect(response.status).toBe(201);
  const stored = (await response.json()) as FindingDedupeGroup[];
  expect(stored.map((group) => group.findingIds)).toEqual(
    groups.map((group) => [...group].sort()),
  );
  expect(new Set(stored.map((group) => group.groupId)).size).toBe(3);
  for (const id of [a, b, c]) {
    expect(
      (await getGroups(base, id)).map((group) => group.groupId).sort(),
    ).toEqual(
      stored
        .filter((group) => group.findingIds.includes(id))
        .map((group) => group.groupId)
        .sort(),
    );
  }
  const retried = await storeGroups(
    base,
    groups.map((group) => [...group].reverse()),
  );
  expect(await retried.json()).toEqual(stored);
  const reopened = new SqliteFindingsStore(environment);
  await reopened.initialize();
  expect(await reopened.listDedupeGroups(b)).toEqual(await getGroups(base, b));
  expect((await reopened.list({ limit: 50, offset: 0 })).findings).toEqual(
    entries.map((entry) => entry.finding),
  );
  expect(
    await database(
      environment,
      `print(json.dumps({
    "memberships": db.execute("SELECT COUNT(*) FROM finding_dedupe_group_members").fetchone()[0],
    "embeddings": [list(row) for row in db.execute("SELECT finding_id, model, vector_json FROM finding_embeddings ORDER BY finding_id")]
}))`,
    ),
  ).toEqual({
    memberships: 6,
    embeddings: entries.map((entry) => [
      entry.finding.findingId,
      "synthetic",
      "[1, 0]",
    ]),
  });
  expect(await getGroups(base, "missing-finding")).toEqual([]);
});

test("rolls back the entire dedupe batch if a finding is missing and rejects invalid groups", async () => {
  const { store, environment } = await fixture();
  const base = await start(store, {
    embed: async () => {
      throw new Error("Grouping must not embed");
    },
  });
  await store.insert([embedded(1), embedded(2), embedded(3)]);
  const [a, b, c] = [1, 2, 3].map((index) => finding(index).findingId) as [
    string,
    string,
    string,
  ];
  const original = (await (
    await storeGroups(base, [[a, b]])
  ).json()) as FindingDedupeGroup[];
  const response = await storeGroups(base, [
    [b, c],
    [a, "missing-finding"],
  ]);
  expect(response.status).toBe(409);
  expect(await response.json()).toMatchObject({ error: "finding_conflict" });
  expect(await getGroups(base, c)).toEqual([]);
  expect(await getGroups(base, a)).toEqual(original);
  expect(
    await database(
      environment,
      `print(json.dumps({
    "groups": db.execute("SELECT COUNT(*) FROM finding_dedupe_groups").fetchone()[0],
    "memberships": db.execute("SELECT COUNT(*) FROM finding_dedupe_group_members").fetchone()[0]
}))`,
    ),
  ).toEqual({ groups: 1, memberships: 2 });
  for (const groups of [
    null,
    {},
    [a, b],
    [[]],
    [[a]],
    [[a, a]],
    [[a, 1]],
    [[a, ""]],
  ]) {
    expect((await storeGroups(base, groups)).status).toBe(400);
  }
  expect(await (await storeGroups(base, [])).json()).toEqual([]);
});

test("lists stable pages of 50 by default and supports limit and offset", async () => {
  const { store } = await fixture();
  const base = await start(store);
  const findings = Array.from({ length: 53 }, (_, index) => finding(index + 1));
  expect((await insert(base, findings)).status).toBe(201);
  const first = (await (
    await fetch(`${base}/v1/findings`)
  ).json()) as FindingsPage;
  expect(first).toEqual({
    findings: findings.slice(0, 50),
    limit: 50,
    offset: 0,
    total: 53,
    nextOffset: 50,
  });
  const second = await (
    await fetch(`${base}/v1/findings?offset=${first.nextOffset}&limit=2`)
  ).json();
  expect(second).toEqual({
    findings: findings.slice(50, 52),
    limit: 2,
    offset: 50,
    total: 53,
    nextOffset: 52,
  });
  expect(await (await fetch(`${base}/v1/findings?offset=52`)).json()).toEqual({
    findings: findings.slice(52),
    limit: 50,
    offset: 52,
    total: 53,
    nextOffset: null,
  });
  expect(await (await fetch(`${base}/v1/findings?offset=100`)).json()).toEqual({
    findings: [],
    limit: 50,
    offset: 100,
    total: 53,
    nextOffset: null,
  });
});

test("upserts retries and rolls back the entire batch on identity conflicts", async () => {
  const { store, environment } = await fixture();
  const base = await start(store);
  const original = finding();
  expect((await insert(base, [original])).status).toBe(201);
  const updated = { ...original, summary: "Updated complete summary" };
  expect((await insert(base, [updated])).status).toBe(201);
  const conflicting = { ...finding(2), fingerprints: original.fingerprints };
  const response = await insert(
    base,
    [{ ...original, summary: "Must roll back" }, conflicting],
    "repository-b",
  );
  expect(response.status).toBe(409);
  expect(await response.json()).toMatchObject({ error: "finding_conflict" });
  const replacedIdentity = {
    ...updated,
    fingerprints: finding(3).fingerprints,
  };
  expect((await insert(base, [replacedIdentity])).status).toBe(409);
  expect((await store.list({ limit: 50, offset: 0 })).findings).toEqual([
    updated,
  ]);
  expect(
    await database(
      environment,
      `print(json.dumps([json.loads(row[0]) for row in db.execute("SELECT vector_json FROM finding_embeddings")]))`,
    ),
  ).toEqual([[0, 0.5]]);
  expect(
    await database(
      environment,
      "print(json.dumps([list(row) for row in db.execute('SELECT repository_id, finding_id FROM finding_repositories')]))",
    ),
  ).toEqual([["repository-a", original.findingId]]);
});

test("retrieves complete potential duplicates without vectors or review calls", async () => {
  const { store } = await fixture();
  const base = await start(store);
  const findings = [finding(1), finding(2), finding(3)];
  await store.insert(
    findings.map((finding, index) => ({
      finding,
      embedding: { model: "synthetic", vector: index === 2 ? [0, 1] : [1, 0] },
    })),
    "repository-a",
  );
  const response = await fetch(
    `${base}/v1/finding/${findings[0]!.findingId}/potential-duplicates?repositoryId=repository-a`,
  );
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({
    finding: findings[0],
    potentialDuplicates: [findings[1]],
  });
  const isolated = await fetch(
    `${base}/v1/finding/${findings[2]!.findingId}/potential-duplicates?repositoryId=repository-a`,
  );
  expect(await isolated.json()).toEqual({
    finding: findings[2],
    potentialDuplicates: [],
  });
  const missing = await fetch(
    `${base}/v1/finding/${finding(4).findingId}/potential-duplicates?repositoryId=repository-a`,
  );
  expect(missing.status).toBe(404);
  expect(await missing.json()).toMatchObject({ error: "finding_not_indexed" });
  expect((await store.list({ limit: 50, offset: 0 })).findings).toEqual(
    findings,
  );
});

test("SQLite filters repository and embedding compatibility before exact cosine ranking", async () => {
  const { store, environment } = await fixture();
  await store.initialize();
  const anchor = embedded(1, [7, 0]);
  const boundary = embedded(2, [0.55, Math.sqrt(1 - 0.55 ** 2)]);
  const below = embedded(3, [0.54, Math.sqrt(1 - 0.54 ** 2)]);
  const otherModel = embedded(4, [1, 0], "other-model");
  const otherDimensions = embedded(5, [1, 0, 0]);
  const foreign = embedded(6);
  await store.insert(
    [anchor, below, otherModel, otherDimensions, boundary],
    "repository-a",
  );
  await store.insert([foreign], "repository-b");
  expect(
    await store.findPotentialDuplicates(anchor.finding.findingId, {
      repositoryId: "repository-a",
    }),
  ).toEqual({
    finding: anchor.finding,
    potentialDuplicates: [boundary.finding],
  });
  expect(
    await store.findPotentialDuplicates(anchor.finding.findingId, {
      allRepositories: true,
    }),
  ).toEqual({
    finding: anchor.finding,
    potentialDuplicates: [foreign.finding, boundary.finding],
  });
  await expect(
    store.findPotentialDuplicates(anchor.finding.findingId, {
      repositoryId: "repository-b",
    }),
  ).rejects.toMatchObject({ code: "finding_not_indexed" });
  await database(
    environment,
    `with db:
    db.execute("UPDATE finding_embeddings SET vector_json = '[0,0]' WHERE finding_id = ?", (json.load(sys.stdin),))
print("null")`,
    foreign.finding.findingId,
  );
  expect(
    (
      await store.findPotentialDuplicates(anchor.finding.findingId, {
        repositoryId: "repository-a",
      })
    ).potentialDuplicates,
  ).toEqual([boundary.finding]);
  await expect(
    store.findPotentialDuplicates(anchor.finding.findingId, {
      allRepositories: true,
    }),
  ).rejects.toMatchObject({ code: "embedding_failed" });
});

test("SQLite reads only IDs and vectors before fetching the anchor and stable top 50 documents", async () => {
  const { store, environment } = await fixture();
  await store.initialize();
  const entries = Array.from({ length: 61 }, (_, index) => embedded(index + 1));
  await store.insert(entries, "repository-a");
  await store.insert([entries[1]!], "repository-b");
  const { result, queries } = (await database(
    environment,
    `from workbench_findings import find_potential_duplicates
queries = []
db.set_trace_callback(queries.append)
result = find_potential_duplicates(db, json.load(sys.stdin), "repository-a")
print(json.dumps({"result": result, "queries": queries}))`,
    entries[0]!.finding.findingId,
  )) as {
    result: { finding: Finding; potentialDuplicates: Finding[] };
    queries: string[];
  };
  expect(result).toEqual({
    finding: entries[0]!.finding,
    potentialDuplicates: entries.slice(1, 51).map((entry) => entry.finding),
  });
  const reads = queries.filter((query) => query.startsWith("SELECT"));
  expect(reads).toHaveLength(3);
  expect(reads[0]).toStartWith(
    "SELECT embeddings.model, embeddings.vector_json ",
  );
  expect(reads[1]).toStartWith(
    "SELECT embeddings.finding_id, embeddings.vector_json ",
  );
  expect(reads[1]).toContain("repositories.repository_id = 'repository-a'");
  expect(reads[2]).toStartWith(
    "SELECT id, details_json FROM findings WHERE id IN (",
  );
  const loadedIds = [...reads[2]!.matchAll(/csf_[0-9a-f]+/g)].map(([id]) => id);
  expect(loadedIds).toEqual(
    entries.slice(0, 51).map((entry) => entry.finding.findingId),
  );
  expect(
    (
      await store.findPotentialDuplicates(entries[0]!.finding.findingId, {
        allRepositories: true,
      })
    ).potentialDuplicates,
  ).toEqual(result.potentialDuplicates);
});

test("imports persist repository associations and keep untagged findings in explicit all-repository scope", async () => {
  const { store, environment } = await fixture();
  const base = await start(store, {
    async embed(findings) {
      return findings.map(() => ({ model: "synthetic", vector: [1, 0] }));
    },
  });
  const findings = [finding(1), finding(2), finding(3)];
  expect((await insert(base, [findings[0]!], "repository-a")).status).toBe(201);
  expect(
    (await insert(base, [findings[0]!, findings[1]!], "repository-b")).status,
  ).toBe(201);
  expect((await insert(base, [findings[0]!], "repository-a")).status).toBe(201);
  expect(
    (
      await fetch(`${base}/v1/bulk/findings`, {
        method: "POST",
        body: JSON.stringify({ findings: [findings[2]] }),
      })
    ).status,
  ).toBe(201);
  const reopened = await start(new SqliteFindingsStore(environment));
  const path = `${reopened}/v1/finding/${findings[0]!.findingId}/potential-duplicates`;
  expect(
    await (await fetch(`${path}?repositoryId=repository-a`)).json(),
  ).toEqual({ finding: findings[0], potentialDuplicates: [] });
  expect(
    await (await fetch(`${path}?repositoryId=repository-b`)).json(),
  ).toEqual({ finding: findings[0], potentialDuplicates: [findings[1]] });
  expect(await (await fetch(`${path}?allRepositories=true`)).json()).toEqual({
    finding: findings[0],
    potentialDuplicates: findings.slice(1),
  });
  expect(
    (
      await fetch(
        `${reopened}/v1/finding/${findings[2]!.findingId}/potential-duplicates?repositoryId=repository-a`,
      )
    ).status,
  ).toBe(404);
  expect(
    await database(
      environment,
      "print(json.dumps([list(row) for row in db.execute('SELECT repository_id, finding_id FROM finding_repositories ORDER BY repository_id, finding_id')]))",
    ),
  ).toEqual([
    ["repository-a", findings[0]!.findingId],
    ["repository-b", findings[0]!.findingId],
    ["repository-b", findings[1]!.findingId],
  ]);
});

test("rejects invalid requests before embedding and preserves unknown-route behavior", async () => {
  const { store } = await fixture();
  let calls = 0;
  const base = await start(store, {
    async embed() {
      calls++;
      return [];
    },
  });
  for (const body of [
    "not json",
    "null",
    "[]",
    "{}",
    '{"findings":{}}',
    '{"findings":[{}]}',
    '{"repositoryId":"","findings":[]}',
    '{"repositoryId":42,"findings":[]}',
  ]) {
    const response = await fetch(`${base}/v1/bulk/findings`, {
      method: "POST",
      body,
    });
    expect(response.status).toBe(400);
  }
  for (const query of [
    "limit=0",
    "limit=1.5",
    "limit=NaN",
    "offset=-1",
    "offset=9007199254740992",
  ]) {
    expect((await fetch(`${base}/v1/findings?${query}`)).status).toBe(400);
  }
  for (const query of [
    "",
    "repositoryId=",
    "allRepositories=false",
    "allRepositories=yes",
    "repositoryId=repository-a&allRepositories=true",
  ]) {
    expect(
      (
        await fetch(
          `${base}/v1/finding/${finding().findingId}/potential-duplicates?${query}`,
        )
      ).status,
    ).toBe(400);
  }
  for (const [method, path] of [
    ["GET", "/unknown"],
    ["POST", "/v1/findings"],
    ["GET", "/v1/bulk/findings"],
    ["POST", "/v1/bulk/findings/dedupe"],
  ]) {
    const response = await fetch(`${base}${path}`, { method });
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "not_found" });
  }
  expect(calls).toBe(0);
});

test("embedding failure leaves no partial findings or vectors", async () => {
  const { store, environment } = await fixture();
  const base = await start(store, {
    async embed() {
      throw new FindingsError(
        "embedding_failed",
        "Embedding provider returned HTTP 429.",
      );
    },
  });
  const response = await insert(base, [finding()]);
  expect(response.status).toBe(502);
  expect(await response.json()).toMatchObject({ error: "embedding_failed" });
  expect((await store.list({ limit: 50, offset: 0 })).total).toBe(0);
  expect(
    await database(
      environment,
      `print(db.execute("SELECT COUNT(*) FROM finding_embeddings").fetchone()[0])`,
    ),
  ).toBe(0);
});

test("does not start when storage initialization fails", async () => {
  const { store, environment } = await fixture();
  await writeFile(environment.CODEX_SECURITY_STATE_DIR, "synthetic file");
  await expect(
    startFindingsServer({
      store,
      embeddings: embedder,
      host: "127.0.0.1",
      port: 0,
    }),
  ).rejects.toThrow("Could not access the findings database");
});

test("migrates existing complete scan findings and invalidates stale embeddings on CLI updates", async () => {
  const { store, environment } = await fixture();
  const original = finding();
  await database(
    environment,
    `from workbench_schema import MIGRATIONS, apply_migrations
finding = json.load(sys.stdin)
timestamp = "2026-01-01T00:00:00Z"
apply_migrations(db, tuple(m for m in MIGRATIONS if m[0] <= 32), lambda: timestamp, lambda _: None)
with db:
    db.execute("INSERT INTO workspaces (id, created_at, updated_at) VALUES ('workspace', ?, ?)", (timestamp, timestamp))
    db.execute("INSERT INTO security_targets (id, current_path, display_name, created_at, updated_at) VALUES ('repository-history', '/synthetic/repository', 'Synthetic repository', ?, ?)", (timestamp, timestamp))
    db.execute("INSERT INTO scans (id, workspace_id, target_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, created_at, updated_at) VALUES ('scan', 'workspace', 'repository-history', '/synthetic/repository', 'revision', '.', 'standard', '/synthetic/output', 'complete', 'reporting', ?, ?, ?)", (timestamp, timestamp, timestamp))
    db.execute("INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)", (finding["findingId"], finding["fingerprints"]["primary"], finding["ruleId"], finding["identity"]["anchor"], timestamp, timestamp))
    db.execute("INSERT INTO finding_occurrences (id, finding_id, scan_id, title, summary, severity, confidence, remediation, details_json, created_at) VALUES (?, ?, 'scan', ?, ?, ?, ?, ?, ?, ?)", (finding["occurrenceId"], finding["findingId"], finding["title"], finding["summary"], finding["severity"]["level"], finding["confidence"]["level"], finding["remediation"], json.dumps(finding), timestamp))
print("null")`,
    original,
  );
  await store.initialize();
  expect((await store.list({ limit: 50, offset: 0 })).findings).toEqual([
    original,
  ]);
  expect(
    await database(
      environment,
      "print(json.dumps([list(row) for row in db.execute('SELECT repository_id, finding_id FROM finding_repositories')]))",
    ),
  ).toEqual([["repository-history", original.findingId]]);
  await store.insert([
    { finding: original, embedding: { model: "synthetic", vector: [1, 0] } },
  ]);

  const update = `from workbench_finding_index import index_findings
with db:
    index_findings(db, "scan", {"findings": [json.load(sys.stdin)]}, "2026-01-02T00:00:00Z")
print(db.execute("SELECT COUNT(*) FROM finding_embeddings").fetchone()[0])`;
  expect(await database(environment, update, original)).toBe(1);
  const changed = { ...original, summary: "A newer scan updated this finding" };
  expect(await database(environment, update, changed)).toBe(0);
  await expect(
    store.findPotentialDuplicates(original.findingId, {
      allRepositories: true,
    }),
  ).rejects.toMatchObject({ code: "finding_not_indexed" });
  expect((await store.list({ limit: 50, offset: 0 })).findings).toEqual([
    changed,
  ]);
  await database(environment, update, finding(2));
  expect(
    await database(
      environment,
      "print(json.dumps([list(row) for row in db.execute('SELECT repository_id, finding_id FROM finding_repositories ORDER BY finding_id')]))",
    ),
  ).toEqual([
    ["repository-history", original.findingId],
    ["repository-history", finding(2).findingId],
  ]);
});
