import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import type { Finding, FindingsDocument } from "../src/models.js";
import { resolvePluginPython, runCodexCommand } from "../src/runtime.js";
import type { DeduplicationService } from "../src/server/deduplication/deduplication.js";
import type { FindingEmbedder } from "../src/server/embeddings.js";
import { FindingsError } from "../src/server/errors.js";
import { startFindingsServer } from "../src/server/server.js";
import { SqliteFindingsStore } from "../src/server/sqlite-store.js";
import type { FindingsPage } from "../src/server/storage.js";
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
  deduplication?: Pick<DeduplicationService, "run">,
): Promise<string> {
  const server = await startFindingsServer({
    store,
    embeddings,
    deduplication,
    host: "127.0.0.1",
    port: 0,
  });
  servers.push(server);
  const address = server.address();
  if (address === null || typeof address === "string")
    throw new Error("No port");
  return `http://127.0.0.1:${address.port}`;
}

function insert(base: string, findings: Finding[], path = "/v1/bulk/findings") {
  return fetch(`${base}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ findings }),
  });
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
  expect(await reopened.listEmbedded()).toEqual(
    findings.map((finding, index) => ({
      finding,
      embedding: { model: "synthetic-model", vector: [index, 0.5] },
    })),
  );
  expect((await reopened.list({ limit: 50, offset: 0 })).findings).toEqual(
    findings,
  );
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
  const response = await insert(base, [
    { ...original, summary: "Must roll back" },
    conflicting,
  ]);
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
});

test("dedupe endpoint awaits the workflow after persistence and returns its result", async () => {
  const { store } = await fixture();
  const findings = [finding(1), finding(2)];
  const workflow: Pick<DeduplicationService, "run"> = {
    async run(ids) {
      expect((await store.list({ limit: 50, offset: 0 })).findings).toEqual(
        findings,
      );
      await Promise.resolve();
      return {
        uniqueFindingIds: [...ids],
        duplicateGroups: [],
        deduplicationStatus: "completed",
      };
    },
  };
  const run = spyOn(workflow, "run");
  try {
    const base = await start(store, embedder, workflow);
    const response = await insert(base, findings, "/v1/bulk/findings/dedupe");
    expect(response.status).toBe(201);
    expect(await response.json()).toEqual({
      uniqueFindingIds: findings.map((finding) => finding.findingId),
      duplicateGroups: [],
      deduplicationStatus: "completed",
    });
    expect(run).toHaveBeenCalledWith(
      findings.map((finding) => finding.findingId),
    );
    expect((await insert(base, findings)).status).toBe(201);
    expect(run).toHaveBeenCalledTimes(1);
  } finally {
    run.mockRestore();
  }
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
  for (const [method, path] of [
    ["GET", "/unknown"],
    ["POST", "/v1/findings"],
    ["GET", "/v1/bulk/findings"],
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
  const response = await insert(base, [finding()], "/v1/bulk/findings/dedupe");
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

test("review failure reports an error after insertion without claiming unique findings", async () => {
  const { store } = await fixture();
  const findings = [finding()];
  const base = await start(store, embedder, {
    async run() {
      throw new FindingsError(
        "deduplication_failed",
        "Synthetic review failed",
      );
    },
  });
  const response = await insert(base, findings, "/v1/bulk/findings/dedupe");
  expect(response.status).toBe(502);
  expect(await response.json()).toEqual({
    error: "deduplication_failed",
    message: "Synthetic review failed",
  });
  expect((await store.list({ limit: 50, offset: 0 })).findings).toEqual(
    findings,
  );
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
    db.execute("INSERT INTO scans (id, workspace_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, created_at, updated_at) VALUES ('scan', 'workspace', '/synthetic/repository', 'revision', '.', 'standard', '/synthetic/output', 'complete', 'reporting', ?, ?, ?)", (timestamp, timestamp, timestamp))
    db.execute("INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)", (finding["findingId"], finding["fingerprints"]["primary"], finding["ruleId"], finding["identity"]["anchor"], timestamp, timestamp))
    db.execute("INSERT INTO finding_occurrences (id, finding_id, scan_id, title, summary, severity, confidence, remediation, details_json, created_at) VALUES (?, ?, 'scan', ?, ?, ?, ?, ?, ?, ?)", (finding["occurrenceId"], finding["findingId"], finding["title"], finding["summary"], finding["severity"]["level"], finding["confidence"]["level"], finding["remediation"], json.dumps(finding), timestamp))
print("null")`,
    original,
  );
  await store.initialize();
  expect((await store.list({ limit: 50, offset: 0 })).findings).toEqual([
    original,
  ]);
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
  expect(await store.listEmbedded()).toEqual([]);
  expect((await store.list({ limit: 50, offset: 0 })).findings).toEqual([
    changed,
  ]);
});
