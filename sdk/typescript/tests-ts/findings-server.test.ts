import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { handleFindingsRequest } from "../src/server/routes.js";
import { findingsRequestValidator } from "../src/server/validation.js";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { afterEach, expect, spyOn, test, mock } from "bun:test";
import type { Finding, FindingsDocument } from "../src/models.js";
import type { FindingDedupeGroup } from "../src/finding-dedupe-groups.js";
import {
  resolvePluginPython,
  runCodexCommand,
  runWorkbench,
} from "../src/runtime.js";
import type { FindingEmbedder } from "../src/server/embeddings.js";
import { FindingsError } from "../src/server/errors.js";
import { startFindingsServer } from "../src/server/server.js";
import { SqliteFindingsStore } from "../src/server/sqlite-store.js";
import type { EmbeddedFinding, FindingsPage } from "../src/server/storage.js";
import type { DashboardSnapshot } from "../src/server/dashboard-types.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { rejecting } from "./support/errors.js";

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
  return {
    environment,
    store: new SqliteFindingsStore({
      ...environment,
      PYTHON: join(directory, "missing-python"),
    }),
  };
}

test("initializes the shared database concurrently without Python", async () => {
  const { environment } = await fixture();
  const nativeEnvironment = {
    ...environment,
    PYTHON: join(environment.CODEX_SECURITY_STATE_DIR, "missing-python"),
  };
  await Promise.all([
    new SqliteFindingsStore(nativeEnvironment).initialize(),
    new SqliteFindingsStore(nativeEnvironment).initialize(),
  ]);
  const result = await runWorkbench(
    { pluginRoot: PLUGIN_ROOT, environment: nativeEnvironment },
    ["database-info"],
  );
  expect(result).toEqual({
    databasePath: join(
      await realpath(environment.CODEX_SECURITY_STATE_DIR),
      "workbench.sqlite3",
    ),
  });
});

test("invalid findings pagination is rejected before database creation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "findings-page-"));
  directories.push(directory);
  const stateDirectory = join(directory, "state");
  for (const payload of [
    { limit: 0, offset: 0 },
    { limit: 1, offset: -1 },
  ]) {
    const result = await runCodexCommand(
      { command: "node" },
      [join(PLUGIN_ROOT, "mcp", "helpers.mjs"), "list-stored-findings"],
      process.env,
      JSON.stringify({ stateDirectory, payload }),
    );
    expect(result.success).toBe(false);
    expect(result.stderr).toContain("limit must be a positive integer");
  }
  expect(await readdir(directory)).toEqual([]);
});

test.skipIf(process.platform === "win32")(
  "database initialization under Bun ignores repository-local Node shims",
  async () => {
    const directory = await mkdtemp(join(tmpdir(), "database-info-node-"));
    directories.push(directory);
    const repository = join(directory, "repository");
    const other = join(directory, "other", "nested");
    await mkdir(other, { recursive: true });
    const bin = join(repository, "node_modules", ".bin");
    await mkdir(bin, { recursive: true });
    await writeFile(
      join(bin, "node"),
      `#!/bin/sh
: > "$SYNTHETIC_NODE_SHIM_MARKER"
printf '%s\n' '{"databasePath":"shim"}'
`,
      { mode: 0o755 },
    );
    const node = Bun.which("node");
    expect(node).not.toBeNull();
    const tools = join(directory, "tools");
    const replacementTools = join(directory, "other", "tools");
    await Promise.all([mkdir(tools), mkdir(replacementTools)]);
    await symlink(node!, join(tools, "node"));
    await writeFile(
      join(replacementTools, "node"),
      '#!/bin/sh\nprintf invoked > "$SYNTHETIC_NODE_SHIM_MARKER"\nexit 1\n',
      { mode: 0o755 },
    );
    const state = join(directory, "state");
    const result = Bun.spawnSync(
      [
        process.execPath,
        "--eval",
        `const { SqliteFindingsStore } = await import(${JSON.stringify(new URL("../src/server/sqlite-store.ts", import.meta.url).href)});
const store = new SqliteFindingsStore();
await store.initialize();
process.chdir(${JSON.stringify(other)});
await store.initialize();
await store.list({ limit: 1, offset: 0 });`,
      ],
      {
        cwd: repository,
        env: {
          ...process.env,
          PATH: [bin, "../tools"].join(delimiter),
          CODEX_SECURITY_STATE_DIR: state,
          SYNTHETIC_NODE_SHIM_MARKER: join(bin, "invoked"),
        },
      },
    );
    expect(result.exitCode).toBe(0);
    expect(await readdir(bin)).toEqual(["node"]);
    expect(
      (await readFile(join(state, "workbench.sqlite3")))
        .subarray(0, 16)
        .toString(),
    ).toBe("SQLite format 3\0");
  },
);

test.skipIf(process.platform === "win32")(
  "database initialization and findings operations share the configured state directory",
  async () => {
    const directory = await mkdtemp(join(tmpdir(), "database-info-location-"));
    directories.push(directory);
    const store = new SqliteFindingsStore({
      ...process.env,
      CODEX_SECURITY_STATE_DIR: join(directory, "state ") + "/",
    });
    await store.insert([embedded(1)], "repository-a");
    await store.initialize();
    expect(await readdir(directory)).toEqual(["state "]);
    expect((await store.list({ limit: 50, offset: 0 })).findings).toEqual([
      finding(1),
    ]);
  },
);

test("initialized stores keep relative state in the original directory", async () => {
  const directory = await mkdtemp(join(tmpdir(), "findings-relative-state-"));
  directories.push(directory);
  const first = join(directory, "first");
  const second = join(directory, "second");
  await Promise.all([mkdir(first), mkdir(second)]);
  const result = Bun.spawnSync(
    [
      process.execPath,
      "--eval",
      `const { SqliteFindingsStore } = await import(${JSON.stringify(new URL("../src/server/sqlite-store.ts", import.meta.url).href)});
const store = new SqliteFindingsStore();
await store.initialize();
process.chdir(${JSON.stringify(second)});
await store.insert(${JSON.stringify([embedded(1)])});
console.log(JSON.stringify(await store.list({ limit: 50, offset: 0 })));`,
    ],
    {
      cwd: first,
      env: {
        ...process.env,
        CODEX_SECURITY_STATE_DIR: "state",
        PYTHON: join(directory, "missing-python"),
      },
    },
  );
  expect(result.exitCode, result.stderr.toString()).toBe(0);
  expect(JSON.parse(result.stdout.toString()).findings).toEqual([finding(1)]);
  expect(await readdir(first)).toEqual(["state"]);
  expect(await readdir(second)).toEqual([]);
});

test("initialized stores retain their environment across findings operations", async () => {
  const { environment } = await fixture();
  const store = new SqliteFindingsStore(environment);
  await store.initialize();
  const directory = dirname(environment.CODEX_SECURITY_STATE_DIR);
  environment.CODEX_SECURITY_STATE_DIR = join(directory, "other state");
  const entries = [embedded(1), embedded(2)];
  await store.insert(entries);
  const groups = await store.storeDedupeGroups([
    entries.map(({ finding }) => finding.findingId),
  ]);
  expect(await store.listDedupeGroups(entries[0]!.finding.findingId)).toEqual(
    groups,
  );
  expect((await store.list({ limit: 50, offset: 0 })).findings).toEqual(
    entries.map(({ finding }) => finding),
  );
  expect(await readdir(directory)).toEqual(["state with spaces"]);
});

test("escapes terminal controls in database helper diagnostics", async () => {
  const directory = await mkdtemp(join(tmpdir(), "database-info-"));
  directories.push(directory);
  const blocked = join(directory, "blocked\u202e");
  await writeFile(blocked, "existing file");
  const result = await runCodexCommand(
    { command: "node" },
    [join(PLUGIN_ROOT, "mcp", "helpers.mjs"), "database-info"],
    process.env,
    JSON.stringify(join(blocked, "state")),
  );
  expect(result.success).toBe(false);
  expect(result.stderr).toContain("\\u202e");
  expect(result.stderr).not.toContain("\u202e");
});

test("successful database helper JSON escapes terminal controls without changing the path", async () => {
  const directory = await mkdtemp(join(tmpdir(), "database-info-controls-"));
  directories.push(directory);
  const state = join(directory, "state\u009b\u202e\u{e0001}");
  const result = await runCodexCommand(
    { command: "node" },
    [join(PLUGIN_ROOT, "mcp", "helpers.mjs"), "database-info"],
    process.env,
    JSON.stringify(state),
  );
  expect(result.success).toBe(true);
  expect(JSON.parse(result.stdout)).toEqual({
    databasePath: join(await realpath(state), "workbench.sqlite3"),
  });
  expect(result.stdout.trimEnd()).not.toMatch(/[\p{Cc}\p{Cf}]/u);
  expect(result.stdout).toContain("\\udb40\\udc01");
});

test("database initialization uses the SDK's existing CODEX_HOME configuration", async () => {
  const directory = await mkdtemp(join(tmpdir(), "database-info-home-"));
  directories.push(directory);
  const result = await runWorkbench(
    {
      pluginRoot: PLUGIN_ROOT,
      environment: {
        ...process.env,
        CODEX_SECURITY_STATE_DIR: undefined,
        CODEX_HOME: directory,
        PYTHON: join(directory, "missing-python"),
      },
    },
    ["database-info"],
  );
  expect(result).toEqual({
    databasePath: join(
      await realpath(directory),
      "state/plugins/codex-security/workbench.sqlite3",
    ),
  });
});

test("database helper rejects invalid state-directory input before writing", async () => {
  const directory = await mkdtemp(join(tmpdir(), "database-info-input-"));
  directories.push(directory);
  const ignoredEnvironmentPath = join(directory, "must-not-be-created");
  for (const input of [
    undefined,
    JSON.stringify(null),
    JSON.stringify("~synthetic-user"),
    JSON.stringify("C:"),
    JSON.stringify(directory + "/raw\udcff"),
  ]) {
    const result = await runCodexCommand(
      { command: "node" },
      [join(PLUGIN_ROOT, "mcp", "helpers.mjs"), "database-info"],
      { ...process.env, CODEX_SECURITY_STATE_DIR: ignoredEnvironmentPath },
      input,
    );
    expect(result.success).toBe(false);
    expect(result.stderr).not.toBe("");
  }
  expect(await readdir(directory)).toEqual([]);
});

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
    embed: rejecting("Read-only dashboard called embeddings"),
  });
  for (const path of ["/", "/dashboard"]) {
    const redirect = await fetch(`${base}${path}`, { redirect: "manual" });
    expect(redirect.status).toBe(308);
    for (const prefix of ["", "/service"]) {
      expect(
        new URL(redirect.headers.get("location")!, `${base}${prefix}${path}`)
          .pathname,
      ).toBe(`${prefix}/dashboard/`);
    }
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
    "direction=unknown",
    "direction=ASC",
    "view=findings&sort=members",
    "view=groups&sort=severity",
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

test("dashboard sorts findings across pages with stable ties and filters", async () => {
  const { store, environment } = await fixture();
  const base = await start(store);
  const titles = [
    "Zulu",
    "alpha",
    "Bravo",
    "ALPHA",
    "Éclair",
    "éCLAIR",
    "alpha",
  ];
  const severities: Finding["severity"]["level"][] = [
    "low",
    "critical",
    "high",
    "medium",
    "informational",
    "critical",
    "critical",
  ];
  const repositories = [
    ["zeta"],
    ["zeta", "Alpha"],
    ["beta"],
    ["beta", "Alpha"],
    ["équipe"],
    ["ÉQUIPE"],
    ["Alpha", "beta"],
  ];
  const findings = titles.map((title, index) => {
    const value = finding(index + 1);
    value.title = title;
    value.severity.level = severities[index]!;
    return value;
  });
  for (const [index, value] of findings.entries()) {
    for (const repository of repositories[index]!) {
      await store.insert(
        [{ ...embedded(index + 1), finding: value }],
        repository,
      );
    }
  }
  await database(
    environment,
    `with db:
    db.executemany("UPDATE findings SET created_at = ?, updated_at = ? WHERE id = ?", json.load(sys.stdin))
print("null")`,
    findings.map((value, index) => [
      `2026-01-0${[3, 1, 2, 1, 4, 4, 1][index]}T00:00:00Z`,
      `2026-02-0${[1, 2, 2, 2, 3, 2, 2][index]}T00:00:00Z`,
      value.findingId,
    ]),
  );
  const ids = (indices: number[]) =>
    indices.map((index) => findings[index - 1]!.findingId);
  const orders = {
    activity: { asc: [1, 2, 6, 7, 3, 4, 5], desc: [5, 2, 6, 7, 3, 4, 1] },
    newest: { asc: [2, 4, 7, 3, 1, 5, 6], desc: [5, 6, 1, 3, 2, 4, 7] },
    title: { asc: [2, 4, 7, 3, 1, 5, 6], desc: [5, 6, 1, 3, 2, 4, 7] },
    repository: { asc: [4, 7, 2, 3, 1, 5, 6], desc: [5, 6, 1, 3, 2, 4, 7] },
    severity: { asc: [5, 1, 4, 3, 2, 6, 7], desc: [2, 6, 7, 3, 4, 1, 5] },
  };
  for (const [sort, directions] of Object.entries(orders)) {
    for (const [direction, indices] of Object.entries(directions)) {
      const result = await dashboard(base, { sort, direction });
      expect(result.items.map((item) => item.id)).toEqual(ids(indices));
      const page = await dashboard(base, {
        sort,
        direction,
        limit: "2",
        offset: "2",
      });
      expect(page.items).toEqual(result.items.slice(2, 4));
      expect(page.total).toBe(7);
      expect(page.nextOffset).toBe(4);
    }
  }
  for (const sort of ["activity", "newest"] as const) {
    const result = await dashboard(base, { sort });
    expect(result.items.map((item) => item.id)).toEqual(ids(orders[sort].desc));
  }
  const result = await dashboard(base);
  expect(result.items.map((item) => item.id)).toEqual(
    ids(orders.activity.desc),
  );
  expect(
    result.items.find((item) => item.id === findings[1]!.findingId)!
      .repositoryIds,
  ).toEqual(["Alpha", "zeta"]);
  const filtered = await dashboard(base, {
    sort: "severity",
    direction: "desc",
    query: "ALPHA",
    repository: "Alpha",
    limit: "1",
    offset: "1",
  });
  expect(filtered.items.map((item) => item.id)).toEqual(ids([7]));
  expect(filtered.total).toBe(3);
  expect(filtered.nextOffset).toBe(2);
});

test("dashboard sorts group columns by numeric members and displayed repositories", async () => {
  const { store, environment } = await fixture();
  const base = await start(store);
  const entries = Array.from({ length: 12 }, (_, index) => embedded(index + 1));
  await store.insert(entries, "zeta");
  await store.insert([entries[0]!], "Alpha");
  await store.insert([entries[1]!], "beta");
  const groups = await store.storeDedupeGroups([
    [entries[0]!, entries[2]!].map((entry) => entry.finding.findingId),
    [entries[1]!, entries[2]!, entries[3]!].map(
      (entry) => entry.finding.findingId,
    ),
    entries.slice(2).map((entry) => entry.finding.findingId),
    [entries[0]!, entries[3]!].map((entry) => entry.finding.findingId),
  ]);
  await database(
    environment,
    `with db:
    db.executemany("UPDATE finding_dedupe_groups SET created_at = ? WHERE id = ?", json.load(sys.stdin))
print("null")`,
    groups.map((group, index) => [
      `2026-01-0${[2, 1, 3, 2][index]}T00:00:00Z`,
      group.groupId,
    ]),
  );
  const [first, second, third, fourth] = groups.map(
    (group) => group.groupId,
  ) as [string, string, string, string];
  const tied = [first, fourth].sort();
  const titles = groups.map((group) => group.groupId).sort();
  const orders = {
    activity: { asc: [second, ...tied, third], desc: [third, ...tied, second] },
    newest: { asc: [second, ...tied, third], desc: [third, ...tied, second] },
    title: { asc: titles, desc: [...titles].reverse() },
    repository: {
      asc: [...tied, second, third],
      desc: [third, second, ...tied],
    },
    members: { asc: [...tied, second, third], desc: [third, second, ...tied] },
  };
  for (const [sort, directions] of Object.entries(orders)) {
    for (const [direction, ids] of Object.entries(directions)) {
      const result = await dashboard(base, { view: "groups", sort, direction });
      expect(result.items.map((item) => item.id)).toEqual(ids);
      const page = await dashboard(base, {
        view: "groups",
        sort,
        direction,
        limit: "2",
        offset: "1",
      });
      expect(page.items).toEqual(result.items.slice(1, 3));
      expect(page.nextOffset).toBe(3);
    }
  }
  const filtered = await dashboard(base, {
    view: "groups",
    sort: "members",
    direction: "desc",
    repository: "Alpha",
    limit: "1",
    offset: "1",
  });
  expect(filtered.items.map((item) => item.id)).toEqual(tied.slice(1));
  expect(filtered.items[0]!.repositoryIds).toEqual(["Alpha", "zeta"]);
  expect(filtered.total).toBe(2);
  expect(filtered.nextOffset).toBeNull();
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

test("bulk insert keeps startup dependencies and complete findings without creating scans", async () => {
  const { store, environment } = await fixture();
  const options = { store, embeddings: embedder, host: "127.0.0.1", port: 0 };
  const server = await startFindingsServer(options);
  servers.push(server);
  const address = server.address();
  if (address === null || typeof address === "string")
    throw new Error("No port");
  const base = `http://127.0.0.1:${address.port}`;
  options.store = (await fixture()).store;
  options.embeddings = {
    embed: rejecting("Replaced server embedder was used"),
  };
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
    "embeddings": [[row[0], row[1], json.loads(row[2])] for row in db.execute("SELECT finding_id, model, vector_json FROM finding_embeddings ORDER BY finding_id")]
}))`,
    ),
  ).toEqual({
    memberships: 6,
    embeddings: entries.map((entry) => [
      entry.finding.findingId,
      "synthetic",
      [1, 0],
    ]),
  });
  expect(await getGroups(base, "missing-finding")).toEqual([]);
});

test("rolls back the entire dedupe batch if a finding is missing and rejects invalid groups", async () => {
  const { store, environment } = await fixture();
  const base = await start(store, {
    embed: rejecting("Grouping must not embed"),
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

test("translates native duplicate retrieval failures without broadening scope", async () => {
  const { store } = await fixture();
  const anchor = embedded(1);
  await store.insert([anchor], "repository-a");
  await store.insert([embedded(2, [0, 0])], "repository-b");
  expect(
    await store.findPotentialDuplicates(anchor.finding.findingId, {
      repositoryId: "repository-a",
    }),
  ).toEqual({ finding: anchor.finding, potentialDuplicates: [] });
  await expect(
    store.findPotentialDuplicates(anchor.finding.findingId, {
      repositoryId: "repository-b",
    }),
  ).rejects.toMatchObject({ code: "finding_not_indexed" });
  await expect(
    store.findPotentialDuplicates(anchor.finding.findingId, {
      allRepositories: true,
    }),
  ).rejects.toMatchObject({ code: "embedding_failed" });
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
        headers: { "Content-Type": "application/json" },
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

test.each([
  undefined,
  "text/plain;charset=UTF-8",
  "application/x-www-form-urlencoded",
  "multipart/form-data; boundary=synthetic-qa",
])(
  "rejects non-JSON mutation bodies before side effects: %s",
  async (mediaType) => {
    const { store } = await fixture();
    const embed = mock(embedder.embed);
    const base = await start(store, { embed });
    const existing = [finding(1), finding(2)];
    expect((await insert(base, existing)).status).toBe(201);
    embed.mockClear();
    const writeGroups = spyOn(store, "storeDedupeGroups");
    try {
      for (const [path, body] of [
        ["/v1/bulk/findings", { findings: [finding(3)] }],
        ["/v1/dedupe-groups", { groups: [existing.map((f) => f.findingId)] }],
      ] as const) {
        const response = await fetch(base + path, {
          method: "POST",
          headers: {
            Origin: "null",
            "Sec-Fetch-Site": "cross-site",
            ...(mediaType === undefined ? {} : { "Content-Type": mediaType }),
          },
          body: Buffer.from(JSON.stringify(body)),
        });
        expect(response.status).toBe(400);
        expect(await response.json()).toEqual({
          error: "invalid_request",
          message: "Request body must use application/json.",
        });
      }
      expect(embed).not.toHaveBeenCalled();
      expect(writeGroups).not.toHaveBeenCalled();
      expect(
        (await (await fetch(base + "/v1/findings")).json()).findings,
      ).toEqual(existing);
      expect(await getGroups(base, existing[0]!.findingId)).toEqual([]);
    } finally {
      writeGroups.mockRestore();
    }
  },
);

test.each(["application/json", "Application/JSON; charset=UTF-8"])(
  "accepts JSON mutation bodies with MIME type %s",
  async (mediaType) => {
    const { store } = await fixture();
    const base = await start(store);
    const findings = [finding(1), finding(2)];
    for (const [path, body] of [
      ["/v1/bulk/findings", { findings }],
      ["/v1/dedupe-groups", { groups: [findings.map((f) => f.findingId)] }],
    ] as const) {
      const response = await fetch(base + path, {
        method: "POST",
        headers: { "Content-Type": mediaType },
        body: JSON.stringify(body),
      });
      expect(response.status).toBe(201);
    }
    expect(await getGroups(base, findings[0]!.findingId)).toHaveLength(1);
  },
);

test("rejects invalid requests before embedding and preserves unknown-route behavior", async () => {
  const { store } = await fixture();
  const embed = mock<() => Promise<never[]>>().mockResolvedValue([]);
  const base = await start(store, {
    embed,
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
      headers: { "Content-Type": "application/json" },
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
  expect(embed).toHaveBeenCalledTimes(0);
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

test("dashboard can sort and search a stored title with an unpaired surrogate", async () => {
  const { store } = await fixture();
  const base = await start(store);
  const malformed = finding();
  malformed.title = "Synthetic title \ud800";
  expect((await insert(base, [malformed, finding(2)])).status).toBe(201);
  const queries: Record<string, string>[] = [
    {},
    { sort: "title" },
    { query: "synthetic" },
  ];
  for (const parameters of queries) {
    const result = await dashboard(base, parameters);
    expect(result.items).toHaveLength(2);
    expect(
      result.items.find((item) => item.id === malformed.findingId)?.title,
    ).toContain("Synthetic title");
  }
});

test("malformed request targets return invalid_request at the HTTP handler", async () => {
  const { store } = await fixture();
  let status: number | undefined;
  let body: string | undefined;
  await handleFindingsRequest(
    { method: "GET", url: "//" } as IncomingMessage,
    {
      writeHead(code: number) {
        status = code;
      },
      end(data: string) {
        body = data;
      },
    } as ServerResponse,
    store,
    embedder,
    await findingsRequestValidator(),
  );
  expect(status).toBe(400);
  expect(JSON.parse(body!).error).toBe("invalid_request");
});

test("NUL repository IDs are rejected before ingestion and lookup", async () => {
  const { store } = await fixture();
  const embed = mock(embedder.embed);
  const base = await start(store, { embed });
  for (const repositoryId of ["\0", "repository\0suffix"]) {
    const response = await insert(base, [finding()], repositoryId);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_request" });
    const lookup = await fetch(
      `${base}/v1/finding/${finding().findingId}/potential-duplicates?${new URLSearchParams({ repositoryId })}`,
    );
    expect(lookup.status).toBe(400);
    expect(await lookup.json()).toMatchObject({ error: "invalid_request" });
  }
  expect(embed).toHaveBeenCalledTimes(0);
  expect((await store.list({ limit: 50, offset: 0 })).findings).toEqual([]);

  for (const repositoryId of ["repository-a", "\\^@"]) {
    expect((await insert(base, [finding()], repositoryId)).status).toBe(201);
    const lookup = await fetch(
      `${base}/v1/finding/${finding().findingId}/potential-duplicates?${new URLSearchParams({ repositoryId })}`,
    );
    expect(lookup.status).toBe(200);
    expect(await lookup.json()).toMatchObject({ finding: finding() });
  }
  expect(embed).toHaveBeenCalledTimes(2);
});
