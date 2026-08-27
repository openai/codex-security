import { mkdtemp, rm, writeFile } from "node:fs/promises";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import { resolvePluginPython, runCodexCommand } from "../src/runtime.js";
import { startFindingsServer } from "../src/server/server.js";
import { SqliteFindingsStore } from "../src/server/sqlite-store.js";

const servers: Server[] = [];
const directories: string[] = [];

afterEach(async () => {
  for (const server of servers.splice(0)) {
    await new Promise<void>((resolve, reject) => {
      server.close((error) =>
        error === undefined ? resolve() : reject(error),
      );
    });
  }
  for (const directory of directories.splice(0)) {
    await rm(directory, { recursive: true, force: true });
  }
});

test("serves only the two mock routes after storage is initialized", async () => {
  let initialized = false;
  const server = await startFindingsServer({
    host: "127.0.0.1",
    port: 0,
    store: {
      async initialize() {
        initialized = true;
      },
    },
  });
  servers.push(server);
  expect(initialized).toBe(true);
  const address = server.address();
  if (address === null || typeof address === "string")
    throw new Error("No port");
  const base = `http://127.0.0.1:${address.port}`;
  const log = spyOn(console, "log").mockImplementation(() => undefined);
  try {
    for (const [method, path] of [
      ["GET", "/v1/findings?limit=50&offset=0"],
      ["POST", "/v1/bulk/findings"],
    ] as const) {
      const response = await fetch(`${base}${path}`, {
        method,
        ...(method === "POST" ? { body: "synthetic request body" } : {}),
      });
      expect(response.status).toBe(501);
      expect(response.headers.get("content-type")).toBe("application/json");
      expect(await response.json()).toEqual({ error: "not_implemented" });
    }
    expect(log.mock.calls).toEqual([
      ["GET /v1/findings"],
      ["POST /v1/bulk/findings"],
    ]);

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
  } finally {
    log.mockRestore();
  }
});

test("does not start when storage initialization fails", async () => {
  await expect(
    startFindingsServer({
      host: "127.0.0.1",
      port: 0,
      store: {
        async initialize() {
          throw new Error("Storage unavailable");
        },
      },
    }),
  ).rejects.toThrow("Storage unavailable");
});

test("initializes and reopens the CLI database without losing findings", async () => {
  const directory = await mkdtemp(join(tmpdir(), "findings-store-"));
  directories.push(directory);
  const environment = {
    ...process.env,
    CODEX_SECURITY_STATE_DIR: join(directory, "state with spaces"),
  };
  const store = new SqliteFindingsStore(environment);
  await store.initialize();
  const python = await resolvePluginPython({ environment });
  const database = join(
    environment.CODEX_SECURITY_STATE_DIR,
    "workbench.sqlite3",
  );
  const inserted = await runCodexCommand(
    { command: python },
    [
      "-c",
      `import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as db:
    assert db.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] > 0
    db.execute("INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)", ("example-finding", "example-fingerprint", "example-rule", "example-anchor", "2026-01-01", "2026-01-01"))
`,
      database,
    ],
    environment,
  );
  expect(inserted.success).toBe(true);

  await store.initialize();
  const reopened = await runCodexCommand(
    { command: python },
    [
      "-c",
      `import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as db:
    assert db.execute("SELECT id FROM findings").fetchall() == [("example-finding",)]
    assert db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
`,
      database,
    ],
    environment,
  );
  expect(reopened.success).toBe(true);
});

test("reports a database startup failure for an unusable state path", async () => {
  const directory = await mkdtemp(join(tmpdir(), "findings-store-"));
  directories.push(directory);
  const state = join(directory, "not-a-directory");
  await writeFile(state, "synthetic file");
  const store = new SqliteFindingsStore({
    ...process.env,
    CODEX_SECURITY_STATE_DIR: state,
  });
  await expect(store.initialize()).rejects.toThrow(
    "Could not initialize the findings database",
  );
});
