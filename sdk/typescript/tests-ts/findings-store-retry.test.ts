import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { resolvePluginPython } from "../src/runtime.js";
import { SqliteFindingsStore } from "../src/server/sqlite-store.js";

const directories: string[] = [];
afterEach(async () => {
  for (const directory of directories.splice(0)) {
    await rm(directory, { recursive: true, force: true });
  }
});

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), "findings-runtime-retry-"));
  directories.push(directory);
  const python = await resolvePluginPython();
  const environment = {
    PATH: process.env["PATH"],
    SystemRoot: process.env["SystemRoot"],
    PYTHON: join(directory, "missing-python"),
    CODEX_SECURITY_STATE_DIR: join(directory, "synthetic state"),
  };
  return { python, environment, store: new SqliteFindingsStore(environment) };
}

test("retries initialization after the configured interpreter is corrected", async () => {
  const { store, environment, python } = await fixture();
  await expect(store.initialize()).rejects.toThrow("PYTHON");
  environment.PYTHON = python;
  await store.initialize();
  const page = await store.list({ limit: 10, offset: 0 });
  expect(page).toMatchObject({ findings: [] });
});

test("all callers can recover after sharing a rejected initialization", async () => {
  const { store, environment, python } = await fixture();
  const failures = await Promise.allSettled([
    store.initialize(),
    store.list({ limit: 10, offset: 0 }),
    store.listDedupeGroups("synthetic-finding"),
  ]);
  expect(failures.every((result) => result.status === "rejected")).toBe(true);
  environment.PYTHON = python;
  await Promise.all([store.initialize(), store.initialize()]);
  expect(await store.listDedupeGroups("synthetic-finding")).toEqual([]);
});

test("repeated failures remain retryable without replacing the store", async () => {
  const { store, environment, python } = await fixture();
  for (let attempt = 0; attempt < 2; attempt++) {
    await expect(store.initialize()).rejects.toThrow("PYTHON");
  }
  environment.PYTHON = python;
  await store.initialize();
});

test("keeps a successfully resolved runtime cached", async () => {
  const { store, environment, python } = await fixture();
  environment.PYTHON = python;
  await store.initialize();
  environment.PYTHON = join(directories.at(-1)!, "missing-again");
  await store.initialize();
  expect(await store.listDedupeGroups("synthetic-finding")).toEqual([]);
});
