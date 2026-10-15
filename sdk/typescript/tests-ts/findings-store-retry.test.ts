import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
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
  const stateDirectory = join(directory, "synthetic state");
  const environment = {
    PATH: process.env["PATH"],
    SystemRoot: process.env["SystemRoot"],
    CODEX_SECURITY_STATE_DIR: join(directory, "invalid\nstate"),
  };
  return {
    stateDirectory,
    environment,
    store: new SqliteFindingsStore(environment),
  };
}

test("retries initialization after the configured state directory is corrected", async () => {
  const { store, environment, stateDirectory } = await fixture();
  await expect(store.initialize()).rejects.toThrow("control or line-separator");
  environment.CODEX_SECURITY_STATE_DIR = stateDirectory;
  await store.initialize();
  const page = await store.list({ limit: 10, offset: 0 });
  expect(page).toMatchObject({ findings: [] });
});

test("all callers can recover after sharing a rejected initialization", async () => {
  const { store, environment, stateDirectory } = await fixture();
  const failures = await Promise.allSettled([
    store.initialize(),
    store.list({ limit: 10, offset: 0 }),
    store.listDedupeGroups("synthetic-finding"),
  ]);
  expect(failures.every((result) => result.status === "rejected")).toBe(true);
  const reasons = failures.map((result) =>
    result.status === "rejected" ? result.reason : undefined,
  );
  expect(reasons.every((reason) => reason === reasons[0])).toBe(true);
  environment.CODEX_SECURITY_STATE_DIR = stateDirectory;
  await Promise.all([store.initialize(), store.initialize()]);
  expect(await store.listDedupeGroups("synthetic-finding")).toEqual([]);
});

test("repeated failures remain retryable without replacing the store", async () => {
  const { store, environment, stateDirectory } = await fixture();
  for (let attempt = 0; attempt < 2; attempt++) {
    await expect(store.initialize()).rejects.toThrow(
      "control or line-separator",
    );
  }
  environment.CODEX_SECURITY_STATE_DIR = stateDirectory;
  await store.initialize();
});

test("keeps a successfully resolved runtime cached", async () => {
  const { store, environment, stateDirectory } = await fixture();
  environment.CODEX_SECURITY_STATE_DIR = stateDirectory;
  await store.initialize();
  environment.CODEX_SECURITY_STATE_DIR = join(
    directories.at(-1)!,
    "invalid\nagain",
  );
  await store.initialize();
  expect(await store.listDedupeGroups("synthetic-finding")).toEqual([]);
});
