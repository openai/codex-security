import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { mkdtemp, readFile, readdir, rename, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test, type TestContext } from "node:test";
import { importSource } from "./import-module.ts";

const source = path.join(import.meta.dirname, "../src/deep-scan/artifacts.ts");
const artifacts = await importSource(source);

async function fixture(t: TestContext) {
  const root = await fs.realpath(
    await mkdtemp(path.join(tmpdir(), "deep-scan-json-atomic-")),
  );
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root, destination: path.join(root, "artifacts", "result.json") };
}

async function stagedFiles(root: string): Promise<string[]> {
  const entries = await readdir(root, { recursive: true });
  return entries.filter((entry) => entry.endsWith(".tmp"));
}

test("a failed JSON rename removes its staging file", async (t) => {
  const f = await fixture(t);
  const renameError = Object.assign(new Error("synthetic rename failure"), {
    code: "EIO",
  });
  t.mock.method(fs, "rename", async () => {
    throw renameError;
  });

  await assert.rejects(
    artifacts.writeJsonAtomic(f.destination, { ok: true }),
    (error: unknown) => error === renameError,
  );
  assert.deepEqual(await stagedFiles(f.root), []);
  await assert.rejects(readFile(f.destination, "utf8"), { code: "ENOENT" });
});

test("a transient Windows rename failure is retried", async (t) => {
  if (process.platform !== "win32") return t.skip();
  const f = await fixture(t);
  let attempts = 0;
  t.mock.method(fs, "rename", async (...args: Parameters<typeof fs.rename>) => {
    attempts += 1;
    if (attempts < 3)
      throw Object.assign(new Error("synthetic sharing violation"), {
        code: "EBUSY",
      });
    await rename(args[0], args[1]);
  });

  await artifacts.writeJsonAtomic(f.destination, { ok: true });
  assert.equal(attempts, 3);
  assert.equal(await readFile(f.destination, "utf8"), '{\n  "ok": true\n}\n');
  assert.deepEqual(await stagedFiles(f.root), []);
});
