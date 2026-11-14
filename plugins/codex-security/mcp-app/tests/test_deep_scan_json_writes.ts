import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { after, test, type TestContext } from "node:test";
import { importSource } from "./import-module.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";

const { writeJsonAtomic } = (await importSource(
  join(import.meta.dirname, "../src/deep-scan/artifacts.ts"),
)) as typeof import("../src/deep-scan/artifacts.js");
const directories = createTemporaryDirectories(true);
after(() => directories.cleanup());

function denyRenames(t: TestContext, failures: number): unknown[] {
  const rename = fs.rename.bind(fs);
  const calls: unknown[] = [];
  t.mock.method(fs, "rename", async (...args: Parameters<typeof fs.rename>) => {
    calls.push(args[1]);
    if (calls.length <= failures) {
      throw Object.assign(new Error("held by a reader"), { code: "EPERM" });
    }
    return rename(...args);
  });
  return calls;
}

test("Windows retries a JSON artifact rename denied while a reader holds the old file", async (t) => {
  const directory = join(await directories.create("deep-scan-json-"), "new");
  const destination = join(directory, "heartbeat.json");
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  Object.defineProperty(process, "platform", { value: "win32" });
  t.after(() => Object.defineProperty(process, "platform", platform));
  const renames = denyRenames(t, 1);
  await writeJsonAtomic(destination, { beat: 2 });
  assert.deepEqual(renames, [destination, destination]);
  assert.equal(await fs.readFile(destination, "utf8"), '{\n  "beat": 2\n}\n');
  assert.deepEqual(await fs.readdir(directory), ["heartbeat.json"]);
});

test("a failed JSON artifact rename keeps the old file and removes its temporary file", async (t) => {
  const directory = await directories.create("deep-scan-json-");
  const destination = join(directory, "heartbeat.json");
  await fs.writeFile(destination, "old");
  denyRenames(t, Infinity);
  await assert.rejects(writeJsonAtomic(destination, { beat: 2 }), {
    code: "EPERM",
  });
  assert.equal(await fs.readFile(destination, "utf8"), "old");
  assert.deepEqual(await fs.readdir(directory), ["heartbeat.json"]);
});
