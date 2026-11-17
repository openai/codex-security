import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { setImmediate } from "node:timers/promises";

const builder = new URL(
  "../scripts/build_native_wrappers.mjs",
  import.meta.url,
);
const platform = new URL("../../native/platform.mjs", import.meta.url);
const { buildNativeWrappers } = await import(builder.href);

test("concurrent runtime builds preserve complete native wrapper exports", async () => {
  await buildNativeWrappers();
  const { nativeTarget } = await import(platform.href);
  assert.equal(typeof nativeTarget, "string");
  const source = `
    import assert from 'node:assert/strict';
    import { buildNativeWrappers } from ${JSON.stringify(builder.href)};
    for (let iteration = 0; iteration < 15; iteration++) {
      await buildNativeWrappers();
      const platform = await import(${JSON.stringify(platform.href)} + '?build=' + iteration);
      assert.equal(platform.nativeTarget, ${JSON.stringify(nativeTarget)});
    }
  `;
  const results = await Promise.all(
    Array.from({ length: 3 }, async () => {
      const child = spawn(
        process.execPath,
        ["--input-type=module", "--eval", source],
        {
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
      let output = "";
      for (const stream of [child.stdout, child.stderr])
        stream.on("data", (chunk) => {
          output += chunk;
        });
      const [code] = await once(child, "close");
      return { code, output };
    }),
  );
  for (const { code, output } of results) assert.equal(code, 0, output);
});

async function wrapperFixture(t: TestContext) {
  const root = await fs.mkdtemp(join(tmpdir(), "wrapper-publication-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.writeFile(join(root, "example.mts"), "export const version = 2;");
  await fs.writeFile(join(root, "example.mjs"), "previous");
  return root;
}

test(
  "publishes the same staged wrapper after a transient Windows conflict",
  {
    skip: process.platform !== "win32",
  },
  async (t) => {
    const root = await wrapperFixture(t);
    const destination = join(root, "example.mjs");
    const rename = fs.rename;
    const attempts: string[] = [];
    t.mock.method(fs, "rename", async (source: string, target: string) => {
      assert.equal(target, destination);
      attempts.push(source);
      if (attempts.length === 1) {
        assert.equal(await fs.readFile(target, "utf8"), "previous");
        throw Object.assign(new Error("wrapper is in use"), { code: "EBUSY" });
      }
      await rename(source, target);
    });
    await buildNativeWrappers(root);
    assert.equal(attempts.length, 2);
    assert.equal(attempts[0], attempts[1]);
    assert.match(await fs.readFile(destination, "utf8"), /version = 2/);
    assert.deepEqual((await fs.readdir(root)).sort(), [
      "example.mjs",
      "example.mts",
    ]);
  },
);

test("waits for a delayed sibling and cleans up when wrapper publication fails", async (t) => {
  const root = await wrapperFixture(t);
  await fs.writeFile(join(root, "sibling.mts"), "export const sibling = 1;");
  const rename = fs.rename;
  const remove = fs.rm;
  const failure = Object.assign(new Error("wrapper is in use"), {
    code: "EPERM",
  });
  const failedCleanup = Promise.withResolvers<void>();
  const siblingStaged = Promise.withResolvers<void>();
  const resumeSibling = Promise.withResolvers<void>();
  let attempts = 0;
  t.mock.method(fs, "rename", async (source: string, target: string) => {
    if (target === join(root, "example.mjs")) {
      attempts++;
      throw failure;
    }
    siblingStaged.resolve();
    await resumeSibling.promise;
    await rename(source, target);
  });
  t.mock.method(fs, "rm", async (...args: Parameters<typeof fs.rm>) => {
    await remove(...args);
    if (String(args[0]).startsWith(join(root, "example.mjs.")))
      failedCleanup.resolve();
  });
  let settled = false;
  const result = buildNativeWrappers(root).then(
    () => {
      throw new Error("Expected publication failure");
    },
    (error: unknown) => {
      settled = true;
      return error;
    },
  );
  try {
    await Promise.all([siblingStaged.promise, failedCleanup.promise]);
    // Give a prematurely rejected build a turn to notify its caller.
    await setImmediate();
    assert.equal(settled, false);
  } finally {
    resumeSibling.resolve();
  }
  assert.equal(await result, failure);
  assert.equal(attempts, process.platform === "win32" ? 7 : 1);
  assert.equal(
    await fs.readFile(join(root, "example.mjs"), "utf8"),
    "previous",
  );
  assert.match(
    await fs.readFile(join(root, "sibling.mjs"), "utf8"),
    /sibling = 1/,
  );
  assert.deepEqual((await fs.readdir(root)).sort(), [
    "example.mjs",
    "example.mts",
    "sibling.mjs",
    "sibling.mts",
  ]);
});
