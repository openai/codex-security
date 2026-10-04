import assert from "node:assert/strict";
import { test } from "node:test";
import { loadSourceModule } from "./helpers/source.mjs";

const { executeWorkbench } = await loadSourceModule(
  new URL("../server.ts", import.meta.url),
  {
    loader: { ".md": "text" },
    plugins: [
      {
        name: "capture-workbench-options",
        setup(build) {
          build.onResolve({ filter: /^node:child_process$/ }, () => ({
            path: "child_process",
            namespace: "fixture",
          }));
          build.onLoad({ filter: /.*/, namespace: "fixture" }, () => ({
            contents: `
        export function execFile() {}
        execFile[Symbol.for("nodejs.util.promisify.custom")] = async (_command, _args, options) =>
          ({ stdout: JSON.stringify({ timeout: options.timeout }) });
        export function spawn() { throw new Error("Unexpected process launch"); }
        export function execFileSync() { throw new Error("Unexpected process launch"); }
      `,
          }));
        },
      },
    ],
  },
);

test("workbench gives scan preparation the long timeout at the process boundary", async () => {
  for (const operation of [
    "start-prompt-only-scan",
    "start-scan",
    "begin-deep-scan",
  ])
    assert.deepEqual(await executeWorkbench("fixture-python", [operation]), {
      timeout: 300_000,
    });
  assert.deepEqual(
    await executeWorkbench("fixture-python", ["other-operation"]),
    { timeout: 30_000 },
  );
});
