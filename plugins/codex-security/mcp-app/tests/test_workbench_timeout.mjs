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
        import { PassThrough } from "node:stream";
        export function execFile() {}
        execFile[Symbol.for("nodejs.util.promisify.custom")] = (_command, _args, options) => {
          const result = globalThis.workbenchProcessFailure
            ? Promise.reject(globalThis.workbenchProcessFailure)
            : Promise.resolve({ stdout: JSON.stringify({ timeout: options.timeout }) });
          return Object.assign(result, { child: { stdin: new PassThrough() } });
        };
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
    "cancel-scan",
    "fail-scan",
    "preserve-scan-results",
    "complete-scan",
  ])
    assert.deepEqual(await executeWorkbench("fixture-python", [operation]), {
      timeout: 300_000,
    });
  assert.deepEqual(
    await executeWorkbench("fixture-python", ["other-operation"]),
    { timeout: 30_000 },
  );
});

test("workbench timeout retains the command and diagnostic", async () => {
  const failure = Object.assign(
    new Error("Command failed: fixture-python\nfixture diagnostic"),
    {
      killed: true,
      signal: "SIGTERM",
      stderr: "fixture diagnostic",
      stdout: "",
    },
  );
  globalThis.workbenchProcessFailure = failure;
  try {
    await assert.rejects(
      executeWorkbench("fixture-python", ["cancel-scan"]),
      (error) => {
        assert.match(error.message, /cancel-scan.*timed out.*300/);
        assert.match(error.message, /fixture diagnostic/);
        assert.equal(error.cause, failure);
        return true;
      },
    );
  } finally {
    delete globalThis.workbenchProcessFailure;
  }
});
