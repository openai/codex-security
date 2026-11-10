import assert from "node:assert/strict";
import {
  execFile,
  type ExecFileOptionsWithStringEncoding,
} from "node:child_process";
import { PassThrough } from "node:stream";
import { promisify } from "node:util";
import { loadWorkbenchProcess } from "./support/workbench-process.ts";

type WorkbenchProcessFixture = (
  python: string,
  args: string[],
  options: ExecFileOptionsWithStringEncoding,
) => Promise<{ stdout: string; stderr: string }> & {
  child: { stdin: PassThrough };
};

declare global {
  var workbenchProcessFixture: WorkbenchProcessFixture | undefined;
}

const invocations: {
  args: string[];
  options: ExecFileOptionsWithStringEncoding;
}[] = [];
let failure: Error | undefined;
globalThis.workbenchProcessFixture = (_python, args, options) => {
  invocations.push({ args, options });
  return Object.assign(
    failure
      ? Promise.reject(failure)
      : Promise.resolve({ stdout: "{}", stderr: "" }),
    { child: { stdin: new PassThrough() } },
  );
};
try {
  const { executeWorkbench } = await loadWorkbenchProcess((source) =>
    source.replace(
      "const execFileAsync = promisify(execFile);",
      "const execFileAsync = globalThis.workbenchProcessFixture;",
    ),
  );
  for (const command of [
    "cancel-scan",
    "fail-scan",
    "preserve-scan-results",
    "complete-scan",
    "finding-issues",
    "start-prompt-only-scan",
    "start-scan",
  ]) {
    await executeWorkbench("fixture-python", [command, "--scan-id", "fixture"]);
    assert.equal(
      invocations.at(-1)!.options.timeout,
      300_000,
      `${command} must allow its saved-result publication to finish`,
    );
  }
  await executeWorkbench("fixture-python", [
    "inspect-target",
    "--target-path",
    "/fixture",
  ]);
  assert.equal(invocations.at(-1)!.options.timeout, 30_000);
  failure = Object.assign(
    new Error("Command failed: fixture-python\nfixture diagnostic"),
    {
      killed: true,
      signal: "SIGTERM",
      stderr: "fixture diagnostic",
      stdout: "",
    },
  );
  await assert.rejects(
    executeWorkbench("fixture-python", ["cancel-scan"]),
    (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.match(error.message, /cancel-scan.*timed out.*300/);
      assert.match(error.message, /fixture diagnostic/);
      assert.equal(error.cause, failure);
      return true;
    },
  );
  await assert.rejects(
    promisify(execFile)(
      process.execPath,
      ["-e", 'process.stdout.write("x".repeat(65536))'],
      { maxBuffer: 1024 },
    ),
    (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.ok("code" in error);
      assert.equal(error.code, "ERR_CHILD_PROCESS_STDIO_MAXBUFFER");
      failure = error;
      return true;
    },
  );
  await assert.rejects(
    executeWorkbench("fixture-python", ["cancel-scan"]),
    (error) => error === failure,
  );
} finally {
  delete globalThis.workbenchProcessFixture;
}
