import assert from "node:assert/strict";
import type { ExecFileOptionsWithStringEncoding } from "node:child_process";

type WorkbenchProcessFixture = (
  python: string,
  args: string[],
  options: ExecFileOptionsWithStringEncoding,
) => Promise<{ stdout: string; stderr: string }>;

declare global {
  var workbenchProcessFixture: WorkbenchProcessFixture | undefined;
}

interface WorkbenchModule {
  executeWorkbench(
    python: string,
    args: string[],
    stateDir?: string,
    input?: string | Buffer,
  ): Promise<Record<string, unknown>>;
}
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { importModule } from "./import-module.ts";

const applicationRoot = fileURLToPath(new URL("../", import.meta.url));
const source = await readFile(new URL("../server.ts", import.meta.url), "utf8");
const invocations: {
  args: string[];
  options: ExecFileOptionsWithStringEncoding;
}[] = [];
let failure: Error | undefined;
globalThis.workbenchProcessFixture = (_python, args, options) => {
  invocations.push({ args, options });
  return failure
    ? Promise.reject(failure)
    : Promise.resolve({ stdout: "{}", stderr: "" });
};
try {
  const { executeWorkbench } = (await importModule({
    stdin: {
      contents:
        source.replace(
          "const execFileAsync = promisify(execFile);",
          "const execFileAsync = globalThis.workbenchProcessFixture;",
        ) + "\nexport { executeWorkbench };",
      loader: "ts",
      resolveDir: applicationRoot,
    },
    define: {
      __dirname: JSON.stringify(applicationRoot),
      "import.meta.url": JSON.stringify(
        new URL("../server.ts", import.meta.url).href,
      ),
    },
    loader: { ".md": "text" },
  })) as WorkbenchModule;
  for (const command of [
    "cancel-scan",
    "fail-scan",
    "preserve-scan-results",
    "complete-scan",
    "start-prompt-only-scan",
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
} finally {
  delete globalThis.workbenchProcessFixture;
}
