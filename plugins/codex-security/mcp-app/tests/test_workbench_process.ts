import assert from "node:assert/strict";
import { test } from "node:test";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { mkdir, rm, stat } from "node:fs/promises";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import { loadWorkbenchProcess } from "./support/workbench-process.ts";
import { PassThrough } from "node:stream";
import type { ExecFileOptionsWithStringEncoding } from "node:child_process";

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

interface WorkbenchModule {
  executeWorkbench(
    python: string,
    args: string[],
    input?: string | Buffer,
  ): Promise<Record<string, unknown>>;
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
  const { executeWorkbench } = (await loadWorkbenchProcess((source) =>
    source.replace(
      "const execFileAsync = promisify(execFile);",
      "const execFileAsync = globalThis.workbenchProcessFixture;",
    ),
  )) as WorkbenchModule;
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

const { executeWorkbench } = await loadWorkbenchProcess();
const root = await temporaryDirectory("workbench-framing-", true);
const stateDir = path.join(root, "state");
const previousStateDir = process.env.CODEX_SECURITY_STATE_DIR;
try {
  process.env.CODEX_SECURITY_STATE_DIR = stateDir;
  const target = path.join(root, "target");
  await mkdir(target);
  const title = "--message\0café\n日本語😀high\ud800low\udfff";
  const input = Buffer.from(
    "--raw context\0café\n".repeat(20_000).trim(),
    "utf8",
  );
  for (const stdin of [true, false]) {
    const result = await executeWorkbench(
      process.env.PYTHON?.trim() || "python3",
      [
        "create-workspace",
        "--workspace-id",
        randomUUID(),
        "--target-path",
        target,
        `--target-title=${title}`,
        stdin
          ? "--user-context-stdin"
          : `--user-context=${input.toString("utf8")}`,
      ],
      stdin ? input : undefined,
    );
    assert.equal(result.targetTitle, Buffer.from(title).toString("utf8"));
    assert.equal(result.userContext, input.toString("utf8"));
  }
  assert.equal(
    (await stat(path.join(stateDir, "workbench.sqlite3"))).isFile(),
    true,
  );
  const artifactRoot = path.join(root, "artifacts");
  await mkdir(artifactRoot, { mode: 0o700 });
  const binary = Buffer.from([0xff, 0x00, 0x0a, 0x0d, 0xfe]);
  const artifactArgs = [
    "--artifact-root",
    artifactRoot,
    "--artifact-path",
    "raw.bin",
  ];
  await executeWorkbench(
    process.env.PYTHON?.trim() || "python3",
    ["save-artifact", ...artifactArgs],
    binary,
  );
  const saved = await executeWorkbench(
    process.env.PYTHON?.trim() || "python3",
    ["read-artifact", ...artifactArgs],
  );
  assert.deepEqual(Buffer.from(saved.content, "base64"), binary);
  const replacementTarget = path.join(root, "target-\ufffd");
  await mkdir(replacementTarget);
  for (const rawBytePath of [false, true]) {
    await test(
      `workbench path framing with ${rawBytePath ? "a raw-byte collision" : "a Unicode target"}`,
      { skip: rawBytePath && ["win32", "darwin"].includes(process.platform) },
      async () => {
        if (rawBytePath) {
          await mkdir(
            Buffer.concat([
              Buffer.from(path.join(root, "target-")),
              Buffer.from([0xff]),
            ]),
          );
        }
        const inspected = await executeWorkbench(
          process.env.PYTHON?.trim() || "python3",
          ["inspect-target", "--target-path", path.join(root, "target-\udcff")],
        );
        assert.equal(inspected.targetPath, replacementTarget);
      },
    );
  }
} finally {
  if (previousStateDir === undefined)
    delete process.env.CODEX_SECURITY_STATE_DIR;
  else process.env.CODEX_SECURITY_STATE_DIR = previousStateDir;
  await rm(root, { recursive: true, force: true });
}
