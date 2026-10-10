import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { expect, test } from "bun:test";
import { PassThrough, type Writable } from "node:stream";
import { loadBundledRuntime, PLUGIN_ROOT } from "./plugin-root.js";

type WorkbenchOptions = { timeout: number; maxBuffer: number };
type WorkbenchExecutor = (
  command: string,
  args: string[],
  options: WorkbenchOptions,
) => Promise<{ stdout: string }> & { child: { stdin: Writable | null } };

async function loadExecuteWorkbench(
  executor: WorkbenchExecutor,
): Promise<
  (command: string, args: string[]) => Promise<Record<string, unknown>>
> {
  const runtime = await loadBundledRuntime();
  const source =
    /async function executeWorkbench\([^\n]*\) \{[\s\S]*?\n\}/u.exec(
      runtime,
    )?.[0];
  expect(source).toBeDefined();
  const execFileHelper = /\b(execFileAsync\d*)\(/u.exec(source ?? "")?.[1];
  expect(execFileHelper).toBeDefined();

  return new Function(
    execFileHelper!,
    "workbenchScriptPath",
    "WORKBENCH_PYTHON",
    "PLUGIN_ROOT",
    "isRecord",
    `${source}\nreturn executeWorkbench;`,
  )(
    executor,
    () => "workbench.py",
    "fixture private workbench launcher",
    PLUGIN_ROOT,
    (value: unknown) =>
      value !== null && typeof value === "object" && !Array.isArray(value),
  );
}

test("gives prompt-only scan startup the five-minute scan timeout", async () => {
  const executeWorkbench = await loadExecuteWorkbench(
    (_command, _args, options) =>
      Object.assign(
        Promise.resolve({
          stdout: JSON.stringify({ timeout: options.timeout }),
        }),
        { child: { stdin: new PassThrough() } },
      ),
  );

  expect(await executeWorkbench("python", ["start-prompt-only-scan"])).toEqual({
    timeout: 300_000,
  });
  expect(await executeWorkbench("python", ["start-scan"])).toEqual({
    timeout: 300_000,
  });
  expect(await executeWorkbench("python", ["other-operation"])).toEqual({
    timeout: 30_000,
  });
});

test("reads large native workbench responses", async () => {
  const run = promisify(execFile);
  const executeWorkbench = await loadExecuteWorkbench(
    (command, _args, options) =>
      run(
        command,
        [
          "-e",
          "process.stdin.resume(); process.stdout.write(JSON.stringify({ value: 'x'.repeat(5 * 1024 * 1024) }))",
        ],
        { ...options, encoding: "utf8" },
      ),
  );
  const result = await executeWorkbench(process.execPath, ["large-response"]);
  expect((result["value"] as string).length).toBe(5 * 1024 * 1024);
});
