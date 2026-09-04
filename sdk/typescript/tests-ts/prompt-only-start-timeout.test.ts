import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { expect, test } from "bun:test";
import { loadBundledRuntime, PLUGIN_ROOT } from "./plugin-root.js";

type WorkbenchOptions = { timeout: number; maxBuffer: number };
type WorkbenchExecutor = (
  command: string,
  args: string[],
  options: WorkbenchOptions,
) => Promise<{ stdout: string }>;

async function loadExecuteWorkbench(
  executor: WorkbenchExecutor,
  scriptPath = "workbench.py",
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
    "PLUGIN_ROOT",
    "isJsonObject2",
    `${source}\nreturn executeWorkbench;`,
  )(
    executor,
    () => scriptPath,
    PLUGIN_ROOT,
    (value: unknown) =>
      value !== null && typeof value === "object" && !Array.isArray(value),
  );
}

test("gives prompt-only scan startup the five-minute scan timeout", async () => {
  const executeWorkbench = await loadExecuteWorkbench(
    async (_command, _args, options) => ({
      stdout: JSON.stringify({ timeout: options.timeout }),
    }),
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
    (command, args, options) =>
      run(command, args, { ...options, encoding: "utf8" }),
    "-e",
  );
  const result = await executeWorkbench(process.execPath, [
    "process.stdout.write(JSON.stringify({ value: 'x'.repeat(5 * 1024 * 1024) }))",
  ]);
  expect((result["value"] as string).length).toBe(5 * 1024 * 1024);
});
