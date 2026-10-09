import { expect, test } from "bun:test";
import { PassThrough } from "node:stream";
import { loadBundledRuntime, PLUGIN_ROOT } from "./plugin-root.js";

test("gives prompt-only scan startup the five-minute scan timeout", async () => {
  const runtime = await loadBundledRuntime();
  const source =
    /async function executeWorkbench\([^\n]*\) \{[\s\S]*?\n\}/u.exec(
      runtime,
    )?.[0];
  expect(source).toBeDefined();
  const execFileHelper = /\b(execFileAsync\d*)\(/u.exec(source ?? "")?.[1];
  expect(execFileHelper).toBeDefined();

  const executeWorkbench = new Function(
    execFileHelper!,
    "workbenchScriptPath",
    "WORKBENCH_PYTHON",
    "PLUGIN_ROOT",
    "isRecord",
    `${source}\nreturn executeWorkbench;`,
  )(
    (_command: string, _args: string[], options: { timeout: number }) =>
      Object.assign(
        Promise.resolve({
          stdout: JSON.stringify({ timeout: options.timeout }),
        }),
        { child: { stdin: new PassThrough() } },
      ),
    () => "workbench.py",
    "fixture private workbench launcher",
    PLUGIN_ROOT,
    () => true,
  ) as (command: string, args: string[]) => Promise<{ timeout: number }>;

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
