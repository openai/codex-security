import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { brotliDecompressSync } from "node:zlib";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("gives prompt-only scan startup the five-minute scan timeout", async () => {
  const parts = await Promise.all(
    ["000", "001"].map((part) =>
      readFile(join(PLUGIN_ROOT, "mcp", `server.mjs.br.part-${part}`)),
    ),
  );
  const runtime = brotliDecompressSync(Buffer.concat(parts)).toString("utf8");
  const source =
    /async function executeWorkbench\([^\n]*\) \{[\s\S]*?\n\}/u.exec(
      runtime,
    )?.[0];
  expect(source).toBeDefined();

  const executeWorkbench = new Function(
    "execFileAsync3",
    "workbenchScriptPath",
    "PLUGIN_ROOT",
    "isJsonObject2",
    `${source}\nreturn executeWorkbench;`,
  )(
    async (
      _command: string,
      _args: string[],
      options: { timeout: number },
    ) => ({ stdout: JSON.stringify({ timeout: options.timeout }) }),
    () => "workbench.py",
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
