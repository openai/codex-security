import { afterEach, expect, test } from "bun:test";
import { build } from "esbuild";
import { execFile } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { basename, dirname, join, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { pythonExecutable } from "./support/python.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } =
  createApiTestFixtures("workbench-node-");
afterEach(cleanup);

test("SDK workbench forwards Node to compressed reads without PATH and preserves an explicit runtime", async () => {
  const root = await temporaryDirectory();
  const scripts = join(root, "scripts");
  await mkdir(scripts);
  const rollout = join(root, "rollout.jsonl.zst");
  await writeFile(
    rollout,
    Buffer.from(
      "KLUv/SA2sQEAeyJ0eXBlIjoic2Vzc2lvbl9tZXRhIiwicGF5bG9hZCI6eyJpZCI6ImNvbXByZXNzZWQifX0K",
      "base64",
    ),
  );
  await writeFile(
    join(scripts, "workbench_db.py"),
    `import json, os, sys
from pathlib import Path
sys.path.insert(0, ${JSON.stringify(join(PLUGIN_ROOT, "scripts"))})
from workbench_scan_usage import _rollout_lines
with _rollout_lines(Path(sys.argv[1])) as source:
    contents = b"".join(source).decode("utf-8")
print(json.dumps({"contents": contents, "node": os.environ["CODEX_MCP_NODE_PATH"]}))
`,
  );
  const runtimeSource = new URL("../src/runtime.ts", import.meta.url);
  const runtimeModule = join(root, "runtime.cjs");
  await build({
    entryPoints: [fileURLToPath(runtimeSource)],
    outfile: runtimeModule,
    bundle: true,
    platform: "node",
    format: "cjs",
    define: { "import.meta.url": JSON.stringify(runtimeSource.href) },
  });
  const node = Bun.which("node");
  const python = pythonExecutable();
  expect(node).not.toBeNull();
  expect(python).not.toBeNull();
  const script = `
const { runWorkbench } = require(process.argv[1]);
const [python, pluginRoot, rollout, selected] = process.argv.slice(2);
const environment = { ...process.env, PATH: "" };
for (const name of Object.keys(environment))
  if (name.toUpperCase() === "CODEX_MCP_NODE_PATH") delete environment[name];
if (selected) environment.CODEX_MCP_NODE_PATH = selected;
runWorkbench({ python, pluginRoot, environment }, [rollout])
  .then((result) => process.stdout.write(JSON.stringify({ result, selected: environment.CODEX_MCP_NODE_PATH, node: process.execPath })),
    (error) => { console.error(error); process.exitCode = 1; });
`;
  for (const selected of [
    "",
    `${dirname(node!)}${sep}.${sep}${basename(node!)}`,
  ]) {
    const { stdout } = await promisify(execFile)(
      node!,
      ["--eval", script, runtimeModule, python!, root, rollout, selected],
      { encoding: "utf8", windowsHide: true },
    );
    const observed = JSON.parse(stdout);
    expect(observed.result).toEqual({
      contents: '{"type":"session_meta","payload":{"id":"compressed"}}\n',
      node: selected || observed.node,
    });
    expect(observed.selected).toBe(selected || undefined);
  }
});
