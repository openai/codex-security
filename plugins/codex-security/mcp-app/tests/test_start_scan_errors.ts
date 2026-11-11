import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { buildServer } from "./build-server.ts";
import { fixturePython } from "./support/python.ts";
import { startRpcServer } from "./support/rpc-server.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

test("scan startup failures reach the MCP caller", async (t) => {
  const root = await temporaryDirectory("workbench-start-errors-");
  t.after(() => rm(root, { recursive: true, force: true }));
  const bundle = join(root, "server.cjs");
  await buildServer(bundle, {
    plugins: [
      {
        name: "short-workbench-timeout",
        setup(build) {
          build.onLoad(
            { filter: /workbench-client\.ts$/ },
            async ({ path }) => {
              const source = await readFile(path, "utf8");
              return {
                loader: "ts",
                contents: source.replace("300_000", "2_000"),
              };
            },
          );
        },
      },
    ],
  });
  await mkdir(join(root, "scripts"));
  const server = startRpcServer({
    command: process.execPath,
    args: [bundle, "--stdio"],
    env: {
      ...process.env,
      CODEX_SECURITY_PLUGIN_ROOT: root,
      CODEX_SECURITY_PYTHON_COMMAND: fixturePython,
    },
  });
  t.after(() => server.stop());
  await server.initialize("scan-start-errors");
  let id = 1;
  async function start(beforeExit = "pass") {
    await writeFile(
      join(root, "scripts/workbench_db.py"),
      `import os, signal, sys, time

def main():
    if sys.argv[1] == "resolve-scan-root":
        print('{"scanRoot": "."}')
        return
    assert sys.argv[1] == "start-scan"
    ${beforeExit}
    os._exit(23)
`,
    );
    const { result } = await server.callTool(++id, {
      name: "start_codex_security_scan",
      arguments: { sessionId: randomUUID() },
    });
    assert.equal(result.isError, true);
    assert.equal(result.content[0].type, "text");
    return result.content[0].text;
  }
  assert.match(
    await start("time.sleep(10)"),
    /start-scan timed out after 2 seconds/,
  );
  assert.equal(
    await start(
      'os.write(2, b"Could not open the scan database.\\nFixture diagnostic.")',
    ),
    "Could not open the scan database.\nFixture diagnostic.",
  );
  assert.equal(
    await start(),
    "Codex Security workbench start-scan exited with code 23.",
  );
  if (process.platform !== "win32") {
    assert.equal(
      await start("os.kill(os.getpid(), signal.SIGTERM)"),
      "Codex Security workbench start-scan was terminated by signal SIGTERM.",
    );
  }
});
