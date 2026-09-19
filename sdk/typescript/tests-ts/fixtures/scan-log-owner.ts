import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import { join } from "node:path";
import { mock } from "bun:test";

let heldPath = "";
let release!: () => void;
let held!: () => void;
const reached = new Promise<void>((resolve) => {
  held = resolve;
});
const gate = new Promise<void>((resolve) => {
  release = resolve;
});
const appendFile = fs.appendFile;
mock.module("node:fs/promises", () => ({
  ...fs,
  appendFile: async (...args: Parameters<typeof appendFile>) => {
    if (args[0] === heldPath) {
      held();
      await gate;
    }
    return await appendFile(...args);
  },
}));
const { CodexSecurity } = await import("../../src/api.js");
const { readSavedScanLogs } = await import("../../src/scan-logs.js");
const { runWorkbench } = await import("../../src/runtime.js");
const { createApiTestFixtures, preparedRuntime } =
  await import("../support/api-events.js");
const { savedLogTurn } = await import("../support/scan-log-lifecycle.js");
const { PLUGIN_ROOT } = await import("../plugin-root.js");
const fixtures = createApiTestFixtures();
const clients: InstanceType<typeof CodexSecurity>[] = [];
try {
  const root = await fixtures.temporaryDirectory();
  const home = join(root, "state", "codex-home");
  await fs.mkdir(home, { recursive: true });
  const environment = {
    PATH: process.env["PATH"]!,
    CODEX_HOME: home,
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
  };
  const python = Bun.which("python3") ?? Bun.which("python");
  assert(python);
  const version = JSON.parse(
    await fs.readFile(join(PLUGIN_ROOT, ".codex-plugin/plugin.json"), "utf8"),
  ).version;
  const run = async (name: string) => {
    const repository = join(root, name);
    await fs.mkdir(repository);
    await fs.writeFile(join(repository, "source.py"), "# Synthetic input\n");
    const runtime = preparedRuntime(home);
    runtime.environment = environment;
    runtime.persistentCredentialHome = true;
    runtime.plugin.version = version;
    let threadId: string | null = null;
    let scanId = "";
    const client = new CodexSecurity(
      {},
      {
        environment,
        prepareRuntime: async () => runtime,
        resolvePluginPython: async () => python,
        createCodex: (options) => ({
          startThread: () => ({
            get id() {
              return threadId;
            },
            async runStreamed() {
              scanId = options.env!["CODEX_SECURITY_SCAN_ID"]!;
              if (name === "b")
                heldPath = join(
                  home,
                  "scan-log-turns",
                  createHash("sha256").update(scanId).digest("hex") + ".jsonl",
                );
              return savedLogTurn(
                {
                  environment: options.env!,
                  threadId: name,
                  turnId: name + "-main",
                  outcome: "completed",
                  draft: true,
                },
                (id) => {
                  threadId = id;
                },
              );
            },
          }),
        }),
      },
      { surface: "sdk" },
    );
    clients.push(client);
    await client.run(repository, { outputDir: join(root, "scan-" + name) });
    const saved = await runWorkbench(
      { python, pluginRoot: PLUGIN_ROOT, environment },
      ["get-scan", "--scan-id", scanId],
    );
    return {
      client,
      scan: saved["scan"] as Parameters<typeof readSavedScanLogs>[0],
    };
  };
  const a = await run("a");
  await readSavedScanLogs(a.scan, home);
  const b = await run("b");
  await reached;
  await readSavedScanLogs(a.scan, home);
  let logsReturned = false;
  const logs = readSavedScanLogs(b.scan, home).then((value) => {
    logsReturned = true;
    return value;
  });
  let bClosed = false;
  const closing = b.client.close().then(() => {
    bClosed = true;
  });
  await a.client.close();
  assert.equal(logsReturned, false);
  assert.equal(bClosed, false);
  release();
  assert((await logs).events.length > 0);
  await closing;
  assert((await fs.readFile(heldPath, "utf8")).includes('"turnId":"b-main"'));
  assert((await fs.stat(home)).isDirectory());
} finally {
  release();
  await Promise.all(clients.map((client) => client.close()));
  mock.restore();
  await fixtures.cleanup();
}
