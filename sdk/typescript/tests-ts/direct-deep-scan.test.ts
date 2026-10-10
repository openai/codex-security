import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { runDeepScan } from "../src/deep-scan.js";
import { ScanCostTracker } from "../src/cost.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { writeSession } from "./support/usage-rollout.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

async function fixture() {
  const root = await temporaryDirectory();
  const pluginRoot = join(root, "plugin");
  await mkdir(join(pluginRoot, "mcp"), { recursive: true });
  await mkdir(join(pluginRoot, "scripts"));
  await mkdir(join(root, "codex-home"), { mode: 0o700 });
  await copyFile(
    join(PLUGIN_ROOT, "scripts", "codex_profile.mjs"),
    join(pluginRoot, "scripts", "codex_profile.mjs"),
  );
  await writeFile(
    join(pluginRoot, "mcp", "permission-profile-preflight.mjs"),
    `
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
let initializing = false;
export async function prepareCliDeepScanSession(options) {
  // Reproduce the native SQLite cold-start conflict while initialization does I/O.
  if (initializing) throw new Error('Concurrent native SQLite initialization');
  initializing = true;
  try {
    await writeFile(join(options.env.CODEX_HOME, 'initialized'), 'ready');
    return { threadId: options.env.SYNTHETIC_THREAD_ID,
    model: 'synthetic-model', reasoningEffort: 'high',
    permissionProfile: { configOverrides: options.configOverrides, commandArgs: options.commandArgs } };
  } finally { initializing = false; }
}
`,
  );
  await writeFile(
    join(pluginRoot, "mcp", "server.mjs"),
    `
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
const lines = createInterface({input: process.stdin});
const request = JSON.parse((await lines[Symbol.asyncIterator]().next()).value);
writeFileSync(process.env.SYNTHETIC_RECEIPT, JSON.stringify({
  request, argv: process.argv.slice(2), key: process.env.CODEX_API_KEY,
  awsProfile: process.env.AWS_PROFILE, snapshot: process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH,
}));
if (process.env.SYNTHETIC_WAIT === '1') {
  lines.once('close', () => { writeFileSync(process.env.SYNTHETIC_RECEIPT + '.stopped', 'stopped'); process.exit(0); });
  setInterval(() => {}, 1000);
} else {
  process.stdout.write(JSON.stringify({ scanId: request.scanId,
    manifestPath: join(process.env.CODEX_SECURITY_SCAN_DIR, 'scan-manifest.json') }) + '\\n');
  lines.close();
  process.stdin.destroy();
}
`,
  );
  return { root, pluginRoot };
}

test("isolates direct engine credentials and runtime snapshots across concurrent scans", async () => {
  const { root, pluginRoot } = await fixture();
  const events = await Promise.all(
    ["first", "second"].map(async (name) => {
      const scanDir = join(root, name);
      const receipt = join(root, `${name}.json`);
      await mkdir(scanDir);
      const environment = {
        PATH: process.env["PATH"]!,
        CODEX_HOME: join(root, "codex-home"),
        SYNTHETIC_RECEIPT: receipt,
        SYNTHETIC_THREAD_ID: `thread-${name}`,
        CODEX_SECURITY_SCAN_DIR: scanDir,
        CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: join(
          scanDir,
          "private-snapshot.toml",
        ),
        AWS_PROFILE: `profile-${name}`,
      };
      const before = { ...environment };
      const collected = [];
      for await (const event of runDeepScan({
        preflightCommand: {
          command: "/synthetic/codex",
          args: ["--config", `model_provider="provider_${name}"`],
        },
        pluginRoot,
        repository: root,
        scanDir,
        scanId: `scan-${name}`,
        prompt: "Synthetic audit request.",
        signal: new AbortController().signal,
        codexOptions: {
          codexPathOverride: "/synthetic/codex",
          nativeProfile: `provider_${name}`,
          apiKey: `synthetic-key-${name}`,
          env: environment,
          config: { model: "synthetic-model" },
          configOverrides: ['permissions.scan.filesystem={":root"="read"}'],
        },
      }))
        collected.push(event);
      const saved = JSON.parse(await readFile(receipt, "utf8"));
      expect(saved).toMatchObject({
        key: `synthetic-key-${name}`,
        awsProfile: `profile-${name}`,
        snapshot: environment.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH,
        argv: ["--deep-scan-engine"],
        request: {
          scanId: `scan-${name}`,
          threadId: `thread-${name}`,
          permissionProfile: {
            commandArgs: ["--config", `model_provider="provider_${name}"`],
            configOverrides: [
              'model="synthetic-model"',
              'permissions.scan.filesystem={":root"="read"}',
              "features.plugins=false",
            ],
          },
        },
      });
      expect(environment).toEqual(before);
      return collected;
    }),
  );
  for (const run of events)
    expect(run.map((event) => event.type)).toEqual([
      "thread.started",
      "turn.completed",
    ]);
});

test("preserves complete worker usage and cost after direct engine completion", async () => {
  const { root, pluginRoot } = await fixture();
  const codexHome = join(root, "codex-home");
  const scanDir = join(root, "scan");
  await mkdir(scanDir);
  await writeSession(
    codexHome,
    "discovery-session",
    {
      input_tokens: 1_000,
      cached_input_tokens: 200,
      cache_write_input_tokens: 100,
      output_tokens: 100,
    },
    {
      cwd: join(
        scanDir,
        "artifacts",
        "deep_discovery",
        "workers",
        "1",
        "output",
      ),
      timestamp: "2026-07-26T12:00:01.000Z",
    },
  );
  await writeSession(
    codexHome,
    "reducer-session",
    {
      input_tokens: 500,
      cached_input_tokens: 50,
      cache_write_input_tokens: 40,
      output_tokens: 60,
    },
    {
      cwd: join(scanDir, "artifacts"),
      timestamp: "2026-07-26T12:00:02.000Z",
    },
  );
  await writeFile(
    join(codexHome, "sessions", "owner.jsonl"),
    JSON.stringify({
      type: "session_meta",
      payload: {
        id: "engine-session",
        cwd: scanDir,
        timestamp: "2026-07-26T12:00:00.000Z",
      },
    }) + "\n",
  );
  const events = runDeepScan({
    preflightCommand: { command: "/synthetic/codex" },
    pluginRoot,
    repository: root,
    scanDir,
    scanId: "usage-scan",
    prompt: "Synthetic audit.",
    signal: new AbortController().signal,
    codexOptions: {
      env: {
        PATH: process.env["PATH"]!,
        CODEX_HOME: codexHome,
        CODEX_SECURITY_SCAN_DIR: scanDir,
        SYNTHETIC_RECEIPT: join(root, "engine.json"),
        SYNTHETIC_THREAD_ID: "engine-session",
      },
    },
  });
  expect((await events.next()).value).toMatchObject({
    type: "thread.started",
    thread_id: "engine-session",
  });
  const tracker = new ScanCostTracker({
    codexHome,
    scanDirectory: scanDir,
    model: "gpt-6.1-sol",
  });
  tracker.start("engine-session");
  const running = await tracker.refresh();
  const completed = (await events.next()).value;
  expect(completed?.type).toBe("turn.completed");
  const final = await tracker.stop(completed?.["usage"]);
  expect(running.usage).toEqual({
    input_tokens: 1_500,
    cached_input_tokens: 250,
    cache_write_input_tokens: 140,
    output_tokens: 160,
    reasoning_output_tokens: 0,
    total_tokens: 1_660,
  });
  expect(running.cost).not.toBeNull();
  expect(final).toEqual(running);
  expect(final.cost?.cacheWriteInputTokensReported).toBeUndefined();
  expect((await events.next()).done).toBe(true);
});

test("waits for the direct engine to stop when the scan is canceled", async () => {
  const { root, pluginRoot } = await fixture();
  const receipt = join(root, "engine.json");
  const controller = new AbortController();
  const events = runDeepScan({
    preflightCommand: { command: "/synthetic/codex" },
    pluginRoot,
    repository: root,
    scanDir: root,
    scanId: "canceled-scan",
    prompt: "Synthetic audit.",
    signal: controller.signal,
    codexOptions: {
      codexPathOverride: "/synthetic/codex",
      env: {
        PATH: process.env["PATH"]!,
        CODEX_HOME: join(root, "codex-home"),
        SYNTHETIC_RECEIPT: receipt,
        SYNTHETIC_THREAD_ID: "cancel-session",
        SYNTHETIC_WAIT: "1",
      },
    },
  });
  expect((await events.next()).value).toMatchObject({ type: "thread.started" });
  const running = events.next();
  const outcome = running.then(
    () => undefined,
    (error: unknown) => error,
  );
  try {
    while (!(await readFile(receipt).catch(() => undefined)))
      await Bun.sleep(10);
    controller.abort();
    expect(await outcome).toBeInstanceOf(Error);
    expect(await readFile(receipt + ".stopped", "utf8")).toBe("stopped");
  } finally {
    controller.abort();
    await outcome;
  }
});
