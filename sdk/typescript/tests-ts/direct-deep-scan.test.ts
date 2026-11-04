import assert from "node:assert/strict";
import {
  copyFile,
  mkdir,
  readFile,
  realpath,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { afterEach, test } from "node:test";
import { setTimeout } from "node:timers/promises";
import {
  DIRECT_DEEP_SCAN_CONTROL_USAGE,
  runDeepScan,
} from "../src/deep-scan.js";
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
  execPath: process.execPath, bun: process.versions.bun,
  awsProfile: process.env.AWS_PROFILE, snapshot: process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH,
  externalImports: process.env.CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS,
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
    ["first", "second", "unset", "mixed-case"].map(async (name) => {
      const scanDir = join(root, name);
      const receipt = join(root, `${name}.json`);
      await mkdir(scanDir);
      const environment = {
        PATH: process.versions["bun"] ? process.env["PATH"]! : "",
        CODEX_HOME: join(root, "codex-home"),
        SYNTHETIC_RECEIPT: receipt,
        SYNTHETIC_THREAD_ID: `thread-${name}`,
        CODEX_SECURITY_SCAN_DIR: scanDir,
        CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: join(
          scanDir,
          "private-snapshot.toml",
        ),
        AWS_PROFILE: `profile-${name}`,
        ...(name === "mixed-case"
          ? { Codex_Security_Enable_External_Imports: "1" }
          : name === "unset"
            ? {}
            : {
                CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS:
                  name === "first" ? "1" : "0",
              }),
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
      assert.equal(
        saved.externalImports,
        name === "mixed-case"
          ? process.platform === "win32"
            ? "1"
            : undefined
          : name === "first"
            ? "1"
            : name === "second"
              ? "0"
              : undefined,
      );
      assert.partialDeepStrictEqual(saved, {
        key: `synthetic-key-${name}`,
        awsProfile: `profile-${name}`,
        snapshot: environment.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH,
        request: {
          scanId: `scan-${name}`,
          threadId: `thread-${name}`,
        },
      });
      assert.deepEqual(saved.argv, ["--deep-scan-engine"]);
      assert.deepEqual(saved.request.permissionProfile, {
        commandArgs: ["--config", `model_provider="provider_${name}"`],
        configOverrides: [
          'model="synthetic-model"',
          'permissions.scan.filesystem={":root"="read"}',
          "features.plugins=false",
        ],
      });
      assert.equal(saved.bun, undefined);
      if (!process.versions["bun"])
        assert.equal(
          await realpath(saved.execPath),
          await realpath(process.execPath),
        );
      assert.deepEqual(environment, before);
      return collected;
    }),
  );
  for (const run of events)
    assert.deepEqual(
      run.map((event) => event.type),
      ["thread.started", "turn.completed"],
    );
  const firstUsage = events[0]![1]!["usage"] as Record<string, number>;
  const secondUsage = events[1]![1]!["usage"] as Record<string, number>;
  firstUsage["input_tokens"] = 100;
  assert.equal(secondUsage["input_tokens"], 0);
  assert.equal(DIRECT_DEEP_SCAN_CONTROL_USAGE.input_tokens, 0);
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
        PATH: process.versions["bun"] ? process.env["PATH"]! : "",
        CODEX_HOME: codexHome,
        CODEX_SECURITY_SCAN_DIR: scanDir,
        SYNTHETIC_RECEIPT: join(root, "engine.json"),
        SYNTHETIC_THREAD_ID: "engine-session",
      },
    },
  });
  assert.partialDeepStrictEqual((await events.next()).value, {
    type: "thread.started",
    thread_id: "engine-session",
  });
  const tracker = new ScanCostTracker({
    codexHome,
    scanDirectory: scanDir,
    model: "gpt-6.1-sol",
  });
  tracker.recordUsage(DIRECT_DEEP_SCAN_CONTROL_USAGE, "engine-session");
  tracker.start("engine-session");
  const running = await tracker.refresh();
  await writeSession(
    codexHome,
    "waiting-session",
    {},
    {
      parent: "engine-session",
    },
  );
  assert.deepEqual(await tracker.refresh(), { usage: null, cost: null });
  tracker.recordUsage(
    {
      input_tokens: 0,
      cached_input_tokens: 0,
      cache_write_input_tokens: 0,
      output_tokens: 0,
    },
    "waiting-session",
  );
  const completed = (await events.next()).value;
  assert.equal(completed?.type, "turn.completed");
  const final = await tracker.stop(completed?.["usage"]);
  assert.deepEqual(running.usage, {
    input_tokens: 1_500,
    cached_input_tokens: 250,
    cache_write_input_tokens: 140,
    output_tokens: 160,
    reasoning_output_tokens: 0,
    total_tokens: 1_660,
  });
  assert.notEqual(running.cost, null);
  assert.deepEqual(final, running);
  assert.equal(final.cost?.cacheWriteInputTokensReported, undefined);
  assert.equal((await events.next()).done, true);
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
        PATH: process.versions["bun"] ? process.env["PATH"]! : "",
        CODEX_HOME: join(root, "codex-home"),
        SYNTHETIC_RECEIPT: receipt,
        SYNTHETIC_THREAD_ID: "cancel-session",
        SYNTHETIC_WAIT: "1",
      },
    },
  });
  assert.partialDeepStrictEqual((await events.next()).value, {
    type: "thread.started",
  });
  const running = events.next();
  const outcome = running.then(
    () => undefined,
    (error: unknown) => error,
  );
  try {
    while (!(await readFile(receipt).catch(() => undefined)))
      await setTimeout(10);
    controller.abort();
    assert.ok((await outcome) instanceof Error);
    assert.equal(await readFile(receipt + ".stopped", "utf8"), "stopped");
  } finally {
    controller.abort();
    await outcome;
  }
});
