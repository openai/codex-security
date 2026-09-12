import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  chmod,
  copyFile,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { startRpc } from "./package-rpc.mjs";
import { packageSmokeTimeouts } from "../package-smoke-timeouts.mjs";

const installedRoot = await realpath(process.argv[2]);
const root = await realpath(
  await mkdtemp(join(tmpdir(), "package deep % fixture-")),
);
const installedPlugin = join(installedRoot, "_bundled_plugin");
try {
  const detachedPlugin = join(root, "standalone plugin %", "codex-security");
  await cp(installedPlugin, detachedPlugin, { recursive: true });
  // Assert physical independence instead of merely changing the working directory.
  for (let ancestor = detachedPlugin; ; ancestor = dirname(ancestor)) {
    for (const dependency of ["node_modules", join("sdk", "typescript")]) {
      await assert.rejects(stat(join(ancestor, dependency)), {
        code: "ENOENT",
      });
    }
    if (ancestor === dirname(ancestor)) break;
  }
  for (const name of [
    "package-deep-codex.mjs",
    "package-rpc.mjs",
    "package-deep-spawn.mjs",
  ]) {
    await copyFile(new URL(name, import.meta.url), join(root, name));
  }
  const executable = join(
    root,
    process.platform === "win32"
      ? "package-codex.exe"
      : "package-deep-codex.mjs",
  );
  if (process.platform === "win32")
    await copyFile(process.execPath, executable);
  await chmod(executable, 0o700);

  await runInstalledSdk(installedPlugin, executable);
  await runDetachedPlugin(detachedPlugin, executable);
  console.log(
    "Validated installed SDK and detached plugin: real Deep processes, bound artifact tools, checkpoints, reducer acceptance, restart before finalization, and sealed results.",
  );
} catch (error) {
  for (const name of ["installed", "detached"]) {
    try {
      error.message += `\n${await readFile(join(root, name, "executions.jsonl"), "utf8")}`;
    } catch (readError) {
      if (readError.code !== "ENOENT") throw readError;
    }
  }
  throw error;
} finally {
  await rm(root, {
    recursive: true,
    force: true,
    maxRetries: 10,
    retryDelay: 100,
  });
}

async function fixture(name, pluginRoot, executable) {
  const directory = join(root, name);
  const target = join(directory, "target with spaces %");
  const home = join(directory, "home");
  await mkdir(target, { recursive: true });
  await mkdir(join(home, "codex-security"), { recursive: true });
  await writeFile(
    join(target, "fixture.py"),
    "print('synthetic package fixture')\n",
  );
  await writeFile(
    join(home, "codex-security", "config.toml"),
    "[deep_scan]\nworkers = 1\nsubagents = 0\nstop_after_no_new = 1\nmax_discovery_runs = 2\n",
  );
  const env = Object.fromEntries(
    [
      "PATH",
      "Path",
      "SystemRoot",
      "WINDIR",
      "ComSpec",
      "PATHEXT",
      "TMP",
      "TEMP",
      "TMPDIR",
    ]
      .filter((key) => process.env[key] !== undefined)
      .map((key) => [key, process.env[key]]),
  );
  Object.assign(env, {
    HOME: home,
    USERPROFILE: home,
    CODEX_HOME: home,
    CODEX_CLI_PATH: executable,
    CODEX_SECURITY_PLUGIN_ROOT: pluginRoot,
    CODEX_SECURITY_STATE_DIR: join(directory, "state"),
    CODEX_SECURITY_SCAN_ROOT: join(directory, "scans"),
    PYTHON: process.env.PYTHON || "python3",
    OPENAI_API_KEY: "synthetic-package-deep-key",
    ...(process.platform === "win32"
      ? {
          PACKAGE_DEEP_EXECUTABLE: executable,
          NODE_OPTIONS: `--import=${pathToFileURL(join(root, "package-deep-spawn.mjs")).href}`,
        }
      : {}),
    PACKAGE_DEEP_TRACE: join(directory, "executions.jsonl"),
  });
  return { directory, target, home, env, pluginRoot };
}

function metadata(f, owner) {
  return {
    "openai/threadId": owner,
    "codex/sandbox-state-meta": {
      permissionProfile: {
        type: "managed",
        file_system: {
          type: "restricted",
          entries: [
            {
              path: { type: "special", value: { kind: "root" } },
              access: "read",
            },
          ],
        },
        network: "restricted",
      },
      sandboxCwd: pathToFileURL(f.target).href,
    },
    "x-codex-turn-metadata": { model: "gpt-5.5", reasoning_effort: "high" },
  };
}

function server(f, env = f.env) {
  return startRpc(
    process.execPath,
    [join(f.pluginRoot, "mcp", "server.mjs"), "--stdio"],
    {
      cwd: f.target,
      env,
      requestTimeoutMs: packageSmokeTimeouts().commandTimeoutMs,
    },
  );
}

async function runDetachedPlugin(pluginRoot, executable) {
  const f = await fixture("detached", pluginRoot, executable);
  const owner = "package-detached-owner";
  f.env.PACKAGE_DEEP_HOLD = join(f.directory, "hold-second-worker");
  await writeFile(f.env.PACKAGE_DEEP_HOLD, "hold");
  let rpc = await server(f);
  let scanId;
  let scanDir;
  let partial;
  const handoffClaimToken = randomUUID();
  try {
    const opened = await rpc.call(
      "open_codex_security_workspace",
      {
        targetPath: f.target,
        scope: ".",
        mode: "deep",
      },
      metadata(f, owner),
    );
    const sessionId = opened.workspace.id;
    await rpc.call(
      "submit_codex_security_setup",
      {
        sessionId,
        targetPath: f.target,
        scope: ".",
        mode: "deep",
      },
      metadata(f, owner),
    );
    const started = await rpc.call(
      "start_codex_security_scan",
      { sessionId },
      metadata(f, owner),
    );
    ({ scanId, scanDir } = started.workspace.results);
    await rpc.call(
      "claim_codex_security_scan_handoff_delivery",
      {
        scanId,
        claimToken: handoffClaimToken,
      },
      metadata(f, owner),
    );
    await rpc.call(
      "attach_codex_security_scan_continuation_thread",
      {
        scanId,
        claimToken: handoffClaimToken,
        threadId: owner,
      },
      metadata(f, owner),
    );
    const pending = rpc
      .call(
        "start_codex_security_deep_scan",
        { scanId, handoffClaimToken },
        metadata(f, owner),
      )
      .catch((error) => error);
    const deadline = Date.now() + 30_000;
    while (!(await readExecutions(f)).some((entry) => entry.phase === "held")) {
      assert.ok(
        Date.now() < deadline,
        "Second worker did not reach the interruption boundary.",
      );
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    partial = (
      await workbench(f, [
        "get-deep-scan",
        "--scan-id",
        scanId,
        "--thread-id",
        owner,
      ])
    ).deepScan;
    assert.equal(
      partial.workers.filter(
        (worker) =>
          worker.kind === "discovery" && worker.status === "succeeded",
      ).length,
      1,
    );
    await rpc.close();
    await pending;
  } finally {
    await rpc.close();
  }
  // Simulate an expired owner lease without waiting for wall-clock expiry. Keep
  // the real stored workers/results and use the production recovery path.
  await rm(
    join(
      scanDir,
      "artifacts",
      "deep_discovery",
      `coordinator-heartbeat-${partial.coordinatorGeneration}.json`,
    ),
    { force: true },
  );
  await promisify(execFile)(
    f.env.PYTHON,
    [
      "-c",
      "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('UPDATE deep_scan_runs SET updated_at = ? WHERE scan_id = ?', ('2000-01-01T00:00:00Z',sys.argv[2])); c.commit()",
      join(f.env.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
      scanId,
    ],
    { env: f.env },
  );
  await rm(f.env.PACKAGE_DEEP_HOLD);
  rpc = await server(f);
  try {
    const result = await rpc.call(
      "start_codex_security_deep_scan",
      { scanId, handoffClaimToken },
      metadata(f, owner),
    );
    await assertDraft(result.manifestPath);
    const recovered = (
      await workbench(f, [
        "get-deep-scan",
        "--scan-id",
        scanId,
        "--thread-id",
        owner,
      ])
    ).deepScan;
    assert.equal(
      recovered.coordinatorGeneration,
      partial.coordinatorGeneration + 1,
    );
    assert.equal(recovered.dispatchedCount, 2);
    const retained = partial.workers.find(
      (worker) => worker.status === "succeeded",
    );
    assert.equal(
      recovered.workers.find((worker) => worker.id === retained.id).status,
      "succeeded",
    );
  } finally {
    await rpc.close();
  }
  // Publication uses the saved aggregate after the recovered executor exits too.
  rpc = await server(f);
  try {
    await rpc.call(
      "complete_codex_security_scan",
      { scanId, handoffClaimToken },
      metadata(f, owner),
    );
    const completed = await rpc.call(
      "get_codex_security_completed_scan",
      { scanId, handoffClaimToken },
      metadata(f, owner),
    );
    assert.equal(completed.manifest.scan.id, scanId);
    assert.equal(completed.manifest.scan.status, "completed");
    assert.ok(completed.manifest.scan.sealedAt);
  } finally {
    await rpc.close();
  }
  await assertExecutions(f, scanId, 4);
}

async function workbench(f, args) {
  const { stdout } = await promisify(execFile)(
    f.env.PYTHON,
    [join(f.pluginRoot, "scripts", "workbench_db.py"), ...args],
    {
      env: f.env,
      cwd: f.target,
      maxBuffer: 4 * 1024 * 1024,
    },
  );
  return JSON.parse(stdout);
}

async function runInstalledSdk(pluginRoot, executable) {
  const f = await fixture("installed", pluginRoot, executable);
  f.env.PACKAGE_DEEP_EMPTY_ONCE = join(
    f.directory,
    "missing-result-completion",
  );
  const sdk = await import(
    pathToFileURL(join(installedRoot, "dist", "index.js")).href
  );
  const manifest = JSON.parse(
    await readFile(join(pluginRoot, ".codex-plugin", "plugin.json"), "utf8"),
  );
  const owner = "package-sdk-owner";
  const postScanPrompt = "Explain the completed synthetic scan.";
  const prompts = [];
  let threadCount = 0;
  let manifestBeforeFollowUp;
  let scanId;
  const client = new sdk.CodexSecurity(
    { pythonPath: f.env.PYTHON },
    {
      environment: f.env,
      prepareRuntime: async () => ({
        codexHome: f.home,
        environment: f.env,
        credentialsAvailable: true,
        plugin: {
          pluginRoot,
          marketplaceRoot: pluginRoot,
          installedRoot: pluginRoot,
          marketplaceName: "codex-security-sdk",
          name: manifest.name,
          version: manifest.version,
        },
      }),
      // Replace only the parent model's tool choice. The installed SDK registers
      // and finalizes the scan; the packaged MCP runs the real Deep lifecycle.
      createCodex({ env, apiKey }) {
        return {
          startThread() {
            threadCount += 1;
            return {
              id: owner,
              async runStreamed(prompt) {
                prompts.push(prompt);
                return {
                  events: (async function* () {
                    yield { type: "thread.started", thread_id: owner };
                    if (prompts.length > 1) {
                      assert.equal(prompt, postScanPrompt);
                      manifestBeforeFollowUp = await readFile(
                        join(env.CODEX_SECURITY_SCAN_DIR, "scan-manifest.json"),
                        "utf8",
                      );
                      const completed = JSON.parse(manifestBeforeFollowUp);
                      assert.equal(completed.scan.status, "completed");
                      assert.ok(completed.scan.sealedAt);
                      yield {
                        type: "turn.completed",
                        usage: {
                          input_tokens: 100_000,
                          cached_input_tokens: 0,
                          output_tokens: 100_000,
                        },
                      };
                      return;
                    }
                    scanId = env.CODEX_SECURITY_SCAN_ID;
                    // The pinned SDK maps its apiKey option to this child variable.
                    const rpc = await server(f, {
                      ...env,
                      ...(apiKey ? { CODEX_API_KEY: apiKey } : {}),
                    });
                    try {
                      const result = await rpc.call(
                        "start_codex_security_deep_scan",
                        { scanId },
                        metadata(f, owner),
                      );
                      await assertDraft(result.manifestPath);
                    } finally {
                      await rpc.close();
                    }
                    yield {
                      type: "turn.completed",
                      usage: {
                        input_tokens: 1,
                        cached_input_tokens: 0,
                        output_tokens: 1,
                      },
                    };
                  })(),
                };
              },
            };
          },
        };
      },
    },
  );
  try {
    const result = await client.run(f.target, {
      mode: "deep",
      auth: "api-key",
      workers: 1,
      subagents: 0,
      maxDiscoveryRuns: 2,
      stopAfterNoNew: 1,
      postScanPrompt,
      outputDir: join(f.directory, "output"),
    });
    assert.equal(threadCount, 1);
    assert.equal(prompts.length, 2);
    assert.equal(prompts[1], postScanPrompt);
    assert.equal(result.threadId, owner);
    assert.equal(result.manifest.scan.status, "completed");
    assert.ok(result.manifest.scan.sealedAt);
    assert.equal(result.manifest.scan.id, scanId);
    assert.deepEqual(result.findings.findings, []);
    assert.equal(
      await readFile(result.manifestPath, "utf8"),
      manifestBeforeFollowUp,
    );
    assert.ok(result.cost === null || result.cost.inputTokens < 100_000);
    assert.equal(result.toJSON().threadId, owner);
    assert.ok(
      (await readFile(join(f.directory, "output", "report.md"), "utf8"))
        .length > 0,
    );
  } finally {
    await client.close();
  }
  await assertExecutions(f, scanId, 4);
}

async function assertDraft(path) {
  const document = JSON.parse(await readFile(path, "utf8"));
  const findings = JSON.parse(
    await readFile(join(dirname(path), "findings.json"), "utf8"),
  );
  assert.deepEqual(findings.findings, []);
  assert.ok(document.scan.target);
}

async function readExecutions(f) {
  try {
    return (await readFile(f.env.PACKAGE_DEEP_TRACE, "utf8"))
      .trim()
      .split("\n")
      .filter(Boolean)
      .map(JSON.parse);
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

async function assertExecutions(f, scanId, preflights = 3) {
  const executions = await readExecutions(f);
  const workers = executions.filter((entry) => entry.phase === "worker");
  const reducers = executions.filter((entry) => entry.phase === "reducer");
  const incomplete = f.env.PACKAGE_DEEP_EMPTY_ONCE ? 1 : 0;
  assert.equal(workers.length, 2 + incomplete);
  assert.equal(workers.filter((entry) => !entry.complete).length, incomplete);
  assert.equal(workers.filter((entry) => entry.resumed).length, incomplete);
  assert.equal(reducers.length, 1);
  assert.equal(
    executions.filter((entry) => entry.phase === "preflight").length,
    preflights,
  );
  for (const execution of [...workers, ...reducers]) {
    assert.equal(execution.scanId, scanId);
    assert.equal(execution.home, f.home);
    assert.equal(execution.hasApiKey, true);
    assert.equal(
      execution.args[execution.args.indexOf("--model") + 1],
      "gpt-5.5",
    );
    assert.ok(execution.args.includes('approval_policy="never"'));
  }
}
