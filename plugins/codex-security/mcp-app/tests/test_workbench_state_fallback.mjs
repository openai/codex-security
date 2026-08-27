import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

if (process.platform !== "win32") {
  await testWorkbenchStateFallback();
}

async function testWorkbenchStateFallback() {
  const mcpAppRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const pluginRoot = path.resolve(mcpAppRoot, "..");
  const fixtureRoot = await mkdtemp(path.join(tmpdir(), "codex-security-state-fallback-"));
  const targetPath = path.join(fixtureRoot, "target");
  const fakePythonPath = path.join(fixtureRoot, "fake-python.mjs");
  const invocationLog = path.join(fixtureRoot, "python-invocations.jsonl");
  const serverBundlePath = path.join(pluginRoot, "mcp", `.state-fallback-test-${randomUUID()}.cjs`);
  const pythonCommand = process.env.PYTHON?.trim() || "python3";
  const realPython = execFileSync(pythonCommand, ["-c", "import sys; print(sys.executable)"], {
    encoding: "utf8"
  }).trim();

  await mkdir(targetPath, { recursive: true });
  await writeFile(path.join(targetPath, "fixture.py"), "print('fixture')\n");
  await writeFakePython(fakePythonPath);
  await build({
    bundle: true,
    define: { "import.meta.url": "__filename" },
    entryPoints: [path.join(mcpAppRoot, "main.ts")],
    external: ["fsevents"],
    format: "cjs",
    loader: { ".md": "text" },
    logLevel: "silent",
    outfile: serverBundlePath,
    platform: "node",
    target: "node20"
  });

  try {
    const scanRoot = path.join(fixtureRoot, "fallback-scans");
    await mkdir(scanRoot, { recursive: true });
    const fallbackServer = startServer(serverBundlePath, childEnvironment({
      CODEX_SECURITY_SCAN_ROOT: scanRoot,
      CODEX_SECURITY_STATE_DIR: undefined,
      FAKE_PYTHON_ALWAYS_FAIL: undefined,
      FAKE_PYTHON_FAILURE: undefined,
      FAKE_PYTHON_LOG: invocationLog,
      FAKE_REAL_PYTHON: realPython,
      PYTHON: fakePythonPath
    }));
    try {
      await initialize(fallbackServer, 1);
      const promptOnly = await startPromptOnlyScan(fallbackServer, 3, targetPath);
      assertNoError(promptOnly);
      assert.equal(promptOnly.result.structuredContent.startDisposition, "created");
      assert.equal(promptOnly.result.structuredContent.scan.handoffStatus, "delivered");
      const opened = await openWorkspace(fallbackServer, 4, targetPath);
      assertNoError(opened);
      const sessionId = opened.result.structuredContent.workspace.id;
      assertNoError(await reopenWorkspace(fallbackServer, 5, sessionId));
      assertNoError(await submitSetup(fallbackServer, 7, sessionId, targetPath));
      assertNoError(await startScan(fallbackServer, 8, sessionId));
      const invocations = await readJsonLines(invocationLog);
      const fallbackStateDir = path.join(scanRoot, "workbench-state");
      assert.equal(invocations[0].stateDir, null);
      assert.equal(invocations.slice(1).every((entry) => entry.stateDir === fallbackStateDir), true);
      assert.equal((await stat(fallbackStateDir)).isDirectory(), true);
      const events = fallbackServer.stderrEvents().filter((event) => event.event === "state_fallback_pinned");
      assert.equal(events.length, 1);
      assert.deepEqual(events[0], {
        component: "codex_security_workbench",
        event: "state_fallback_pinned",
        reason: "persistent_sqlite_unwritable"
      });
      assert.doesNotMatch(JSON.stringify(events[0]), new RegExp(escapeRegex(fixtureRoot)));
    } finally {
      await fallbackServer.stop();
    }

    await writeFile(invocationLog, "");
    const explicitStateDir = path.join(fixtureRoot, "explicit-state");
    await mkdir(explicitStateDir, { recursive: true });
    const explicitServer = startServer(serverBundlePath, childEnvironment({
      CODEX_SECURITY_SCAN_ROOT: path.join(fixtureRoot, "explicit-scans"),
      CODEX_SECURITY_STATE_DIR: explicitStateDir,
      FAKE_PYTHON_ALWAYS_FAIL: "1",
      FAKE_PYTHON_FAILURE: "sqlite3.OperationalError: unable to open database file",
      FAKE_PYTHON_LOG: invocationLog,
      FAKE_REAL_PYTHON: realPython,
      PYTHON: fakePythonPath
    }));
    try {
      await initialize(explicitServer, 10);
      assertToolError(await inspectTarget(explicitServer, 11, targetPath), /unable to open database file/);
      assert.deepEqual((await readJsonLines(invocationLog)).map((entry) => entry.stateDir), [explicitStateDir]);
      assert.equal(explicitServer.stderrEvents().some((event) => event.event === "state_fallback_pinned"), false);
    } finally {
      await explicitServer.stop();
    }

    await writeFile(invocationLog, "");
    const inspectionFirstScanRoot = path.join(fixtureRoot, "inspection-first-scans");
    const inspectionFirstCodexHome = path.join(fixtureRoot, "inspection-first-codex-home");
    await mkdir(inspectionFirstCodexHome, { recursive: true });
    const inspectionFirstServer = startServer(serverBundlePath, childEnvironment({
      CODEX_HOME: inspectionFirstCodexHome,
      CODEX_SECURITY_SCAN_ROOT: inspectionFirstScanRoot,
      CODEX_SECURITY_STATE_DIR: undefined,
      FAKE_PYTHON_ALWAYS_FAIL: undefined,
      FAKE_PYTHON_FAILURE: "sqlite3.OperationalError: unable to open database file",
      FAKE_PYTHON_LOG: invocationLog,
      FAKE_PYTHON_PERSISTENT_SUCCESSES: "1",
      FAKE_REAL_PYTHON: realPython,
      PYTHON: fakePythonPath
    }));
    try {
      await initialize(inspectionFirstServer, 15);
      assertNoError(await inspectTarget(inspectionFirstServer, 16, targetPath));
      assertNoError(await openWorkspace(inspectionFirstServer, 17, targetPath));
      const fallbackStateDir = path.join(inspectionFirstScanRoot, "workbench-state");
      const invocationStateDirs = (await readJsonLines(invocationLog)).map((entry) => entry.stateDir);
      assert.deepEqual(invocationStateDirs.slice(0, 2), [null, null]);
      assert.equal(invocationStateDirs.slice(2).every((stateDir) => stateDir === fallbackStateDir), true);
      assert.ok(invocationStateDirs.length > 2);
      const fallbackEvents = inspectionFirstServer.stderrEvents()
        .filter((event) => event.event === "state_fallback_pinned");
      assert.equal(fallbackEvents.length, 1);
      assert.equal(await pathExists(fallbackStateDir), true);
    } finally {
      await inspectionFirstServer.stop();
    }

    await writeFile(invocationLog, "");
    const provenCodexHome = path.join(fixtureRoot, "proven-codex-home");
    const provenScanRoot = path.join(fixtureRoot, "proven-scans");
    await mkdir(provenCodexHome, { recursive: true });
    const provenServer = startServer(serverBundlePath, childEnvironment({
      CODEX_HOME: provenCodexHome,
      CODEX_SECURITY_SCAN_ROOT: provenScanRoot,
      CODEX_SECURITY_STATE_DIR: undefined,
      FAKE_PYTHON_ALWAYS_FAIL: undefined,
      FAKE_PYTHON_FAILURE: "sqlite3.OperationalError: unable to open database file",
      FAKE_PYTHON_LOG: invocationLog,
      FAKE_PYTHON_PERSISTENT_SUCCESSES: "1",
      FAKE_REAL_PYTHON: realPython,
      PYTHON: fakePythonPath
    }));
    try {
      await initialize(provenServer, 18);
      assertNoError(await openWorkspace(provenServer, 19, targetPath, "proven-thread-1"));
      assertToolError(
        await openWorkspace(provenServer, 20, targetPath, "proven-thread-2"),
        /unable to open database file/
      );
      assert.deepEqual((await readJsonLines(invocationLog)).map((entry) => entry.stateDir), [null, null]);
      assert.equal(provenServer.stderrEvents().some((event) => event.event === "state_fallback_pinned"), false);
      assert.equal(await pathExists(path.join(provenScanRoot, "workbench-state")), false);
    } finally {
      await provenServer.stop();
    }

    await writeFile(invocationLog, "");
    const genericScanRoot = path.join(fixtureRoot, "generic-scans");
    const genericServer = startServer(serverBundlePath, childEnvironment({
      CODEX_SECURITY_SCAN_ROOT: genericScanRoot,
      CODEX_SECURITY_STATE_DIR: undefined,
      FAKE_PYTHON_ALWAYS_FAIL: "1",
      FAKE_PYTHON_FAILURE: "sqlite3.OperationalError: database disk image is malformed",
      FAKE_PYTHON_LOG: invocationLog,
      FAKE_REAL_PYTHON: realPython,
      PYTHON: fakePythonPath
    }));
    try {
      await initialize(genericServer, 20);
      assertToolError(await inspectTarget(genericServer, 21, targetPath), /database disk image is malformed/);
      assert.deepEqual((await readJsonLines(invocationLog)).map((entry) => entry.stateDir), [null]);
      assert.equal(genericServer.stderrEvents().some((event) => event.event === "state_fallback_pinned"), false);
    } finally {
      await genericServer.stop();
    }
  } finally {
    await rm(serverBundlePath, { force: true });
    await rm(fixtureRoot, { recursive: true, force: true });
  }
}

function childEnvironment(overrides) {
  const environment = { ...process.env };
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete environment[key];
    else environment[key] = value;
  }
  return environment;
}

async function writeFakePython(executablePath) {
  await writeFile(executablePath, [
    "#!/usr/bin/env node",
    'import { appendFileSync, readFileSync } from "node:fs";',
    'import { spawnSync } from "node:child_process";',
    "let priorInvocations = 0;",
    "try { priorInvocations = readFileSync(process.env.FAKE_PYTHON_LOG, 'utf8').split(/\\r?\\n/).filter(Boolean).length; } catch {}",
    "appendFileSync(process.env.FAKE_PYTHON_LOG, JSON.stringify({ stateDir: process.env.CODEX_SECURITY_STATE_DIR || null }) + '\\n');",
    "const persistentSuccesses = Number(process.env.FAKE_PYTHON_PERSISTENT_SUCCESSES || 0);",
    "if (process.env.FAKE_PYTHON_ALWAYS_FAIL === '1' || (!process.env.CODEX_SECURITY_STATE_DIR && priorInvocations >= persistentSuccesses)) {",
    "  console.error(process.env.FAKE_PYTHON_FAILURE || 'sqlite3.OperationalError: unable to open database file');",
    "  process.exit(1);",
    "}",
    "const result = spawnSync(process.env.FAKE_REAL_PYTHON, process.argv.slice(2), { env: process.env, stdio: 'inherit' });",
    "process.exit(result.status ?? 1);",
    ""
  ].join("\n"));
  await chmod(executablePath, 0o755);
}

function startServer(serverPath, env) {
  const child = spawn(process.execPath, [serverPath, "--stdio"], {
    cwd: path.dirname(path.dirname(serverPath)),
    env,
    stdio: ["pipe", "pipe", "pipe"]
  });
  const responses = new Map();
  const waiters = new Map();
  const stderrEvents = [];
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
    stdout = consumeLines(stdout, (line) => {
      const response = JSON.parse(line);
      responses.set(response.id, response);
      waiters.get(response.id)?.(response);
      waiters.delete(response.id);
    });
  });
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
    stderr = consumeLines(stderr, (line) => {
      try {
        const event = JSON.parse(line);
        if (event.component === "codex_security_workbench") stderrEvents.push(event);
      } catch {
        // Tool errors are asserted from MCP responses; only structured diagnostics matter here.
      }
    });
  });
  return {
    request(id, method, params = {}) {
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
      const existing = responses.get(id);
      if (existing) return Promise.resolve(existing);
      return withTimeout(new Promise((resolve) => waiters.set(id, resolve)), 15_000, `response ${id}`);
    },
    stderrEvents() {
      return [...stderrEvents];
    },
    async stop() {
      if (child.exitCode !== null) return;
      child.stdin.end();
      const exited = new Promise((resolve) => child.once("exit", resolve));
      const graceful = await Promise.race([exited.then(() => true), delay(2_000).then(() => false)]);
      if (!graceful && child.exitCode === null) child.kill("SIGKILL");
      await exited;
    }
  };
}

async function initialize(server, id) {
  const response = await server.request(id, "initialize", {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "workbench-state-fallback", version: "0.1.0" }
  });
  assertNoError(response);
}

function inspectTarget(server, id, targetPath) {
  return server.request(id, "tools/call", {
    name: "inspect_codex_security_target",
    arguments: { targetPath }
  });
}

function startPromptOnlyScan(server, id, targetPath) {
  return server.request(id, "tools/call", {
    name: "start_codex_security_prompt_only_scan",
    arguments: { mode: "standard", scope: ".", targetPath },
    _meta: { "openai/threadId": "state-fallback-prompt-only-thread" }
  });
}

function submitSetup(server, id, sessionId, targetPath) {
  return server.request(id, "tools/call", {
    name: "submit_codex_security_setup",
    arguments: { sessionId, targetPath, scope: ".", mode: "standard" }
  });
}

function startScan(server, id, sessionId) {
  return server.request(id, "tools/call", {
    name: "start_codex_security_scan",
    arguments: { sessionId }
  });
}

function openWorkspace(server, id, targetPath, threadId = "state-fallback-thread") {
  return server.request(id, "tools/call", {
    name: "open_codex_security_workspace",
    arguments: { targetPath, scope: ".", mode: "standard" },
    _meta: { "openai/threadId": threadId }
  });
}

function reopenWorkspace(server, id, sessionId, threadId = "state-fallback-thread") {
  return server.request(id, "tools/call", {
    name: "open_codex_security_workspace",
    arguments: { sessionId },
    _meta: { "openai/threadId": threadId }
  });
}

function assertNoError(response) {
  assert.equal(response.error, undefined, response.error?.message);
  assert.equal(response.result?.isError, undefined, response.result?.content?.[0]?.text);
}

function assertToolError(response, pattern) {
  assert.equal(response.error, undefined);
  assert.equal(response.result?.isError, true);
  assert.match(response.result.content.map((item) => item.text).join(" "), pattern);
}

async function readJsonLines(filePath) {
  const content = await readFile(filePath, "utf8");
  return content.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
}

async function pathExists(filePath) {
  try {
    await stat(filePath);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

function consumeLines(buffer, consume) {
  let newline = buffer.indexOf("\n");
  while (newline >= 0) {
    const line = buffer.slice(0, newline).trim();
    buffer = buffer.slice(newline + 1);
    if (line) consume(line);
    newline = buffer.indexOf("\n");
  }
  return buffer;
}

function withTimeout(promise, timeoutMs, label) {
  return Promise.race([
    promise,
    delay(timeoutMs).then(() => {
      throw new Error(`Timed out waiting for ${label}`);
    })
  ]);
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
