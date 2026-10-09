import { readJsonLines } from "./support/json.ts";
import { assertNoError } from "./assertions.ts";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { applicationRoot as mcpAppRoot, buildServer } from "./build-server.ts";
import { startRpcServer } from "./support/rpc-server.ts";

if (process.platform !== "win32") {
  await testWorkbenchStateFallback();
}

async function testWorkbenchStateFallback() {
  const pluginRoot = path.resolve(mcpAppRoot, "..");
  const fixtureRoot = await realpath(
    await mkdtemp(path.join(tmpdir(), "codex-security-state-fallback-")),
  );
  const targetPath = path.join(fixtureRoot, "target");
  const fakePythonPath = path.join(fixtureRoot, "fake-python.mjs");
  const invocationLog = path.join(fixtureRoot, "python-invocations.jsonl");
  const serverBundlePath = path.join(
    pluginRoot,
    "mcp",
    `.state-fallback-test-${randomUUID()}.cjs`,
  );
  const pythonCommand = process.env.PYTHON?.trim() || "python3";
  const realPython = execFileSync(
    pythonCommand,
    ["-c", "import sys; print(sys.executable)"],
    {
      encoding: "utf8",
    },
  ).trim();

  await mkdir(targetPath, { recursive: true });
  await writeFile(path.join(targetPath, "fixture.py"), "print('fixture')\n");
  await writeFakePython(fakePythonPath);
  await buildServer(serverBundlePath, { target: "node20" });

  try {
    if (process.getuid?.() !== 0) {
      for (const firstOperation of ["scan", "standalone"]) {
        const codexHome = path.join(
          fixtureRoot,
          `default-${firstOperation}-home`,
        );
        const defaultState = path.join(
          codexHome,
          "state",
          "plugins",
          "codex-security",
        );
        await mkdir(defaultState, { recursive: true });
        await chmod(defaultState, 0o500);
        const server = startServer(serverBundlePath, {
          CODEX_HOME: codexHome,
          CODEX_SECURITY_SCAN_ROOT: undefined,
          CODEX_SECURITY_STATE_DIR: undefined,
          PYTHON: realPython,
        });
        let fallbackState;
        try {
          await initialize(server, 1);
          const standaloneInput = {
            targetPath,
            storage: "persistent",
            path: "threatmodel.md",
            content: "retained context\n",
          };
          if (firstOperation === "standalone") {
            assertNoError(
              await server.request(2, "tools/call", {
                name: "save_codex_security_artifact",
                arguments: standaloneInput,
              }),
            );
          }
          const started = await server.request(3, "tools/call", {
            name: "start_codex_security_standard_scan",
            arguments: { targetPath },
            _meta: { "openai/threadId": "default-state-fallback" },
          });
          assertNoError(started);
          const { scanId, scanDir, handoffClaimToken } =
            started.result.structuredContent;
          fallbackState = path.dirname(path.dirname(path.dirname(scanDir)));
          assert.ok(
            fallbackState.startsWith(
              path.join(await realpath(tmpdir()), "codex-security-state-"),
            ),
          );
          assert.equal(
            (
              await stat(path.join(fallbackState, "workbench.sqlite3"))
            ).isFile(),
            true,
          );
          const standalone = await server.request(4, "tools/call", {
            name: "save_codex_security_artifact",
            arguments: standaloneInput,
          });
          assertNoError(standalone);
          assert.ok(
            standalone.result.structuredContent.path.startsWith(
              path.join(fallbackState, "scans") + path.sep,
            ),
          );
          assert.equal(
            await readFile(standalone.result.structuredContent.path, "utf8"),
            standaloneInput.content,
          );
          const location = {
            scanId,
            handoffClaimToken,
            storage: "persistent",
            path: "artifacts/proof.txt",
          };
          const saved = await server.request(5, "tools/call", {
            name: "save_codex_security_artifact",
            arguments: { ...location, content: "exact café bytes\n" },
          });
          assertNoError(saved);
          assert.ok(
            saved.result.structuredContent.path.startsWith(scanDir + path.sep),
          );
          const read = await server.request(6, "tools/call", {
            name: "read_codex_security_artifact",
            arguments: location,
          });
          assertNoError(read);
          assert.equal(
            read.result.structuredContent.content,
            "exact café bytes\n",
          );
          assert.equal(
            server
              .stderrEvents()
              .filter((event) => event.event === "state_fallback_pinned")
              .length,
            1,
          );
          assert.equal(
            await pathExists(path.join(defaultState, "scans")),
            false,
          );
        } finally {
          await server.stop();
          await chmod(defaultState, 0o700);
          if (fallbackState)
            await rm(fallbackState, { recursive: true, force: true });
        }
      }

      const readFirstHome = path.join(fixtureRoot, "read-first-home");
      const readFirstDefaultState = path.join(
        readFirstHome,
        "state",
        "plugins",
        "codex-security",
      );
      const readFirstScanRoot = path.join(fixtureRoot, "read-first-scans");
      await mkdir(readFirstDefaultState, { recursive: true });
      await chmod(readFirstDefaultState, 0o500);
      const readFirstEnvironment = {
        CODEX_HOME: readFirstHome,
        CODEX_SECURITY_SCAN_ROOT: readFirstScanRoot,
        CODEX_SECURITY_STATE_DIR: undefined,
        PYTHON: realPython,
      };
      let readFirstServer = startServer(serverBundlePath, readFirstEnvironment);
      try {
        await initialize(readFirstServer, 1);
        const artifact = {
          targetPath,
          storage: "persistent",
          path: "threatmodel.md",
        };
        const saved = await readFirstServer.request(2, "tools/call", {
          name: "save_codex_security_artifact",
          arguments: { ...artifact, content: "retained context\n" },
        });
        assertNoError(saved);
        await readFirstServer.stop();
        readFirstServer = startServer(serverBundlePath, readFirstEnvironment);
        await initialize(readFirstServer, 1);
        const read = await readFirstServer.request(2, "tools/call", {
          name: "read_codex_security_artifact",
          arguments: artifact,
        });
        assertNoError(read);
        assert.equal(
          read.result.structuredContent.content,
          "retained context\n",
        );
        const fallbackStateDir = path.join(
          readFirstScanRoot,
          "workbench-state",
        );
        assert.equal(
          await pathExists(path.join(fallbackStateDir, "workbench.sqlite3")),
          false,
        );
        const started = await startPromptOnlyScan(
          readFirstServer,
          3,
          targetPath,
        );
        assertNoError(started);
        assert.ok(
          started.result.structuredContent.scan.scanDir.startsWith(
            (await realpath(readFirstScanRoot)) + path.sep,
          ),
        );
        assert.equal(
          (
            await stat(path.join(fallbackStateDir, "workbench.sqlite3"))
          ).isFile(),
          true,
        );
        assert.equal(
          await pathExists(
            path.join(readFirstDefaultState, "workbench.sqlite3"),
          ),
          false,
        );
        assert.equal(
          readFirstServer
            .stderrEvents()
            .filter((event) => event.event === "state_fallback_pinned").length,
          1,
        );
        assert.equal(
          await readFile(saved.result.structuredContent.path, "utf8"),
          "retained context\n",
        );
      } finally {
        await readFirstServer.stop();
        await chmod(readFirstDefaultState, 0o700);
      }
    }

    const scanRoot = path.join(fixtureRoot, "fallback-scans");
    const fallbackServer = startServer(serverBundlePath, {
      CODEX_SECURITY_SCAN_ROOT: scanRoot,
      CODEX_SECURITY_STATE_DIR: undefined,
      FAKE_PYTHON_ALWAYS_FAIL: undefined,
      FAKE_PYTHON_FAILURE: undefined,
      FAKE_PYTHON_LOG: invocationLog,
      FAKE_REAL_PYTHON: realPython,
      PYTHON: fakePythonPath,
    });
    try {
      await initialize(fallbackServer, 1);
      const promptOnly = await startPromptOnlyScan(
        fallbackServer,
        3,
        targetPath,
      );
      assertNoError(promptOnly);
      assert.equal(
        promptOnly.result.structuredContent.startDisposition,
        "created",
      );
      assert.equal(
        promptOnly.result.structuredContent.scan.handoffStatus,
        "delivered",
      );
      const opened = await openWorkspace(fallbackServer, 4, targetPath);
      assertNoError(opened);
      const sessionId = opened.result.structuredContent.workspace.id;
      assertNoError(await reopenWorkspace(fallbackServer, 5, sessionId));
      assertNoError(
        await submitSetup(fallbackServer, 7, sessionId, targetPath),
      );
      assertNoError(await startScan(fallbackServer, 8, sessionId));
      const invocations = await readJsonLines(invocationLog);
      const fallbackStateDir = path.join(scanRoot, "workbench-state");
      assert.equal(invocations[0].stateDir, null);
      assert.equal(
        invocations
          .slice(1)
          .every((entry) => entry.stateDir === fallbackStateDir),
        true,
      );
      assert.equal((await stat(fallbackStateDir)).isDirectory(), true);
      const events = fallbackServer
        .stderrEvents()
        .filter((event) => event.event === "state_fallback_pinned");
      assert.equal(events.length, 1);
      assert.deepEqual(events[0], {
        component: "codex_security_workbench",
        event: "state_fallback_pinned",
        reason: "persistent_sqlite_unwritable",
      });
    } finally {
      await fallbackServer.stop();
    }

    await writeFile(invocationLog, "");
    const explicitStateDir = path.join(fixtureRoot, "explicit-state");
    const explicitServer = startServer(serverBundlePath, {
      CODEX_SECURITY_SCAN_ROOT: path.join(fixtureRoot, "explicit-scans"),
      CODEX_SECURITY_STATE_DIR: explicitStateDir,
      FAKE_PYTHON_ALWAYS_FAIL: "1",
      FAKE_PYTHON_FAILURE:
        "sqlite3.OperationalError: unable to open database file",
      FAKE_PYTHON_LOG: invocationLog,
      FAKE_REAL_PYTHON: realPython,
      PYTHON: fakePythonPath,
    });
    try {
      await initialize(explicitServer, 10);
      assertToolError(
        await inspectTarget(explicitServer, 11, targetPath),
        /unable to open database file/,
      );
      assert.deepEqual(
        (await readJsonLines(invocationLog)).map((entry) => entry.stateDir),
        [explicitStateDir],
      );
      assert.equal(
        explicitServer
          .stderrEvents()
          .some((event) => event.event === "state_fallback_pinned"),
        false,
      );
    } finally {
      await explicitServer.stop();
    }

    await writeFile(invocationLog, "");
    const inspectionFirstScanRoot = path.join(
      fixtureRoot,
      "inspection-first-scans",
    );
    const inspectionFirstServer = startServer(serverBundlePath, {
      CODEX_HOME: path.join(fixtureRoot, "inspection-first-codex-home"),
      CODEX_SECURITY_SCAN_ROOT: inspectionFirstScanRoot,
      CODEX_SECURITY_STATE_DIR: undefined,
      FAKE_PYTHON_ALWAYS_FAIL: undefined,
      FAKE_PYTHON_FAILURE:
        "sqlite3.OperationalError: unable to open database file",
      FAKE_PYTHON_LOG: invocationLog,
      FAKE_PYTHON_PERSISTENT_SUCCESSES: "1",
      FAKE_REAL_PYTHON: realPython,
      PYTHON: fakePythonPath,
    });
    try {
      await initialize(inspectionFirstServer, 15);
      assertNoError(await inspectTarget(inspectionFirstServer, 16, targetPath));
      assertNoError(await openWorkspace(inspectionFirstServer, 17, targetPath));
      const fallbackStateDir = path.join(
        inspectionFirstScanRoot,
        "workbench-state",
      );
      const invocationStateDirs = (await readJsonLines(invocationLog)).map(
        (entry) => entry.stateDir,
      );
      assert.deepEqual(invocationStateDirs.slice(0, 2), [null, null]);
      assert.equal(
        invocationStateDirs
          .slice(2)
          .every((stateDir) => stateDir === fallbackStateDir),
        true,
      );
      assert.ok(invocationStateDirs.length > 2);
      const fallbackEvents = inspectionFirstServer
        .stderrEvents()
        .filter((event) => event.event === "state_fallback_pinned");
      assert.equal(fallbackEvents.length, 1);
      assert.equal(await pathExists(fallbackStateDir), true);
    } finally {
      await inspectionFirstServer.stop();
    }

    await writeFile(invocationLog, "");
    const provenScanRoot = path.join(fixtureRoot, "proven-scans");
    const provenServer = startServer(serverBundlePath, {
      CODEX_HOME: path.join(fixtureRoot, "proven-codex-home"),
      CODEX_SECURITY_SCAN_ROOT: provenScanRoot,
      CODEX_SECURITY_STATE_DIR: undefined,
      FAKE_PYTHON_ALWAYS_FAIL: undefined,
      FAKE_PYTHON_FAILURE:
        "sqlite3.OperationalError: unable to open database file",
      FAKE_PYTHON_LOG: invocationLog,
      FAKE_PYTHON_PERSISTENT_SUCCESSES: "1",
      FAKE_REAL_PYTHON: realPython,
      PYTHON: fakePythonPath,
    });
    try {
      await initialize(provenServer, 18);
      assertNoError(
        await openWorkspace(provenServer, 19, targetPath, "proven-thread-1"),
      );
      assertToolError(
        await openWorkspace(provenServer, 20, targetPath, "proven-thread-2"),
        /unable to open database file/,
      );
      assert.deepEqual(
        (await readJsonLines(invocationLog)).map((entry) => entry.stateDir),
        [null, null],
      );
      assert.equal(
        provenServer
          .stderrEvents()
          .some((event) => event.event === "state_fallback_pinned"),
        false,
      );
      assert.equal(
        await pathExists(path.join(provenScanRoot, "workbench-state")),
        false,
      );
    } finally {
      await provenServer.stop();
    }

    await writeFile(invocationLog, "");
    const genericScanRoot = path.join(fixtureRoot, "generic-scans");
    const genericServer = startServer(serverBundlePath, {
      CODEX_SECURITY_SCAN_ROOT: genericScanRoot,
      CODEX_SECURITY_STATE_DIR: undefined,
      FAKE_PYTHON_ALWAYS_FAIL: "1",
      FAKE_PYTHON_FAILURE:
        "sqlite3.OperationalError: database disk image is malformed",
      FAKE_PYTHON_LOG: invocationLog,
      FAKE_REAL_PYTHON: realPython,
      PYTHON: fakePythonPath,
    });
    try {
      await initialize(genericServer, 20);
      assertToolError(
        await inspectTarget(genericServer, 21, targetPath),
        /database disk image is malformed/,
      );
      assert.deepEqual(
        (await readJsonLines(invocationLog)).map((entry) => entry.stateDir),
        [null],
      );
      assert.equal(
        genericServer
          .stderrEvents()
          .some((event) => event.event === "state_fallback_pinned"),
        false,
      );
    } finally {
      await genericServer.stop();
    }
  } finally {
    await rm(serverBundlePath, { force: true });
    await rm(fixtureRoot, { recursive: true, force: true });
  }
}

async function writeFakePython(executablePath: string) {
  await writeFile(
    executablePath,
    [
      "#!/usr/bin/env node",
      'import { appendFileSync, readFileSync } from "node:fs";',
      'import { spawnSync } from "node:child_process";',
      // Root resolution does not open SQLite and must bypass the injected database failure.
      "if (process.argv[3] !== 'resolve-scan-root') {",
      "let priorInvocations = 0;",
      "try { priorInvocations = readFileSync(process.env.FAKE_PYTHON_LOG, 'utf8').split(/\\r?\\n/).filter(Boolean).length; } catch {}",
      "appendFileSync(process.env.FAKE_PYTHON_LOG, JSON.stringify({ stateDir: process.env.CODEX_SECURITY_STATE_DIR || null }) + '\\n');",
      "const persistentSuccesses = Number(process.env.FAKE_PYTHON_PERSISTENT_SUCCESSES || 0);",
      "if (process.env.FAKE_PYTHON_ALWAYS_FAIL === '1' || (!process.env.CODEX_SECURITY_STATE_DIR && priorInvocations >= persistentSuccesses)) {",
      "  console.error(process.env.FAKE_PYTHON_FAILURE || 'sqlite3.OperationalError: unable to open database file');",
      "  process.exit(1);",
      "}",
      "}",
      "const result = spawnSync(process.env.FAKE_REAL_PYTHON, process.argv.slice(2), { env: process.env, stdio: 'inherit' });",
      "process.exit(result.status ?? 1);",
      "",
    ].join("\n"),
  );
  await chmod(executablePath, 0o755);
}

function startServer(serverPath: string, env: NodeJS.ProcessEnv) {
  return startRpcServer(
    {
      command: process.execPath,
      args: [serverPath, "--stdio"],
      cwd: path.dirname(path.dirname(serverPath)),
      env: { ...process.env, ...env },
      stderr: "pipe",
    },
    { component: "codex_security_workbench", timeoutMs: 15_000 },
  );
}

async function initialize(server: ReturnType<typeof startServer>, id: number) {
  const response = await server.request(id, "initialize", {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "workbench-state-fallback", version: "0.1.0" },
  });
  assertNoError(response);
}

function inspectTarget(
  server: ReturnType<typeof startServer>,
  id: number,
  targetPath: string,
) {
  return server.request(id, "tools/call", {
    name: "inspect_codex_security_target",
    arguments: { targetPath },
  });
}

function startPromptOnlyScan(
  server: ReturnType<typeof startServer>,
  id: number,
  targetPath: string,
) {
  return server.request(id, "tools/call", {
    name: "start_codex_security_prompt_only_scan",
    arguments: { mode: "standard", scope: ".", targetPath },
    _meta: { "openai/threadId": "state-fallback-prompt-only-thread" },
  });
}

function submitSetup(
  server: ReturnType<typeof startServer>,
  id: number,
  sessionId: string,
  targetPath: string,
) {
  return server.request(id, "tools/call", {
    name: "submit_codex_security_setup",
    arguments: { sessionId, targetPath, scope: ".", mode: "standard" },
  });
}

function startScan(
  server: ReturnType<typeof startServer>,
  id: number,
  sessionId: string,
) {
  return server.request(id, "tools/call", {
    name: "start_codex_security_scan",
    arguments: { sessionId },
  });
}

function openWorkspace(
  server: ReturnType<typeof startServer>,
  id: number,
  targetPath: string,
  threadId = "state-fallback-thread",
) {
  return server.request(id, "tools/call", {
    name: "open_codex_security_workspace",
    arguments: { targetPath, scope: ".", mode: "standard" },
    _meta: { "openai/threadId": threadId },
  });
}

function reopenWorkspace(
  server: ReturnType<typeof startServer>,
  id: number,
  sessionId: string,
  threadId = "state-fallback-thread",
) {
  return server.request(id, "tools/call", {
    name: "open_codex_security_workspace",
    arguments: { sessionId },
    _meta: { "openai/threadId": threadId },
  });
}

function assertToolError(
  response: {
    error?: unknown;
    result: { isError?: boolean; content: { text: string }[] };
  },
  pattern: RegExp,
) {
  assert.equal(response.error, undefined);
  assert.equal(response.result?.isError, true);
  assert.match(
    response.result.content.map((item) => item.text).join(" "),
    pattern,
  );
}

async function pathExists(filePath: string) {
  try {
    await stat(filePath);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return false;
    throw error;
  }
}
