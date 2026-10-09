import { assertNoError } from "./assertions.ts";
import {
  WORKBENCH_PYTHON,
  WORKBENCH_STATE_UNAVAILABLE_EXIT_CODE,
} from "../src/server/workbench-process.ts";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
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
  await buildServer(serverBundlePath, { target: "node20" });

  try {
    if (process.getuid?.() !== 0) {
      for (const firstOperation of [
        "scan",
        "standalone",
        "fresh-home",
        "inspection",
      ]) {
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
        const lockedDirectory =
          firstOperation === "fresh-home" ? codexHome : defaultState;
        await mkdir(lockedDirectory, { recursive: true });
        await chmod(lockedDirectory, 0o500);
        const environment = {
          ...process.env,
          CODEX_HOME: codexHome,
          CODEX_SECURITY_STATE_DIR: undefined,
        };
        const direct = spawnSync(
          realPython,
          [path.join(pluginRoot, "scripts/workbench_db.py"), "database-info"],
          { env: environment, encoding: "utf8" },
        );
        const wrapped = spawnSync(
          realPython,
          [
            "-c",
            WORKBENCH_PYTHON,
            path.join(pluginRoot, "scripts/workbench_db.py"),
          ],
          { env: environment, encoding: "utf8", input: '["database-info"]\n' },
        );
        assert.equal(direct.status, 1);
        assert.equal(wrapped.status, WORKBENCH_STATE_UNAVAILABLE_EXIT_CODE);
        assert.equal(
          wrapped.stderr.trim().split("\n").at(-1),
          direct.stderr.trim().split("\n").at(-1),
        );
        const server = startServer(serverBundlePath, {
          CODEX_HOME: codexHome,
          CODEX_SECURITY_SCAN_ROOT: undefined,
          CODEX_SECURITY_STATE_DIR: undefined,
          PYTHON: realPython,
        });
        let fallbackState;
        try {
          await initialize(server, 1);
          if (firstOperation === "inspection")
            assertNoError(await inspectTarget(server, 2, targetPath));
          if (firstOperation === "fresh-home") {
            const opened = await Promise.all([
              openWorkspace(server, 20, targetPath, "first-thread"),
              openWorkspace(server, 21, targetPath, "second-thread"),
            ]);
            opened.forEach(assertNoError);
          }
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
          await chmod(lockedDirectory, 0o700);
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

    for (const [index, name] of [
      "ordinary-missing",
      "WorkbenchStateDirectoryError:missing",
      "newline\nWorkbenchStateDirectoryError: [Errno 13] Permission denied: state",
      "sqlite3.OperationalError: unable to open database file",
    ].entries()) {
      const codexHome = path.join(fixtureRoot, `collision-${index}`);
      const scanRoot = path.join(fixtureRoot, `collision-scans-${index}`);
      const server = startServer(serverBundlePath, {
        CODEX_HOME: codexHome,
        CODEX_SECURITY_STATE_DIR: undefined,
        CODEX_SECURITY_SCAN_ROOT: scanRoot,
        PYTHON: realPython,
      });
      try {
        await initialize(server, 1);
        const missing = path.join(fixtureRoot, name);
        const failure = await startPromptOnlyScan(server, 2, missing);
        assertToolError(
          failure,
          /Scan target is not a readable local directory/,
        );
        assert.ok(failure.result.content[0].text.includes(missing));
        assertNoError(await openWorkspace(server, 3, targetPath));
        assert.equal(server.stderrEvents().length, 0);
        assert.equal(
          await pathExists(path.join(scanRoot, "workbench-state")),
          false,
        );
        assert.equal(
          await pathExists(
            path.join(
              codexHome,
              "state/plugins/codex-security/workbench.sqlite3",
            ),
          ),
          true,
        );
      } finally {
        await server.stop();
      }
    }

    for (const scenario of [
      "explicit",
      "explicit-open",
      "proven",
      "proven-open",
      "malformed",
    ]) {
      if (scenario !== "malformed" && process.getuid?.() === 0) continue;
      const codexHome = path.join(fixtureRoot, `${scenario}-home`);
      const stateDir = path.join(codexHome, "state/plugins/codex-security");
      const scanRoot = path.join(fixtureRoot, `${scenario}-scans`);
      await mkdir(stateDir, { recursive: true });
      const server = startServer(serverBundlePath, {
        CODEX_HOME: codexHome,
        CODEX_SECURITY_STATE_DIR:
          scenario === "explicit"
            ? path.join(stateDir, "explicit-state")
            : scenario === "explicit-open"
              ? stateDir
              : undefined,
        CODEX_SECURITY_SCAN_ROOT: scanRoot,
        PYTHON: realPython,
      });
      try {
        await initialize(server, 1);
        if (scenario.startsWith("proven"))
          assertNoError(await openWorkspace(server, 2, targetPath));
        if (scenario === "malformed")
          await writeFile(
            path.join(stateDir, "workbench.sqlite3"),
            "not a database",
          );
        else await chmod(stateDir, 0o500);
        if (scenario === "proven-open")
          await chmod(path.join(stateDir, "workbench.sqlite3"), 0o000);
        assertToolError(
          await openWorkspace(server, 3, targetPath, "next-thread"),
          /Permission denied|readonly|read-only|not a database|unable to open database file/,
        );
        assert.equal(server.stderrEvents().length, 0);
        assert.equal(
          await pathExists(path.join(scanRoot, "workbench-state")),
          false,
        );
      } finally {
        await server.stop();
        await chmod(stateDir, 0o700);
      }
    }

    const script = path.join(pluginRoot, "scripts/workbench_db.py");
    for (const args of [
      ["--help"],
      ["create-workspace", "--help"],
      ["resolve-scan-root"],
      ["database-info"],
      ["inspect-target", "--target-path", path.join(fixtureRoot, "missing")],
    ]) {
      const env = {
        ...process.env,
        CODEX_SECURITY_STATE_DIR: path.join(fixtureRoot, "parity-state"),
        PYTHONSAFEPATH: "1",
        PYTHONIOENCODING: "ascii",
      };
      const direct = spawnSync(realPython, [script, ...args], {
        env,
        encoding: "utf8",
      });
      const wrapped = spawnSync(realPython, ["-c", WORKBENCH_PYTHON, script], {
        env,
        encoding: "utf8",
        input: `${JSON.stringify(args)}\n`,
      });
      assert.deepEqual(
        [wrapped.status, wrapped.stdout, wrapped.stderr],
        [direct.status, direct.stdout, direct.stderr],
      );
    }
  } finally {
    await rm(serverBundlePath, { force: true });
    await rm(fixtureRoot, { recursive: true, force: true });
  }
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
