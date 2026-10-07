import { temporaryDirectory } from "./support/temporary-directories.ts";
import { readJson, writeJson } from "./support/json.ts";
import { gitText } from "../scripts/git.mjs";
import { assertNoError } from "./assertions.ts";
import { consumeStreamLines, writeMessage } from "./support/streams.ts";
import { readOnlyParentSandboxState } from "./sandbox-state.ts";
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { hash, randomUUID } from "node:crypto";
import {
  chmod,
  mkdir,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

const continuationOptions = [
  {
    label: "Continue",
    description: "Continue the current workflow.",
  },
  {
    label: "Cancel",
    description: "Leave the current workflow paused.",
  },
];

const sourcePluginRoot = path.resolve(import.meta.dirname, "../..");
const pluginRoot = process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT
  ? path.resolve(process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT)
  : path.resolve(sourcePluginRoot, "../../sdk/typescript/_bundled_plugin");
const mcpAppRoot = path.join(sourcePluginRoot, "mcp-app");
const pluginManifest = await readJson(
  pluginRoot,
  ".codex-plugin",
  "plugin.json",
);
const PLUGIN_VERSION = pluginManifest.version;
assert.equal(typeof PLUGIN_VERSION, "string");
const parentSandboxState = readOnlyParentSandboxState(pluginRoot);
const serverPath = path.join(pluginRoot, "mcp", "server.mjs");
const mcpConfig = await readJson(pluginRoot, ".mcp.json");
assert.equal(
  mcpConfig.mcpServers["codex-security"].command,
  "./scripts/launch_codex_security_mcp",
);
assert.deepEqual(mcpConfig.mcpServers["codex-security"].args, ["--stdio"]);
assert.equal(mcpConfig.mcpServers["codex-security"].tool_timeout_sec, 349_200);
assert.deepEqual(
  mcpConfig.mcpServers["codex-security"].env_vars,
  [
    "CODEX_HOME",
    "CODEX_SQLITE_HOME",
    "CODEX_API_KEY",
    "CODEX_SAFETY_IDENTIFIER",
    "CODEX_BROWSER_USE_NODE_PATH",
    "CODEX_CLI_PATH",
    "CODEX_ELECTRON_RESOURCES_PATH",
    "CODEX_MANAGED_PACKAGE_ROOT",
    "CODEX_MCP_NODE_PATH",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "FIREWORKS_API_KEY",
    "AWS_BEARER_TOKEN_BEDROCK",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_ROLE_ARN",
    "AWS_ROLE_SESSION_NAME",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "PYTHON",
    "PYTHONUTF8",
    "CODEX_SECURITY_GIT",
    "CODEX_SECURITY_KNOWLEDGE_BASE",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    "CODEX_SECURITY_SCAN_ROOT",
    "CODEX_SECURITY_STATE_DIR",
    "CODEX_SECURITY_SURFACE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "XDG_CACHE_HOME",
  ],
  "The MCP process and SDK workers must inherit Codex, external-provider, and Bedrock authentication, AWS credential-chain settings, runtime paths, and enterprise proxy/certificate configuration.",
);
const serverSource = await readFile(path.join(mcpAppRoot, "server.ts"), "utf8");
assert.match(
  serverSource,
  /timeout:\s*\[[^\]]*"start-prompt-only-scan"[^\]]*\]\.includes\(args\[0\] \?\? ""\)\s*\?\s*300_000\s*:\s*30_000/,
  "Prompt-only scan startup must use the same five-minute timeout as other scan starts.",
);
const authenticatedArtifactClaimSource = serverSource.match(
  /if \(\s*handoffClaimToken\s*&&\s*threadId[\s\S]*?authenticatedArtifactClaims\.set\(scanId,[\s\S]*?\n\s*\}/,
)?.[0];
assert.ok(
  authenticatedArtifactClaimSource,
  "Expected artifact claim authentication to require a handoff token and trusted request thread.",
);
assert.match(
  authenticatedArtifactClaimSource,
  /scan\?\.handoffStatus === "delivered"/,
  "Artifact claims must be cached only after durable handoff delivery.",
);
assert.match(
  authenticatedArtifactClaimSource,
  /scan\.handoffClaimToken === handoffClaimToken/,
  "Artifact claims must match the current persisted handoff token exactly.",
);
assert.match(
  authenticatedArtifactClaimSource,
  /scan\.continuationThreadId === threadId/,
  "Ordinary artifact claims must remain bound to the owning Codex thread.",
);
assert.match(
  authenticatedArtifactClaimSource,
  /recoveryHandoffClaimTokenSchema\.safeParse\(handoffClaimToken\)\.success/,
  "Cross-thread artifact recovery must require an exact recovery-token schema match.",
);
assert.match(
  serverSource,
  /throw new Error\(error\.stderr\.trim\(\),\s*\{\s*cause:\s*error\s*\}\)/,
  "Workbench failures must preserve subprocess exit, signal, and stderr diagnostics.",
);
const target = await temporaryDirectory("codex-security-target-");
const replacementTarget = await temporaryDirectory(
  "codex-security-replacement-",
);
const gitTarget = await temporaryDirectory("codex-security-git-target-");
const stateDir = path.join(tmpdir(), randomUUID());
const scanRoot = await temporaryDirectory("codex-security-scan-root-");
const resolvedScanRoot = await realpath(scanRoot);
const launchCwd = await temporaryDirectory("codex-security-launch-cwd-");
await mkdir(path.join(target, "src"));
await writeFile(path.join(target, "src/a.py"), "vulnerable\n");
execFileSync("git", ["init", "-q", gitTarget]);
await writeFile(path.join(gitTarget, "fixture.txt"), "fixture\n");
execFileSync("git", ["-C", gitTarget, "add", "fixture.txt"]);
execFileSync("git", [
  "-C",
  gitTarget,
  "-c",
  "user.name=Fixture",
  "-c",
  "user.email=fixture@example.com",
  "commit",
  "-qm",
  "fixture",
]);
const gitBase = gitText(["-C", gitTarget, "rev-parse", "HEAD"]).trim();
await writeFile(path.join(gitTarget, "fixture.txt"), "fixture\nupdated\n");
execFileSync("git", ["-C", gitTarget, "add", "fixture.txt"]);
execFileSync("git", [
  "-C",
  gitTarget,
  "-c",
  "user.name=Fixture",
  "-c",
  "user.email=fixture@example.com",
  "commit",
  "-qm",
  "update fixture",
]);
const gitHead = gitText(["-C", gitTarget, "rev-parse", "HEAD"]).trim();

function startTestServer({
  args = [serverPath, "--stdio"],
  command = process.execPath,
  cwd,
  env = {},
}: {
  args?: string[];
  command?: string;
  cwd: string;
  env?: NodeJS.ProcessEnv;
}) {
  const childEnvironment = { ...process.env, ...env };
  for (const [name, value] of Object.entries(env)) {
    if (value === undefined) {
      delete childEnvironment[name];
    }
  }
  const childProcess = spawn(command, args, {
    cwd,
    env: childEnvironment,
    stdio: ["pipe", "pipe", "inherit"],
  });
  const responses: ReturnType<typeof JSON.parse>[] = [];
  consumeStreamLines(childProcess.stdout, (line) =>
    responses.push(JSON.parse(line)),
  );

  return {
    notify(method: string, params = {}) {
      writeMessage(childProcess, { jsonrpc: "2.0", method, params });
    },
    sendRequest(id: number, method: string, params = {}) {
      writeMessage(childProcess, { jsonrpc: "2.0", id, method, params });
    },
    sendResponse(id: string, result: unknown) {
      writeMessage(childProcess, { jsonrpc: "2.0", id, result });
    },
    sendError(id: string, code: number, message: string) {
      writeMessage(childProcess, {
        jsonrpc: "2.0",
        id,
        error: { code, message },
      });
    },
    async waitForMessage(
      predicate: (message: ReturnType<typeof JSON.parse>) => boolean,
      description = "matching JSON-RPC message",
    ) {
      const started = Date.now();
      while (Date.now() - started < 30000) {
        const message = responses.find(predicate);
        if (message) return message;
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      throw new Error(`Timed out waiting for ${description}`);
    },
    initialize(name: string, capabilities: Record<string, unknown> = {}) {
      return this.requestAndWait(1, "initialize", {
        protocolVersion: "2025-11-25",
        capabilities,
        clientInfo: { name, version: "0.1.0" },
      });
    },
    callTool(id: number, params: Record<string, unknown>) {
      return this.requestAndWait(id, "tools/call", params);
    },
    async requestAndWait(id: number, method: string, params = {}) {
      writeMessage(childProcess, { jsonrpc: "2.0", id, method, params });
      const started = Date.now();
      while (Date.now() - started < 30000) {
        const response = responses.find((candidate) => candidate.id === id);
        if (response) return response;
        if (childProcess.exitCode !== null) {
          throw new Error(
            `MCP server exited with code ${childProcess.exitCode} while waiting for JSON-RPC response ${id}`,
          );
        }
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      throw new Error(`Timed out waiting for JSON-RPC response ${id}`);
    },
    async stop() {
      if (childProcess.exitCode != null || childProcess.signalCode != null) {
        return;
      }
      const closed = new Promise((resolve) => {
        childProcess.once("close", resolve);
      });
      childProcess.stdin.end();
      childProcess.kill();
      await closed;
    },
  };
}

const testServer = startTestServer({
  cwd: launchCwd,
  env: {
    CODEX_SECURITY_SCAN_ROOT: undefined,
    CODEX_SECURITY_STATE_DIR: stateDir,
    TEMP: scanRoot,
    TMP: scanRoot,
    TMPDIR: scanRoot,
  },
});
const requestAndWait = testServer.requestAndWait;

async function assertBundledNodeLauncher() {
  const emptyPath = await temporaryDirectory("codex-security-empty-path-");
  const launcherPath = path.join(
    pluginRoot,
    "scripts",
    "launch_codex_security_mcp",
  );
  const windows = process.platform === "win32";
  if (!windows) {
    const bundledNodePath = path.join(
      emptyPath,
      "codex-runtimes/codex-primary-runtime/dependencies/node/bin/node",
    );
    await mkdir(path.dirname(bundledNodePath), { recursive: true });
    await writeFile(
      bundledNodePath,
      `#!/bin/sh\nprintf bundled > ${JSON.stringify(path.join(emptyPath, "bundled-node-used"))}\nexec ${JSON.stringify(process.execPath)} "$@"\n`,
      { mode: 0o755 },
    );
  }
  const bundledNodeServer = startTestServer({
    args: windows
      ? ["/d", "/s", "/c", "call", `${launcherPath}.cmd`, "--stdio"]
      : ["--stdio"],
    command: windows
      ? (process.env.ComSpec ??
        path.join(
          process.env.SystemRoot ?? "C:\\Windows",
          "System32",
          "cmd.exe",
        ))
      : launcherPath,
    cwd: emptyPath,
    env: {
      CODEX_BROWSER_USE_NODE_PATH: undefined,
      CODEX_CLI_PATH: undefined,
      CODEX_ELECTRON_RESOURCES_PATH: undefined,
      CODEX_MCP_NODE_PATH: windows ? process.execPath : undefined,
      CODEX_SECURITY_STATE_DIR: stateDir,
      PATH: emptyPath,
      XDG_CACHE_HOME: emptyPath,
    },
  });
  try {
    assertNoError(
      await bundledNodeServer.initialize("codex-security-bundled-node-smoke"),
    );
    assertNoError(await bundledNodeServer.requestAndWait(2, "tools/list"));
    if (!windows) {
      assert.equal(
        await readFile(path.join(emptyPath, "bundled-node-used"), "utf8"),
        "bundled",
      );
    }
  } finally {
    bundledNodeServer.stop();
    await rm(emptyPath, { recursive: true, force: true });
  }
}

async function assertMissingPythonError() {
  const missingPythonServer = startTestServer({
    cwd: pluginRoot,
    env: {
      CODEX_SECURITY_STATE_DIR: stateDir,
      PYTHON: path.join(
        tmpdir(),
        `codex-security-missing-python-${randomUUID()}`,
      ),
    },
  });
  try {
    assertNoError(
      await missingPythonServer.initialize(
        "codex-security-missing-python-smoke",
      ),
    );
    const response = await missingPythonServer.callTool(2, {
      name: "inspect_codex_security_target",
      arguments: { targetPath: target },
    });
    assert.equal(response.result.isError, true);
    const errorText = response.result.content
      .map((item: { text: string }) => item.text)
      .join(" ");
    assert.match(errorText, /could not start its Python 3 helper/);
    assert.match(errorText, /bundled Python runtime/);
    assert.match(errorText, /set the PYTHON environment variable/);
    assert.doesNotMatch(
      errorText,
      /ENOENT|spawn .*codex-security-missing-python/,
    );
  } finally {
    await missingPythonServer.stop();
  }
}

async function assertWorkbenchStdinFailureDoesNotCrashServer() {
  if (process.platform === "win32") return;
  const helperRoot = await temporaryDirectory(
    "codex-security-early-exit-helper-",
  );
  const helper = path.join(helperRoot, "python");
  await writeFile(helper, "#!/bin/sh\nexit 2\n");
  await chmod(helper, 0o755);
  const server = startTestServer({
    cwd: pluginRoot,
    env: { CODEX_SECURITY_STATE_DIR: stateDir, PYTHON: helper },
  });
  try {
    assertNoError(await server.initialize("codex-security-early-exit-smoke"));
    const response = await server.callTool(2, {
      name: "update_codex_security_scan_context",
      arguments: {
        scanId: randomUUID(),
        userContext: "x".repeat(2 * 1024 * 1024),
      },
      _meta: { "openai/threadId": "fixture-thread" },
    });
    assert.equal(response.result.isError, true);
    assertNoError(await server.requestAndWait(3, "tools/list"));
  } finally {
    server.stop();
    await rm(helperRoot, { recursive: true, force: true });
  }
}

async function assertUnavailableUserInputFallback() {
  const noElicitationServer = startTestServer({
    cwd: pluginRoot,
    env: { CODEX_SECURITY_STATE_DIR: stateDir },
  });
  try {
    assertNoError(
      await noElicitationServer.initialize(
        "codex-security-no-elicitation-smoke",
      ),
    );
    const response = await noElicitationServer.callTool(2, {
      name: "request_codex_security_user_input",
      arguments: {
        questions: [
          {
            header: "Continue?",
            id: "continue_scan",
            question: "Should Codex Security continue?",
            options: continuationOptions,
          },
        ],
      },
    });
    assertNoError(response);
    assert.deepEqual(response.result.structuredContent, {
      status: "unavailable",
    });
  } finally {
    await noElicitationServer.stop();
  }
}

async function assertWorkspaceWorksWithoutUiCapability() {
  const nonUiStateDir = path.join(tmpdir(), randomUUID());
  const nonUiServer = startTestServer({
    cwd: pluginRoot,
    env: { CODEX_SECURITY_STATE_DIR: nonUiStateDir },
  });
  try {
    assertNoError(await nonUiServer.initialize("codex-security-non-ui-smoke"));
    const response = await nonUiServer.callTool(2, {
      name: "open_codex_security_workspace",
      arguments: { targetPath: target, mode: "standard", scope: "." },
      _meta: { "openai/threadId": "fixture-non-ui-thread" },
    });
    assertNoError(response);
    const workspace = response.result.structuredContent.workspace;
    assert.match(workspace.id, /^[0-9a-f-]{36}$/);
    assert.equal(workspace.targetPath, await realpath(target));
    assert.equal(workspace.mode, "standard");
    assert.equal(workspace.scope, ".");
    assert.equal(workspace.setup.submitted, false);
    assert.ok(
      (await readFile(path.join(nonUiStateDir, "workbench.sqlite3"))).length >
        0,
    );
  } finally {
    await nonUiServer.stop();
    await rm(nonUiStateDir, { recursive: true, force: true });
  }
}

async function assertHeadlessStandardScanWorksWithoutUiCapability() {
  const headlessStateDir = path.join(tmpdir(), randomUUID());
  const headlessScanRoot = path.join(tmpdir(), randomUUID());
  const headlessServer = startTestServer({
    cwd: pluginRoot,
    env: {
      CODEX_SECURITY_SCAN_ROOT: headlessScanRoot,
      CODEX_SECURITY_STATE_DIR: headlessStateDir,
    },
  });
  const ownerThread = "fixture-headless-standard-thread";
  const headlessContext =
    `Review https://example.test/internal. ${"Assess the HTTP boundary. ".repeat(44_000)}`.trim();
  assert.ok(headlessContext.length > 1_000_000);
  try {
    assertNoError(
      await headlessServer.initialize("codex-security-headless-smoke"),
    );
    const withoutOwner = await headlessServer.callTool(2, {
      name: "start_codex_security_standard_scan",
      arguments: { targetPath: target },
    });
    assert.equal(withoutOwner.result.isError, true);
    assert.match(
      withoutOwner.result.content[0].text,
      /owning Codex thread context/,
    );

    const started = await headlessServer.callTool(3, {
      name: "start_codex_security_standard_scan",
      arguments: {
        targetPath: target,
        userContext: headlessContext,
      },
      _meta: {
        "openai/threadId": ownerThread,
        "x-codex-turn-metadata": {
          model: "gpt-5.6-sol",
          reasoning_effort: "high",
        },
      },
    });
    assertNoError(started);
    assert.equal(started.result._meta, undefined);
    const result = started.result.structuredContent;
    assert.equal(result.startDisposition, "created");
    assert.match(result.scanId, /^[0-9a-f-]{36}$/);
    assert.match(result.handoffClaimToken, /^[0-9a-f-]{36}$/);
    assert.equal(result.scan.scanId, result.scanId);
    assert.equal(result.scan.scanDir, result.scanDir);
    assert.equal(result.scan.handoffClaimToken, undefined);
    assert.equal(result.workspace.results.handoffClaimToken, undefined);
    assert.equal(result.scan.continuationThreadId, ownerThread);
    assert.equal(result.scan.progress.phase, "preflight");
    assert.equal(result.scan.progress.status, "running");
    assert.equal(result.scan.model, "gpt-5.6-sol");
    assert.equal(result.scan.reasoningEffort, "high");
    assert.equal(result.scan.userContext, headlessContext);
    assert.equal(result.workspace.userContext, headlessContext);

    const joined = await headlessServer.callTool(4, {
      name: "start_codex_security_standard_scan",
      arguments: {
        targetPath: target,
        userContext: headlessContext,
      },
      _meta: { "openai/threadId": ownerThread },
    });
    assertNoError(joined);
    assert.equal(joined.result.structuredContent.startDisposition, "joined");
    assert.equal(joined.result.structuredContent.scanId, result.scanId);
    assert.equal(
      joined.result.structuredContent.handoffClaimToken,
      result.handoffClaimToken,
    );

    const wrongThread = await headlessServer.callTool(6, {
      name: "list_codex_security_review_items",
      arguments: { scanId: result.scanId },
      _meta: { "openai/threadId": "fixture-headless-other-thread" },
    });
    assert.equal(wrongThread.result.isError, true);
    assert.match(
      wrongThread.result.content[0].text,
      /current continuation claim/,
    );

    const standardInventory = await headlessServer.callTool(7, {
      name: "list_codex_security_review_items",
      arguments: {
        scanId: result.scanId,
        handoffClaimToken: result.handoffClaimToken,
      },
      _meta: { "openai/threadId": "fixture-headless-delegated-thread" },
    });
    assert.equal(standardInventory.result.isError, true);
    assert.match(
      standardInventory.result.content[0].text,
      /only available for Deep or diff scans/,
    );

    const progressed = await headlessServer.callTool(8, {
      name: "update_codex_security_scan_progress",
      arguments: {
        scanId: result.scanId,
        handoffClaimToken: result.handoffClaimToken,
        preflightChecks: [],
      },
      _meta: { "openai/threadId": ownerThread },
    });
    assertNoError(progressed);

    const advanced = await headlessServer.callTool(81, {
      name: "update_codex_security_scan_progress",
      arguments: {
        scanId: result.scanId,
        handoffClaimToken: result.handoffClaimToken,
        phase: "threat_model",
      },
      _meta: { "openai/threadId": ownerThread },
    });
    assertNoError(advanced);
    const rejoinedAfterPreflight = await headlessServer.callTool(82, {
      name: "start_codex_security_standard_scan",
      arguments: {
        targetPath: target,
        userContext: headlessContext,
      },
      _meta: { "openai/threadId": ownerThread },
    });
    assertNoError(rejoinedAfterPreflight);
    assert.equal(
      rejoinedAfterPreflight.result.structuredContent.startDisposition,
      "joined",
    );
    assert.equal(
      rejoinedAfterPreflight.result.structuredContent.scan.progress.phase,
      "threat_model",
    );

    await writeCompletedContract(
      result.scanDir,
      result.scanId,
      result.scan.contract.target.requiredSnapshotDigest,
    );
    const completed = await headlessServer.callTool(9, {
      name: "complete_codex_security_scan",
      arguments: {
        scanId: result.scanId,
        handoffClaimToken: result.handoffClaimToken,
      },
      _meta: { "openai/threadId": ownerThread },
    });
    assertNoError(completed);
    assert.equal(
      completed.result.structuredContent.scan.progress.status,
      "complete",
    );
  } finally {
    await headlessServer.stop();
    await rm(headlessStateDir, { recursive: true, force: true });
    await rm(headlessScanRoot, { recursive: true, force: true });
  }
}

async function assertDeepScanPersistsRetryableWorkerStartupError() {
  const fixtureRoot = await temporaryDirectory(
    "codex-security-deep-inventory-",
  );
  const fixtureTarget = path.join(fixtureRoot, "repository");
  const fixtureState = path.join(fixtureRoot, "state");
  const fixtureScanRoot = path.join(fixtureRoot, "scans");
  await mkdir(path.join(fixtureTarget, "app"), { recursive: true });
  await writeFile(path.join(fixtureTarget, "app", "routes.py"), "route = 1\n");

  const fixtureEnvironment = {
    CODEX_CLI_PATH: path.join(fixtureRoot, "missing-deep-scan-codex"),
    CODEX_SECURITY_SCAN_ROOT: fixtureScanRoot,
    CODEX_SECURITY_STATE_DIR: fixtureState,
  };
  const deepServer = startTestServer({
    cwd: pluginRoot,
    env: fixtureEnvironment,
  });
  try {
    assertNoError(
      await deepServer.initialize("codex-security-deep-inventory-smoke"),
    );

    deepServer.sendRequest(2, "tools/call", {
      name: "start_codex_security_deep_scan",
      arguments: { targetPath: fixtureTarget },
      _meta: {
        "openai/threadId": "fixture-deep-inventory-thread",
        "codex/sandbox-state-meta": parentSandboxState,
      },
    });
    let scan;
    let startupErrorWorker;
    const pollingStarted = Date.now();
    for (
      let requestId = 100;
      Date.now() - pollingStarted < 30_000;
      requestId++
    ) {
      const listed = await deepServer.callTool(requestId, {
        name: "list_codex_security_scans",
        arguments: {},
      });
      assertNoError(listed);
      [scan] = listed.result.structuredContent.scans;
      if (scan) {
        assert.equal(listed.result.structuredContent.scans.length, 1);
        assert.equal(scan.progress.status, "running");
        const { deepScan } = JSON.parse(
          execFileSync(
            process.env.PYTHON?.trim() || "python3",
            [
              path.join(pluginRoot, "scripts", "workbench_db.py"),
              "get-deep-scan",
              "--scan-id",
              scan.scanId,
              "--thread-id",
              "fixture-deep-inventory-thread",
            ],
            {
              env: { ...process.env, ...fixtureEnvironment },
              encoding: "utf8",
            },
          ),
        );
        assert.equal(deepScan.status, "running");
        startupErrorWorker = deepScan.workers.find(
          (worker: { status: string; error?: string }) =>
            worker.error?.includes("missing-deep-scan-codex"),
        );
        if (startupErrorWorker) break;
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.ok(
      startupErrorWorker,
      "Expected a persisted retryable startup error",
    );
    assert.equal(startupErrorWorker.status, "running");

    const canceled = await deepServer.callTool(3, {
      name: "cancel_codex_security_scan",
      arguments: { scanId: scan.scanId },
      _meta: { "openai/threadId": "fixture-deep-inventory-thread" },
    });
    assertNoError(canceled);
    await deepServer.waitForMessage(
      (message) => message.id === 2,
      "Deep Scan start response after cancellation",
    );
    await assert.rejects(
      readFile(
        path.join(
          scan.scanDir,
          "artifacts",
          "02_discovery",
          "in_scope_files.txt",
        ),
      ),
      { code: "ENOENT" },
    );

    const publicationFailure =
      "Saved result publication failed: fixture retained result publication failure";
    execFileSync(process.env.PYTHON?.trim() || "python3", [
      "-c",
      `import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as connection:
    updated = connection.execute("UPDATE deep_scan_runs SET status = 'canceled', phase = 'terminal', cancel_requested = 1, error_message = ? WHERE scan_id = ?", (sys.argv[2], sys.argv[3]))
    assert updated.rowcount == 1`,
      path.join(fixtureState, "workbench.sqlite3"),
      publicationFailure,
      scan.scanId,
    ]);
    const canceledWithPublicationFailure = await deepServer.callTool(4, {
      name: "start_codex_security_deep_scan",
      arguments: { scanId: scan.scanId },
      _meta: {
        "openai/threadId": "fixture-deep-inventory-thread",
        "codex/sandbox-state-meta": parentSandboxState,
      },
    });
    const publicationFailureText = canceledWithPublicationFailure.result.content
      .map((item: { text: string }) => item.text)
      .join(" ");
    assert.equal(canceledWithPublicationFailure.result.isError, true);
    assert.equal(
      canceledWithPublicationFailure.result.structuredContent,
      undefined,
    );
    assert.match(
      publicationFailureText,
      /fixture retained result publication failure/,
    );
  } finally {
    await deepServer.stop();
    await rm(fixtureRoot, { recursive: true, force: true });
  }
}

async function assertUserInputFailureLogging() {
  const failingElicitationServer = startTestServer({
    cwd: pluginRoot,
    env: { CODEX_SECURITY_STATE_DIR: stateDir },
  });
  try {
    assertNoError(
      await failingElicitationServer.initialize(
        "codex-security-failing-elicitation-smoke",
        { elicitation: { form: {} } },
      ),
    );
    failingElicitationServer.sendRequest(2, "tools/call", {
      name: "request_codex_security_user_input",
      arguments: {
        questions: [
          {
            header: "Continue?",
            id: "continue_scan",
            question: "Should Codex Security continue?",
            options: continuationOptions,
          },
        ],
      },
    });
    const elicitationRequest = await failingElicitationServer.waitForMessage(
      (message) => message.method === "elicitation/create",
      "failing Codex Security elicitation request",
    );
    failingElicitationServer.sendError(
      elicitationRequest.id,
      -32603,
      "Fixture elicitation failure",
    );
    const logMessage = await failingElicitationServer.waitForMessage(
      (message) => message.method === "notifications/message",
      "Codex Security elicitation failure log",
    );
    assert.equal(logMessage.params.level, "warning");
    assert.equal(logMessage.params.logger, "codex-security.user-input");
    assert.equal(logMessage.params.data.event, "elicitation_failed");
    assert.match(
      logMessage.params.data.error.message,
      /Fixture elicitation failure/,
    );
    assert.equal(logMessage.params.data.error.stack, undefined);
    assert.doesNotMatch(
      JSON.stringify(logMessage.params.data),
      /Should Codex Security continue/,
    );

    const response = await failingElicitationServer.waitForMessage(
      (message) => message.id === 2,
      "Codex Security unavailable response after elicitation failure",
    );
    assertNoError(response);
    assert.deepEqual(response.result.structuredContent, {
      status: "unavailable",
    });
  } finally {
    await failingElicitationServer.stop();
  }
}

async function assertBundledPythonRuntime() {
  if (process.platform === "win32") return;

  const runtimeHome = await temporaryDirectory("codex-security-runtime-home-");
  const bundledPythonPath = path.join(
    runtimeHome,
    ".cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3",
  );
  const launchMarkerPath = path.join(runtimeHome, "bundled-python-launched");
  const systemPythonPath = execFileSync(
    process.env.PYTHON?.trim() || "python3",
    ["-c", "import sys; print(sys.executable)"],
    { encoding: "utf8" },
  ).trim();

  const bundledPythonServer = startTestServer({
    cwd: pluginRoot,
    env: {
      CODEX_SECURITY_BUNDLED_PYTHON_MARKER: launchMarkerPath,
      CODEX_SECURITY_STATE_DIR: stateDir,
      CODEX_SECURITY_TEST_SYSTEM_PYTHON: systemPythonPath,
      HOME: runtimeHome,
      PYTHON: undefined,
    },
  });
  try {
    assertNoError(
      await bundledPythonServer.initialize(
        "codex-security-bundled-python-smoke",
      ),
    );
    // Codex can install the primary runtime after the MCP server has started.
    // Creating this wrapper after initialization verifies call-time discovery.
    await mkdir(path.dirname(bundledPythonPath), { recursive: true });
    await writeFile(
      bundledPythonPath,
      `#!/bin/sh
printf bundled > "$CODEX_SECURITY_BUNDLED_PYTHON_MARKER"
exec "$CODEX_SECURITY_TEST_SYSTEM_PYTHON" "$@"
`,
      { mode: 0o755 },
    );
    assertNoError(
      await bundledPythonServer.callTool(2, {
        name: "inspect_codex_security_target",
        arguments: { targetPath: target },
      }),
    );
    assert.equal(await readFile(launchMarkerPath, "utf8"), "bundled");
  } finally {
    await bundledPythonServer.stop();
    await rm(runtimeHome, { recursive: true, force: true });
  }
}

async function writeCompletedContract(
  scanDir: string,
  scanId: string,
  snapshotDigest: string,
) {
  const targetId = `target_sha256_${hash("sha256", `local-workspace\0${await realpath(target)}`)}`;
  await writeJson(path.join(scanDir, "findings.json"), {
    documentType: "codex-security.findings",
    schemaVersion: "1.0",
    scanId,
    findings: [
      {
        ruleId: "path-traversal.archive-extraction",
        identity: { anchor: "archive-entry-write-without-containment" },
        title: "Fixture finding",
        summary: "An attacker-controlled path reaches a filesystem write.",
        severity: { level: "high" },
        confidence: { level: "high", rationale: "Direct source trace." },
        taxonomy: { category: "path-traversal", cwe: ["CWE-22"] },
        locations: [{ path: "src/a.py", startLine: 1 }],
        remediation: "Reject archive entries that escape the extraction root.",
        provenance: { source: "local_plugin" },
      },
      {
        ruleId: "fixture.informational",
        identity: { anchor: "informational-observation" },
        title: "Fixture informational observation",
        summary: "A low-risk implementation detail is worth recording.",
        severity: { level: "informational" },
        confidence: { level: "high", rationale: "Direct source inspection." },
        taxonomy: { category: "hardening", cwe: [] },
        locations: [{ path: "src/info.py", startLine: 2 }],
        remediation: "Consider hardening this implementation detail.",
        provenance: { source: "local_plugin" },
      },
    ],
  });
  await writeJson(path.join(scanDir, "coverage.json"), {
    documentType: "codex-security.coverage",
    schemaVersion: "1.0",
    scanId,
    mode: "repository",
    completeness: "complete",
    inventoryStrategy: "repository",
    includePaths: ["."],
    excludePaths: [],
    surfaces: [
      {
        id: "surface_fixture",
        label: "Fixture surface",
        disposition: "reported",
        receiptRefs: [],
      },
    ],
    explicitExclusions: [],
    deferred: [],
  });
  await writeJson(path.join(scanDir, "scan-manifest.json"), {
    documentType: "codex-security.scan-manifest",
    schemaVersion: "1.0",
    scan: {
      id: scanId,
      producer: { name: "codex-security-plugin", version: PLUGIN_VERSION },
      status: "completed",
      startedAt: "2026-06-02T18:00:00Z",
      completedAt: "2026-06-02T18:09:00Z",
      target: {
        kind: "directory_snapshot",
        targetId,
        displayName: path.basename(target),
        snapshotDigest,
      },
      scope: { includePaths: ["."], excludePaths: [] },
      coverageRef: "coverage.json",
      findingsRef: "findings.json",
    },
  });
}

try {
  const initialized = await testServer.initialize("codex-security-smoke", {
    elicitation: { form: {} },
  });
  assertNoError(initialized);
  assert.equal(initialized.result.capabilities.resources, undefined);
  assert.deepEqual(
    initialized.result.capabilities.experimental["codex/sandbox-state-meta"],
    {},
  );
  assert.deepEqual(
    initialized.result.capabilities.extensions["com.openai"],
    {},
  );
  assert.deepEqual(initialized.result.capabilities.logging, {});

  const trustedAccessToolList = await requestAndWait(9600, "tools/list");
  assertNoError(trustedAccessToolList);
  const trustedAccessTool = trustedAccessToolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "get_codex_security_daybreak_access",
  );
  assert.ok(
    trustedAccessTool,
    "Expected the plugin-owned Daybreak access tool.",
  );
  assert.doesNotMatch(
    JSON.stringify({
      name: trustedAccessTool.name,
      title: trustedAccessTool.title,
      description: trustedAccessTool.description,
    }),
    /\btac(?:[123])?\b/i,
  );
  assert.deepEqual(trustedAccessTool.inputSchema.properties, {});
  assert.deepEqual(trustedAccessTool.inputSchema.required ?? [], []);
  assert.deepEqual(trustedAccessTool._meta.ui.visibility, ["model"]);
  assert.deepEqual(trustedAccessTool._meta["openai/requestedEntitlements"], [
    "cyber_trusted_access",
  ]);
  assert.equal(trustedAccessTool.annotations.readOnlyHint, true);
  assert.equal(trustedAccessTool.annotations.destructiveHint, false);
  assert.equal(trustedAccessTool.annotations.openWorldHint, false);
  assert.match(trustedAccessTool.description, /ChatGPT account/);
  assert.match(
    trustedAccessTool.description,
    /Skip it for Amazon Bedrock scans/,
  );

  const unknownTrustedAccess = await testServer.callTool(9601, {
    name: "get_codex_security_daybreak_access",
    arguments: {},
  });
  assertNoError(unknownTrustedAccess);
  assert.equal(unknownTrustedAccess.result._meta, undefined);
  assert.deepEqual(
    {
      ...unknownTrustedAccess.result.structuredContent,
      checkedAt: undefined,
    },
    {
      schemaVersion: 1,
      status: "unknown",
      programs: [],
      checkedAt: undefined,
      stale: false,
    },
  );
  assert.ok(
    Number.isFinite(
      Date.parse(unknownTrustedAccess.result.structuredContent.checkedAt),
    ),
  );
  assert.doesNotMatch(
    unknownTrustedAccess.result.content[0].text,
    /protected results associated with this account may not be displayable/,
  );

  const grantedTrustedAccess = {
    schemaVersion: 1,
    status: "granted",
    grants: [
      { level: "tac1", source: "user" },
      { level: "tac3", source: "current_account" },
      { level: "tac2", source: "user" },
      { level: "tac1", source: "project" },
      { level: "government", source: "current_account" },
    ],
    checkedAt: "2026-07-13T12:00:00.000Z",
    stale: false,
  };
  const grantedDaybreakAccess = {
    schemaVersion: 1,
    status: "granted",
    programs: ["Daybreak Blue", "Daybreak Red"],
    checkedAt: "2026-07-13T12:00:00.000Z",
    stale: false,
  };
  const hostedTrustedAccess = await testServer.callTool(9602, {
    name: "get_codex_security_daybreak_access",
    arguments: {},
    _meta: {
      threadId: "fixture-trusted-access-thread",
      "openai/entitlementContext": {
        schemaVersion: 1,
        entitlements: {
          cyber_trusted_access: grantedTrustedAccess,
        },
      },
    },
  });
  assertNoError(hostedTrustedAccess);
  assert.equal(hostedTrustedAccess.result._meta, undefined);
  assert.deepEqual(
    hostedTrustedAccess.result.structuredContent,
    grantedDaybreakAccess,
  );
  assert.doesNotMatch(
    JSON.stringify(hostedTrustedAccess.result),
    /\btac(?:[123])?\b/i,
  );
  assert.match(hostedTrustedAccess.result.content[0].text, /Daybreak Blue/);
  assert.match(hostedTrustedAccess.result.content[0].text, /Daybreak Red/);

  const invalidGrantPairs = [
    { level: "tac2", source: "project" },
    { level: "tac2", source: "current_account" },
    { level: "tac3", source: "user" },
    { level: "tac3", source: "project" },
    { level: "government", source: "user" },
    { level: "government", source: "project" },
  ];
  for (const [index, invalidGrant] of invalidGrantPairs.entries()) {
    const response = await testServer.callTool(9620 + index, {
      name: "get_codex_security_daybreak_access",
      arguments: {},
      _meta: {
        threadId: "fixture-invalid-grant-thread",
        "openai/entitlementContext": {
          schemaVersion: 1,
          entitlements: {
            cyber_trusted_access: {
              ...grantedTrustedAccess,
              grants: [{ level: "tac1", source: "user" }, invalidGrant],
            },
          },
        },
      },
    });
    assertNoError(response);
    assert.equal(response.result.structuredContent.status, "unknown");
    assert.deepEqual(response.result.structuredContent.programs, []);
  }

  const staleGrantedAccess = await testServer.callTool(9626, {
    name: "get_codex_security_daybreak_access",
    arguments: {},
    _meta: {
      threadId: "fixture-stale-granted-thread",
      "openai/entitlementContext": {
        schemaVersion: 1,
        entitlements: {
          cyber_trusted_access: { ...grantedTrustedAccess, stale: true },
        },
      },
    },
  });
  assertNoError(staleGrantedAccess);
  assert.deepEqual(staleGrantedAccess.result.structuredContent, {
    schemaVersion: 1,
    status: "unknown",
    programs: [],
    checkedAt: grantedTrustedAccess.checkedAt,
    stale: true,
  });
  assert.doesNotMatch(
    staleGrantedAccess.result.content[0].text,
    /protected results may not be displayable/,
  );

  const untrustedReplay = await testServer.callTool(9603, {
    name: "get_codex_security_daybreak_access",
    arguments: {},
    _meta: { threadId: "fixture-trusted-access-thread" },
  });
  assertNoError(untrustedReplay);
  assert.equal(untrustedReplay.result._meta, undefined);
  assert.equal(untrustedReplay.result.structuredContent.status, "unknown");

  const deniedTrustedAccess = {
    schemaVersion: 1,
    status: "not_granted",
    grants: [],
    checkedAt: "2026-07-13T12:01:00.000Z",
    stale: false,
    enrollmentUrl: "https://chatgpt.com/cyber",
  };
  const refreshedTrustedAccess = await testServer.callTool(9604, {
    name: "get_codex_security_daybreak_access",
    arguments: {},
    _meta: {
      threadId: "fixture-trusted-access-thread",
      "openai/entitlementContext": {
        schemaVersion: 1,
        entitlements: {
          cyber_trusted_access: deniedTrustedAccess,
        },
      },
    },
  });
  assertNoError(refreshedTrustedAccess);
  assert.equal(refreshedTrustedAccess.result._meta, undefined);
  assert.deepEqual(refreshedTrustedAccess.result.structuredContent, {
    schemaVersion: 1,
    status: "not_granted",
    programs: [],
    checkedAt: "2026-07-13T12:01:00.000Z",
    stale: false,
    enrollmentUrl: "https://chatgpt.com/cyber",
  });
  assert.doesNotMatch(
    JSON.stringify(refreshedTrustedAccess.result),
    /\btac(?:[123])?\b/i,
  );
  assert.match(
    refreshedTrustedAccess.result.content[0].text,
    /protected results associated with this account may not be displayable/,
  );
  assert.match(
    refreshedTrustedAccess.result.content[0].text,
    /does not determine Amazon Bedrock model access/,
  );

  const timestampedTrustedAccess = await testServer.callTool(9608, {
    name: "get_codex_security_daybreak_access",
    arguments: {},
    _meta: {
      threadId: "fixture-timestamped-trusted-access-thread",
      "openai/entitlementContext": {
        schemaVersion: 1,
        entitlements: {
          cyber_trusted_access: {
            schemaVersion: 1,
            status: "granted",
            grants: [{ level: "tac2", source: "user" }],
            stale: false,
          },
        },
      },
    },
  });
  assertNoError(timestampedTrustedAccess);
  assert.equal(
    timestampedTrustedAccess.result.structuredContent.status,
    "granted",
  );
  assert.deepEqual(timestampedTrustedAccess.result.structuredContent.programs, [
    "Daybreak Blue",
  ]);
  assert.ok(
    Number.isFinite(
      Date.parse(timestampedTrustedAccess.result.structuredContent.checkedAt),
    ),
  );

  const unownedTrustedAccess = await testServer.callTool(9605, {
    name: "get_codex_security_daybreak_access",
    arguments: {},
    _meta: {
      "openai/threadId": "fixture-spoofed-missing-canonical-thread",
      "openai/entitlementContext": {
        schemaVersion: 1,
        entitlements: {
          cyber_trusted_access: grantedTrustedAccess,
        },
      },
    },
  });
  assertNoError(unownedTrustedAccess);
  assert.equal(unownedTrustedAccess.result.structuredContent.status, "unknown");

  const malformedTrustedAccess = await testServer.callTool(9606, {
    name: "get_codex_security_daybreak_access",
    arguments: {},
    _meta: {
      threadId: "fixture-malformed-trusted-access-thread",
      "openai/entitlementContext": {
        schemaVersion: 1,
        entitlements: {
          cyber_trusted_access: {
            ...grantedTrustedAccess,
            grants: [],
          },
        },
      },
    },
  });
  assertNoError(malformedTrustedAccess);
  assert.equal(
    malformedTrustedAccess.result.structuredContent.status,
    "unknown",
  );

  const argumentTrustedAccess = await testServer.callTool(9607, {
    name: "get_codex_security_daybreak_access",
    arguments: {
      "openai/entitlementContext": {
        schemaVersion: 1,
        entitlements: {
          cyber_trusted_access: grantedTrustedAccess,
        },
      },
    },
    _meta: { threadId: "fixture-argument-trusted-access-thread" },
  });
  assert.equal(argumentTrustedAccess.result.isError, true);

  const replayedTrustedAccess = await testServer.callTool(9609, {
    name: "get_codex_security_daybreak_access",
    arguments: {},
    _meta: { threadId: "fixture-trusted-access-thread" },
  });
  assertNoError(replayedTrustedAccess);
  assert.equal(
    replayedTrustedAccess.result.structuredContent.status,
    "unknown",
  );

  const spoofedThreadTrustedAccess = await testServer.callTool(9610, {
    name: "get_codex_security_daybreak_access",
    arguments: {},
    _meta: {
      threadId: "fixture-trusted-access-owner",
      "openai/threadId": "fixture-spoofed-trusted-access-owner",
      "openai/entitlementContext": {
        schemaVersion: 1,
        entitlements: {
          cyber_trusted_access: grantedTrustedAccess,
        },
      },
    },
  });
  assertNoError(spoofedThreadTrustedAccess);
  assert.deepEqual(
    spoofedThreadTrustedAccess.result.structuredContent,
    grantedDaybreakAccess,
  );
  const canonicalThreadTrustedAccess = await testServer.callTool(9611, {
    name: "get_codex_security_daybreak_access",
    arguments: {},
    _meta: { threadId: "fixture-trusted-access-owner" },
  });
  assertNoError(canonicalThreadTrustedAccess);
  assert.equal(
    canonicalThreadTrustedAccess.result.structuredContent.status,
    "unknown",
  );

  const isolatedHostedTrustedAccess = await testServer.callTool(9612, {
    name: "get_codex_security_daybreak_access",
    arguments: {},
    _meta: {
      threadId: "fixture-isolated-trusted-access-owner",
      "openai/entitlementContext": {
        schemaVersion: 1,
        entitlements: {
          cyber_trusted_access: grantedTrustedAccess,
        },
      },
    },
  });
  assertNoError(isolatedHostedTrustedAccess);
  assert.deepEqual(
    isolatedHostedTrustedAccess.result.structuredContent,
    grantedDaybreakAccess,
  );
  const isolatedOtherTrustedAccess = await testServer.callTool(9613, {
    name: "get_codex_security_daybreak_access",
    arguments: {},
    _meta: { threadId: "fixture-isolated-trusted-access-other" },
  });
  assertNoError(isolatedOtherTrustedAccess);
  assert.equal(
    isolatedOtherTrustedAccess.result.structuredContent.status,
    "unknown",
  );

  await assertBundledNodeLauncher();
  await assertBundledPythonRuntime();
  await assertMissingPythonError();
  await assertWorkbenchStdinFailureDoesNotCrashServer();
  await assertUnavailableUserInputFallback();
  await assertWorkspaceWorksWithoutUiCapability();
  await assertHeadlessStandardScanWorksWithoutUiCapability();
  await assertDeepScanPersistsRetryableWorkerStartupError();
  await assertUserInputFailureLogging();
  if (process.platform !== "win32") {
    await rm(launchCwd, { recursive: true, force: true });
  }
  const toolList = await requestAndWait(2, "tools/list");
  assertNoError(toolList);
  for (const tool of toolList.result.tools) {
    assert.equal(tool._meta?.["openai/outputTemplate"], undefined);
    assert.equal(tool._meta?.["ui/resourceUri"], undefined);
    assert.equal(tool._meta?.ui?.resourceUri, undefined);
  }
  await assert.rejects(readFile(path.join(stateDir, "workbench.sqlite3")), {
    code: "ENOENT",
  });

  const launcher = toolList.result.tools.find(
    (tool: { name: string }) => tool.name === "open_codex_security_workspace",
  );
  const startPromptOnlyScan = toolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "start_codex_security_prompt_only_scan",
  );
  assert.match(
    startPromptOnlyScan.description,
    /Standard and diff scans save progress checkpoints before their final semantic draft/,
    "Prompt-only scan instructions must align Diff callers with checkpointed handoffs",
  );
  const startHeadlessStandardScan = toolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "start_codex_security_standard_scan",
  );
  const getScan = toolList.result.tools.find(
    (tool: { name: string }) => tool.name === "get_codex_security_scan",
  );
  const recoverScanResults = toolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "recover_codex_security_scan_results",
  );
  const listScans = toolList.result.tools.find(
    (tool: { name: string }) => tool.name === "list_codex_security_scans",
  );
  const listGlobalFindings = toolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "list_codex_security_global_findings",
  );
  const listRepositories = toolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "list_codex_security_repositories",
  );
  const getScanContext = toolList.result.tools.find(
    (tool: { name: string }) => tool.name === "get_codex_security_scan_context",
  );
  const updateScanContext = toolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "update_codex_security_scan_context",
  );
  const updateScanContextFromApp = toolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "update_codex_security_scan_context_from_app",
  );
  const submit = toolList.result.tools.find(
    (tool: { name: string }) => tool.name === "submit_codex_security_setup",
  );
  const inspectTarget = toolList.result.tools.find(
    (tool: { name: string }) => tool.name === "inspect_codex_security_target",
  );
  const inspectSetup = toolList.result.tools.find(
    (tool: { name: string }) => tool.name === "inspect_codex_security_setup",
  );
  const requestUserInput = toolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "request_codex_security_user_input",
  );
  assert.ok(
    requestUserInput,
    "Expected the Codex Security user-input fallback tool.",
  );
  assert.deepEqual(requestUserInput.inputSchema.required, ["questions"]);
  testServer.sendRequest(9000, "tools/call", {
    name: "request_codex_security_user_input",
    arguments: {
      questions: [
        {
          header: "Deep scan?",
          id: "concurrent_deep_scan",
          question: "Another Deep Security Scan is running. Continue this one?",
          options: [
            {
              label: "Cancel (Recommended)",
              description:
                "Stop this new scan before preflight or substantive work.",
            },
            {
              label: "Continue",
              description:
                "Proceed even though both scans may use more resources.",
            },
          ],
        },
        {
          header: "Preflight?",
          id: "preflight_action",
          question: "How should Codex Security handle the blocked preflight?",
          options: [
            {
              label: "Apply and retry",
              description:
                "Apply the proposed Codex configuration change and rerun preflight.",
            },
            {
              label: "Leave paused",
              description: "Keep the scan available for a later retry.",
            },
            {
              label: "Cancel scan",
              description: "Cancel this scan without changing configuration.",
            },
          ],
        },
      ],
    },
  });
  const elicitationRequest = await testServer.waitForMessage(
    (message) => message.method === "elicitation/create",
    "Codex Security elicitation request",
  );
  assert.equal(elicitationRequest.params.mode, "form");
  assert.equal(
    elicitationRequest.params.message,
    "Codex Security needs your input before it can continue.",
  );
  assert.deepEqual(
    elicitationRequest.params.requestedSchema.properties.concurrent_deep_scan
      .oneOf,
    [
      { const: "Cancel (Recommended)", title: "Cancel (Recommended)" },
      {
        const: "Continue",
        title: "Continue",
      },
    ],
  );
  assert.equal(
    Object.hasOwn(
      elicitationRequest.params.requestedSchema.properties.concurrent_deep_scan,
      "description",
    ),
    false,
  );
  assert.deepEqual(
    elicitationRequest.params.requestedSchema.properties.preflight_action.oneOf,
    [
      { const: "Apply and retry", title: "Apply and retry" },
      {
        const: "Leave paused",
        title: "Leave paused",
      },
      {
        const: "Cancel scan",
        title: "Cancel scan",
      },
    ],
  );
  assert.equal(
    Object.hasOwn(
      elicitationRequest.params.requestedSchema.properties.preflight_action,
      "description",
    ),
    false,
  );
  testServer.sendResponse(elicitationRequest.id, {
    action: "accept",
    content: {
      concurrent_deep_scan: "Cancel (Recommended)",
      preflight_action: "Leave paused",
    },
  });
  const userInputResponse = await testServer.waitForMessage(
    (message) => message.id === 9000,
    "Codex Security user-input tool response",
  );
  assertNoError(userInputResponse);
  assert.deepEqual(userInputResponse.result.structuredContent, {
    status: "accepted",
    answers: {
      concurrent_deep_scan: "Cancel (Recommended)",
      preflight_action: "Leave paused",
    },
  });
  const invalidUserInput = await testServer.callTool(9001, {
    name: "request_codex_security_user_input",
    arguments: {
      questions: [
        {
          header: "Duplicate?",
          id: "duplicate_options",
          question: "Should duplicate option labels be rejected?",
          options: [
            {
              label: "Same",
              description: "The first duplicate option.",
            },
            {
              label: "Same",
              description: "The second duplicate option.",
            },
          ],
        },
      ],
    },
  });
  assert.equal(invalidUserInput.result.isError, true);

  testServer.sendRequest(9002, "tools/call", {
    name: "request_codex_security_user_input",
    arguments: {
      questions: [
        {
          header: "Decline?",
          id: "decline_request",
          question: "Decline this Codex Security input request?",
          options: continuationOptions,
        },
      ],
    },
  });
  const declinedElicitation = await testServer.waitForMessage(
    (message) =>
      message.method === "elicitation/create" &&
      message.params?.message === "Decline this Codex Security input request?",
    "declined Codex Security elicitation request",
  );
  testServer.sendResponse(declinedElicitation.id, { action: "decline" });
  const declinedUserInput = await testServer.waitForMessage(
    (message) => message.id === 9002,
    "declined Codex Security user-input response",
  );
  assertNoError(declinedUserInput);
  assert.deepEqual(declinedUserInput.result.structuredContent, {
    status: "declined",
  });

  testServer.sendRequest(9003, "tools/call", {
    name: "request_codex_security_user_input",
    arguments: {
      questions: [
        {
          header: "Cancel?",
          id: "cancel_request",
          question: "Cancel this Codex Security input request?",
          options: continuationOptions,
        },
      ],
    },
  });
  const cancelledElicitation = await testServer.waitForMessage(
    (message) =>
      message.method === "elicitation/create" &&
      message.params?.message === "Cancel this Codex Security input request?",
    "cancelled Codex Security elicitation request",
  );
  testServer.sendResponse(cancelledElicitation.id, { action: "cancel" });
  const cancelledUserInput = await testServer.waitForMessage(
    (message) => message.id === 9003,
    "cancelled Codex Security user-input response",
  );
  assertNoError(cancelledUserInput);
  assert.deepEqual(cancelledUserInput.result.structuredContent, {
    status: "cancelled",
  });
  const start = toolList.result.tools.find(
    (tool: { name: string }) => tool.name === "start_codex_security_scan",
  );
  const startDeepScan = toolList.result.tools.find(
    (tool: { name: string }) => tool.name === "start_codex_security_deep_scan",
  );
  const cancel = toolList.result.tools.find(
    (tool: { name: string }) => tool.name === "cancel_codex_security_scan",
  );
  const cancelFromApp = toolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "cancel_codex_security_scan_from_app",
  );
  const markHandoff = toolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "mark_codex_security_scan_handoff_delivered",
  );
  const claimHandoff = toolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "claim_codex_security_scan_handoff_delivery",
  );
  const releaseHandoff = toolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "release_codex_security_scan_handoff_delivery",
  );
  const attachHandoff = toolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "attach_codex_security_scan_continuation_thread",
  );
  const progress = toolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "update_codex_security_scan_progress",
  );
  const complete = toolList.result.tools.find(
    (tool: { name: string }) => tool.name === "complete_codex_security_scan",
  );
  const fail = toolList.result.tools.find(
    (tool: { name: string }) => tool.name === "fail_codex_security_scan",
  );
  const setFindingTriage = toolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "set_codex_security_finding_triage",
  );
  const requestFindingRemediation = toolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "request_codex_security_finding_remediation",
  );
  const requestFindingRemediationAction = toolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "request_codex_security_finding_remediation_action",
  );
  const claimFindingRemediationResend = toolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "claim_codex_security_finding_remediation_resend",
  );
  const releaseFindingRemediationClaim = toolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "release_codex_security_finding_remediation_claim",
  );
  const cancelFindingRemediationRequest = toolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "cancel_codex_security_finding_remediation_request",
  );
  const markFindingRemediationDelivered = toolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "mark_codex_security_finding_remediation_delivered",
  );
  const setFindingRemediation = toolList.result.tools.find(
    (tool: { name: string }) =>
      tool.name === "set_codex_security_finding_remediation",
  );
  const exportFindings = toolList.result.tools.find(
    (tool: { name: string }) => tool.name === "export_codex_security_findings",
  );
  const listFindings = toolList.result.tools.find(
    (tool: { name: string }) => tool.name === "list_codex_security_findings",
  );
  assert.ok(launcher);
  assert.ok(startPromptOnlyScan);
  assert.ok(startHeadlessStandardScan);
  assert.ok(getScan);
  assert.ok(listScans);
  assert.ok(listGlobalFindings);
  assert.ok(listRepositories);
  assert.ok(getScanContext);
  assert.ok(updateScanContext);
  assert.ok(updateScanContextFromApp);
  assert.ok(submit);
  assert.ok(inspectTarget);
  assert.ok(inspectSetup);
  assert.ok(start);
  assert.deepEqual(start.inputSchema.required, ["sessionId"]);
  assert.ok(startDeepScan);
  assert.equal(startDeepScan.annotations.idempotentHint, true);
  assert.ok(cancel);
  assert.ok(cancelFromApp);
  assert.ok(markHandoff);
  assert.ok(claimHandoff);
  assert.ok(releaseHandoff);
  assert.ok(attachHandoff);
  assert.ok(progress);
  assert.equal(
    progress.inputSchema.properties.phase.description,
    "Current workflow phase. Send it immediately when the scan enters a new phase so persisted progress advances.",
  );
  assert.equal(
    progress.inputSchema.properties.phaseItemsCompleted.description,
    "Completed authoritative coverage, receipts, or artifacts for the current phase. Increase it only after the corresponding work product exists.",
  );
  assert.equal(
    progress.inputSchema.properties.phaseItemsTotal.description,
    "Expected authoritative coverage, receipts, or artifacts for the current phase. Increase it before newly discovered work begins.",
  );
  assert.deepEqual(
    progress.inputSchema.properties.preflightChecks.items.properties.severity
      .enum,
    ["block", "warn", "suggest"],
  );
  assert.deepEqual(
    progress.inputSchema.properties.preflightChecks.items.properties.status
      .enum,
    ["pass", "fail", "unknown"],
  );
  assert.equal(
    progress.inputSchema.properties.deepReviewPass.description,
    "Current Deep Scan discovery pass. Send it when starting each pass together with that pass's total and zero completed items.",
  );
  assert.equal(
    progress.inputSchema.properties.reviewItemsCompleted.description,
    "Cumulative completed reviews or coverage surfaces in the current discovery pass. Increment only after the corresponding review is complete.",
  );
  assert.equal(
    progress.inputSchema.properties.reviewItemsTotal.description,
    "Expected reviews or coverage surfaces in the current discovery pass. Increase it before assigning newly discovered work.",
  );
  assert.ok(complete);
  assert.ok(fail);
  assert.ok(setFindingTriage);
  assert.ok(requestFindingRemediation);
  assert.ok(requestFindingRemediationAction);
  assert.ok(claimFindingRemediationResend);
  assert.ok(releaseFindingRemediationClaim);
  assert.ok(cancelFindingRemediationRequest);
  assert.ok(markFindingRemediationDelivered);
  assert.ok(setFindingRemediation);
  assert.ok(exportFindings);
  assert.ok(listFindings);
  for (const tool of [
    listScans,
    listGlobalFindings,
    listRepositories,
    listFindings,
  ]) {
    assert.ok(tool.inputSchema.properties.query);
    assert.ok(tool.inputSchema.properties.limit);
    assert.ok(tool.inputSchema.properties.offset);
  }
  assert.deepEqual(listGlobalFindings.inputSchema.properties.severity.enum, [
    "critical",
    "high",
    "medium",
    "low",
    "informational",
  ]);
  assert.deepEqual(listGlobalFindings.inputSchema.properties.status.enum, [
    "open",
    "closed",
  ]);
  assert.ok(listGlobalFindings.inputSchema.properties.targetId);
  assert.deepEqual(listScans.inputSchema.properties.status.enum, [
    "running",
    "complete",
    "failed",
    "canceled",
  ]);
  assert.deepEqual(listRepositories.inputSchema.properties.status.enum, [
    "scanned",
    "not_scanned",
    "open_findings",
  ]);
  assert.deepEqual(listFindings.inputSchema.properties.status.enum, [
    "open",
    "closed",
  ]);
  assert.deepEqual(launcher.inputSchema.properties.mode.enum, [
    "diff",
    "standard",
    "deep",
  ]);
  assert.equal(getScan.annotations.readOnlyHint, false);
  assert.deepEqual(getScan._meta.ui.visibility, ["app"]);
  assert.equal(recoverScanResults.annotations.readOnlyHint, false);
  assert.equal(recoverScanResults.annotations.destructiveHint, true);
  assert.equal(recoverScanResults.annotations.idempotentHint, true);
  assert.deepEqual(recoverScanResults._meta.ui.visibility, ["app"]);
  assert.equal(listScans.annotations.readOnlyHint, true);
  assert.deepEqual(listScans._meta.ui.visibility, ["app"]);
  assert.equal(listGlobalFindings.annotations.readOnlyHint, true);
  assert.deepEqual(listGlobalFindings._meta.ui.visibility, ["app"]);
  assert.deepEqual(listGlobalFindings.inputSchema.required ?? [], []);
  assert.equal(listGlobalFindings.inputSchema.properties.limit.maximum, 20);
  assert.ok(listGlobalFindings.inputSchema.properties.offset);
  assert.equal(listRepositories.annotations.readOnlyHint, true);
  assert.deepEqual(listRepositories._meta.ui.visibility, ["app"]);
  assert.deepEqual(listRepositories.inputSchema.required ?? [], []);
  assert.equal(getScanContext.annotations.readOnlyHint, false);
  assert.ok(getScanContext.inputSchema.properties.occurrenceId);
  assert.deepEqual(launcher._meta.ui.visibility, ["app"]);
  assert.deepEqual(startPromptOnlyScan._meta.ui.visibility, ["model"]);
  assert.deepEqual(startHeadlessStandardScan._meta.ui.visibility, ["model"]);
  assert.deepEqual(startHeadlessStandardScan.inputSchema.required, [
    "targetPath",
  ]);
  assert.equal(
    startHeadlessStandardScan.inputSchema.properties.userContext.maxLength,
    undefined,
  );
  assert.ok(getScanContext.inputSchema.properties.handoffClaimToken);
  assert.deepEqual(updateScanContext._meta.ui.visibility, ["model"]);
  assert.deepEqual(updateScanContextFromApp._meta.ui.visibility, ["app"]);
  assert.ok(updateScanContext.inputSchema.properties.handoffClaimToken);
  assert.equal(
    updateScanContext.inputSchema.properties.userContext.maxLength,
    undefined,
  );
  assert.equal(
    updateScanContextFromApp.inputSchema.properties.userContext.maxLength,
    undefined,
  );
  assert.deepEqual(updateScanContextFromApp.inputSchema.required, [
    "scanId",
    "userContext",
  ]);
  assert.deepEqual(submit._meta.ui.visibility, ["app"]);
  assert.deepEqual(inspectTarget._meta.ui.visibility, ["app"]);
  assert.deepEqual(inspectSetup._meta.ui.visibility, ["app"]);
  assert.deepEqual(start._meta.ui.visibility, ["app"]);
  assert.deepEqual(startDeepScan._meta.ui.visibility, ["model"]);
  assert.ok(startDeepScan.inputSchema.properties.scanId);
  assert.ok(startDeepScan.inputSchema.properties.targetPath);
  assert.ok(startDeepScan.inputSchema.properties.handoffClaimToken);
  assert.deepEqual(cancel._meta.ui.visibility, ["model"]);
  assert.deepEqual(cancelFromApp._meta.ui.visibility, ["app"]);
  assert.deepEqual(claimHandoff._meta.ui.visibility, ["app"]);
  assert.deepEqual(releaseHandoff._meta.ui.visibility, ["app"]);
  assert.deepEqual(attachHandoff._meta.ui.visibility, ["app"]);
  assert.deepEqual(progress._meta.ui.visibility, ["model"]);
  assert.deepEqual(complete._meta.ui.visibility, ["model"]);
  assert.deepEqual(fail._meta.ui.visibility, ["model"]);
  for (const tool of [
    launcher,
    getScan,
    submit,
    start,
    cancelFromApp,
    claimHandoff,
    releaseHandoff,
    attachHandoff,
  ]) {
    assert.ok(
      tool._meta.ui.visibility.includes("app"),
      `${tool.name} must be callable by the native Codex Security workbench.`,
    );
  }
  for (const tool of [
    getScanContext,
    updateScanContext,
    progress,
    complete,
    fail,
  ]) {
    assert.ok(tool._meta.ui.visibility.includes("model"));
    assert.ok(tool.inputSchema.properties.handoffClaimToken);
  }
  assert.match(complete.description, /Finalization only/);
  assert.match(
    complete.description,
    /does not create missing artifacts or run skipped phases/,
  );
  assert.match(
    complete.description,
    /If it fails, surface the exact error and stop the current response/,
  );
  assert.deepEqual(setFindingTriage._meta.ui.visibility, ["app"]);
  assert.deepEqual(requestFindingRemediation._meta.ui.visibility, ["app"]);
  assert.deepEqual(requestFindingRemediationAction._meta.ui.visibility, [
    "app",
  ]);
  assert.deepEqual(claimFindingRemediationResend._meta.ui.visibility, ["app"]);
  assert.deepEqual(releaseFindingRemediationClaim._meta.ui.visibility, ["app"]);
  assert.deepEqual(markFindingRemediationDelivered._meta.ui.visibility, [
    "app",
  ]);
  assert.deepEqual(setFindingRemediation._meta.ui.visibility, ["model"]);
  assert.deepEqual(setFindingRemediation.inputSchema.properties.state.enum, [
    "generated",
    "applied",
    "verifying",
    "verified",
    "failed",
  ]);
  assert.deepEqual(exportFindings._meta.ui.visibility, ["app"]);
  assert.deepEqual(listFindings._meta.ui.visibility, ["app"]);
  const missingDeepIdentity = await testServer.callTool(9100, {
    name: "start_codex_security_deep_scan",
    arguments: {},
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assert.equal(missingDeepIdentity.result.isError, true);
  assert.match(
    missingDeepIdentity.result.content[0].text,
    /exactly one Deep Scan identity/,
  );
  const mixedDeepIdentity = await testServer.callTool(9101, {
    name: "start_codex_security_deep_scan",
    arguments: { scanId: randomUUID(), targetPath: target },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assert.equal(mixedDeepIdentity.result.isError, true);
  assert.match(
    mixedDeepIdentity.result.content[0].text,
    /exactly one Deep Scan identity/,
  );
  const invalidDeepScope = await testServer.callTool(9102, {
    name: "start_codex_security_deep_scan",
    arguments: { targetPath: target, scope: "src" },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assert.equal(invalidDeepScope.result.isError, true);
  assert.match(
    invalidDeepScope.result.content[0].text,
    /requires the whole target/,
  );
  const missingDeepThread = await testServer.callTool(9103, {
    name: "start_codex_security_deep_scan",
    arguments: { targetPath: target },
  });
  assert.equal(missingDeepThread.result.isError, true);
  assert.match(
    missingDeepThread.result.content[0].text,
    /owning Codex thread context/,
  );
  const missingPersistedDeepScan = await testServer.callTool(9104, {
    name: "start_codex_security_deep_scan",
    arguments: { scanId: randomUUID() },
    _meta: {
      "openai/threadId": "fixture-thread",
      "codex/sandbox-state-meta": parentSandboxState,
    },
  });
  const missingPersistedDeepScanText = missingPersistedDeepScan.result.content
    .map((item: { text: string }) => item.text)
    .join(" ");
  assert.equal(missingPersistedDeepScan.result.isError, true);
  assert.equal(missingPersistedDeepScan.result.structuredContent, undefined);
  assert.match(missingPersistedDeepScanText, /Codex Security scan not found/);
  assert.match(
    missingPersistedDeepScanText,
    /discovery did not start or rejoin/,
  );
  assert.match(
    missingPersistedDeepScanText,
    /Stop the current response and surface this exact MCP error/,
  );
  assert.match(
    missingPersistedDeepScanText,
    /Do not call start_codex_security_deep_scan again/,
  );
  assert.match(missingPersistedDeepScanText, /get_codex_security_scan_context/);
  assert.match(missingPersistedDeepScanText, /complete_codex_security_scan/);
  assert.match(missingPersistedDeepScanText, /emit benchmark JSON/);
  assert.equal(listFindings.annotations.readOnlyHint, false);
  assert.equal(progress._meta.ui.resourceUri, undefined);
  assert.equal(launcher.annotations.idempotentHint, false);
  assert.equal(start.annotations.idempotentHint, false);
  assert.equal(cancel.annotations.destructiveHint, true);
  assert.equal(cancel.annotations.idempotentHint, true);
  assert.equal(fail.annotations.destructiveHint, true);
  assert.match(fail.description, /terminal/);
  assert.match(fail.description, /unrecoverable/);
  assert.match(fail.description, /use cancel_codex_security_scan/i);
  assert.equal(setFindingRemediation.annotations.idempotentHint, false);

  const urlContext =
    "Deployment details came from https://example.test/internal.";
  const urlContextAccepted = await testServer.callTool(1290, {
    name: "open_codex_security_workspace",
    arguments: {
      targetPath: target,
      userContext: urlContext,
    },
    _meta: { "openai/threadId": "fixture-url-context-thread" },
  });
  assertNoError(urlContextAccepted);
  assert.equal(
    urlContextAccepted.result.structuredContent.workspace.userContext,
    urlContext,
  );

  const opened = await testServer.callTool(4, {
    name: "open_codex_security_workspace",
    arguments: {
      targetPath: target,
      targetTitle: "Fixture Repository",
      targetSummary: "Revision fixture123.",
      scope: ".",
      userContext: "Focus on uploaded archives.",
    },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assertNoError(opened);
  const workspace = opened.result.structuredContent.workspace;
  assert.equal(workspace.setup.submitted, false);
  assert.equal(workspace.mode, "standard");
  assert.equal(workspace.userContext, "Focus on uploaded archives.");
  assert.deepEqual(workspace.targetMetadata, {
    hasHead: false,
    isGit: false,
    isWorktree: false,
    reviewChangesSupported: false,
  });

  const sameThreadReopen = await testServer.callTool(1162, {
    name: "open_codex_security_workspace",
    arguments: { sessionId: workspace.id },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assertNoError(sameThreadReopen);
  assert.equal(
    sameThreadReopen.result.structuredContent.workspace.id,
    workspace.id,
  );

  const otherThreadOpened = await testServer.callTool(1163, {
    name: "open_codex_security_workspace",
    arguments: { targetPath: replacementTarget },
    _meta: { "openai/threadId": "fixture-other-thread" },
  });
  assertNoError(otherThreadOpened);
  assert.notEqual(
    otherThreadOpened.result.structuredContent.workspace.id,
    workspace.id,
  );
  assert.equal(
    otherThreadOpened.result.structuredContent.workspace.targetPath,
    await realpath(replacementTarget),
  );

  const crossThreadReopen = await testServer.callTool(1164, {
    name: "open_codex_security_workspace",
    arguments: { sessionId: workspace.id },
    _meta: { "openai/threadId": "fixture-other-thread" },
  });
  assert.equal(crossThreadReopen.result.isError, true);
  assert.match(
    crossThreadReopen.result.content[0].text,
    /workspace not found in this thread/,
  );

  const metadataFreeReopen = await testServer.callTool(1165, {
    name: "open_codex_security_workspace",
    arguments: { sessionId: workspace.id },
  });
  assert.equal(metadataFreeReopen.result.isError, true);
  assert.match(
    metadataFreeReopen.result.content[0].text,
    /thread metadata is required/i,
  );

  const metadataFreeCreate = await testServer.callTool(1166, {
    name: "open_codex_security_workspace",
    arguments: { targetPath: target },
  });
  assertNoError(metadataFreeCreate);
  assert.match(
    metadataFreeCreate.result.structuredContent.workspace.id,
    /^[0-9a-f-]{36}$/,
  );

  const savedOtherWorkspace = await testServer.callTool(2020, {
    name: "submit_codex_security_setup",
    arguments: {
      sessionId: otherThreadOpened.result.structuredContent.workspace.id,
      targetPath: replacementTarget,
      scope: ".",
      mode: "standard",
    },
  });
  assertNoError(savedOtherWorkspace);
  await new Promise((resolve) => setTimeout(resolve, 100));
  testServer.notify("notifications/cancelled", {
    requestId: 2021,
    reason: "Smoke-test cancellation",
  });
  await new Promise((resolve) => setTimeout(resolve, 100));
  const otherStarted = await testServer.callTool(2023, {
    name: "start_codex_security_scan",
    arguments: {
      sessionId: otherThreadOpened.result.structuredContent.workspace.id,
    },
  });
  assertNoError(otherStarted);

  const absoluteScopeOpened = await testServer.callTool(150, {
    name: "open_codex_security_workspace",
    arguments: { targetPath: target, scope: target, mode: "standard" },
    _meta: { "openai/threadId": "fixture-aux-thread" },
  });
  assertNoError(absoluteScopeOpened);
  assert.equal(
    absoluteScopeOpened.result.structuredContent.workspace.scope,
    ".",
  );

  const invalidReopen = await testServer.callTool(151, {
    name: "open_codex_security_workspace",
    arguments: { sessionId: workspace.id, scope: "." },
  });
  assert.equal(invalidReopen.result.isError, true);
  assert.match(invalidReopen.result.content[0].text, /sessionId only reopens/);

  const deepOpened = await testServer.callTool(44, {
    name: "open_codex_security_workspace",
    arguments: { targetPath: target, scope: ".", mode: "deep" },
    _meta: { "openai/threadId": "fixture-aux-thread" },
  });
  assertNoError(deepOpened);
  assert.equal(deepOpened.result.structuredContent.workspace.mode, "deep");
  assert.equal(deepOpened.result.structuredContent.workspace.scope, ".");

  const diffOpened = await testServer.callTool(45, {
    name: "open_codex_security_workspace",
    arguments: {
      targetPath: gitTarget,
      scope: ".",
      mode: "diff",
      targetSummary: "Latest commit · fixture",
      diffTarget: { kind: "commit", headRevision: gitHead },
    },
    _meta: { "openai/threadId": "fixture-aux-thread" },
  });
  assertNoError(diffOpened);
  assert.equal(diffOpened.result.structuredContent.workspace.mode, "diff");
  assert.equal(
    diffOpened.result.structuredContent.workspace.targetSummary,
    "Latest commit · fixture",
  );
  assert.equal(
    diffOpened.result.structuredContent.workspace.diffTarget.headRevision,
    gitHead,
  );
  assert.equal(
    diffOpened.result.structuredContent.workspace.setupValidation.valid,
    true,
  );

  const inferredDiffOpened = await testServer.callTool(152, {
    name: "open_codex_security_workspace",
    arguments: {
      targetPath: gitTarget,
      scope: ".",
      diffTarget: { kind: "commit", headRevision: gitHead },
    },
    _meta: { "openai/threadId": "fixture-aux-thread" },
  });
  assertNoError(inferredDiffOpened);
  assert.equal(
    inferredDiffOpened.result.structuredContent.workspace.mode,
    "diff",
  );

  const contradictoryDiffOpened = await testServer.callTool(153, {
    name: "open_codex_security_workspace",
    arguments: {
      targetPath: gitTarget,
      scope: ".",
      mode: "standard",
      diffTarget: { kind: "commit", headRevision: gitHead },
    },
  });
  assert.equal(contradictoryDiffOpened.result.isError, true);
  assert.match(
    contradictoryDiffOpened.result.content[0].text,
    /requires mode 'diff'/,
  );

  const scopedDeepOpened = await testServer.callTool(154, {
    name: "open_codex_security_workspace",
    arguments: { targetPath: target, scope: "src", mode: "deep" },
  });
  assert.equal(scopedDeepOpened.result.isError, true);
  assert.match(
    scopedDeepOpened.result.content[0].text,
    /requires the whole target/,
  );

  const nestedGitTarget = path.join(gitTarget, "nested");
  await mkdir(nestedGitTarget);
  const nestedDiffOpened = await testServer.callTool(155, {
    name: "open_codex_security_workspace",
    arguments: {
      targetPath: nestedGitTarget,
      scope: ".",
      mode: "diff",
      diffTarget: { kind: "commit", headRevision: gitHead },
    },
    _meta: { "openai/threadId": "fixture-aux-thread" },
  });
  assertNoError(nestedDiffOpened);
  assert.equal(
    nestedDiffOpened.result.structuredContent.workspace.setupValidation.valid,
    false,
  );
  assert.match(
    nestedDiffOpened.result.structuredContent.workspace.setupValidation.error,
    /repository root/,
  );
  assert.equal(
    nestedDiffOpened.result.structuredContent.workspace.targetMetadata
      .reviewChangesSupported,
    false,
  );

  const inspectedSetup = await testServer.callTool(46, {
    name: "inspect_codex_security_setup",
    arguments: {
      targetPath: gitTarget,
      scope: ".",
      mode: "diff",
      diffTarget: { kind: "commit", headRevision: "HEAD" },
    },
  });
  assertNoError(inspectedSetup);
  const inspectedCommitTarget =
    inspectedSetup.result.structuredContent.setup.diffTarget;
  assert.equal(inspectedCommitTarget.baseRevision, gitBase);
  assert.equal(
    inspectedSetup.result.structuredContent.setup.diffTarget.headRevision,
    gitHead,
  );
  assert.equal(
    inspectedSetup.result.structuredContent.setup.target.targetMetadata
      .commitSubject,
    "update fixture",
  );

  const inspectedCommitOpened = await testServer.callTool(2200, {
    name: "open_codex_security_workspace",
    arguments: {
      targetPath: gitTarget,
      scope: ".",
      mode: "diff",
      targetSummary: "Latest commit · fixture",
      diffTarget: { kind: "commit", headRevision: gitHead },
    },
    _meta: { "openai/threadId": "fixture-inspected-commit-thread" },
  });
  assertNoError(inspectedCommitOpened);

  const inspectedCommitSaved = await testServer.callTool(2201, {
    name: "submit_codex_security_setup",
    arguments: {
      sessionId: inspectedCommitOpened.result.structuredContent.workspace.id,
      targetPath: gitTarget,
      scope: ".",
      mode: "diff",
      targetSummary: "Latest commit · fixture",
      diffTarget: inspectedCommitTarget,
    },
  });
  assertNoError(inspectedCommitSaved);
  assert.deepEqual(
    inspectedCommitSaved.result.structuredContent.workspace.diffTarget,
    inspectedCommitTarget,
  );

  const invalidOpened = await testServer.callTool(47, {
    name: "open_codex_security_workspace",
    arguments: {
      targetPath: path.join(target, "missing"),
      scope: ".",
      mode: "standard",
    },
    _meta: { "openai/threadId": "fixture-aux-thread" },
  });
  assertNoError(invalidOpened);
  assert.equal(
    invalidOpened.result.structuredContent.workspace.setupValidation.valid,
    false,
  );
  assert.equal(
    invalidOpened.result.structuredContent.workspace.targetMetadata,
    undefined,
  );

  const inspected = await testServer.callTool(40, {
    name: "inspect_codex_security_target",
    arguments: { targetPath: target },
  });
  assertNoError(inspected);
  assert.equal(
    inspected.result.structuredContent.target.displayName,
    path.basename(target),
  );
  assert.equal(
    inspected.result.structuredContent.target.targetPath,
    await realpath(target),
  );
  assert.equal(
    inspected.result.structuredContent.target.targetMetadata
      .reviewChangesSupported,
    false,
  );

  const saved = await testServer.callTool(5, {
    name: "submit_codex_security_setup",
    arguments: {
      sessionId: workspace.id,
      targetPath: target,
      scope: ".",
      mode: "standard",
      userContext: "Pay attention to the HTTP API.",
    },
  });
  assertNoError(saved);
  assert.equal(saved.result._meta, undefined);
  const savedWorkspace = saved.result.structuredContent.workspace;
  assert.equal(savedWorkspace.setup.submitted, true);
  assert.equal(savedWorkspace.userContext, "Pay attention to the HTTP API.");
  const started = await testServer.callTool(6, {
    name: "start_codex_security_scan",
    arguments: {
      model: "gpt-5.6-sol",
      reasoningEffort: "high",
      sessionId: workspace.id,
    },
  });
  assertNoError(started);
  const startedWorkspace = started.result.structuredContent.workspace;
  assert.equal(startedWorkspace.results.model, "gpt-5.6-sol");
  assert.equal(startedWorkspace.results.reasoningEffort, "high");

  const initializedScanDir = startedWorkspace.results.scanDir;
  assert.equal(
    initializedScanDir.startsWith(
      path.join(await realpath(stateDir), "scans") + path.sep,
    ),
    true,
  );
  assert.equal(
    initializedScanDir.startsWith(`${resolvedScanRoot}${path.sep}`),
    false,
  );
  const scanId = startedWorkspace.results.scanId;
  assert.equal(startedWorkspace.results.progress.phase, "preflight");
  assert.equal(startedWorkspace.results.progress.status, "running");
  assert.equal(startedWorkspace.results.handoffStatus, "pending");
  assert.deepEqual(
    startedWorkspace.results.contract.scope.requiredIncludePaths,
    ["."],
  );
  const snapshotDigest =
    startedWorkspace.results.contract.target.requiredSnapshotDigest;
  assert.match(
    snapshotDigest,
    /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/,
  );
  await assert.rejects(
    readFile(path.join(initializedScanDir, "progress.json"), "utf8"),
    { code: "ENOENT" },
  );
  await assert.rejects(
    readFile(path.join(initializedScanDir, "events.jsonl"), "utf8"),
    { code: "ENOENT" },
  );

  const handoffClaimToken = randomUUID();
  const claimedHandoff = await testServer.callTool(2002, {
    name: "claim_codex_security_scan_handoff_delivery",
    arguments: { claimToken: handoffClaimToken, scanId },
  });
  assertNoError(claimedHandoff);
  assert.equal(
    claimedHandoff.result.structuredContent.workspace.results.handoffClaimToken,
    handoffClaimToken,
  );
  const attachedHandoff = await testServer.callTool(20021, {
    name: "attach_codex_security_scan_continuation_thread",
    arguments: {
      claimToken: handoffClaimToken,
      scanId,
      threadId: "fixture-thread",
    },
  });
  assertNoError(attachedHandoff);
  const threadOwnedScan = await testServer.callTool(2202, {
    name: "get_codex_security_scan",
    arguments: { scanId },
  });
  assertNoError(threadOwnedScan);
  assert.equal(
    threadOwnedScan.result.structuredContent.scan.continuationThreadId,
    "fixture-thread",
  );

  const wrongThreadDelivery = await testServer.callTool(2009, {
    name: "get_codex_security_scan_context",
    arguments: { handoffClaimToken, scanId },
    _meta: { "openai/threadId": "fixture-other-thread" },
  });
  assert.equal(wrongThreadDelivery.result.isError, true);
  assert.match(
    wrongThreadDelivery.result.content[0].text,
    /owning Codex thread/,
  );

  const missingClaimToken = await testServer.callTool(2005, {
    name: "get_codex_security_scan_context",
    arguments: { scanId },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assert.equal(missingClaimToken.result.isError, true);
  assert.match(
    missingClaimToken.result.content[0].text,
    /Pass the handoffClaimToken/,
  );

  const delivered = await testServer.callTool(2003, {
    name: "get_codex_security_scan_context",
    arguments: { handoffClaimToken, scanId },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assertNoError(delivered);
  assert.equal(
    delivered.result.structuredContent.scan.handoffStatus,
    "delivered",
  );
  assert.equal(
    delivered.result.structuredContent.scan.handoffClaimToken,
    undefined,
  );
  assert.equal(
    delivered.result.structuredContent.workspace.results.handoffClaimToken,
    undefined,
  );
  const reopenedWorkspace = await testServer.callTool(2203, {
    name: "open_codex_security_workspace",
    arguments: { sessionId: workspace.id },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assertNoError(reopenedWorkspace);
  assert.equal(
    reopenedWorkspace.result.structuredContent.workspace.results
      .handoffClaimToken,
    undefined,
  );

  const supersededClaim = await testServer.callTool(2006, {
    name: "get_codex_security_scan_context",
    arguments: { handoffClaimToken: randomUUID(), scanId },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assert.equal(supersededClaim.result.isError, true);
  assert.match(
    supersededClaim.result.content[0].text,
    /owned by another continuation/,
  );

  const deliveredWithoutToken = await testServer.callTool(2007, {
    name: "get_codex_security_scan_context",
    arguments: { scanId },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assertNoError(deliveredWithoutToken);

  const longUserContext = "Prioritize tenant isolation. ".repeat(120).trim();
  const updatedContext = await testServer.callTool(92010, {
    name: "update_codex_security_scan_context",
    arguments: { handoffClaimToken, scanId, userContext: longUserContext },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assertNoError(updatedContext);
  assert.equal(
    updatedContext.result.structuredContent.scan.userContext,
    longUserContext,
  );
  assert.equal(
    updatedContext.result.structuredContent.workspace.userContext,
    longUserContext,
  );

  const appUserContext = "Focus on account recovery. ".repeat(120).trim();
  const appUpdatedContext = await testServer.callTool(92011, {
    name: "update_codex_security_scan_context_from_app",
    arguments: { scanId, userContext: appUserContext },
  });
  assertNoError(appUpdatedContext);
  assert.equal(
    appUpdatedContext.result.structuredContent.scan.userContext,
    appUserContext,
  );

  const urlContextUpdate = "Read https://example.test/context.";
  const updatedContextUrl = await testServer.callTool(92012, {
    name: "update_codex_security_scan_context",
    arguments: {
      handoffClaimToken,
      scanId,
      userContext: urlContextUpdate,
    },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assertNoError(updatedContextUrl);
  assert.equal(
    updatedContextUrl.result.structuredContent.scan.userContext,
    urlContextUpdate,
  );
  assert.equal(
    updatedContextUrl.result.structuredContent.workspace.userContext,
    urlContextUpdate,
  );

  const conflictingPreflightCounts = await testServer.callTool(90161, {
    name: "update_codex_security_scan_progress",
    arguments: {
      scanId,
      handoffClaimToken,
      phaseItemsTotal: 1,
      preflightChecks: [
        {
          capability: "delegated_workers",
          reason: "Delegated workers are available.",
          severity: "warn",
          status: "pass",
        },
      ],
    },
  });
  assert.equal(conflictingPreflightCounts.result.isError, true);
  assert.match(
    conflictingPreflightCounts.result.content[0].text,
    /preflightChecks derives/,
  );

  const successfulPreflightChecks = [
    {
      capability: "delegated_workers",
      reason: "Delegated workers are available.",
      severity: "warn",
      status: "pass",
    },
    {
      capability: "goal_tools",
      reason: "Goal tools help long scans preserve completion criteria.",
      severity: "suggest",
      status: "pass",
    },
    {
      capability: "goals_enabled",
      reason: "Goals are enabled.",
      severity: "suggest",
      status: "pass",
    },
  ];
  const incompletePreflightProgress = await testServer.callTool(90162, {
    name: "update_codex_security_scan_progress",
    arguments: {
      scanId,
      handoffClaimToken,
      preflightChecks: [
        {
          capability: "usable_worker_slots_6",
          reason: "The runtime did not report worker capacity.",
          severity: "block",
          status: "unknown",
        },
        ...successfulPreflightChecks,
      ],
    },
  });
  assertNoError(incompletePreflightProgress);
  assert.equal(
    incompletePreflightProgress.result.structuredContent.scan.progress
      .preflightIssues[0].status,
    "unknown",
  );
  assert.deepEqual(
    incompletePreflightProgress.result.structuredContent.scan.progress
      .preflightProgress,
    { completed: 3, total: 4 },
  );

  const blockedPreflightProgress = await testServer.callTool(90163, {
    name: "update_codex_security_scan_progress",
    arguments: {
      scanId,
      handoffClaimToken,
      preflightChecks: [
        {
          capability: "usable_worker_slots_6",
          reason: "Only three usable worker slots are available.",
          severity: "block",
          status: "fail",
        },
        ...successfulPreflightChecks,
      ],
    },
  });
  assertNoError(blockedPreflightProgress);
  assert.equal(
    blockedPreflightProgress.result.structuredContent.scan.progress
      .preflightIssues[0].capability,
    "usable_worker_slots_6",
  );
  assert.deepEqual(
    blockedPreflightProgress.result.structuredContent.scan.progress
      .preflightProgress,
    { completed: 4, total: 4 },
  );

  const readyPreflightProgress = await testServer.callTool(90164, {
    name: "update_codex_security_scan_progress",
    _meta: {
      "openai/threadId": "fixture-thread",
      "x-codex-turn-metadata": {
        model: "gpt-5.6-terra",
        reasoning_effort: "low",
      },
    },
    arguments: {
      scanId,
      handoffClaimToken,
      preflightChecks: [
        {
          capability: "usable_worker_slots_6",
          reason: "The scan will continue with reduced parallelism.",
          severity: "warn",
          status: "fail",
        },
        ...successfulPreflightChecks,
      ],
    },
  });
  assertNoError(readyPreflightProgress);
  assert.equal(
    readyPreflightProgress.result.structuredContent.scan.model,
    "gpt-5.6-terra",
  );
  assert.equal(
    readyPreflightProgress.result.structuredContent.scan.reasoningEffort,
    "low",
  );
  assert.equal(
    readyPreflightProgress.result.structuredContent.scan.progress
      .preflightIssues[0].severity,
    "warn",
  );
  assert.deepEqual(
    readyPreflightProgress.result.structuredContent.scan.progress
      .preflightProgress,
    { completed: 4, total: 4 },
  );
  assert.equal(
    readyPreflightProgress.result.structuredContent.scan.userContext,
    urlContextUpdate,
  );

  const nextPhaseUserContext = "Prioritize password-reset token validation.";
  const updatedPhaseContext = await testServer.callTool(92013, {
    name: "update_codex_security_scan_context",
    arguments: {
      handoffClaimToken,
      scanId,
      userContext: nextPhaseUserContext,
    },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assertNoError(updatedPhaseContext);

  const updated = await testServer.callTool(8, {
    name: "update_codex_security_scan_progress",
    arguments: {
      scanId,
      phase: "validation",
      phaseItemsTotal: 4,
      phaseItemsCompleted: 1,
      phaseProgressUnit: "candidate_findings",
      reviewItemsTotal: 31,
      reviewItemsCompleted: 22,
      reportableFindingsCount: 1,
      handoffClaimToken,
    },
  });
  assertNoError(updated);
  assert.equal(
    updated.result.structuredContent.scan.userContext,
    nextPhaseUserContext,
  );
  assert.deepEqual(updated.result.structuredContent.scan.progress.coverage, {
    closedRows: 22,
    filesTotal: 1,
    worklistRows: 31,
  });
  assert.deepEqual(
    updated.result.structuredContent.scan.progress.phaseProgress,
    {
      completed: 1,
      total: 4,
      unit: "candidate_findings",
    },
  );
  assert.equal(
    updated.result.structuredContent.scan.progress.preflightIssues[0]
      .capability,
    "usable_worker_slots_6",
  );
  assert.deepEqual(
    updated.result.structuredContent.scan.progress.preflightProgress,
    {
      completed: 4,
      total: 4,
    },
  );

  await writeCompletedContract(initializedScanDir, scanId, snapshotDigest);
  await writeFile(path.join(target, "src/a.py"), "changed\n");
  const completed = await testServer.callTool(802, {
    name: "complete_codex_security_scan",
    arguments: { handoffClaimToken, scanId },
  });
  assertNoError(completed);
  assert.deepEqual(completed.result.structuredContent.scan.warnings, [
    "Directory contents changed while the scan was running; results were saved for the original snapshot.",
  ]);
  await writeFile(path.join(target, "src/a.py"), "vulnerable\n");
  assert.equal(
    completed.result.structuredContent.scan.progress.status,
    "complete",
  );
  assert.equal(completed.result.structuredContent.scan.findings.length, 2);
  assert.equal(
    completed.result.structuredContent.workspace.results.progress.status,
    "complete",
  );
  const refreshed = await testServer.callTool(10, {
    name: "get_codex_security_scan",
    arguments: { scanId },
  });
  assertNoError(refreshed);
  const results = refreshed.result.structuredContent.scan;
  assert.equal(results.findings.length, 2);
  assert.equal(results.findingCount, 2);
  assert.deepEqual(results.severityCounts, { high: 1, informational: 1 });
  assert.equal(results.reportAvailable, true);
  assert.equal(
    results.artifacts.findings,
    path.join(initializedScanDir, "findings.json"),
  );
  assert.equal(
    results.artifacts.markdownReport,
    path.join(initializedScanDir, "report.md"),
  );
  assert.equal(
    results.findings[0].locations[0].absolutePath,
    path.join(await realpath(target), "src/a.py"),
  );
  assert.deepEqual(results.findings[0].triage, { status: "open" });
  assert.deepEqual(results.findings[0].remediationState, { state: "idle" });

  const occurrenceId = results.findings[0].occurrenceId;
  const remediationRequestId = randomUUID();
  const closedFinding = await testServer.callTool(60, {
    name: "set_codex_security_finding_triage",
    arguments: {
      occurrenceId,
      status: "closed",
      closeReason: "false_positive",
      note: "The archive path is normalized before the write.",
    },
  });
  assertNoError(closedFinding);
  assert.equal(
    closedFinding.result.structuredContent.scan.findings[0].triage.status,
    "closed",
  );
  assert.equal(
    closedFinding.result.structuredContent.scan.findings[0].triage.closeReason,
    "false_positive",
  );

  const generationActionToken = randomUUID();
  const rejectedClosedPatch = await testServer.callTool(159, {
    name: "request_codex_security_finding_remediation",
    arguments: {
      actionToken: generationActionToken,
      occurrenceId,
      requestId: remediationRequestId,
    },
  });
  assert.equal(rejectedClosedPatch.result.isError, true);
  assert.match(
    rejectedClosedPatch.result.content[0].text,
    /Reopen this finding/,
  );
  const reopenedFinding = await testServer.callTool(160, {
    name: "set_codex_security_finding_triage",
    arguments: { occurrenceId, status: "open" },
  });
  assertNoError(reopenedFinding);

  const canceledRequestId = randomUUID();
  const canceledActionToken = randomUUID();
  const requestedThenCanceledPatch = await testServer.callTool(500, {
    name: "request_codex_security_finding_remediation",
    arguments: {
      actionToken: canceledActionToken,
      occurrenceId,
      requestId: canceledRequestId,
    },
  });
  assertNoError(requestedThenCanceledPatch);
  const canceledPatch = await testServer.callTool(501, {
    name: "cancel_codex_security_finding_remediation_request",
    arguments: {
      actionToken: canceledActionToken,
      occurrenceId,
      requestId: canceledRequestId,
    },
  });
  assertNoError(canceledPatch);
  assert.deepEqual(
    canceledPatch.result.structuredContent.scan.findings[0].remediationState,
    {
      state: "idle",
    },
  );

  const requestedPatch = await testServer.callTool(61, {
    name: "request_codex_security_finding_remediation",
    arguments: {
      actionToken: generationActionToken,
      occurrenceId,
      requestId: remediationRequestId,
    },
  });
  assertNoError(requestedPatch);
  assert.equal(
    requestedPatch.result.structuredContent.scan.findings[0].remediationState
      .state,
    "requested",
  );
  const rejectedPendingClose = await testServer.callTool(161, {
    name: "set_codex_security_finding_triage",
    arguments: { occurrenceId, status: "closed", closeReason: "already_fixed" },
  });
  assert.equal(rejectedPendingClose.result.isError, true);
  assert.match(
    rejectedPendingClose.result.content[0].text,
    /pending remediation operation/,
  );
  const remediationPatch = `diff --git a/src/a.py b/src/a.py
--- a/src/a.py
+++ b/src/a.py
@@ -1 +1 @@
-vulnerable
+fixed
`;
  await writeFile(
    path.join(initializedScanDir, "remediation.patch"),
    remediationPatch,
  );
  const generatedPatch = await testServer.callTool(62, {
    name: "set_codex_security_finding_remediation",
    arguments: {
      actionToken: generationActionToken,
      occurrenceId,
      requestId: remediationRequestId,
      expectedVersion: 1,
      state: "generated",
      patchPath: "remediation.patch",
      patchDigest: `sha256:${hash("sha256", remediationPatch)}`,
      summary: "Contain archive extraction under the output root.",
    },
  });
  assertNoError(generatedPatch);
  assert.equal(
    generatedPatch.result.structuredContent.scan.findings[0].remediationState
      .state,
    "generated",
  );
  assert.equal(
    generatedPatch.result.structuredContent.scan.findings[0].remediationState
      .patch,
    remediationPatch,
  );

  const applyActionToken = randomUUID();
  const requestedApply = await testServer.callTool(65, {
    name: "request_codex_security_finding_remediation_action",
    arguments: {
      action: "apply",
      actionToken: applyActionToken,
      expectedVersion: 2,
      occurrenceId,
      requestId: remediationRequestId,
    },
  });
  assertNoError(requestedApply);
  assert.equal(
    requestedApply.result.structuredContent.scan.findings[0].remediationState
      .pendingAction,
    "apply",
  );
  assert.equal(
    requestedApply.result.structuredContent.scan.findings[0].remediationState
      .version,
    3,
  );
  const markedApplyDelivered = await testServer.callTool(166, {
    name: "mark_codex_security_finding_remediation_delivered",
    arguments: {
      actionToken: applyActionToken,
      occurrenceId,
      requestId: remediationRequestId,
    },
  });
  assertNoError(markedApplyDelivered);
  assert.ok(
    markedApplyDelivered.result.structuredContent.scan.findings[0]
      .remediationState.actionDeliveredAt,
  );
  execFileSync(
    "git",
    ["apply", "--no-index", path.join(initializedScanDir, "remediation.patch")],
    {
      cwd: target,
    },
  );

  const appliedPatch = await testServer.callTool(66, {
    name: "set_codex_security_finding_remediation",
    arguments: {
      actionToken: applyActionToken,
      baseRevision: "unversioned",
      expectedVersion: 3,
      occurrenceId,
      requestId: remediationRequestId,
      state: "applied",
    },
  });
  assertNoError(appliedPatch);
  assert.equal(
    appliedPatch.result.structuredContent.scan.findings[0].remediationState
      .state,
    "applied",
  );

  const verifyActionToken = randomUUID();
  const requestedVerify = await testServer.callTool(168, {
    name: "request_codex_security_finding_remediation_action",
    arguments: {
      action: "verify",
      actionToken: verifyActionToken,
      expectedVersion: 4,
      occurrenceId,
      requestId: remediationRequestId,
    },
  });
  assertNoError(requestedVerify);
  assert.equal(
    requestedVerify.result.structuredContent.scan.findings[0].remediationState
      .pendingAction,
    "verify",
  );
  assert.equal(
    requestedVerify.result.structuredContent.scan.findings[0].remediationState
      .version,
    5,
  );

  const verifyingPatch = await testServer.callTool(169, {
    name: "set_codex_security_finding_remediation",
    arguments: {
      actionToken: verifyActionToken,
      baseRevision: "unversioned",
      expectedVersion: 5,
      occurrenceId,
      requestId: remediationRequestId,
      state: "verifying",
    },
  });
  assertNoError(verifyingPatch);
  assert.equal(
    verifyingPatch.result.structuredContent.scan.findings[0].remediationState
      .state,
    "verifying",
  );
  assert.equal(
    verifyingPatch.result.structuredContent.scan.findings[0].remediationState
      .pendingAction,
    "verify",
  );

  const verifiedPatch = await testServer.callTool(170, {
    name: "set_codex_security_finding_remediation",
    arguments: {
      actionToken: verifyActionToken,
      baseRevision: "unversioned",
      expectedVersion: 6,
      occurrenceId,
      requestId: remediationRequestId,
      state: "verified",
      verificationSummary: "Focused remediation checks passed.",
    },
  });
  assertNoError(verifiedPatch);
  assert.equal(
    verifiedPatch.result.structuredContent.scan.findings[0].remediationState
      .state,
    "verified",
  );
  assert.equal(
    verifiedPatch.result.structuredContent.scan.findings[0].remediationState
      .pendingAction,
    null,
  );
  assert.equal(
    verifiedPatch.result.structuredContent.scan.findings[0].remediationState
      .verificationSummary,
    "Focused remediation checks passed.",
  );

  const findingsPage = await testServer.callTool(67, {
    name: "list_codex_security_findings",
    arguments: { scanId, offset: 0, limit: 1 },
  });
  assertNoError(findingsPage);
  assert.equal(
    findingsPage.result.structuredContent.findingsPage.findings.length,
    1,
  );
  assert.equal(
    findingsPage.result.structuredContent.findingsPage.nextOffset,
    1,
  );
  assert.equal(findingsPage.result.structuredContent.findingsPage.total, 2);
  const filteredFindingsPage = await testServer.callTool(94001, {
    name: "list_codex_security_findings",
    arguments: {
      scanId,
      query: "SRC/A.PY",
      severity: "high",
      status: "open",
      limit: 1,
    },
  });
  assertNoError(filteredFindingsPage);
  assert.deepEqual(
    filteredFindingsPage.result.structuredContent.findingsPage.findings.map(
      (finding: { occurrenceId: string }) => finding.occurrenceId,
    ),
    [occurrenceId],
  );
  assert.equal(
    filteredFindingsPage.result.structuredContent.findingsPage.total,
    1,
  );

  const csvExport = await testServer.callTool(63, {
    name: "export_codex_security_findings",
    arguments: { scanId, format: "csv" },
  });
  assertNoError(csvExport);
  assert.equal(
    csvExport.result.structuredContent.export.path,
    path.join(initializedScanDir, "exports", "findings.csv"),
  );
  assert.match(
    await readFile(csvExport.result.structuredContent.export.path, "utf8"),
    /occurrence_id,finding_id,title/,
  );

  const sarifExport = await testServer.callTool(64, {
    name: "export_codex_security_findings",
    arguments: { scanId, format: "sarif" },
  });
  assertNoError(sarifExport);
  assert.equal(
    sarifExport.result.structuredContent.export.path,
    path.join(initializedScanDir, "exports", "results.sarif"),
  );

  const restarted = await testServer.callTool(171, {
    name: "start_codex_security_scan",
    arguments: { sessionId: workspace.id },
  });
  assertNoError(restarted);
  const canceledScanId =
    restarted.result.structuredContent.workspace.results.scanId;
  const unclaimedContext = await testServer.callTool(2010, {
    name: "get_codex_security_scan_context",
    arguments: { scanId: canceledScanId },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assert.equal(unclaimedContext.result.isError, true);
  assert.match(
    unclaimedContext.result.content[0].text,
    /handoff has not been delivered/,
  );
  assert.match(
    unclaimedContext.result.content[0].text,
    /Claim the pending Codex Security scan handoff/,
  );
  const rejectedWrongThreadCancel = await testServer.callTool(1169, {
    name: "cancel_codex_security_scan",
    arguments: { scanId: canceledScanId },
    _meta: { "openai/threadId": "fixture-other-thread" },
  });
  assert.equal(rejectedWrongThreadCancel.result.isError, true);
  assert.match(
    rejectedWrongThreadCancel.result.content[0].text,
    /owning Codex thread/,
  );
  const rejectedMissingThreadCancel = await testServer.callTool(1170, {
    name: "cancel_codex_security_scan",
    arguments: { scanId: canceledScanId },
  });
  assert.equal(rejectedMissingThreadCancel.result.isError, true);
  assert.match(
    rejectedMissingThreadCancel.result.content[0].text,
    /continuation thread.*Codex Security workbench/,
  );
  const canceledFromNativeRoute = await testServer.callTool(2210, {
    name: "cancel_codex_security_scan_from_app",
    arguments: { scanId: canceledScanId },
  });
  assertNoError(canceledFromNativeRoute);

  const canceled = await testServer.callTool(172, {
    name: "cancel_codex_security_scan",
    arguments: { scanId: canceledScanId },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assertNoError(canceled);
  assert.equal(
    canceled.result.structuredContent.workspace.results.progress.status,
    "canceled",
  );
  assert.equal(
    typeof canceled.result.structuredContent.workspace.results.canceledAt,
    "string",
  );

  const rejectedCanceledProgress = await testServer.callTool(173, {
    name: "update_codex_security_scan_progress",
    arguments: { scanId: canceledScanId, phase: "discovery" },
  });
  assert.equal(rejectedCanceledProgress.result.isError, true);
  assert.match(
    rejectedCanceledProgress.result.content[0].text,
    /Only a running scan/,
  );

  const fallbackStarted = await testServer.callTool(2011, {
    name: "start_codex_security_scan",
    arguments: { sessionId: workspace.id },
  });
  assertNoError(fallbackStarted);
  const fallbackScanId =
    fallbackStarted.result.structuredContent.workspace.results.scanId;
  const fallbackClaimToken = `recovery_${randomUUID()}`;
  const fallbackClaimed = await testServer.callTool(2012, {
    name: "claim_codex_security_scan_handoff_delivery",
    arguments: {
      claimToken: fallbackClaimToken,
      scanId: fallbackScanId,
      takeOverStale: true,
    },
  });
  assertNoError(fallbackClaimed);
  assert.equal(
    fallbackClaimed.result.structuredContent.workspace.results
      .handoffClaimToken,
    fallbackClaimToken,
  );
  const fallbackAttached = await testServer.callTool(2017, {
    name: "attach_codex_security_scan_continuation_thread",
    arguments: {
      claimToken: fallbackClaimToken,
      scanId: fallbackScanId,
      threadId: "fixture-recovery-thread",
    },
  });
  assertNoError(fallbackAttached);
  assert.equal(
    fallbackAttached.result.structuredContent.workspace.results
      .continuationThreadId,
    "fixture-recovery-thread",
  );
  const wrongRecoveryContext = await testServer.callTool(20171, {
    name: "get_codex_security_scan_context",
    arguments: {
      handoffClaimToken: `recovery_${randomUUID()}`,
      scanId: fallbackScanId,
    },
    _meta: { "openai/threadId": "fixture-replacement-recovery-thread" },
  });
  assert.equal(wrongRecoveryContext.result.isError, true);
  assert.match(
    wrongRecoveryContext.result.content[0].text,
    /handoff delivery could not be recorded|owned by another continuation/i,
  );
  const fallbackContext = await testServer.callTool(2013, {
    name: "get_codex_security_scan_context",
    arguments: {
      handoffClaimToken: fallbackClaimToken,
      scanId: fallbackScanId,
    },
  });
  assertNoError(fallbackContext);
  assert.equal(
    fallbackContext.result.structuredContent.scan.handoffStatus,
    "delivered",
  );
  assert.equal(
    fallbackContext.result.structuredContent.scan.handoffClaimToken,
    undefined,
  );
  assert.equal(
    fallbackContext.result.structuredContent.workspace.results
      .handoffClaimToken,
    undefined,
  );
  const recoveredThreadContext = await testServer.callTool(20172, {
    name: "get_codex_security_scan_context",
    arguments: {
      handoffClaimToken: fallbackClaimToken,
      scanId: fallbackScanId,
    },
    _meta: { "openai/threadId": "fixture-replacement-recovery-thread" },
  });
  assertNoError(recoveredThreadContext);
  assert.equal(
    recoveredThreadContext.result.structuredContent.scan.handoffStatus,
    "delivered",
  );
  assert.equal(
    recoveredThreadContext.result.structuredContent.scan.continuationThreadId,
    "fixture-recovery-thread",
  );
  assert.equal(
    recoveredThreadContext.result.structuredContent.scan.handoffClaimToken,
    undefined,
  );
  assert.equal(
    recoveredThreadContext.result.structuredContent.workspace.results
      .handoffClaimToken,
    undefined,
  );
  const fallbackAppAcknowledgement = await testServer.callTool(2014, {
    name: "mark_codex_security_scan_handoff_delivered",
    arguments: { claimToken: fallbackClaimToken, scanId: fallbackScanId },
  });
  assertNoError(fallbackAppAcknowledgement);
  assert.equal(
    fallbackAppAcknowledgement.result.structuredContent.workspace.results
      .handoffStatus,
    "delivered",
  );
  const rotatedFallbackClaimToken = `recovery_${randomUUID()}`;
  execFileSync(process.env.PYTHON?.trim() || "python3", [
    "-c",
    `import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as connection:
    updated = connection.execute("UPDATE scans SET handoff_status = 'pending', handoff_claim_token = ?, continuation_thread_id = NULL WHERE id = ?", (sys.argv[2], sys.argv[3]))
    assert updated.rowcount == 1`,
    path.join(stateDir, "workbench.sqlite3"),
    rotatedFallbackClaimToken,
    fallbackScanId,
  ]);
  const staleRecoveryContext = await testServer.callTool(20173, {
    name: "get_codex_security_scan_context",
    arguments: {
      handoffClaimToken: fallbackClaimToken,
      scanId: fallbackScanId,
    },
    _meta: { "openai/threadId": "fixture-replacement-recovery-thread" },
  });
  assert.equal(staleRecoveryContext.result.isError, true);
  assert.match(
    staleRecoveryContext.result.content[0].text,
    /handoff delivery could not be recorded|owned by another continuation/i,
  );
  const scanList = await testServer.callTool(2212, {
    name: "list_codex_security_scans",
    arguments: {},
  });
  assertNoError(scanList);
  const listedFallback = scanList.result.structuredContent.scans.find(
    (scan: { targetId: string; scanId: string }) =>
      scan.scanId === fallbackScanId,
  );
  assert.equal(listedFallback.progress.status, "running");
  assert.equal("artifacts" in listedFallback, false);
  assert.equal("findings" in listedFallback, false);
  const globalFindings = await testServer.callTool(2213, {
    name: "list_codex_security_global_findings",
    arguments: { limit: 1 },
  });
  assertNoError(globalFindings);
  const indexedFinding = globalFindings.result.structuredContent.findings.find(
    (finding: { occurrenceId: string }) =>
      finding.occurrenceId === occurrenceId,
  );
  assert.equal(globalFindings.result.structuredContent.limit, 1);
  assert.equal(globalFindings.result.structuredContent.nextOffset, 1);
  assert.equal(indexedFinding.scanId, scanId);
  assert.equal(indexedFinding.status, "open");
  assert.equal(indexedFinding.occurrenceCount, 1);
  assert.match(indexedFinding.targetId, /^target_sha256_[0-9a-f]{64}$/);
  const globalFindingsNext = await testServer.callTool(2215, {
    name: "list_codex_security_global_findings",
    arguments: { limit: 20, offset: 1 },
  });
  assertNoError(globalFindingsNext);
  assert.equal(globalFindingsNext.result.structuredContent.findings.length, 1);
  assert.equal(globalFindingsNext.result.structuredContent.limit, 20);
  assert.equal(globalFindingsNext.result.structuredContent.offset, 1);
  assert.equal(globalFindingsNext.result.structuredContent.nextOffset, null);
  const filteredGlobalFindings = await testServer.callTool(94002, {
    name: "list_codex_security_global_findings",
    arguments: {
      limit: 1,
      query: "SRC/A.PY",
      severity: "high",
      status: "open",
      targetId: indexedFinding.targetId,
    },
  });
  assertNoError(filteredGlobalFindings);
  assert.deepEqual(
    filteredGlobalFindings.result.structuredContent.findings.map(
      (finding: { occurrenceId: string }) => finding.occurrenceId,
    ),
    [occurrenceId],
  );
  assert.equal(
    filteredGlobalFindings.result.structuredContent.nextOffset,
    null,
  );
  const repositories = await testServer.callTool(2214, {
    name: "list_codex_security_repositories",
    arguments: {},
  });
  assertNoError(repositories);
  const indexedRepository =
    repositories.result.structuredContent.repositories.find(
      (repository: { targetId: string }) =>
        repository.targetId === indexedFinding.targetId,
    );
  assert.equal(indexedRepository.checkoutAvailable, true);
  assert.equal(indexedRepository.latestScan.scanId, fallbackScanId);
  assert.equal(indexedRepository.openFindingsCount, 2);
  assert.equal(
    indexedRepository.scanCount,
    scanList.result.structuredContent.scans.filter(
      (scan: { targetId: string; scanId: string }) =>
        scan.targetId === indexedFinding.targetId,
    ).length,
  );
  const filteredScans = await testServer.callTool(94003, {
    name: "list_codex_security_scans",
    arguments: {
      limit: 1,
      mode: "standard",
      query: indexedFinding.targetPath.toUpperCase(),
      status: "running",
      targetId: indexedFinding.targetId,
    },
  });
  assertNoError(filteredScans);
  assert.equal(
    filteredScans.result.structuredContent.scans[0].scanId,
    fallbackScanId,
  );
  assert.equal(filteredScans.result.structuredContent.limit, 1);
  const filteredRepositories = await testServer.callTool(94004, {
    name: "list_codex_security_repositories",
    arguments: {
      limit: 1,
      query: indexedFinding.targetPath.toUpperCase(),
      status: "open_findings",
      targetId: indexedFinding.targetId,
    },
  });
  assertNoError(filteredRepositories);
  assert.deepEqual(
    filteredRepositories.result.structuredContent.repositories.map(
      (repository: { targetId: string }) => repository.targetId,
    ),
    [indexedFinding.targetId],
  );
  const rotatedAttached = await testServer.callTool(2030, {
    name: "attach_codex_security_scan_continuation_thread",
    arguments: {
      claimToken: rotatedFallbackClaimToken,
      scanId: fallbackScanId,
      threadId: "fixture-rotated-recovery-thread",
    },
  });
  assertNoError(rotatedAttached);
  const observedRotatedScan = await testServer.callTool(2031, {
    name: "get_codex_security_scan",
    arguments: { scanId: fallbackScanId },
  });
  assertNoError(observedRotatedScan);
  assert.equal(
    observedRotatedScan.result.structuredContent.scan.continuationThreadId,
    "fixture-rotated-recovery-thread",
  );
  let rejectedRequestId = 2032;
  for (const operation of [
    {
      name: "update_codex_security_scan_progress",
      arguments: { phase: "discovery" },
    },
    { name: "complete_codex_security_scan", arguments: {} },
    {
      name: "fail_codex_security_scan",
      arguments: { message: "stale continuation" },
    },
  ]) {
    for (const staleClaimToken of [undefined, fallbackClaimToken]) {
      const rejected = await testServer.callTool(rejectedRequestId++, {
        name: operation.name,
        arguments: {
          ...operation.arguments,
          ...(staleClaimToken == null
            ? {}
            : { handoffClaimToken: staleClaimToken }),
          scanId: fallbackScanId,
        },
      });
      assert.equal(rejected.result.isError, true);
      assert.match(
        rejected.result.content[0].text,
        /owned by another continuation/,
      );
    }
  }
  const rotatedProgress = await testServer.callTool(2038, {
    name: "update_codex_security_scan_progress",
    arguments: {
      handoffClaimToken: rotatedFallbackClaimToken,
      phase: "discovery",
      scanId: fallbackScanId,
    },
  });
  assertNoError(rotatedProgress);
  const rotatedFailure = await testServer.callTool(2039, {
    name: "fail_codex_security_scan",
    arguments: {
      handoffClaimToken: rotatedFallbackClaimToken,
      message: "rotated continuation stopped",
      scanId: fallbackScanId,
    },
  });
  assertNoError(rotatedFailure);
  assert.equal(
    rotatedFailure.result.structuredContent.scan.progress.status,
    "failed",
  );
  const unavailableRecovery = await testServer.callTool(2040, {
    name: "recover_codex_security_scan_results",
    arguments: { scanId: fallbackScanId },
  });
  assert.equal(unavailableRecovery.result.isError, true);
  assert.match(
    unavailableRecovery.result.content[0].text,
    /No saved stopped-scan results were available to recover/,
  );

  const silentRefresh = await testServer.callTool(11, {
    name: "open_codex_security_workspace",
    arguments: { sessionId: workspace.id },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assertNoError(silentRefresh);

  const replacementWorkspaceResponse = await testServer.callTool(42, {
    name: "open_codex_security_workspace",
    arguments: { targetPath: target, targetTitle: "Old target title" },
    _meta: { "openai/threadId": "fixture-aux-thread" },
  });
  assertNoError(replacementWorkspaceResponse);
  const replacementWorkspace =
    replacementWorkspaceResponse.result.structuredContent.workspace;
  const replacementSaved = await testServer.callTool(43, {
    name: "submit_codex_security_setup",
    arguments: {
      sessionId: replacementWorkspace.id,
      targetPath: replacementTarget,
      scope: ".",
      mode: "standard",
    },
  });
  assertNoError(replacementSaved);
  assert.equal(
    replacementSaved.result.structuredContent.workspace.targetTitle,
    path.basename(replacementTarget),
  );

  const nativeSetupOpen = await testServer.callTool(9226, {
    name: "open_codex_security_workspace",
    arguments: {
      targetPath: target,
      scope: ".",
      mode: "standard",
    },
    _meta: { "openai/threadId": "fixture-native-setup-thread" },
  });
  assertNoError(nativeSetupOpen);
  assert.match(
    nativeSetupOpen.result.structuredContent.workspace.id,
    /^[0-9a-f-]{36}$/,
  );
  assert.equal(
    nativeSetupOpen.result.structuredContent.workspace.results,
    undefined,
  );

  const invalidScanStarted = await testServer.callTool(9401, {
    name: "start_codex_security_scan",
    arguments: { sessionId: workspace.id },
  });
  assertNoError(invalidScanStarted);
  const invalidScanId =
    invalidScanStarted.result.structuredContent.workspace.results.scanId;
  const invalidScanClaimToken = randomUUID();
  const invalidScanClaimed = await testServer.callTool(9402, {
    name: "claim_codex_security_scan_handoff_delivery",
    arguments: { claimToken: invalidScanClaimToken, scanId: invalidScanId },
  });
  assertNoError(invalidScanClaimed);
  const prematureCompletion = await testServer.callTool(9403, {
    name: "complete_codex_security_scan",
    arguments: {
      handoffClaimToken: invalidScanClaimToken,
      scanId: invalidScanId,
    },
  });
  assert.equal(prematureCompletion.result.isError, true);
  assert.match(
    prematureCompletion.result.content[0].text,
    /scan-manifest\.json/,
  );
  const resumableScan = await testServer.callTool(9404, {
    name: "get_codex_security_scan",
    arguments: { scanId: invalidScanId },
  });
  assertNoError(resumableScan);
  assert.equal(
    resumableScan.result.structuredContent.scan.progress.status,
    "running",
  );

  assert.equal(
    (await readFile(path.join(stateDir, "workbench.sqlite3"))).length > 0,
    true,
  );
} finally {
  await testServer.stop();
  await rm(target, { recursive: true, force: true });
  await rm(gitTarget, { recursive: true, force: true });
  await rm(replacementTarget, { recursive: true, force: true });
  await rm(stateDir, { recursive: true, force: true });
  await rm(scanRoot, { recursive: true, force: true });
  await rm(launchCwd, { recursive: true, force: true });
}
