import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const sourcePluginRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../..",
);
const pluginRoot = path.resolve(
  sourcePluginRoot,
  "../../sdk/typescript/_bundled_plugin",
);
const mcpAppRoot = path.join(sourcePluginRoot, "mcp-app");
const pluginManifest = JSON.parse(
  await readFile(path.join(pluginRoot, ".codex-plugin", "plugin.json"), "utf8"),
);
const PLUGIN_VERSION = pluginManifest.version;
assert.equal(typeof PLUGIN_VERSION, "string");
const parentSandboxState = {
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
  sandboxCwd: pathToFileURL(pluginRoot).href,
};
const packageManifest = JSON.parse(
  await readFile(path.join(mcpAppRoot, "package.json"), "utf8"),
);
const packageLock = JSON.parse(
  await readFile(path.join(mcpAppRoot, "package-lock.json"), "utf8"),
);
const MCP_APP_VERSION = packageManifest.version;
assert.equal(packageLock.version, MCP_APP_VERSION);
assert.equal(packageLock.packages[""].version, MCP_APP_VERSION);
const installedPluginRoot = pluginRoot;
const serverPath = path.join(installedPluginRoot, "mcp", "server.mjs");
const mcpConfig = JSON.parse(
  await readFile(path.join(installedPluginRoot, ".mcp.json"), "utf8"),
);
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
    "CODEX_SECURITY_KNOWLEDGE_BASE",
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
const scanHandoffSource = await readFile(
  path.join(mcpAppRoot, "src", "scan-handoff.ts"),
  "utf8",
);
const serverSource = await readFile(
  path.join(mcpAppRoot, "server.ts"),
  "utf8",
);
assert.match(
  serverSource,
  /timeout:\s*\[[^\]]*"start-prompt-only-scan"[^\]]*\]\.includes\(args\[0\] \?\? ""\) \? 300_000 : 30_000/,
  "Prompt-only scan startup must use the same five-minute timeout as other scan starts.",
);
const authenticatedArtifactClaimSource = serverSource.match(
  /if \(\s*handoffClaimToken\s*&& threadId[\s\S]*?authenticatedArtifactClaims\.set\(scanId,[\s\S]*?\n\s*\}/,
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
assert.match(scanHandoffSource, /handoffClaimToken: string/);
assert.match(scanHandoffSource, /using scanId .* and handoffClaimToken/);
assert.match(
  scanHandoffSource,
  /record_codex_security_scan_draft\(\{ scanId,[^}]*handoffClaimToken/,
);
assert.match(
  scanHandoffSource,
  /derived findings\/<slug>\/<slug>\.md write-up/,
);
assert.match(
  scanHandoffSource,
  /other derived scan outputs required by the active scan skills/,
);
assert.match(scanHandoffSource, /Do not author report\.md/);
assert.match(
  scanHandoffSource,
  /workbench writes findings\.json, coverage\.json, and scan-manifest\.json/,
);
assert.match(scanHandoffSource, /canonical-artifact write/);
assert.match(
  scanHandoffSource,
  /Do not call completion with missing artifacts/,
);
assert.match(
  scanHandoffSource,
  /Completion is finalization only; it does not create missing artifacts or run skipped phases/,
);
assert.match(
  scanHandoffSource,
  /If complete_codex_security_scan fails, stop the current response and surface the exact MCP error/,
);
assert.match(scanHandoffSource, /Do not retry completion in the same response/);
assert.doesNotMatch(scanHandoffSource, /report\.html/);
assert.doesNotMatch(
  scanHandoffSource,
  /HTML report as one bare absolute file:\/\/ URL on its own line/,
);
assert.doesNotMatch(
  scanHandoffSource,
  /link the generated HTML report.*with markdown local-file links/,
);
assert.doesNotMatch(
  scanHandoffSource,
  /Write the completed findings\.json, coverage\.json, scan-manifest\.json, HTML report, and markdown report/,
);
const target = await mkdtemp(path.join(tmpdir(), "codex-security-target-"));
const replacementTarget = await mkdtemp(
  path.join(tmpdir(), "codex-security-replacement-"),
);
const gitTarget = await mkdtemp(
  path.join(tmpdir(), "codex-security-git-target-"),
);
const stateDir = await mkdtemp(path.join(tmpdir(), "codex-security-state-"));
const scanRoot = await mkdtemp(
  path.join(tmpdir(), "codex-security-scan-root-"),
);
const resolvedScanRoot = await realpath(scanRoot);
const launchCwd = await mkdtemp(
  path.join(tmpdir(), "codex-security-launch-cwd-"),
);
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
const gitBase = execFileSync("git", ["-C", gitTarget, "rev-parse", "HEAD"], {
  encoding: "utf8",
}).trim();
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
const gitHead = execFileSync("git", ["-C", gitTarget, "rev-parse", "HEAD"], {
  encoding: "utf8",
}).trim();

function startTestServer({
  args = [serverPath, "--stdio"],
  command = process.execPath,
  cwd,
  env = {},
}) {
  const childEnvironment = { ...process.env };
  for (const [name, value] of Object.entries(env)) {
    if (value === undefined) {
      delete childEnvironment[name];
    } else {
      childEnvironment[name] = value;
    }
  }
  const childProcess = spawn(command, args, {
    cwd,
    env: childEnvironment,
    stdio: ["pipe", "pipe", "inherit"],
  });
  const responses = [];
  let stdout = "";
  childProcess.stdout.setEncoding("utf8");
  childProcess.stdout.on("data", (chunk) => {
    stdout += chunk;
    let newlineIndex = stdout.indexOf("\n");
    while (newlineIndex >= 0) {
      const line = stdout.slice(0, newlineIndex).trim();
      stdout = stdout.slice(newlineIndex + 1);
      if (line) responses.push(JSON.parse(line));
      newlineIndex = stdout.indexOf("\n");
    }
  });

  return {
    notify(method, params = {}) {
      childProcess.stdin.write(
        `${JSON.stringify({ jsonrpc: "2.0", method, params })}\n`,
      );
    },
    sendRequest(id, method, params = {}) {
      childProcess.stdin.write(
        `${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`,
      );
    },
    sendResponse(id, result) {
      childProcess.stdin.write(
        `${JSON.stringify({ jsonrpc: "2.0", id, result })}\n`,
      );
    },
    sendError(id, code, message) {
      childProcess.stdin.write(
        `${JSON.stringify({
          jsonrpc: "2.0",
          id,
          error: { code, message },
        })}\n`,
      );
    },
    async waitForMessage(predicate, description = "matching JSON-RPC message") {
      const started = Date.now();
      while (Date.now() - started < 30000) {
        const message = responses.find(predicate);
        if (message) return message;
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      throw new Error(`Timed out waiting for ${description}`);
    },
    async requestAndWait(id, method, params = {}) {
      childProcess.stdin.write(
        `${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`,
      );
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
  const emptyPath = await mkdtemp(
    path.join(tmpdir(), "codex-security-empty-path-"),
  );
  const launcherPath = path.join(pluginRoot, "scripts", "launch_codex_security_mcp");
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
      ? process.env.ComSpec ??
        path.join(process.env.SystemRoot ?? "C:\\Windows", "System32", "cmd.exe")
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
      await bundledNodeServer.requestAndWait(1, "initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "codex-security-bundled-node-smoke", version: "0.1.0" },
      }),
    );
    assertNoError(await bundledNodeServer.requestAndWait(2, "tools/list"));
    if (!windows) {
      assert.equal(await readFile(path.join(emptyPath, "bundled-node-used"), "utf8"), "bundled");
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
      await missingPythonServer.requestAndWait(1, "initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: {
          name: "codex-security-missing-python-smoke",
          version: "0.1.0",
        },
      }),
    );
    const response = await missingPythonServer.requestAndWait(2, "tools/call", {
      name: "inspect_codex_security_target",
      arguments: { targetPath: target },
    });
    assert.equal(response.result.isError, true);
    const errorText = response.result.content
      .map((item) => item.text)
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
  const helperRoot = await mkdtemp(
    path.join(tmpdir(), "codex-security-early-exit-helper-"),
  );
  const helper = path.join(helperRoot, "python");
  await writeFile(helper, "#!/bin/sh\nexit 2\n");
  await chmod(helper, 0o755);
  const server = startTestServer({
    cwd: pluginRoot,
    env: { CODEX_SECURITY_STATE_DIR: stateDir, PYTHON: helper },
  });
  try {
    assertNoError(
      await server.requestAndWait(1, "initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: {
          name: "codex-security-early-exit-smoke",
          version: "0.1.0",
        },
      }),
    );
    const response = await server.requestAndWait(2, "tools/call", {
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
      await noElicitationServer.requestAndWait(1, "initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: {
          name: "codex-security-no-elicitation-smoke",
          version: "0.1.0",
        },
      }),
    );
    const response = await noElicitationServer.requestAndWait(2, "tools/call", {
      name: "request_codex_security_user_input",
      arguments: {
        questions: [
          {
            header: "Continue?",
            id: "continue_scan",
            question: "Should Codex Security continue?",
            options: [
              {
                label: "Continue",
                description: "Continue the current workflow.",
              },
              {
                label: "Cancel",
                description: "Leave the current workflow paused.",
              },
            ],
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
  const nonUiStateDir = await mkdtemp(
    path.join(tmpdir(), "codex-security-non-ui-state-"),
  );
  const nonUiServer = startTestServer({
    cwd: pluginRoot,
    env: { CODEX_SECURITY_STATE_DIR: nonUiStateDir },
  });
  try {
    assertNoError(
      await nonUiServer.requestAndWait(1, "initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "codex-security-non-ui-smoke", version: "0.1.0" },
      }),
    );
    const response = await nonUiServer.requestAndWait(2, "tools/call", {
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
  const headlessStateDir = await mkdtemp(
    path.join(tmpdir(), "codex-security-headless-state-"),
  );
  const headlessScanRoot = await mkdtemp(
    path.join(tmpdir(), "codex-security-headless-scans-"),
  );
  const headlessServer = startTestServer({
    cwd: pluginRoot,
    env: {
      CODEX_SECURITY_SCAN_ROOT: headlessScanRoot,
      CODEX_SECURITY_STATE_DIR: headlessStateDir,
    },
  });
  const ownerThread = "fixture-headless-standard-thread";
  const headlessContext = (
    `Review https://example.test/internal. ${"Assess the HTTP boundary. ".repeat(44_000)}`
  ).trim();
  assert.ok(headlessContext.length > 1_000_000);
  try {
    assertNoError(
      await headlessServer.requestAndWait(1, "initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "codex-security-headless-smoke", version: "0.1.0" },
      }),
    );
    const withoutOwner = await headlessServer.requestAndWait(2, "tools/call", {
      name: "start_codex_security_standard_scan",
      arguments: { targetPath: target },
    });
    assert.equal(withoutOwner.result.isError, true);
    assert.match(withoutOwner.result.content[0].text, /owning Codex thread context/);

    const started = await headlessServer.requestAndWait(3, "tools/call", {
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

    const joined = await headlessServer.requestAndWait(4, "tools/call", {
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

    const wrongThread = await headlessServer.requestAndWait(6, "tools/call", {
      name: "list_codex_security_review_items",
      arguments: { scanId: result.scanId },
      _meta: { "openai/threadId": "fixture-headless-other-thread" },
    });
    assert.equal(wrongThread.result.isError, true);
    assert.match(wrongThread.result.content[0].text, /current continuation claim/);

    const standardInventory = await headlessServer.requestAndWait(7, "tools/call", {
      name: "list_codex_security_review_items",
      arguments: {
        scanId: result.scanId,
        handoffClaimToken: result.handoffClaimToken,
      },
      _meta: { "openai/threadId": "fixture-headless-delegated-thread" },
    });
    assert.equal(standardInventory.result.isError, true);
    assert.match(standardInventory.result.content[0].text, /only available for Deep or diff scans/);

    const progressed = await headlessServer.requestAndWait(8, "tools/call", {
      name: "update_codex_security_scan_progress",
      arguments: {
        scanId: result.scanId,
        handoffClaimToken: result.handoffClaimToken,
        preflightChecks: [],
      },
      _meta: { "openai/threadId": ownerThread },
    });
    assertNoError(progressed);

    const advanced = await headlessServer.requestAndWait(81, "tools/call", {
      name: "update_codex_security_scan_progress",
      arguments: {
        scanId: result.scanId,
        handoffClaimToken: result.handoffClaimToken,
        phase: "threat_model",
      },
      _meta: { "openai/threadId": ownerThread },
    });
    assertNoError(advanced);
    const rejoinedAfterPreflight = await headlessServer.requestAndWait(82, "tools/call", {
      name: "start_codex_security_standard_scan",
      arguments: {
        targetPath: target,
        userContext: headlessContext,
      },
      _meta: { "openai/threadId": ownerThread },
    });
    assertNoError(rejoinedAfterPreflight);
    assert.equal(rejoinedAfterPreflight.result.structuredContent.startDisposition, "joined");
    assert.equal(rejoinedAfterPreflight.result.structuredContent.scan.progress.phase, "threat_model");

    await writeCompletedContract(
      result.scanDir,
      result.scanId,
      result.scan.contract.target.requiredSnapshotDigest,
    );
    const completed = await headlessServer.requestAndWait(9, "tools/call", {
      name: "complete_codex_security_scan",
      arguments: {
        scanId: result.scanId,
        handoffClaimToken: result.handoffClaimToken,
      },
      _meta: { "openai/threadId": ownerThread },
    });
    assertNoError(completed);
    assert.equal(completed.result.structuredContent.scan.progress.status, "complete");
  } finally {
    await headlessServer.stop();
    await rm(headlessStateDir, { recursive: true, force: true });
    await rm(headlessScanRoot, { recursive: true, force: true });
  }
}

async function assertDeepScanPersistsWorkerStartupFailure() {
  const fixtureRoot = await mkdtemp(
    path.join(tmpdir(), "codex-security-deep-inventory-"),
  );
  const fixtureTarget = path.join(fixtureRoot, "repository");
  const fixtureState = path.join(fixtureRoot, "state");
  const fixtureScanRoot = path.join(fixtureRoot, "scans");
  await mkdir(path.join(fixtureTarget, "app"), { recursive: true });
  await writeFile(path.join(fixtureTarget, "app", "routes.py"), "route = 1\n");

  const deepServer = startTestServer({
    cwd: pluginRoot,
    env: {
      CODEX_CLI_PATH: path.join(fixtureRoot, "missing-deep-scan-codex"),
      CODEX_SECURITY_SCAN_ROOT: fixtureScanRoot,
      CODEX_SECURITY_STATE_DIR: fixtureState,
    },
  });
  try {
    assertNoError(
      await deepServer.requestAndWait(1, "initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: {
          name: "codex-security-deep-inventory-smoke",
          version: "0.1.0",
        },
      }),
    );

    const started = await deepServer.requestAndWait(2, "tools/call", {
      name: "start_codex_security_deep_scan",
      arguments: { targetPath: fixtureTarget },
      _meta: {
        "openai/threadId": "fixture-deep-inventory-thread",
        "codex/sandbox-state-meta": parentSandboxState,
      },
    });
    assert.equal(started.result.isError, true);
    assert.match(
      started.result.content.map((item) => item.text).join(" "),
      /missing-deep-scan-codex/,
    );

    const listed = await deepServer.requestAndWait(3, "tools/call", {
      name: "list_codex_security_scans",
      arguments: {},
    });
    assertNoError(listed);
    assert.equal(listed.result.structuredContent.scans.length, 1);
    const scan = listed.result.structuredContent.scans[0];
    assert.equal(scan.progress.status, "failed");
    await assert.rejects(
      readFile(path.join(scan.scanDir, "artifacts", "02_discovery", "in_scope_files.txt")),
      { code: "ENOENT" },
    );

    const publicationFailure =
      "Saved result publication failed: fixture retained result publication failure";
    execFileSync(process.env.PYTHON?.trim() || "python3", [
      "-c",
      [
        "import sqlite3, sys",
        "with sqlite3.connect(sys.argv[1]) as connection:",
        "    updated = connection.execute(\"UPDATE deep_scan_runs SET status = 'canceled', phase = 'terminal', cancel_requested = 1, error_message = ? WHERE scan_id = ?\", (sys.argv[2], sys.argv[3]))",
        "    assert updated.rowcount == 1",
      ].join("\n"),
      path.join(fixtureState, "workbench.sqlite3"),
      publicationFailure,
      scan.scanId,
    ]);
    const canceledWithPublicationFailure = await deepServer.requestAndWait(
      4,
      "tools/call",
      {
        name: "start_codex_security_deep_scan",
        arguments: { scanId: scan.scanId },
        _meta: {
          "openai/threadId": "fixture-deep-inventory-thread",
          "codex/sandbox-state-meta": parentSandboxState,
        },
      },
    );
    const publicationFailureText = canceledWithPublicationFailure.result.content
      .map((item) => item.text)
      .join(" ");
    assert.equal(canceledWithPublicationFailure.result.isError, true);
    assert.equal(canceledWithPublicationFailure.result.structuredContent, undefined);
    assert.match(publicationFailureText, /fixture retained result publication failure/);
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
      await failingElicitationServer.requestAndWait(1, "initialize", {
        protocolVersion: "2025-11-25",
        capabilities: { elicitation: { form: {} } },
        clientInfo: {
          name: "codex-security-failing-elicitation-smoke",
          version: "0.1.0",
        },
      }),
    );
    failingElicitationServer.sendRequest(2, "tools/call", {
      name: "request_codex_security_user_input",
      arguments: {
        questions: [
          {
            header: "Continue?",
            id: "continue_scan",
            question: "Should Codex Security continue?",
            options: [
              {
                label: "Continue",
                description: "Continue the current workflow.",
              },
              {
                label: "Cancel",
                description: "Leave the current workflow paused.",
              },
            ],
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

  const runtimeHome = await mkdtemp(
    path.join(tmpdir(), "codex-security-runtime-home-"),
  );
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
      await bundledPythonServer.requestAndWait(1, "initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: {
          name: "codex-security-bundled-python-smoke",
          version: "0.1.0",
        },
      }),
    );
    // Codex can install the primary runtime after the MCP server has started.
    // Creating this wrapper after initialization verifies call-time discovery.
    await mkdir(path.dirname(bundledPythonPath), { recursive: true });
    await writeFile(
      bundledPythonPath,
      [
        "#!/bin/sh",
        'printf bundled > "$CODEX_SECURITY_BUNDLED_PYTHON_MARKER"',
        'exec "$CODEX_SECURITY_TEST_SYSTEM_PYTHON" "$@"',
        "",
      ].join("\n"),
      { mode: 0o755 },
    );
    assertNoError(
      await bundledPythonServer.requestAndWait(2, "tools/call", {
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

function assertNoError(response) {
  assert.equal(response.error, undefined, response.error?.message);
  assert.equal(
    response.result?.isError,
    undefined,
    response.result?.content?.map((item) => item.text).join(" "),
  );
}

async function writeCompletedContract(scanDir, scanId, snapshotDigest) {
  const targetId = `target_sha256_${createHash("sha256")
    .update(`local-workspace\0${await realpath(target)}`)
    .digest("hex")}`;
  await writeFile(
    path.join(scanDir, "findings.json"),
    JSON.stringify({
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
          remediation:
            "Reject archive entries that escape the extraction root.",
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
    }),
  );
  await writeFile(
    path.join(scanDir, "coverage.json"),
    JSON.stringify({
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
    }),
  );
  await writeFile(
    path.join(scanDir, "scan-manifest.json"),
    JSON.stringify({
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
    }),
  );
}

try {
  const initialized = await requestAndWait(1, "initialize", {
    protocolVersion: "2025-11-25",
    capabilities: {
      elicitation: { form: {} },
    },
    clientInfo: { name: "codex-security-smoke", version: "0.1.0" },
  });
  assertNoError(initialized);
  assert.equal(initialized.result.capabilities.resources, undefined);
  assert.deepEqual(
    initialized.result.capabilities.experimental["codex/sandbox-state-meta"],
    {},
  );
  assert.deepEqual(initialized.result.capabilities.extensions["com.openai"], {});
  assert.deepEqual(initialized.result.capabilities.logging, {});
  await assertBundledNodeLauncher();
  await assertBundledPythonRuntime();
  await assertMissingPythonError();
  await assertWorkbenchStdinFailureDoesNotCrashServer();
  await assertUnavailableUserInputFallback();
  await assertWorkspaceWorksWithoutUiCapability();
  await assertHeadlessStandardScanWorksWithoutUiCapability();
  await assertDeepScanPersistsWorkerStartupFailure();
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
    (tool) => tool.name === "open_codex_security_workspace",
  );
  const startPromptOnlyScan = toolList.result.tools.find(
    (tool) => tool.name === "start_codex_security_prompt_only_scan",
  );
  assert.match(
    startPromptOnlyScan.description,
    /Standard and diff scans save progress checkpoints before their final semantic draft/,
    "Prompt-only scan instructions must align Diff callers with checkpointed handoffs",
  );
  const startHeadlessStandardScan = toolList.result.tools.find(
    (tool) => tool.name === "start_codex_security_standard_scan",
  );
  const getScan = toolList.result.tools.find(
    (tool) => tool.name === "get_codex_security_scan",
  );
  const listScans = toolList.result.tools.find(
    (tool) => tool.name === "list_codex_security_scans",
  );
  const listGlobalFindings = toolList.result.tools.find(
    (tool) => tool.name === "list_codex_security_global_findings",
  );
  const listRepositories = toolList.result.tools.find(
    (tool) => tool.name === "list_codex_security_repositories",
  );
  const getScanContext = toolList.result.tools.find(
    (tool) => tool.name === "get_codex_security_scan_context",
  );
  const updateScanContext = toolList.result.tools.find(
    (tool) => tool.name === "update_codex_security_scan_context",
  );
  const updateScanContextFromApp = toolList.result.tools.find(
    (tool) => tool.name === "update_codex_security_scan_context_from_app",
  );
  const submit = toolList.result.tools.find(
    (tool) => tool.name === "submit_codex_security_setup",
  );
  const inspectTarget = toolList.result.tools.find(
    (tool) => tool.name === "inspect_codex_security_target",
  );
  const inspectSetup = toolList.result.tools.find(
    (tool) => tool.name === "inspect_codex_security_setup",
  );
  const requestUserInput = toolList.result.tools.find(
    (tool) => tool.name === "request_codex_security_user_input",
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
  const invalidUserInput = await requestAndWait(9001, "tools/call", {
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
          options: [
            {
              label: "Continue",
              description: "Continue the current workflow.",
            },
            {
              label: "Cancel",
              description: "Leave the current workflow paused.",
            },
          ],
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
          options: [
            {
              label: "Continue",
              description: "Continue the current workflow.",
            },
            {
              label: "Cancel",
              description: "Leave the current workflow paused.",
            },
          ],
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
    (tool) => tool.name === "start_codex_security_scan",
  );
  const startDeepScan = toolList.result.tools.find(
    (tool) => tool.name === "start_codex_security_deep_scan",
  );
  const cancel = toolList.result.tools.find(
    (tool) => tool.name === "cancel_codex_security_scan",
  );
  const cancelFromApp = toolList.result.tools.find(
    (tool) => tool.name === "cancel_codex_security_scan_from_app",
  );
  const markHandoff = toolList.result.tools.find(
    (tool) => tool.name === "mark_codex_security_scan_handoff_delivered",
  );
  const claimHandoff = toolList.result.tools.find(
    (tool) => tool.name === "claim_codex_security_scan_handoff_delivery",
  );
  const releaseHandoff = toolList.result.tools.find(
    (tool) => tool.name === "release_codex_security_scan_handoff_delivery",
  );
  const attachHandoff = toolList.result.tools.find(
    (tool) => tool.name === "attach_codex_security_scan_continuation_thread",
  );
  const progress = toolList.result.tools.find(
    (tool) => tool.name === "update_codex_security_scan_progress",
  );
  const complete = toolList.result.tools.find(
    (tool) => tool.name === "complete_codex_security_scan",
  );
  const fail = toolList.result.tools.find(
    (tool) => tool.name === "fail_codex_security_scan",
  );
  const setFindingTriage = toolList.result.tools.find(
    (tool) => tool.name === "set_codex_security_finding_triage",
  );
  const requestFindingRemediation = toolList.result.tools.find(
    (tool) => tool.name === "request_codex_security_finding_remediation",
  );
  const requestFindingRemediationAction = toolList.result.tools.find(
    (tool) => tool.name === "request_codex_security_finding_remediation_action",
  );
  const claimFindingRemediationResend = toolList.result.tools.find(
    (tool) => tool.name === "claim_codex_security_finding_remediation_resend",
  );
  const releaseFindingRemediationClaim = toolList.result.tools.find(
    (tool) => tool.name === "release_codex_security_finding_remediation_claim",
  );
  const cancelFindingRemediationRequest = toolList.result.tools.find(
    (tool) => tool.name === "cancel_codex_security_finding_remediation_request",
  );
  const markFindingRemediationDelivered = toolList.result.tools.find(
    (tool) => tool.name === "mark_codex_security_finding_remediation_delivered",
  );
  const setFindingRemediation = toolList.result.tools.find(
    (tool) => tool.name === "set_codex_security_finding_remediation",
  );
  const exportFindings = toolList.result.tools.find(
    (tool) => tool.name === "export_codex_security_findings",
  );
  const listFindings = toolList.result.tools.find(
    (tool) => tool.name === "list_codex_security_findings",
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
  assert.deepEqual(startHeadlessStandardScan.inputSchema.required, ["targetPath"]);
  assert.equal(
    startHeadlessStandardScan.inputSchema.properties.userContext.maxLength,
    undefined,
  );
  assert.ok(getScanContext.inputSchema.properties.handoffClaimToken);
  assert.deepEqual(updateScanContext._meta.ui.visibility, ["model"]);
  assert.deepEqual(updateScanContextFromApp._meta.ui.visibility, ["app"]);
  assert.ok(updateScanContext.inputSchema.properties.handoffClaimToken);
  assert.equal(updateScanContext.inputSchema.properties.userContext.maxLength, undefined);
  assert.equal(updateScanContextFromApp.inputSchema.properties.userContext.maxLength, undefined);
  assert.deepEqual(updateScanContextFromApp.inputSchema.required, ["scanId", "userContext"]);
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
  for (const tool of [getScanContext, updateScanContext, progress, complete, fail]) {
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
  const missingDeepIdentity = await requestAndWait(9100, "tools/call", {
    name: "start_codex_security_deep_scan",
    arguments: {},
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assert.equal(missingDeepIdentity.result.isError, true);
  assert.match(
    missingDeepIdentity.result.content[0].text,
    /exactly one Deep Scan identity/,
  );
  const mixedDeepIdentity = await requestAndWait(9101, "tools/call", {
    name: "start_codex_security_deep_scan",
    arguments: { scanId: randomUUID(), targetPath: target },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assert.equal(mixedDeepIdentity.result.isError, true);
  assert.match(
    mixedDeepIdentity.result.content[0].text,
    /exactly one Deep Scan identity/,
  );
  const invalidDeepScope = await requestAndWait(9102, "tools/call", {
    name: "start_codex_security_deep_scan",
    arguments: { targetPath: target, scope: "src" },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assert.equal(invalidDeepScope.result.isError, true);
  assert.match(
    invalidDeepScope.result.content[0].text,
    /requires the whole target/,
  );
  const missingDeepThread = await requestAndWait(9103, "tools/call", {
    name: "start_codex_security_deep_scan",
    arguments: { targetPath: target },
  });
  assert.equal(missingDeepThread.result.isError, true);
  assert.match(
    missingDeepThread.result.content[0].text,
    /owning Codex thread context/,
  );
  const missingPersistedDeepScan = await requestAndWait(9104, "tools/call", {
    name: "start_codex_security_deep_scan",
    arguments: { scanId: randomUUID() },
    _meta: {
      "openai/threadId": "fixture-thread",
      "codex/sandbox-state-meta": parentSandboxState,
    },
  });
  const missingPersistedDeepScanText = missingPersistedDeepScan.result.content
    .map((item) => item.text)
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

  const urlContext = "Deployment details came from https://example.test/internal.";
  const urlContextAccepted = await requestAndWait(1290, "tools/call", {
    name: "open_codex_security_workspace",
    arguments: {
      targetPath: target,
      userContext: urlContext
    },
    _meta: { "openai/threadId": "fixture-url-context-thread" }
  });
  assertNoError(urlContextAccepted);
  assert.equal(
    urlContextAccepted.result.structuredContent.workspace.userContext,
    urlContext,
  );

  const opened = await requestAndWait(4, "tools/call", {
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

  const sameThreadReopen = await requestAndWait(1162, "tools/call", {
    name: "open_codex_security_workspace",
    arguments: { sessionId: workspace.id },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assertNoError(sameThreadReopen);
  assert.equal(
    sameThreadReopen.result.structuredContent.workspace.id,
    workspace.id,
  );

  const otherThreadOpened = await requestAndWait(1163, "tools/call", {
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

  const crossThreadReopen = await requestAndWait(1164, "tools/call", {
    name: "open_codex_security_workspace",
    arguments: { sessionId: workspace.id },
    _meta: { "openai/threadId": "fixture-other-thread" },
  });
  assert.equal(crossThreadReopen.result.isError, true);
  assert.match(
    crossThreadReopen.result.content[0].text,
    /workspace not found in this thread/,
  );

  const metadataFreeReopen = await requestAndWait(1165, "tools/call", {
    name: "open_codex_security_workspace",
    arguments: { sessionId: workspace.id },
  });
  assert.equal(metadataFreeReopen.result.isError, true);
  assert.match(
    metadataFreeReopen.result.content[0].text,
    /thread metadata is required/i,
  );

  const metadataFreeCreate = await requestAndWait(1166, "tools/call", {
    name: "open_codex_security_workspace",
    arguments: { targetPath: target },
  });
  assertNoError(metadataFreeCreate);
  assert.match(
    metadataFreeCreate.result.structuredContent.workspace.id,
    /^[0-9a-f-]{36}$/,
  );

  const savedOtherWorkspace = await requestAndWait(2020, "tools/call", {
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
  const otherStarted = await requestAndWait(2023, "tools/call", {
    name: "start_codex_security_scan",
    arguments: {
      sessionId: otherThreadOpened.result.structuredContent.workspace.id,
    },
  });
  assertNoError(otherStarted);

  const absoluteScopeOpened = await requestAndWait(150, "tools/call", {
    name: "open_codex_security_workspace",
    arguments: { targetPath: target, scope: target, mode: "standard" },
    _meta: { "openai/threadId": "fixture-aux-thread" },
  });
  assertNoError(absoluteScopeOpened);
  assert.equal(
    absoluteScopeOpened.result.structuredContent.workspace.scope,
    ".",
  );

  const invalidReopen = await requestAndWait(151, "tools/call", {
    name: "open_codex_security_workspace",
    arguments: { sessionId: workspace.id, scope: "." },
  });
  assert.equal(invalidReopen.result.isError, true);
  assert.match(invalidReopen.result.content[0].text, /sessionId only reopens/);

  const deepOpened = await requestAndWait(44, "tools/call", {
    name: "open_codex_security_workspace",
    arguments: { targetPath: target, scope: ".", mode: "deep" },
    _meta: { "openai/threadId": "fixture-aux-thread" },
  });
  assertNoError(deepOpened);
  assert.equal(deepOpened.result.structuredContent.workspace.mode, "deep");
  assert.equal(deepOpened.result.structuredContent.workspace.scope, ".");

  const diffOpened = await requestAndWait(45, "tools/call", {
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

  const inferredDiffOpened = await requestAndWait(152, "tools/call", {
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

  const contradictoryDiffOpened = await requestAndWait(153, "tools/call", {
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

  const scopedDeepOpened = await requestAndWait(154, "tools/call", {
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
  const nestedDiffOpened = await requestAndWait(155, "tools/call", {
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

  const inspectedSetup = await requestAndWait(46, "tools/call", {
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

  const inspectedCommitOpened = await requestAndWait(2200, "tools/call", {
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

  const inspectedCommitSaved = await requestAndWait(2201, "tools/call", {
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

  const invalidOpened = await requestAndWait(47, "tools/call", {
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

  const inspected = await requestAndWait(40, "tools/call", {
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

  const saved = await requestAndWait(5, "tools/call", {
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
  const started = await requestAndWait(6, "tools/call", {
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
      path.join(resolvedScanRoot, "codex-security-scans-"),
    ),
    true,
  );
  assert.equal(initializedScanDir.startsWith(`${stateDir}${path.sep}`), false);
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
  const claimedHandoff = await requestAndWait(2002, "tools/call", {
    name: "claim_codex_security_scan_handoff_delivery",
    arguments: { claimToken: handoffClaimToken, scanId },
  });
  assertNoError(claimedHandoff);
  assert.equal(
    claimedHandoff.result.structuredContent.workspace.results.handoffClaimToken,
    handoffClaimToken,
  );
  const attachedHandoff = await requestAndWait(20021, "tools/call", {
    name: "attach_codex_security_scan_continuation_thread",
    arguments: { claimToken: handoffClaimToken, scanId, threadId: "fixture-thread" },
  });
  assertNoError(attachedHandoff);
  const threadOwnedScan = await requestAndWait(2202, "tools/call", {
    name: "get_codex_security_scan",
    arguments: { scanId },
  });
  assertNoError(threadOwnedScan);
  assert.equal(
    threadOwnedScan.result.structuredContent.scan.continuationThreadId,
    "fixture-thread",
  );

  const wrongThreadDelivery = await requestAndWait(2009, "tools/call", {
    name: "get_codex_security_scan_context",
    arguments: { handoffClaimToken, scanId },
    _meta: { "openai/threadId": "fixture-other-thread" },
  });
  assert.equal(wrongThreadDelivery.result.isError, true);
  assert.match(
    wrongThreadDelivery.result.content[0].text,
    /owning Codex thread/,
  );

  const missingClaimToken = await requestAndWait(2005, "tools/call", {
    name: "get_codex_security_scan_context",
    arguments: { scanId },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assert.equal(missingClaimToken.result.isError, true);
  assert.match(
    missingClaimToken.result.content[0].text,
    /Pass the handoffClaimToken/,
  );

  const delivered = await requestAndWait(2003, "tools/call", {
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
  const reopenedWorkspace = await requestAndWait(2203, "tools/call", {
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

  const supersededClaim = await requestAndWait(2006, "tools/call", {
    name: "get_codex_security_scan_context",
    arguments: { handoffClaimToken: randomUUID(), scanId },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assert.equal(supersededClaim.result.isError, true);
  assert.match(
    supersededClaim.result.content[0].text,
    /owned by another continuation/,
  );

  const deliveredWithoutToken = await requestAndWait(2007, "tools/call", {
    name: "get_codex_security_scan_context",
    arguments: { scanId },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assertNoError(deliveredWithoutToken);

  const longUserContext = "Prioritize tenant isolation. ".repeat(120).trim();
  const updatedContext = await requestAndWait(92010, "tools/call", {
    name: "update_codex_security_scan_context",
    arguments: { handoffClaimToken, scanId, userContext: longUserContext },
    _meta: { "openai/threadId": "fixture-thread" }
  });
  assertNoError(updatedContext);
  assert.equal(updatedContext.result.structuredContent.scan.userContext, longUserContext);
  assert.equal(
    updatedContext.result.structuredContent.workspace.userContext,
    longUserContext
  );

  const appUserContext = "Focus on account recovery. ".repeat(120).trim();
  const appUpdatedContext = await requestAndWait(92011, "tools/call", {
    name: "update_codex_security_scan_context_from_app",
    arguments: { scanId, userContext: appUserContext }
  });
  assertNoError(appUpdatedContext);
  assert.equal(appUpdatedContext.result.structuredContent.scan.userContext, appUserContext);

  const urlContextUpdate = "Read https://example.test/context.";
  const updatedContextUrl = await requestAndWait(92012, "tools/call", {
    name: "update_codex_security_scan_context",
    arguments: {
      handoffClaimToken,
      scanId,
      userContext: urlContextUpdate
    },
    _meta: { "openai/threadId": "fixture-thread" }
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

  const conflictingPreflightCounts = await requestAndWait(90161, "tools/call", {
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

  const incompletePreflightProgress = await requestAndWait(
    90162,
    "tools/call",
    {
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
        ],
      },
    },
  );
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

  const blockedPreflightProgress = await requestAndWait(90163, "tools/call", {
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

  const readyPreflightProgress = await requestAndWait(90164, "tools/call", {
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
  const updatedPhaseContext = await requestAndWait(92013, "tools/call", {
    name: "update_codex_security_scan_context",
    arguments: {
      handoffClaimToken,
      scanId,
      userContext: nextPhaseUserContext,
    },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assertNoError(updatedPhaseContext);

  const updated = await requestAndWait(8, "tools/call", {
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
  const completed = await requestAndWait(802, "tools/call", {
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
  const refreshed = await requestAndWait(10, "tools/call", {
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
  const closedFinding = await requestAndWait(60, "tools/call", {
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
  const rejectedClosedPatch = await requestAndWait(159, "tools/call", {
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
  const reopenedFinding = await requestAndWait(160, "tools/call", {
    name: "set_codex_security_finding_triage",
    arguments: { occurrenceId, status: "open" },
  });
  assertNoError(reopenedFinding);

  const canceledRequestId = randomUUID();
  const canceledActionToken = randomUUID();
  const requestedThenCanceledPatch = await requestAndWait(500, "tools/call", {
    name: "request_codex_security_finding_remediation",
    arguments: {
      actionToken: canceledActionToken,
      occurrenceId,
      requestId: canceledRequestId,
    },
  });
  assertNoError(requestedThenCanceledPatch);
  const canceledPatch = await requestAndWait(501, "tools/call", {
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

  const requestedPatch = await requestAndWait(61, "tools/call", {
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
  const rejectedPendingClose = await requestAndWait(161, "tools/call", {
    name: "set_codex_security_finding_triage",
    arguments: { occurrenceId, status: "closed", closeReason: "already_fixed" },
  });
  assert.equal(rejectedPendingClose.result.isError, true);
  assert.match(
    rejectedPendingClose.result.content[0].text,
    /pending remediation operation/,
  );
  const remediationPatch = [
    "diff --git a/src/a.py b/src/a.py",
    "--- a/src/a.py",
    "+++ b/src/a.py",
    "@@ -1 +1 @@",
    "-vulnerable",
    "+fixed",
    "",
  ].join("\n");
  await writeFile(
    path.join(initializedScanDir, "remediation.patch"),
    remediationPatch,
  );
  const generatedPatch = await requestAndWait(62, "tools/call", {
    name: "set_codex_security_finding_remediation",
    arguments: {
      actionToken: generationActionToken,
      occurrenceId,
      requestId: remediationRequestId,
      expectedVersion: 1,
      state: "generated",
      patchPath: "remediation.patch",
      patchDigest: `sha256:${createHash("sha256").update(remediationPatch).digest("hex")}`,
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
  const requestedApply = await requestAndWait(65, "tools/call", {
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
  const markedApplyDelivered = await requestAndWait(166, "tools/call", {
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

  const appliedPatch = await requestAndWait(66, "tools/call", {
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
  const requestedVerify = await requestAndWait(168, "tools/call", {
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

  const verifyingPatch = await requestAndWait(169, "tools/call", {
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

  const verifiedPatch = await requestAndWait(170, "tools/call", {
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

  const findingsPage = await requestAndWait(67, "tools/call", {
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
  const filteredFindingsPage = await requestAndWait(94001, "tools/call", {
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
      (finding) => finding.occurrenceId,
    ),
    [occurrenceId],
  );
  assert.equal(
    filteredFindingsPage.result.structuredContent.findingsPage.total,
    1,
  );

  const csvExport = await requestAndWait(63, "tools/call", {
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

  const sarifExport = await requestAndWait(64, "tools/call", {
    name: "export_codex_security_findings",
    arguments: { scanId, format: "sarif" },
  });
  assertNoError(sarifExport);
  assert.equal(
    sarifExport.result.structuredContent.export.path,
    path.join(initializedScanDir, "exports", "results.sarif"),
  );

  const restarted = await requestAndWait(171, "tools/call", {
    name: "start_codex_security_scan",
    arguments: { sessionId: workspace.id },
  });
  assertNoError(restarted);
  const canceledScanId =
    restarted.result.structuredContent.workspace.results.scanId;
  const unclaimedContext = await requestAndWait(2010, "tools/call", {
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
  const rejectedWrongThreadCancel = await requestAndWait(1169, "tools/call", {
    name: "cancel_codex_security_scan",
    arguments: { scanId: canceledScanId },
    _meta: { "openai/threadId": "fixture-other-thread" },
  });
  assert.equal(rejectedWrongThreadCancel.result.isError, true);
  assert.match(
    rejectedWrongThreadCancel.result.content[0].text,
    /owning Codex thread/,
  );
  const rejectedMissingThreadCancel = await requestAndWait(1170, "tools/call", {
    name: "cancel_codex_security_scan",
    arguments: { scanId: canceledScanId },
  });
  assert.equal(rejectedMissingThreadCancel.result.isError, true);
  assert.match(
    rejectedMissingThreadCancel.result.content[0].text,
    /continuation thread.*Codex Security workbench/,
  );
  const canceledFromNativeRoute = await requestAndWait(2210, "tools/call", {
    name: "cancel_codex_security_scan_from_app",
    arguments: { scanId: canceledScanId },
  });
  assertNoError(canceledFromNativeRoute);

  const canceled = await requestAndWait(172, "tools/call", {
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

  const rejectedCanceledProgress = await requestAndWait(173, "tools/call", {
    name: "update_codex_security_scan_progress",
    arguments: { scanId: canceledScanId, phase: "discovery" },
  });
  assert.equal(rejectedCanceledProgress.result.isError, true);
  assert.match(
    rejectedCanceledProgress.result.content[0].text,
    /Only a running scan/,
  );

  const fallbackStarted = await requestAndWait(2011, "tools/call", {
    name: "start_codex_security_scan",
    arguments: { sessionId: workspace.id },
  });
  assertNoError(fallbackStarted);
  const fallbackScanId =
    fallbackStarted.result.structuredContent.workspace.results.scanId;
  const fallbackClaimToken = `recovery_${randomUUID()}`;
  const fallbackClaimed = await requestAndWait(2012, "tools/call", {
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
  const fallbackAttached = await requestAndWait(2017, "tools/call", {
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
  const wrongRecoveryContext = await requestAndWait(20171, "tools/call", {
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
  const fallbackContext = await requestAndWait(2013, "tools/call", {
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
    fallbackContext.result.structuredContent.workspace.results.handoffClaimToken,
    undefined,
  );
  const recoveredThreadContext = await requestAndWait(20172, "tools/call", {
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
  const fallbackAppAcknowledgement = await requestAndWait(2014, "tools/call", {
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
    [
      "import sqlite3, sys",
      "with sqlite3.connect(sys.argv[1]) as connection:",
      "    updated = connection.execute(\"UPDATE scans SET handoff_status = 'pending', handoff_claim_token = ?, continuation_thread_id = NULL WHERE id = ?\", (sys.argv[2], sys.argv[3]))",
      "    assert updated.rowcount == 1",
    ].join("\n"),
    path.join(stateDir, "workbench.sqlite3"),
    rotatedFallbackClaimToken,
    fallbackScanId,
  ]);
  const staleRecoveryContext = await requestAndWait(20173, "tools/call", {
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
  const scanList = await requestAndWait(2212, "tools/call", {
    name: "list_codex_security_scans",
    arguments: {},
  });
  assertNoError(scanList);
  const listedFallback = scanList.result.structuredContent.scans.find(
    (scan) => scan.scanId === fallbackScanId,
  );
  assert.equal(listedFallback.progress.status, "running");
  assert.equal("artifacts" in listedFallback, false);
  assert.equal("findings" in listedFallback, false);
  const globalFindings = await requestAndWait(2213, "tools/call", {
    name: "list_codex_security_global_findings",
    arguments: { limit: 1 },
  });
  assertNoError(globalFindings);
  const indexedFinding = globalFindings.result.structuredContent.findings.find(
    (finding) => finding.occurrenceId === occurrenceId,
  );
  assert.equal(globalFindings.result.structuredContent.limit, 1);
  assert.equal(globalFindings.result.structuredContent.nextOffset, 1);
  assert.equal(indexedFinding.scanId, scanId);
  assert.equal(indexedFinding.status, "open");
  assert.equal(indexedFinding.occurrenceCount, 1);
  assert.match(indexedFinding.targetId, /^target_sha256_[0-9a-f]{64}$/);
  const globalFindingsNext = await requestAndWait(2215, "tools/call", {
    name: "list_codex_security_global_findings",
    arguments: { limit: 20, offset: 1 },
  });
  assertNoError(globalFindingsNext);
  assert.equal(globalFindingsNext.result.structuredContent.findings.length, 1);
  assert.equal(globalFindingsNext.result.structuredContent.limit, 20);
  assert.equal(globalFindingsNext.result.structuredContent.offset, 1);
  assert.equal(globalFindingsNext.result.structuredContent.nextOffset, null);
  const filteredGlobalFindings = await requestAndWait(94002, "tools/call", {
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
      (finding) => finding.occurrenceId,
    ),
    [occurrenceId],
  );
  assert.equal(
    filteredGlobalFindings.result.structuredContent.nextOffset,
    null,
  );
  const repositories = await requestAndWait(2214, "tools/call", {
    name: "list_codex_security_repositories",
    arguments: {},
  });
  assertNoError(repositories);
  const indexedRepository =
    repositories.result.structuredContent.repositories.find(
      (repository) => repository.targetId === indexedFinding.targetId,
    );
  assert.equal(indexedRepository.checkoutAvailable, true);
  assert.equal(indexedRepository.latestScan.scanId, fallbackScanId);
  assert.equal(indexedRepository.openFindingsCount, 2);
  assert.equal(
    indexedRepository.scanCount,
    scanList.result.structuredContent.scans.filter(
      (scan) => scan.targetId === indexedFinding.targetId,
    ).length,
  );
  const filteredScans = await requestAndWait(94003, "tools/call", {
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
  const filteredRepositories = await requestAndWait(94004, "tools/call", {
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
      (repository) => repository.targetId,
    ),
    [indexedFinding.targetId],
  );
  const rotatedAttached = await requestAndWait(2030, "tools/call", {
    name: "attach_codex_security_scan_continuation_thread",
    arguments: {
      claimToken: rotatedFallbackClaimToken,
      scanId: fallbackScanId,
      threadId: "fixture-rotated-recovery-thread",
    },
  });
  assertNoError(rotatedAttached);
  const observedRotatedScan = await requestAndWait(2031, "tools/call", {
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
      const rejected = await requestAndWait(rejectedRequestId++, "tools/call", {
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
  const rotatedProgress = await requestAndWait(2038, "tools/call", {
    name: "update_codex_security_scan_progress",
    arguments: {
      handoffClaimToken: rotatedFallbackClaimToken,
      phase: "discovery",
      scanId: fallbackScanId,
    },
  });
  assertNoError(rotatedProgress);
  const rotatedFailure = await requestAndWait(2039, "tools/call", {
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

  const silentRefresh = await requestAndWait(11, "tools/call", {
    name: "open_codex_security_workspace",
    arguments: { sessionId: workspace.id },
    _meta: { "openai/threadId": "fixture-thread" },
  });
  assertNoError(silentRefresh);

  const replacementWorkspaceResponse = await requestAndWait(42, "tools/call", {
    name: "open_codex_security_workspace",
    arguments: { targetPath: target, targetTitle: "Old target title" },
    _meta: { "openai/threadId": "fixture-aux-thread" },
  });
  assertNoError(replacementWorkspaceResponse);
  const replacementWorkspace =
    replacementWorkspaceResponse.result.structuredContent.workspace;
  const replacementSaved = await requestAndWait(43, "tools/call", {
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

  const nativeSetupOpen = await requestAndWait(9226, "tools/call", {
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

  const invalidScanStarted = await requestAndWait(9401, "tools/call", {
    name: "start_codex_security_scan",
    arguments: { sessionId: workspace.id },
  });
  assertNoError(invalidScanStarted);
  const invalidScanId =
    invalidScanStarted.result.structuredContent.workspace.results.scanId;
  const invalidScanClaimToken = randomUUID();
  const invalidScanClaimed = await requestAndWait(9402, "tools/call", {
    name: "claim_codex_security_scan_handoff_delivery",
    arguments: { claimToken: invalidScanClaimToken, scanId: invalidScanId },
  });
  assertNoError(invalidScanClaimed);
  const prematureCompletion = await requestAndWait(9403, "tools/call", {
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
  const resumableScan = await requestAndWait(9404, "tools/call", {
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
