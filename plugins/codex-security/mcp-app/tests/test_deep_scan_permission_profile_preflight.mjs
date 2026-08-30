import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { chmod, copyFile, mkdir, mkdtemp, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  entryPoints: [fileURLToPath(new URL("../src/deep-scan/permission-profile-preflight.ts", import.meta.url))],
  format: "esm",
  platform: "node",
  write: false
});
const {
  DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID,
  deepScanPermissionProfileFallbackError,
  preflightDeepScanWorkerPermissionProfile
} = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);

const profileId = DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID;
const expectedProfile = {
  description: "Generated Deep Scan worker profile.",
  filesystem: {
    ":root": "read",
    "/repo/.env": "deny"
  },
  network: { enabled: false }
};
const rawOverrides = [
  `default_permissions="${profileId}"`,
  `permissions.${profileId}={filesystem={":root"="read","/repo/.env"="deny"},network={enabled=false}}`
];

await testAllowedProfileAndRawArgv();
await testPreflightStartsInWorkerCwd();
await testProvidedEnvForwardedWithoutMutation();
await testSequentialPaginatedResponsesAcrossChunks();
await testMalformedStreamFailsClosed();
await testRepeatedCatalogCursorFailsClosed();
await testDisallowedProfileGivesAdminGuidance();
await testOtherManagedPolicyRejectionIsGeneric();
await testMergedProfileCollisionFailsClosed();
await testLiteralProtoKeyCollisionFailsClosed();
await testMalformedAndUnsupportedResponsesFailClosed();
await testEarlyExecutableExitIsNotVersionError();
await testNonVersionJsonRpcFailureIsSafe();
await testRuntimeFallbackWarningClassification();
await testSpawnErrorFailsClosed();
await testAbortKillsPreflightChild();

async function testAllowedProfileAndRawArgv() {
  await withFakeCodex({
    configResult: configReadResult({
      ...expectedProfile,
      description: "Display text from a normal config layer.",
      workspace_roots: null,
      filesystem: {
        ...expectedProfile.filesystem,
        glob_scan_max_depth: null
      },
      network: {
        ...expectedProfile.network,
        proxy_url: null,
        domains: null
      }
    }),
    catalogResults: [{
      data: [
        // Catalog ids are opaque; an unrelated empty id must not make the
        // desired Deep Scan profile unverifiable.
        { id: "", description: null, allowed: false },
        { id: profileId, description: null, allowed: true }
      ],
      nextCursor: null
    }]
  }, async ({ codexPath, cwd, argvPath, callsPath }) => {
    await preflight(codexPath, cwd);

    assert.deepEqual(JSON.parse(await readFile(argvPath, "utf8")), [
      "--config",
      rawOverrides[0],
      "--config",
      rawOverrides[1],
      "app-server",
      "--stdio"
    ]);
    const calls = await readJsonLines(callsPath);
    assert.deepEqual(calls.map((call) => call.method), [
      "initialize",
      "initialized",
      "config/read",
      "permissionProfile/list"
    ]);
    assert.deepEqual(calls[0].params.capabilities, { experimentalApi: true });
    assert.deepEqual(calls[2].params, { cwd, includeLayers: false });
    assert.deepEqual(calls[3].params, { cwd });
  }, { longExecutable: true });
}

async function testProvidedEnvForwardedWithoutMutation() {
  const codexHome = "/fixture/canonical-codex-home";
  const env = Object.freeze({
    ...stringEnvironment(),
    CODEX_HOME: codexHome,
    DEEP_SCAN_PREFLIGHT_ENV_SENTINEL: "same-snapshot"
  });
  const originalEntries = Object.entries(env);

  await withFakeCodex({
    configResult: configReadResult(expectedProfile),
    catalogResults: [catalogResult(true)]
  }, async ({ codexPath, cwd, envPath }) => {
    await preflight(codexPath, cwd, env);
    assert.deepEqual(JSON.parse(await readFile(envPath, "utf8")), {
      codexHome,
      sentinel: "same-snapshot"
    });
    assert.deepEqual(Object.entries(env), originalEntries);
  });
}

async function testPreflightStartsInWorkerCwd() {
  await withFakeCodex({
    configResult: configReadResult(expectedProfile),
    catalogResults: [catalogResult(true)]
  }, async ({ codexPath, cwd, cwdPath, callsPath, terminatedPath, children }) => {
    assert.notEqual(cwd, process.cwd());
    await preflight(codexPath, cwd);

    const childCwd = JSON.parse(await readFile(cwdPath, "utf8"));
    assert.equal(await realpath(childCwd), await realpath(cwd));
    const calls = await readJsonLines(callsPath);
    assert.deepEqual(calls.find((call) => call.method === "config/read").params, {
      cwd,
      includeLayers: false
    });
    assert.deepEqual(calls.find((call) => call.method === "permissionProfile/list").params, {
      cwd
    });
    await assertPreflightStopped(children, terminatedPath);
  });
}

async function testSequentialPaginatedResponsesAcrossChunks() {
  await withFakeCodex({
    streamResponses: true,
    configResult: configReadResult(expectedProfile),
    catalogResults: [
      {
        data: [{ id: "unrelated", description: null, allowed: false }],
        nextCursor: "second-page"
      },
      catalogResult(true)
    ]
  }, async ({ codexPath, cwd, callsPath }) => {
    await preflight(codexPath, cwd);

    const calls = await readJsonLines(callsPath);
    assert.deepEqual(calls.filter((call) => call.id !== undefined).map((call) => call.id), [1, 2, 3, 4]);
    assert.deepEqual(calls.filter((call) => call.method === "permissionProfile/list").map((call) => call.params), [
      { cwd },
      { cwd, cursor: "second-page" }
    ]);
  });
}

async function testMalformedStreamFailsClosed() {
  for (const output of [
    "not JSON\n",
    "[]\n",
    JSON.stringify({ jsonrpc: "2.0", id: 2, result: {} }) + "\n",
    JSON.stringify({ jsonrpc: "2.0", id: 1 }) + "\n"
  ]) {
    await withFakeCodex({
      rawOutputByMethod: { initialize: output }
    }, async ({ codexPath, cwd, terminatedPath, children }) => {
      await assert.rejects(
        preflight(codexPath, cwd),
        (error) => error?.name === "DeepScanNonRetryableError"
          && error.message.includes("with this Codex configuration")
      );
      await assertPreflightStopped(children, terminatedPath);
    });
  }
}

async function testRepeatedCatalogCursorFailsClosed() {
  await withFakeCodex({
    configResult: configReadResult(expectedProfile),
    catalogResults: [
      { data: [], nextCursor: "same-page" },
      { data: [], nextCursor: "same-page" }
    ]
  }, async ({ codexPath, cwd, callsPath }) => {
    await assert.rejects(
      preflight(codexPath, cwd),
      (error) => error?.name === "DeepScanNonRetryableError"
        && error.message.includes("with this Codex configuration")
    );
    const calls = await readJsonLines(callsPath);
    assert.equal(calls.filter((call) => call.method === "permissionProfile/list").length, 2);
  });
}

async function testDisallowedProfileGivesAdminGuidance() {
  await withFakeCodex({
    stderr: "SECRET_REPOSITORY_PATH=/repo/private\n",
    configResult: configReadResult(expectedProfile, "enterprise-default"),
    catalogResults: [catalogResult(false)],
    requirementsResult: {
      requirements: {
        allowedPermissionProfiles: { "enterprise-default": true }
      }
    }
  }, async ({ codexPath, cwd, callsPath }) => {
    await assert.rejects(
      preflight(codexPath, cwd),
      (error) => error?.name === "DeepScanNonRetryableError"
        && error.message.includes(`\`${profileId}\``)
        && error.message.includes(`[permissions.${profileId}]`)
        && error.message.includes("[allowed_permission_profiles]")
        && error.message.includes("existing allowlist")
        && error.message.includes(`${profileId} = true`)
        && error.message.includes("Deep Scan did not run.")
        && !error.message.includes("SECRET_REPOSITORY_PATH")
    );
    const calls = await readJsonLines(callsPath);
    assert.deepEqual(calls.map((call) => call.method), [
      "initialize",
      "initialized",
      "config/read",
      "permissionProfile/list",
      "configRequirements/read"
    ]);
    assert.equal(Object.hasOwn(calls[4], "params"), false);
  });
}

async function testOtherManagedPolicyRejectionIsGeneric() {
  await withFakeCodex({
    configResult: configReadResult(expectedProfile, "enterprise-default"),
    catalogResults: [catalogResult(false)],
    requirementsResult: {
      requirements: {
        allowedPermissionProfiles: { [profileId]: true }
      }
    }
  }, async ({ codexPath, cwd }) => {
    await assert.rejects(
      preflight(codexPath, cwd),
      (error) => error?.name === "DeepScanNonRetryableError"
        && error.message.includes("managed Codex policy rejected")
        && error.message.includes(`\`${profileId}\``)
        && !error.message.includes("[allowed_permission_profiles]")
        && !error.message.includes(`[permissions.${profileId}]`)
    );
  });
}

async function testMergedProfileCollisionFailsClosed() {
  await withFakeCodex({
    configResult: configReadResult({
      ...expectedProfile,
      extends: ":workspace"
    }),
    catalogResults: [catalogResult(true)]
  }, async ({ codexPath, cwd }) => {
    await assert.rejects(
      preflight(codexPath, cwd),
      (error) => error?.name === "DeepScanNonRetryableError"
        && error.message.includes("existing Codex configuration changes")
        && error.message.includes(`\`${profileId}\``)
        && error.message.includes('extends = ":read-only"')
    );
  });
}

async function testLiteralProtoKeyCollisionFailsClosed() {
  const profileWithLiteralProtoKey = Object.fromEntries([
    ...Object.entries(expectedProfile),
    ["__proto__", "write"]
  ]);
  assert.equal(Object.hasOwn(profileWithLiteralProtoKey, "__proto__"), true);

  await withFakeCodex({
    configResult: configReadResult(profileWithLiteralProtoKey),
    catalogResults: [catalogResult(true)]
  }, async ({ codexPath, cwd }) => {
    await assert.rejects(
      preflight(codexPath, cwd),
      (error) => error?.name === "DeepScanNonRetryableError"
        && error.message.includes("existing Codex configuration changes")
    );
  });
}

async function testMalformedAndUnsupportedResponsesFailClosed() {
  await withFakeCodex({
    configResult: configReadResult(expectedProfile),
    catalogResults: [{ data: [{ id: profileId, description: null, allowed: "yes" }], nextCursor: null }]
  }, async ({ codexPath, cwd }) => {
    await assert.rejects(
      preflight(codexPath, cwd),
      (error) => error?.name === "DeepScanNonRetryableError"
        && error.message.includes("with this Codex configuration")
    );
  });

  await withFakeCodex({
    configResult: configReadResult(expectedProfile),
    catalogResults: [{ data: [{ id: profileId, description: null }], nextCursor: null }]
  }, async ({ codexPath, cwd }) => {
    await assert.rejects(
      preflight(codexPath, cwd),
      (error) => error?.name === "DeepScanNonRetryableError"
        && error.message.includes(JSON.stringify(codexPath))
        && error.message.includes("permissionProfile/list.allowed")
        && error.message.includes("does not support")
        && error.message.includes("Update the Codex installation at that path")
        && error.message.includes("desktop app if it is bundled")
        && error.message.includes("otherwise the selected CLI")
        && !error.message.includes("host/CLI")
    );
  });

  await withFakeCodex({
    configResult: configReadResult(expectedProfile),
    methodErrors: { "permissionProfile/list": { code: -32601, message: "Method not found" } }
  }, async ({ codexPath, cwd }) => {
    await assert.rejects(
      preflight(codexPath, cwd),
      (error) => error?.name === "DeepScanNonRetryableError"
        && error.message.includes(JSON.stringify(codexPath))
        && error.message.includes("permissionProfile/list")
        && error.message.includes("does not support")
        && error.message.includes("Update the Codex installation at that path")
        && error.message.includes("desktop app if it is bundled")
        && error.message.includes("otherwise the selected CLI")
        && !error.message.includes("host/CLI")
    );
  });
}

async function testEarlyExecutableExitIsNotVersionError() {
  await withFakeCodex({
    exitOnMethod: "initialize",
    exitCode: 17
  }, async ({ codexPath, cwd }) => {
    await assert.rejects(
      preflight(codexPath, cwd),
      (error) => error?.name === "DeepScanNonRetryableError"
        && error.message.includes(JSON.stringify(codexPath))
        && error.message.includes("exited before permission-profile verification completed")
        && error.message.includes("code 17")
        && error.message.includes("with --version")
        && error.message.includes("CODEX_CLI_PATH/PATH")
        && !error.message.includes("does not support")
        && !error.message.includes("host/CLI")
    );
  });
}

async function testNonVersionJsonRpcFailureIsSafe() {
  await withFakeCodex({
    methodErrors: {
      "config/read": { code: -32603, message: "SECRET_REPOSITORY_PATH=/repo/private" }
    }
  }, async ({ codexPath, cwd }) => {
    await assert.rejects(
      preflight(codexPath, cwd),
      (error) => error?.name === "DeepScanNonRetryableError"
        && error.message.includes(JSON.stringify(codexPath))
        && error.message.includes("config/read")
        && error.message.includes("JSON-RPC code -32603")
        && !error.message.includes("SECRET_REPOSITORY_PATH")
        && !error.message.includes("does not support")
    );
  });
}

async function testSpawnErrorFailsClosed() {
  const missingCodex = path.join(tmpdir(), `missing-codex-${process.pid}`);
  await assert.rejects(
    preflight(missingCodex, tmpdir()),
    (error) => error?.name === "DeepScanNonRetryableError"
      && error.message.includes(JSON.stringify(missingCodex))
      && error.message.includes("could not start")
      && error.message.includes("with --version")
      && error.message.includes("CODEX_CLI_PATH/PATH")
      && !error.message.includes("does not support")
  );
}

async function testRuntimeFallbackWarningClassification() {
  const warning = `Configured value for \`permission_profile\` is disallowed by requirements; falling back from \`${profileId}\` to required value \`enterprise-default\`.`;
  const error = deepScanPermissionProfileFallbackError(warning, profileId);
  assert.equal(error?.name, "DeepScanNonRetryableError");
  assert.equal(error?.message.includes("worker was stopped and its results were discarded"), true);
  assert.equal(error?.message.includes("existing allowlist"), true);
  assert.equal(error?.message.includes("Deep Scan did not run."), false);
  assert.equal(deepScanPermissionProfileFallbackError(`prefix ${warning}`, profileId), undefined);
  assert.equal(
    deepScanPermissionProfileFallbackError(warning.replace(profileId, "different-profile"), profileId),
    undefined
  );
  const unusualDestination = "\n`quoted destination`\n";
  const unusualWarning = `Configured value for \`permission_profile\` is disallowed by requirements; falling back from \`${profileId}\` to required value \`${unusualDestination}\`.`;
  assert.equal(
    deepScanPermissionProfileFallbackError(unusualWarning, profileId)?.name,
    "DeepScanNonRetryableError"
  );
  const emptyDestinationWarning = `Configured value for \`permission_profile\` is disallowed by requirements; falling back from \`${profileId}\` to required value \`\`.`;
  assert.equal(
    deepScanPermissionProfileFallbackError(emptyDestinationWarning, profileId)?.name,
    "DeepScanNonRetryableError"
  );
}

async function testAbortKillsPreflightChild() {
  await withFakeCodex({
    hangAt: "config/read"
  }, async ({ codexPath, cwd, readyPath, terminatedPath, children }) => {
    const controller = new AbortController();
    const running = preflightDeepScanWorkerPermissionProfile({
      codexPath,
      cwd,
      profileId,
      configOverrides: rawOverrides,
      expectedProfile,
      signal: controller.signal
    });
    await waitForFile(readyPath);
    controller.abort(new DOMException("fixture aborted", "AbortError"));
    await assert.rejects(running, (error) => error?.name === "AbortError");
    await assertPreflightStopped(children, terminatedPath);
  });
}

async function assertPreflightStopped(children, terminatedPath) {
  if (process.platform === "win32") {
    // Windows termination need not run the fixture's signal or stdin handlers.
    assert.equal(children.length, 1);
    assert.ok(children[0].exitCode !== null || children[0].signalCode !== null);
  } else {
    await waitForFile(terminatedPath);
    assert.ok(["SIGTERM", "stdin-end"].includes(await readFile(terminatedPath, "utf8")));
  }
}

function preflight(codexPath, cwd, env) {
  return preflightDeepScanWorkerPermissionProfile({
    codexPath,
    cwd,
    profileId,
    configOverrides: rawOverrides,
    expectedProfile,
    ...(env === undefined ? {} : { env }),
    signal: new AbortController().signal
  });
}

function stringEnvironment() {
  return Object.fromEntries(
    Object.entries(process.env).filter((entry) => typeof entry[1] === "string")
  );
}

function configReadResult(profile, defaultPermissions = profileId) {
  return {
    config: {
      default_permissions: defaultPermissions,
      permissions: { [profileId]: profile }
    },
    origins: {},
    layers: null
  };
}

function catalogResult(allowed) {
  return {
    data: [{ id: profileId, description: null, allowed }],
    nextCursor: null
  };
}

async function withFakeCodex(scenario, callback, { longExecutable = false } = {}) {
  const root = await mkdtemp(path.join(tmpdir(), "deep-scan-profile-preflight-"));
  const scriptPath = path.join(root, "fake-codex.mjs");
  let codexPath = scriptPath;
  const argvPath = path.join(root, "argv.json");
  const callsPath = path.join(root, "calls.jsonl");
  const cwdPath = path.join(root, "cwd.json");
  const envPath = path.join(root, "env.json");
  const readyPath = path.join(root, "ready");
  const terminatedPath = path.join(root, "terminated");
  const fixture = { ...scenario, argvPath, callsPath, cwdPath, envPath, readyPath, terminatedPath };
  await writeFile(scriptPath, fakeCodexSource(fixture), "utf8");
  await chmod(scriptPath, 0o755);
  const originalSpawn = childProcess.spawn;
  const children = [];
  try {
    if (process.platform === "win32") {
      codexPath = process.execPath;
      if (longExecutable) {
        codexPath = path.join(root, ...Array(10).fill("nested executable directory"), "node.exe");
        await mkdir(path.dirname(codexPath), { recursive: true });
        await copyFile(process.execPath, codexPath);
        assert.ok(codexPath.length > 260);
      }
      childProcess.spawn = (command, args, options) => {
        if (command !== codexPath && command !== path.toNamespacedPath(codexPath)) {
          return originalSpawn(command, args, options);
        }
        // Reuse the protocol script without replacing or normalizing the executable.
        const child = originalSpawn(command, [scriptPath, ...args], options);
        children.push(child);
        return child;
      };
      syncBuiltinESMExports();
    }
    await callback({ codexPath, cwd: root, argvPath, callsPath, cwdPath, envPath, readyPath, terminatedPath, children });
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    await rm(root, { recursive: true, force: true });
  }
}

function fakeCodexSource(scenario) {
  return `#!/usr/bin/env node
import { appendFileSync, writeFileSync } from "node:fs";

const scenario = JSON.parse(${JSON.stringify(JSON.stringify(scenario))});
writeFileSync(scenario.argvPath, JSON.stringify(process.argv.slice(2)));
writeFileSync(scenario.cwdPath, JSON.stringify(process.cwd()));
writeFileSync(scenario.envPath, JSON.stringify({
  codexHome: process.env.CODEX_HOME ?? null,
  sentinel: process.env.DEEP_SCAN_PREFLIGHT_ENV_SENTINEL ?? null
}));
if (scenario.stderr) process.stderr.write(scenario.stderr);
let buffer = "";
let catalogIndex = 0;

process.on("SIGTERM", () => {
  writeFileSync(scenario.terminatedPath, "SIGTERM");
  process.exit(0);
});
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  while (true) {
    const newline = buffer.indexOf("\\n");
    if (newline < 0) return;
    const line = buffer.slice(0, newline).trim();
    buffer = buffer.slice(newline + 1);
    if (!line) continue;
    const message = JSON.parse(line);
    appendFileSync(scenario.callsPath, JSON.stringify(message) + "\\n");
    handle(message);
  }
});
process.stdin.on("end", () => {
  writeFileSync(scenario.terminatedPath, "stdin-end");
  process.exit(0);
});

function handle(message) {
  if (message.method === "initialized") return;
  if (scenario.exitOnMethod === message.method) {
    process.exit(scenario.exitCode ?? 1);
  }
  if (scenario.hangAt === message.method) {
    writeFileSync(scenario.readyPath, "ready");
    return;
  }
  const rawOutput = scenario.rawOutputByMethod?.[message.method];
  if (rawOutput !== undefined) {
    process.stdout.write(rawOutput);
    return;
  }
  const methodError = scenario.methodErrors?.[message.method];
  if (methodError) {
    send(message.id, undefined, methodError);
    return;
  }
  if (message.method === "initialize") {
    send(message.id, { userAgent: "fixture", codexHome: "/fixture", platformFamily: "unix", platformOs: "macos" });
    return;
  }
  if (message.method === "config/read") {
    send(message.id, scenario.configResult);
    return;
  }
  if (message.method === "permissionProfile/list") {
    send(message.id, scenario.catalogResults?.[catalogIndex++] ?? { data: [], nextCursor: null });
    return;
  }
  if (message.method === "configRequirements/read") {
    send(message.id, scenario.requirementsResult ?? { requirements: null });
    return;
  }
  send(message.id, undefined, { code: -32601, message: "Method not found" });
}

function send(id, result, error) {
  const message = error
    ? { jsonrpc: "2.0", id, error }
    : { jsonrpc: "2.0", id, result };
  if (scenario.streamResponses) {
    // Exercise blank lines, ignored notifications/requests, CRLF framing,
    // coalesced messages, and a UTF-8 character split across writes.
    const notification = { jsonrpc: "2.0", method: "fixture/notice", params: { message: "☃" } };
    const request = { jsonrpc: "2.0", id: "server-request", method: "fixture/request" };
    const output = Buffer.from("\\r\\n" + JSON.stringify(notification) + "\\r\\n"
      + JSON.stringify(request) + "\\r\\n" + JSON.stringify(message) + "\\r\\n");
    const split = output.indexOf(Buffer.from("☃")) + 1;
    process.stdout.write(output.subarray(0, split));
    setImmediate(() => process.stdout.write(output.subarray(split)));
    return;
  }
  process.stdout.write(JSON.stringify(message) + "\\n");
}
`;
}

async function readJsonLines(file) {
  const content = await readFile(file, "utf8");
  return content.trim().split(/\r?\n/u).filter(Boolean).map((line) => JSON.parse(line));
}

async function waitForFile(file) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    try {
      await stat(file);
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }
  throw new Error(`Timed out waiting for fixture file: ${file}`);
}
