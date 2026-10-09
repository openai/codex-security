import { createHash } from "node:crypto";
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import {
  mkdtemp,
  mkdir,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createInterface } from "node:readline";

async function recordDraft(request) {
  // Exercise the same bundled tool used by a hosted executor. The plugin
  // derives canonical metadata; the CLI finalizes and seals it afterward.
  const plugin = spawn(
    process.execPath,
    [join(request.runtime.pluginRoot, "mcp/server.mjs"), "--stdio"],
    {
      env: {
        ...request.runtime.environment,
        CODEX_MCP_NODE_PATH: process.execPath,
      },
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  const pluginClosed = new Promise((resolve, reject) => {
    plugin.on("close", resolve);
    plugin.on("error", reject);
  });
  const messages = createInterface({ input: plugin.stdout })[
    Symbol.asyncIterator
  ]();
  let pluginError = "";
  let nextId = 0;
  plugin.stderr.on("data", (chunk) => {
    pluginError += chunk;
  });
  async function rpc(method, rpcParams) {
    const id = ++nextId;
    plugin.stdin.write(
      JSON.stringify({ jsonrpc: "2.0", id, method, params: rpcParams }) + "\n",
    );
    for (;;) {
      const next = await messages.next();
      assert.equal(next.done, false, pluginError);
      const response = JSON.parse(next.value);
      if (response.id !== id) continue;
      assert.equal(response.error, undefined, JSON.stringify(response.error));
      return response.result;
    }
  }
  try {
    await rpc("initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "hosted-package-smoke", version: "1" },
    });
    plugin.stdin.write(
      JSON.stringify({
        jsonrpc: "2.0",
        method: "notifications/initialized",
        params: {},
      }) + "\n",
    );
    const saved = await rpc("tools/call", {
      name: "record_codex_security_scan_draft",
      arguments: {
        scanId: request.scanId,
        complete: true,
        threatModel: {
          summary:
            "The synthetic service exports a constant and has no external inputs.",
        },
        findings: [],
        coverage: {
          completeness: "complete",
          surfaces: [
            {
              label: "Synthetic service",
              disposition: "no_issue_found",
            },
          ],
          explicitExclusions: [],
          deferred: [],
        },
      },
    });
    assert.notEqual(saved.isError, true, JSON.stringify(saved));
  } finally {
    plugin.stdin.end();
    plugin.kill();
    await pluginClosed;
  }
}

const packageRoot = resolve(process.argv[2] ?? ".");
const environment = Object.fromEntries(
  Object.entries(process.env).filter(([key]) =>
    [
      "PATH",
      "PATHEXT",
      "SYSTEMROOT",
      "WINDIR",
      "TMPDIR",
      "TEMP",
      "TMP",
    ].includes(key.toUpperCase()),
  ),
);
const root = await mkdtemp(
  join(await realpath(tmpdir()), "hosted-package-smoke-"),
);
let child;
try {
  const repository = join(root, "repository");
  for (const name of ["service-a", "service-b", "service-c"]) {
    await mkdir(join(repository, name), { recursive: true });
    await writeFile(
      join(repository, name, "index.ts"),
      "export const value = 1;\n",
    );
  }
  const git = (...args) =>
    execFileSync("git", ["-C", repository, ...args], {
      encoding: "utf8",
    }).trim();
  git("init", "-q");
  git("add", ".");
  git(
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.invalid",
    "commit",
    "-qm",
    "fixture",
  );
  const params = {
    version: 2,
    repository,
    revision: git("rev-parse", "HEAD"),
    scope: { paths: ["service-a", "service-b"] },
    outputDirectory: join(root, "output"),
    stateDirectory: join(root, "state"),
    model: "gpt-5.6-sol",
    reasoningEffort: "high",
    identity: {
      runId: "package-smoke",
      attemptId: "attempt-1",
      buildId: "synthetic-test",
    },
  };
  child = spawn(
    process.execPath,
    [join(packageRoot, "bin/codex-security.mjs"), "scan", "--host"],
    {
      env: environment,
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  const exited = new Promise((resolve, reject) => {
    child.on("exit", resolve);
    child.on("error", reject);
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  child.stdin.write(
    JSON.stringify({ jsonrpc: "2.0", id: "run", method: "run", params }) + "\n",
  );
  let final;
  let request;
  for await (const line of createInterface({ input: child.stdout })) {
    const message = JSON.parse(line);
    if (message.method === "execution.run") {
      assert.equal(request, undefined, "One scan must not resubmit execution");
      request = message.params;
      assert.equal(request.requestId, message.id);
      assert.deepEqual(request.identity, params.identity);
      assert.deepEqual(request.scope, params.scope);
      assert.equal(
        request.runtime.pluginRoot,
        join(packageRoot, "_bundled_plugin"),
      );
      for (const key of ["OPENAI_API_KEY", "CODEX_API_KEY"])
        assert.equal(request.runtime.environment[key], undefined);
      await recordDraft(request);
      child.stdin.write(
        JSON.stringify({
          jsonrpc: "2.0",
          id: message.id,
          result: {
            requestId: request.requestId,
            status: "completed",
            sessionId: "fake-session",
            usage: {
              input_tokens: 10,
              cached_input_tokens: 0,
              output_tokens: 5,
            },
          },
        }) + "\n",
      );
    } else if (message.id === "run") final = message;
  }
  assert.equal(await exited, 0, stderr);
  assert.equal(final?.result?.status, "completed", JSON.stringify(final));
  const manifest = JSON.parse(
    await readFile(join(params.outputDirectory, "scan-manifest.json"), "utf8"),
  );
  const coverage = JSON.parse(
    await readFile(join(params.outputDirectory, "coverage.json"), "utf8"),
  );
  assert.deepEqual(manifest.scan.scope.includePaths, [
    "service-a",
    "service-b",
  ]);
  assert.equal(manifest.scan.id, request.scanId);
  assert.equal(manifest.scan.target.revision, params.revision);
  assert.equal(coverage.completeness, "complete");
  assert.equal(coverage.mode, "scoped_path");
  assert.ok(manifest.scan.sealedAt);
  assert.match(
    await readFile(join(params.outputDirectory, "report.md"), "utf8"),
    /service-a/,
  );
  const report = await readFile(
    join(params.outputDirectory, "report.md"),
    "utf8",
  );
  assert.match(report, /service-b/);
  assert.doesNotMatch(report, /service-c/);
  for (const artifact of final.result.artifacts) {
    const contents = await readFile(
      join(params.outputDirectory, artifact.path),
    );
    assert.equal(artifact.bytes, contents.byteLength);
    assert.equal(
      artifact.sha256,
      createHash("sha256").update(contents).digest("hex"),
    );
  }
  // Installed-package exports must include the fixture and public SDK API.
  const fixture = JSON.parse(
    await readFile(
      createRequire(join(packageRoot, "package.json")).resolve(
        "@openai/codex-security/schemas/hosted-scan-v2.fixture.json",
      ),
      "utf8",
    ),
  );
  assert.equal(fixture.run.params.version, 2);
  const publicSdk = await import(
    pathToFileURL(join(packageRoot, "dist/index.js")).href
  );
  assert.equal(typeof publicSdk.CodexSecurity, "function");
  assert.equal(typeof publicSdk.runHostedScan, "function");
  assert.equal(
    publicSdk.HostedScanInputSchema.parse(fixture.run.params).version,
    2,
  );
  const sdkOutput = join(root, "sdk-output");
  let sdkRequest;
  const sdkResult = await publicSdk.runHostedScan(
    { ...params, scope: undefined, outputDirectory: sdkOutput },
    {
      executor: {
        async run(request) {
          assert.equal(
            sdkRequest,
            undefined,
            "One SDK scan must dispatch once",
          );
          sdkRequest = request;
          assert.deepEqual(request.scope, { paths: ["."] });
          await recordDraft(request);
          return {
            requestId: request.requestId,
            status: "completed",
            sessionId: "fake-sdk-session",
            usage: { input_tokens: 20, output_tokens: 3 },
          };
        },
      },
    },
  );
  assert.equal(sdkResult.status, "completed", JSON.stringify(sdkResult));
  assert.deepEqual(sdkResult.scope, { paths: ["."] });
  assert.equal(sdkResult.execution.sessionId, "fake-sdk-session");
  assert.deepEqual(sdkResult.execution.usage, {
    input_tokens: 20,
    output_tokens: 3,
  });
  const sdkManifest = JSON.parse(
    await readFile(join(sdkOutput, "scan-manifest.json"), "utf8"),
  );
  assert.deepEqual(sdkManifest.scan.scope.includePaths, ["."]);
  assert.equal(sdkManifest.scan.id, sdkRequest.scanId);
  assert.ok(sdkManifest.scan.sealedAt);
  for (const artifact of sdkResult.artifacts) {
    const contents = await readFile(join(sdkOutput, artifact.path));
    assert.equal(artifact.bytes, contents.byteLength);
    assert.equal(
      artifact.sha256,
      createHash("sha256").update(contents).digest("hex"),
    );
  }
  // A single missing path must fail the entire scope before any execution.
  const missing = spawn(
    process.execPath,
    [join(packageRoot, "bin/codex-security.mjs"), "scan", "--host"],
    {
      env: environment,
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  child = missing;
  let missingError = "";
  missing.stderr.on("data", (chunk) => {
    missingError += chunk;
  });
  const missingExit = new Promise((resolve, reject) => {
    missing.on("exit", resolve);
    missing.on("error", reject);
  });
  missing.stdin.write(
    JSON.stringify({
      jsonrpc: "2.0",
      id: "missing",
      method: "run",
      params: {
        ...params,
        scope: { paths: ["service-a", "missing"] },
        outputDirectory: join(root, "missing-output"),
      },
    }) + "\n",
  );
  const rejected = [];
  for await (const line of createInterface({ input: missing.stdout }))
    rejected.push(JSON.parse(line));
  assert.equal(await missingExit, 2, missingError);
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].error.data.reason, "scope_missing");
  console.log(
    JSON.stringify({
      status: "passed",
      executor: "fake",
      installedPackage: packageRoot,
      scanId: request.scanId,
      scope: coverage.includePaths,
      coverage: coverage.completeness,
      sealed: true,
      standaloneSdk: "passed",
    }),
  );
} finally {
  child?.kill();
  await rm(root, {
    recursive: true,
    force: true,
    maxRetries: 10,
    retryDelay: 100,
  });
}
