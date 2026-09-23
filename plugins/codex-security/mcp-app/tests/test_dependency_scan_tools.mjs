import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { build } from "esbuild";

const compiled = await build({
  bundle: true,
  entryPoints: [
    new URL("../src/dependency-scans.ts", import.meta.url).pathname,
  ],
  format: "esm",
  platform: "node",
  write: false,
});
const { getDependencyScan, resolveAardvarkBaseUrl, submitDependencyScan } =
  await import(
    "data:text/javascript;base64," +
      Buffer.from(compiled.outputFiles[0].contents).toString("base64")
  );

const temporaryRoot = await mkdtemp(
  path.join(tmpdir(), "codex-security-dependency-tools-"),
);
const codexHome = path.join(temporaryRoot, "codex-home");
const missingAccountHome = path.join(temporaryRoot, "missing-account-home");
const target = path.join(temporaryRoot, "target");
const scopedDirectory = path.join(target, "packages", "scoped");
const outsideDirectory = path.join(temporaryRoot, "outside");
const stateDir = path.join(temporaryRoot, "state");
const scanRoot = path.join(temporaryRoot, "scans");
const fakeCodexPath = path.join(temporaryRoot, "dependency-estimate-codex.mjs");
const estimationInvocationPath = path.join(
  temporaryRoot,
  "dependency-estimate-invocation.json",
);
await Promise.all([
  mkdir(codexHome),
  mkdir(missingAccountHome),
  mkdir(target),
  mkdir(outsideDirectory),
  mkdir(stateDir),
  mkdir(scanRoot),
]);
await writeFile(
  fakeCodexPath,
  [
    "#!/usr/bin/env node",
    "import { writeFileSync } from 'node:fs';",
    "import { MessageChannel } from 'node:worker_threads';",
    "if (process.argv.includes('app-server')) {",
    "  const profile = { extends: ':read-only', filesystem: { ':root': 'read' }, network: { enabled: false } };",
    "  const { createInterface } = await import('node:readline');",
    "  for await (const line of createInterface({ input: process.stdin })) {",
    "    const message = JSON.parse(line);",
    "    if (message.id === undefined) continue;",
    "    const result = message.method === 'config/read' ? { config: { default_permissions: 'codex_security_deep_scan_worker', permissions: { codex_security_deep_scan_worker: profile } } } : message.method === 'permissionProfile/list' ? { data: [{ id: 'codex_security_deep_scan_worker', allowed: true }], nextCursor: null } : message.method === 'account/read' ? { requiresOpenaiAuth: true, account: { type: 'chatgpt' } } : {};",
    "    console.log(JSON.stringify({ jsonrpc: '2.0', id: message.id, result }));",
    "  }",
    "  process.exit(0);",
    "}",
    "let prompt = '';",
    "for await (const chunk of process.stdin) prompt += chunk;",
    "writeFileSync(process.env.CODEX_SECURITY_ESTIMATE_TEST_MARKER, JSON.stringify({ args: process.argv.slice(2), prompt }));",
    "console.log(JSON.stringify({ type: 'thread.started', thread_id: 'fixture-dependency-estimate-worker' }));",
    'if (prompt.includes(\'\\"mode\\":\\"diff\\"\')) {',
    "  const { port1, port2 } = new MessageChannel();",
    "  port1.on('message', () => {});",
    "  const notify = (phase, details) => fetch(process.env.CODEX_SECURITY_AARDVARK_BASE_URL + '/__fixture__/estimate-' + phase, { method: 'POST', body: JSON.stringify(details) });",
    "  process.once('SIGTERM', () => {",
    "    notify('stopped', { pid: process.pid, signal: 'SIGTERM' }).then(() => { port1.close(); port2.close(); process.exit(0); }, () => process.exit(1));",
    "  });",
    "  await notify('started', { pid: process.pid });",
    "  await new Promise(() => {});",
    "}",
    'const depthCounts = prompt.includes(\'\\"mode\\":\\"deep\\"\') ? [2, -1] : [2, 5, 3];',
    "const response = prompt.includes('\\\"mode\\\":\\\"standard\\\"') ? 'Dependency estimation unavailable: required package-manager resolver is unavailable for offline dependency estimation. Repository: /private/customer/repository; package: @private/internal-dependency.' : JSON.stringify({ depthCounts });",
    "console.log(JSON.stringify({ type: 'item.completed', item: { id: 'estimate-message', type: 'agent_message', text: response } }));",
    "console.log(JSON.stringify({ type: 'turn.completed', usage: { input_tokens: 1, cached_input_tokens: 0, output_tokens: 1 } }));",
    "",
  ].join("\n"),
);
await chmod(fakeCodexPath, 0o755);
const manifestPath = path.join(target, "package.json");
const scopedManifestPath = path.join(scopedDirectory, "package.json");
await mkdir(scopedDirectory, { recursive: true });
await symlink(outsideDirectory, path.join(target, "escaped-scope"), "dir");
await writeFile(
  manifestPath,
  JSON.stringify({ name: "public-package-fixture", version: "1.0.0" }),
);
await writeFile(
  scopedManifestPath,
  JSON.stringify({ name: "scoped-fixture", version: "1.0.0" }),
);
execFileSync("git", ["init", "-q", target]);
execFileSync("git", [
  "-C",
  target,
  "add",
  "package.json",
  "packages/scoped/package.json",
]);
execFileSync("git", [
  "-C",
  target,
  "-c",
  "user.name=Fixture",
  "-c",
  "user.email=fixture@example.com",
  "commit",
  "-qm",
  "initial dependency fixture",
]);
const baseRevision = execFileSync("git", ["-C", target, "rev-parse", "HEAD"], {
  encoding: "utf8",
}).trim();
await writeFile(
  manifestPath,
  JSON.stringify({ name: "public-package-fixture", version: "1.0.1" }),
);
await writeFile(
  scopedManifestPath,
  JSON.stringify({ name: "scoped-fixture", version: "1.0.1" }),
);
execFileSync("git", [
  "-C",
  target,
  "add",
  "package.json",
  "packages/scoped/package.json",
]);
execFileSync("git", [
  "-C",
  target,
  "-c",
  "user.name=Fixture",
  "-c",
  "user.email=fixture@example.com",
  "commit",
  "-qm",
  "update dependency fixture",
]);
const headRevision = execFileSync("git", ["-C", target, "rev-parse", "HEAD"], {
  encoding: "utf8",
}).trim();
await writeFile(
  path.join(codexHome, "auth.json"),
  JSON.stringify({
    auth_mode: "chatgpt",
    tokens: {
      access_token: "fixture-chatgpt-access-token",
      account_id: "fixture-chatgpt-account",
    },
  }),
);
await writeFile(
  path.join(missingAccountHome, "auth.json"),
  JSON.stringify({
    tokens: { access_token: "fixture-chatgpt-access-token" },
  }),
);

const requests = [];
const estimateControlWaiters = { started: undefined, stopped: undefined };
const server = createServer(async (request, response) => {
  let rawBody = "";
  for await (const chunk of request) rawBody += chunk;
  if (
    request.url === "/__fixture__/estimate-started" ||
    request.url === "/__fixture__/estimate-stopped"
  ) {
    const phase = request.url.endsWith("started") ? "started" : "stopped";
    response.writeHead(204);
    response.end();
    estimateControlWaiters[phase]?.(JSON.parse(rawBody));
    return;
  }
  const recorded = {
    method: request.method,
    url: request.url,
    headers: request.headers,
    body: rawBody ? JSON.parse(rawBody) : undefined,
  };
  requests.push(recorded);

  if (request.url === "/api/aardvark/dependency-scans/dps_missing") {
    response.writeHead(404, { "content-type": "application/json" });
    response.end(JSON.stringify({ detail: "Dependency scan not found." }));
    return;
  }
  if (request.url === "/api/aardvark/dependency-scans/dps_redirect") {
    response.writeHead(302, { location: "https://attacker.invalid/leak" });
    response.end();
    return;
  }
  if (
    request.method === "POST" &&
    request.url === "/api/aardvark/dependency-scans"
  ) {
    response.writeHead(202, { "content-type": "application/json" });
    response.end(
      JSON.stringify({
        job_id: "dps_123",
        status: "queued",
      }),
    );
    return;
  }
  if (
    request.method === "GET" &&
    request.url === "/api/aardvark/dependency-scans/dps_running"
  ) {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(
      JSON.stringify({
        job_id: "dps_running",
        status: "running",
        packages: [
          {
            ecosystem: "npm",
            registry: "https://registry.npmjs.org",
            package: "@example/dependency",
            old_version: "1.161.9",
            new_version: "1.161.12",
            status: "running",
            phase: "scanning",
            artifacts: [{ status: "running", cache_hit: false }],
            findings: [],
          },
        ],
      }),
    );
    return;
  }
  if (
    request.method === "GET" &&
    request.url === "/api/aardvark/dependency-scans/dps_123"
  ) {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(
      JSON.stringify({
        job_id: "dps_123",
        status: "completed",
        packages: [
          {
            ecosystem: "npm",
            registry: "https://registry.npmjs.org",
            package: "@example/dependency",
            old_version: "1.161.9",
            new_version: "1.161.12",
            status: "completed",
            artifacts: [
              {
                old_digest: "sha256:old",
                new_digest: "sha256:new",
                cache_hit: true,
              },
            ],
            findings: [
              {
                upstream_finding_id: "dep_fixture",
                code_evidence: [{ start_line: 8 }],
              },
            ],
            prior_finding_assessments: [
              {
                upstream_finding_id: "dep_fixture",
                status: "present",
              },
            ],
          },
        ],
      }),
    );
    return;
  }

  response.writeHead(500, { "content-type": "application/json" });
  response.end(JSON.stringify({ detail: "Unexpected fixture request." }));
});

try {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const baseUrl = `http://127.0.0.1:${address.port}`;

  assert.equal(
    resolveAardvarkBaseUrl(),
    "https://chatgpt.com/backend-api/aardvark",
  );
  assert.equal(resolveAardvarkBaseUrl(baseUrl), `${baseUrl}/api/aardvark`);
  assert.equal(
    resolveAardvarkBaseUrl(`${baseUrl}/api/aardvark/`),
    `${baseUrl}/api/aardvark`,
  );
  assert.equal(
    resolveAardvarkBaseUrl("https://chatgpt-staging.com/backend-api/aardvark"),
    "https://chatgpt-staging.com/backend-api/aardvark",
  );

  for (const unsafeBaseUrl of [
    "https://attacker.invalid/api/aardvark",
    "https://chatgpt.com.attacker.invalid/api/aardvark",
    "http://chatgpt.com/backend-api/aardvark",
    "http://192.168.1.1/api/aardvark",
    "https://token@chatgpt.com/backend-api/aardvark",
    "https://chatgpt.com/backend-api/aardvark?token=leak",
    "https://chatgpt.com/backend-api/aardvark#fragment",
  ]) {
    assert.throws(
      () => resolveAardvarkBaseUrl(unsafeBaseUrl),
      /trusted OpenAI HTTPS origin or local loopback endpoint/i,
      unsafeBaseUrl,
    );
  }

  const submitted = await submitDependencyScan(
    {
      dependencies: [
        {
          ecosystem: "npm",
          registry: "https://registry.npmjs.org",
          package: "@example/dependency",
          oldVersion: "1.161.9",
          newVersion: "1.161.12",
          repositoryPath: "/private/first-party/repository",
        },
        {
          ecosystem: "pypi",
          registry: "https://pypi.org",
          package: "example-python-dependency",
          oldVersion: null,
          newVersion: "1.82.8",
        },
      ],
      firstPartyProjects: ["secret-project"],
    },
    { baseUrl, codexHome },
  );

  assert.deepEqual(submitted, { jobId: "dps_123", status: "queued" });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, "POST");
  assert.equal(requests[0].url, "/api/aardvark/dependency-scans");
  assert.equal(
    requests[0].headers.authorization,
    "Bearer fixture-chatgpt-access-token",
  );
  assert.equal(
    requests[0].headers["chatgpt-account-id"],
    "fixture-chatgpt-account",
  );
  assert.deepEqual(requests[0].body, {
    dependencies: [
      {
        ecosystem: "npm",
        registry: "https://registry.npmjs.org",
        package: "@example/dependency",
        old_version: "1.161.9",
        new_version: "1.161.12",
      },
      {
        ecosystem: "pypi",
        registry: "https://pypi.org",
        package: "example-python-dependency",
        old_version: null,
        new_version: "1.82.8",
      },
    ],
  });
  assert.equal(
    JSON.stringify(requests[0].body).includes("secret-project"),
    false,
  );
  assert.equal(JSON.stringify(requests[0].body).includes("first-party"), false);

  const status = await getDependencyScan("dps_123", { baseUrl, codexHome });
  assert.deepEqual(status, {
    jobId: "dps_123",
    status: "completed",
    packages: [
      {
        ecosystem: "npm",
        registry: "https://registry.npmjs.org",
        package: "@example/dependency",
        oldVersion: "1.161.9",
        newVersion: "1.161.12",
        status: "completed",
        artifacts: [
          {
            oldDigest: "sha256:old",
            newDigest: "sha256:new",
            cacheHit: true,
          },
        ],
        findings: [
          {
            upstreamFindingId: "dep_fixture",
            codeEvidence: [{ startLine: 8 }],
          },
        ],
        priorFindingAssessments: [
          {
            upstreamFindingId: "dep_fixture",
            status: "present",
          },
        ],
      },
    ],
  });
  assert.equal(requests[1].method, "GET");
  assert.equal(
    requests[1].headers.authorization,
    "Bearer fixture-chatgpt-access-token",
  );
  assert.equal(
    requests[1].headers["chatgpt-account-id"],
    "fixture-chatgpt-account",
  );

  const running = await getDependencyScan("dps_running", {
    baseUrl,
    codexHome,
  });
  assert.equal(running.status, "running");
  assert.equal(running.packages[0].status, "running");
  assert.equal(running.packages[0].phase, "scanning");
  assert.equal(running.packages[0].artifacts[0].cacheHit, false);

  await assert.rejects(
    getDependencyScan("../private-account", { baseUrl, codexHome }),
    /invalid dependency scan job identifier/i,
  );
  assert.equal(requests.length, 3);

  await assert.rejects(
    getDependencyScan("dps_missing", { baseUrl, codexHome }),
    /HTTP 404/,
  );
  await assert.rejects(
    getDependencyScan("dps_redirect", { baseUrl, codexHome }),
    /dependency scan request failed/i,
  );

  const requestCountBeforeAuthFailures = requests.length;
  await assert.rejects(
    getDependencyScan("dps_123", {
      baseUrl,
      codexHome: path.join(temporaryRoot, "missing-auth-home"),
    }),
    /ChatGPT login/i,
  );
  await assert.rejects(
    getDependencyScan("dps_123", { baseUrl, codexHome: missingAccountHome }),
    /ChatGPT login/i,
  );
  await assert.rejects(
    getDependencyScan("dps_123", {
      baseUrl: "https://attacker.invalid/api/aardvark",
      codexHome,
    }),
    /trusted OpenAI HTTPS origin or local loopback endpoint/i,
  );
  assert.equal(requests.length, requestCountBeforeAuthFailures);

  const submittedWithModelSettings = await submitDependencyScan(
    {
      dependencies: [
        {
          ecosystem: "npm",
          registry: "https://registry.npmjs.org",
          package: "@example/dependency",
          oldVersion: "1.161.9",
          newVersion: "1.161.12",
        },
      ],
      dependencyScanTarget: "malware",
      modelSettings: {
        acquisition: {
          model: "fixture-acquisition-model",
          reasoningEffort: "medium",
        },
        scan: { model: "fixture-scan-model" },
        verification: { model: "fixture-scan-model", reasoningEffort: "high" },
        history: { reasoningEffort: "high" },
      },
    },
    { baseUrl, codexHome },
  );
  assert.deepEqual(submittedWithModelSettings, {
    jobId: "dps_123",
    status: "queued",
  });
  assert.deepEqual(requests.at(-1).body, {
    dependencies: [
      {
        ecosystem: "npm",
        registry: "https://registry.npmjs.org",
        package: "@example/dependency",
        old_version: "1.161.9",
        new_version: "1.161.12",
      },
    ],
    dependency_scan_target: "malware",
    model_settings: {
      acquisition: {
        model: "fixture-acquisition-model",
        reasoning_effort: "medium",
      },
      scan: { model: "fixture-scan-model" },
      verification: { model: "fixture-scan-model", reasoning_effort: "high" },
      history: { reasoning_effort: "high" },
    },
  });

  const applicationRoot = path.dirname(
    new URL("../server.ts", import.meta.url).pathname,
  );
  const runtimeBundle = path.join(temporaryRoot, "dependency-server.cjs");
  await build({
    bundle: true,
    define: {
      __dirname: JSON.stringify(applicationRoot),
      "import.meta.url": "__filename",
    },
    entryPoints: [path.join(applicationRoot, "main.ts")],
    external: ["fsevents"],
    format: "cjs",
    loader: { ".md": "text" },
    logLevel: "silent",
    logOverride: { "empty-import-meta": "silent" },
    outfile: runtimeBundle,
    platform: "node",
    target: "node20",
  });

  const client = new Client({
    name: "codex-security-dependency-tools-test",
    version: "1.0.0",
  });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [runtimeBundle, "--stdio"],
    cwd: applicationRoot,
    env: {
      ...process.env,
      CODEX_CLI_PATH: fakeCodexPath,
      CODEX_HOME: codexHome,
      CODEX_SECURITY_AARDVARK_BASE_URL: baseUrl,
      CODEX_SECURITY_DEPENDENCY_MODEL_SETTINGS: "",
      CODEX_SECURITY_ESTIMATE_TEST_MARKER: estimationInvocationPath,
      CODEX_SECURITY_SCAN_ROOT: scanRoot,
      CODEX_SECURITY_STATE_DIR: stateDir,
    },
  });
  await client.connect(transport);
  let boundScanId;
  try {
    const tools = await client.listTools();
    const submit = tools.tools.find(
      (tool) => tool.name === "submit_codex_security_dependency_scan",
    );
    const get = tools.tools.find(
      (tool) => tool.name === "get_codex_security_dependency_scan",
    );
    const getProgress = tools.tools.find(
      (tool) => tool.name === "get_codex_security_scan_dependency_progress",
    );
    const estimate = tools.tools.find(
      (tool) => tool.name === "estimate_codex_security_dependencies",
    );
    const open = tools.tools.find(
      (tool) => tool.name === "open_codex_security_workspace",
    );
    const save = tools.tools.find(
      (tool) => tool.name === "submit_codex_security_setup",
    );
    const promptOnly = tools.tools.find(
      (tool) => tool.name === "start_codex_security_prompt_only_scan",
    );
    assert.ok(
      submit,
      "Dependency scan submission must be registered as an MCP tool.",
    );
    assert.ok(
      get,
      "Dependency scan polling must be registered as an MCP tool.",
    );
    assert.ok(
      getProgress,
      "App-owned dependency scan progress must be registered as an MCP tool.",
    );
    assert.ok(
      estimate,
      "Owner-bound dependency estimation must be registered as an MCP tool.",
    );
    assert.ok(open);
    assert.ok(save);
    assert.ok(promptOnly);
    assert.deepEqual(submit._meta.ui.visibility, ["model"]);
    assert.deepEqual(get._meta.ui.visibility, ["model"]);
    assert.deepEqual(getProgress._meta.ui.visibility, ["app"]);
    assert.deepEqual(estimate._meta.ui.visibility, ["model"]);
    assert.equal(submit.annotations.readOnlyHint, false);
    assert.equal(submit.annotations.destructiveHint, false);
    assert.equal(submit.annotations.idempotentHint, false);
    assert.equal(get.annotations.readOnlyHint, true);
    assert.equal(get.annotations.idempotentHint, true);
    assert.equal(getProgress.annotations.readOnlyHint, true);
    assert.equal(getProgress.annotations.idempotentHint, true);
    assert.equal(estimate.annotations.readOnlyHint, false);
    assert.equal(estimate.annotations.idempotentHint, false);
    assert.deepEqual(submit.inputSchema.required, ["dependencies"]);
    assert.equal(submit.inputSchema.properties.scanId.format, "uuid");
    assert.deepEqual(submit.inputSchema.properties.dependencyScanTarget.enum, [
      "malware",
      "malware-and-vulnerabilities",
    ]);
    assert.deepEqual(
      Object.keys(submit.inputSchema.properties.modelSettings.properties),
      ["acquisition", "scan", "verification", "history"],
    );
    assert.deepEqual(
      Object.keys(
        submit.inputSchema.properties.modelSettings.properties.acquisition
          .properties,
      ),
      ["model", "reasoningEffort"],
    );
    assert.deepEqual(get.inputSchema.required, ["jobId"]);
    assert.deepEqual(getProgress.inputSchema.required, ["scanId"]);
    assert.deepEqual(estimate.inputSchema.required, [
      "mode",
      "scope",
      "targetPath",
    ]);
    assert.deepEqual(open.inputSchema.properties.mode.enum, [
      "diff",
      "standard",
      "deep",
      "dependency_update",
      "full_dependency",
    ]);
    assert.ok(open.inputSchema.properties.scanDependencies);
    assert.ok(open.inputSchema.properties.modelSettings);
    assert.ok(open.inputSchema.properties.dependencyDepth);
    assert.deepEqual(open.inputSchema.properties.dependencyScanTarget.enum, [
      "malware",
      "malware-and-vulnerabilities",
    ]);
    assert.ok(save.inputSchema.properties.scanDependencies);
    assert.ok(save.inputSchema.properties.modelSettings);
    assert.ok(save.inputSchema.properties.dependencyDepth);
    assert.deepEqual(save.inputSchema.properties.dependencyScanTarget.enum, [
      "malware",
      "malware-and-vulnerabilities",
    ]);
    assert.deepEqual(promptOnly._meta.ui.visibility, ["model"]);
    assert.deepEqual(
      promptOnly.inputSchema.properties.dependencyScanTarget.enum,
      ["malware", "malware-and-vulnerabilities"],
    );
    assert.deepEqual(promptOnly.inputSchema.properties.mode.enum, [
      "diff",
      "standard",
      "dependency_update",
      "full_dependency",
    ]);

    const estimateWithoutOwner = await client.callTool({
      name: "estimate_codex_security_dependencies",
      arguments: { mode: "full_dependency", scope: ".", targetPath: target },
    });
    assert.equal(estimateWithoutOwner.isError, true);
    assert.match(estimateWithoutOwner.content[0].text, /owning Codex thread/i);

    const estimateWithoutSandbox = await client.callTool({
      name: "estimate_codex_security_dependencies",
      arguments: { mode: "full_dependency", scope: ".", targetPath: target },
      _meta: { "openai/threadId": "fixture-dependency-estimate-owner" },
    });
    assert.equal(estimateWithoutSandbox.isError, true);
    assert.match(
      estimateWithoutSandbox.content[0].text,
      /trusted parent sandbox metadata/i,
    );

    const trustedSandbox = {
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
      sandboxCwd: target,
    };
    for (const mode of ["full_dependency", "standard"]) {
      const scopedWorkspace = await client.callTool({
        name: "open_codex_security_workspace",
        arguments: {
          mode,
          targetPath: target,
          scope: scopedDirectory,
          ...(mode === "standard" ? { scanDependencies: true } : {}),
        },
        _meta: { "openai/threadId": `fixture-scoped-${mode}-thread` },
      });
      assert.equal(
        scopedWorkspace.isError,
        undefined,
        `${mode} should accept an authorized folder scope: ${scopedWorkspace.content[0]?.text}`,
      );
      assert.equal(
        scopedWorkspace.structuredContent.workspace.scope,
        "packages/scoped",
        `${mode} folder scope should normalize: ${JSON.stringify(scopedWorkspace.structuredContent.workspace.setupValidation)}`,
      );

      const savedScopedWorkspace = await client.callTool({
        name: "submit_codex_security_setup",
        arguments: {
          sessionId: scopedWorkspace.structuredContent.workspace.id,
          mode,
          targetPath: target,
          scope: "packages/scoped",
          ...(mode === "standard" ? { scanDependencies: true } : {}),
        },
      });
      assert.equal(savedScopedWorkspace.isError, undefined);
      assert.equal(
        savedScopedWorkspace.structuredContent.workspace.scope,
        "packages/scoped",
      );

      const startedScopedWorkspace = await client.callTool({
        name: "start_codex_security_scan",
        arguments: {
          sessionId: scopedWorkspace.structuredContent.workspace.id,
        },
      });
      assert.equal(startedScopedWorkspace.isError, undefined);
      assert.equal(
        startedScopedWorkspace.structuredContent.workspace.results.mode,
        mode,
      );
      assert.equal(
        startedScopedWorkspace.structuredContent.workspace.results.scope,
        "packages/scoped",
      );
      assert.equal(
        startedScopedWorkspace.structuredContent.workspace.results
          .scanDependencies,
        true,
      );
    }

    for (const mode of ["diff", "dependency_update", "deep"]) {
      const rejectedScopedWorkspace = await client.callTool({
        name: "open_codex_security_workspace",
        arguments: {
          mode,
          targetPath: target,
          scope: "packages/scoped",
          ...(mode === "deep"
            ? {}
            : { diffTarget: { kind: "range", baseRevision, headRevision } }),
        },
        _meta: { "openai/threadId": `fixture-rejected-scoped-${mode}-thread` },
      });
      assert.equal(
        rejectedScopedWorkspace.isError,
        true,
        `${mode} must retain whole-target scope`,
      );
      assert.match(rejectedScopedWorkspace.content[0].text, /whole target/i);
    }

    const beforeEstimation = requests.length;
    const estimated = await client.callTool({
      name: "estimate_codex_security_dependencies",
      arguments: { mode: "full_dependency", scope: ".", targetPath: target },
      _meta: {
        "openai/threadId": "fixture-dependency-estimate-owner",
        "codex/sandbox-state-meta": trustedSandbox,
        "x-codex-turn-metadata": {
          model: "fixture-acquisition-model",
          reasoning_effort: "xhigh",
        },
      },
    });
    assert.equal(estimated.isError, undefined);
    assert.deepEqual(estimated.structuredContent, { depthCounts: [2, 5, 3] });
    assert.equal(requests.length, beforeEstimation);
    const estimateInvocation = JSON.parse(
      await readFile(estimationInvocationPath, "utf8"),
    );
    const estimateModelIndex = estimateInvocation.args.indexOf("--model");
    assert.notEqual(estimateModelIndex, -1);
    assert.equal(
      estimateInvocation.args[estimateModelIndex + 1],
      "fixture-acquisition-model",
    );
    assert.equal(
      estimateInvocation.args.includes('model_reasoning_effort="xhigh"'),
      true,
    );
    assert.equal(
      estimateInvocation.args.includes(
        'default_permissions="codex_security_deep_scan_worker"',
      ),
      true,
    );
    assert.equal(
      estimateInvocation.args.some(
        (arg) =>
          arg.startsWith("permissions.codex_security_deep_scan_worker=") &&
          arg.includes(':root"="read"') &&
          arg.includes("enabled=false"),
      ),
      true,
    );
    assert.equal(estimateInvocation.args.includes("--add-dir"), false);
    assert.equal(
      estimateInvocation.args.includes(
        "--dangerously-bypass-approvals-and-sandbox",
      ),
      false,
    );
    assert.equal(
      estimateInvocation.args.includes('approval_policy="never"'),
      true,
    );
    assert.equal(
      estimateInvocation.args.some((arg) => arg.includes("network_access")),
      false,
    );
    assert.match(
      estimateInvocation.prompt,
      /skills\/dependency-resolution\/SKILL\.md/,
    );
    assert.match(estimateInvocation.prompt, /\boffline\b/i);
    assert.match(
      estimateInvocation.prompt,
      /\b(?:checked[- ]in|local)\b[^\n]*\b(?:lockfiles?|manifests?)\b/i,
    );
    assert.match(
      estimateInvocation.prompt,
      /\bread\b[^\n]*\balready[- ]existing\b[^\n]*\binstalled\b[^\n]*\bmetadata\b[^\n]*\blockfiles?\b/i,
    );
    assert.match(
      estimateInvocation.prompt,
      /\b(?:hidden|ignored)\b[^\n]*\blockfiles?\b/i,
    );
    assert.match(
      estimateInvocation.prompt,
      /\bread[- ]only\b[^\n]*\bonly when\b[^\n]*\b(?:exact|selected)\b[^\n]*\bsnapshot\b/i,
    );
    assert.match(
      estimateInvocation.prompt,
      /\bselected\b[^\n]*\bsnapshot\b[^\n]*\bworkspace\b/i,
    );
    assert.match(
      estimateInvocation.prompt,
      /\bhistorical\b[^\n]*\brevisions?\b/i,
    );
    assert.match(
      estimateInvocation.prompt,
      /\bnever\b[^\n]*\bsubstitute\b[^\n]*\bcurrent\b[^\n]*\binstalled\b/i,
    );
    assert.match(estimateInvocation.prompt, /\b(?:bash|shell)\b/i);
    assert.match(
      estimateInvocation.prompt,
      /\b(?:package[- ]manager|read[- ]only scripts?)\b/i,
    );
    assert.match(
      estimateInvocation.prompt,
      /\b(?:package[- ]manager|ecosystem)\b[^\n]*\b(?:resolv(?:er|ed|ing|ution)|installed[- ]tree)\b/i,
    );
    assert.match(
      estimateInvocation.prompt,
      /\b(?:supported|documented|native)\b[^\n]*\bresolver\b[^\n]*\b(?:api|library)\b/i,
    );
    assert.match(
      estimateInvocation.prompt,
      /\b(?:customer|production|effective)\b[^\n]*\b(?:tree|graph)\b/i,
    );
    for (const resolutionBehavior of [
      /\bhoist(?:ed|ing)?\b/i,
      /\bpeers?\b/i,
      /\boptional\b/i,
      /\bworkspaces?\b/i,
      /\balias(?:es)?\b/i,
      /\bplatforms?\b/i,
      /\bpolic(?:y|ies)\b/i,
    ]) {
      assert.match(estimateInvocation.prompt, resolutionBehavior);
    }
    assert.match(
      estimateInvocation.prompt,
      /\b(?:do not|never)\b[^\n]*\b(?:manual|hand[- ]written|ad[- ]hoc)\b/i,
    );
    assert.match(
      estimateInvocation.prompt,
      /\bnever\b[^\n]*\breconstruct\b[^\n]*\bgraph\b/i,
    );
    assert.match(
      estimateInvocation.prompt,
      /\b(?:hand[- ]written|generic|ad[- ]hoc)\b[^\n]*\b(?:lockfile|parser|traversal)\b/i,
    );
    assert.match(
      estimateInvocation.prompt,
      /\bscripts?\b[^\n]*\bonly when\b[^\n]*\bresolver\b/i,
    );
    assert.match(
      estimateInvocation.prompt,
      /\b(?:unavailable|cannot|unable)\b[^\n]*\b(?:blocker|fail)\b/i,
    );
    assert.match(
      estimateInvocation.prompt,
      /\bmachine[- ]comput(?:e|ed|ing)\b/i,
    );
    assert.match(estimateInvocation.prompt, /\bversion[- ]qualified\b/i);
    assert.match(estimateInvocation.prompt, /\btransitive\b/i);
    assert.match(
      estimateInvocation.prompt,
      /\b(?:histogram|package[- ]count)\b/i,
    );
    assert.match(
      estimateInvocation.prompt,
      /\b(?:tool|command|script)\b[^\n]*\boutput\b/i,
    );
    assert.match(
      estimateInvocation.prompt,
      /\b(?:do not|never)\b[^\n]*\b(?:mentally|mental)\b/i,
    );
    assert.match(
      estimateInvocation.prompt,
      /\b(?:do not|never)\b[^\n]*\b(?:network|registr(?:y|ies))\b/i,
    );
    assert.match(
      estimateInvocation.prompt,
      /\b(?:do not|never)\b[^\n]*\b(?:install|fetch|download)\b/i,
    );
    assert.equal(estimateInvocation.prompt.includes(target), true);

    const beforeUnavailableResolver = requests.length;
    const unavailableResolver = await client.callTool({
      name: "estimate_codex_security_dependencies",
      arguments: { mode: "standard", scope: ".", targetPath: target },
      _meta: {
        "openai/threadId": "fixture-dependency-estimate-owner",
        "codex/sandbox-state-meta": trustedSandbox,
      },
    });
    assert.equal(unavailableResolver.isError, true);
    assert.match(
      unavailableResolver.content[0].text,
      /resolver[^\n]*unavailable/i,
    );
    assert.match(unavailableResolver.content[0].text, /offline/i);
    assert.equal(
      unavailableResolver.content[0].text.includes(
        "/private/customer/repository",
      ),
      false,
    );
    assert.equal(
      unavailableResolver.content[0].text.includes(
        "@private/internal-dependency",
      ),
      false,
    );
    assert.equal(requests.length, beforeUnavailableResolver);

    const invalidEstimate = await client.callTool({
      name: "estimate_codex_security_dependencies",
      arguments: { mode: "deep", scope: ".", targetPath: target },
      _meta: {
        "openai/threadId": "fixture-dependency-estimate-owner",
        "codex/sandbox-state-meta": trustedSandbox,
      },
    });
    assert.equal(invalidEstimate.isError, true);
    assert.match(
      invalidEstimate.content[0].text,
      /exact package-depth histogram/i,
    );

    const exactDiffEstimate = await client.callTool({
      name: "estimate_codex_security_dependencies",
      arguments: {
        mode: "dependency_update",
        scope: ".",
        targetPath: target,
        diffTarget: { kind: "range", baseRevision, headRevision },
      },
      _meta: {
        "openai/threadId": "fixture-dependency-estimate-owner",
        "codex/sandbox-state-meta": trustedSandbox,
      },
    });
    assert.equal(exactDiffEstimate.isError, undefined);
    assert.deepEqual(exactDiffEstimate.structuredContent, {
      depthCounts: [2, 5, 3],
    });
    const exactDiffInvocation = JSON.parse(
      await readFile(estimationInvocationPath, "utf8"),
    );
    assert.equal(exactDiffInvocation.prompt.includes(baseRevision), true);
    assert.equal(exactDiffInvocation.prompt.includes(headRevision), true);

    const beforeScopedEstimation = requests.length;
    const scopedEstimate = await client.callTool({
      name: "estimate_codex_security_dependencies",
      arguments: {
        mode: "full_dependency",
        scope: scopedDirectory,
        targetPath: target,
      },
      _meta: {
        "openai/threadId": "fixture-dependency-estimate-owner",
        "codex/sandbox-state-meta": trustedSandbox,
      },
    });
    assert.equal(
      scopedEstimate.isError,
      undefined,
      `Full-dependency estimation should preserve an authorized folder scope: ${scopedEstimate.content[0]?.text}`,
    );
    assert.deepEqual(scopedEstimate.structuredContent, {
      depthCounts: [2, 5, 3],
    });
    const scopedInvocation = JSON.parse(
      await readFile(estimationInvocationPath, "utf8"),
    );
    assert.equal(
      scopedInvocation.prompt.includes('"scope":"packages/scoped"'),
      true,
    );
    assert.equal(
      scopedInvocation.prompt.includes(`"scope":"${scopedDirectory}"`),
      false,
    );
    assert.equal(requests.length, beforeScopedEstimation);

    for (const escapedScope of ["../outside", "escaped-scope"]) {
      const beforeRejectedScope = requests.length;
      const previousInvocation = await readFile(
        estimationInvocationPath,
        "utf8",
      );
      const rejectedScope = await client.callTool({
        name: "estimate_codex_security_dependencies",
        arguments: {
          mode: "full_dependency",
          scope: escapedScope,
          targetPath: target,
        },
        _meta: {
          "openai/threadId": "fixture-dependency-estimate-owner",
          "codex/sandbox-state-meta": trustedSandbox,
        },
      });
      assert.equal(
        rejectedScope.isError,
        true,
        `${escapedScope} must not leave the authorized target`,
      );
      assert.match(rejectedScope.content[0].text, /stay inside/i);
      assert.equal(
        await readFile(estimationInvocationPath, "utf8"),
        previousInvocation,
      );
      assert.equal(requests.length, beforeRejectedScope);
    }

    const beforeCanceledEstimate = requests.length;
    const cancellationStarted = new Promise((resolve) => {
      estimateControlWaiters.started = resolve;
    });
    const cancellationStopped = new Promise((resolve) => {
      estimateControlWaiters.stopped = resolve;
    });
    const cancellationController = new AbortController();
    const canceledEstimate = client.callTool(
      {
        name: "estimate_codex_security_dependencies",
        arguments: {
          mode: "diff",
          scope: ".",
          targetPath: target,
          diffTarget: { kind: "range", baseRevision, headRevision },
        },
        _meta: {
          "openai/threadId": "fixture-dependency-estimate-cancellation-owner",
          "codex/sandbox-state-meta": trustedSandbox,
        },
      },
      undefined,
      { signal: cancellationController.signal },
    );
    const cancellationRejection = assert.rejects(canceledEstimate, /cancel/i);
    const startedWorker = await Promise.race([
      cancellationStarted,
      canceledEstimate.then(() => {
        throw new Error("Dependency estimation completed before cancellation.");
      }),
    ]);
    assert.ok(Number.isInteger(startedWorker.pid));
    cancellationController.abort(
      new Error("Dependency estimate canceled by user."),
    );
    await cancellationRejection;
    const stoppedWorker = await cancellationStopped;
    assert.equal(stoppedWorker.pid, startedWorker.pid);
    assert.equal(stoppedWorker.signal, "SIGTERM");
    assert.equal(requests.length, beforeCanceledEstimate);
    estimateControlWaiters.started = undefined;
    estimateControlWaiters.stopped = undefined;

    const submittedByTool = await client.callTool({
      name: "submit_codex_security_dependency_scan",
      arguments: {
        dependencies: [
          {
            ecosystem: "npm",
            registry: "https://registry.npmjs.org",
            package: "@example/dependency",
            oldVersion: "1.161.9",
            newVersion: "1.161.12",
          },
        ],
      },
    });
    assert.equal(submittedByTool.isError, undefined);
    assert.deepEqual(submittedByTool.structuredContent, {
      jobId: "dps_123",
      status: "queued",
    });
    assert.equal(
      Object.hasOwn(requests.at(-1).body, "dependency_scan_target"),
      false,
    );
    assert.equal(Object.hasOwn(requests.at(-1).body, "model_settings"), false);

    const submittedWithModelSettingsByTool = await client.callTool({
      name: "submit_codex_security_dependency_scan",
      arguments: {
        dependencies: [
          {
            ecosystem: "npm",
            registry: "https://registry.npmjs.org",
            package: "@example/dependency",
            oldVersion: "1.161.9",
            newVersion: "1.161.12",
          },
        ],
        dependencyScanTarget: "malware",
        modelSettings: {
          acquisition: {
            model: "fixture-acquisition-model",
            reasoningEffort: "medium",
          },
          scan: { model: "fixture-scan-model", reasoningEffort: "xhigh" },
          verification: {
            model: "fixture-scan-model",
            reasoningEffort: "high",
          },
          history: { model: "gpt-5.6-terra", reasoningEffort: "low" },
        },
      },
    });
    assert.equal(submittedWithModelSettingsByTool.isError, undefined);
    assert.equal(requests.at(-1).body.dependency_scan_target, "malware");
    assert.deepEqual(requests.at(-1).body.model_settings, {
      acquisition: {
        model: "fixture-acquisition-model",
        reasoning_effort: "medium",
      },
      scan: { model: "fixture-scan-model", reasoning_effort: "xhigh" },
      verification: { model: "fixture-scan-model", reasoning_effort: "high" },
      history: { model: "gpt-5.6-terra", reasoning_effort: "low" },
    });

    const polledByTool = await client.callTool({
      name: "get_codex_security_dependency_scan",
      arguments: { jobId: "dps_123" },
    });
    assert.equal(polledByTool.isError, undefined);
    assert.equal(polledByTool.structuredContent.jobId, "dps_123");
    assert.equal(
      polledByTool.structuredContent.packages[0].artifacts[0].cacheHit,
      true,
    );

    const privateContext = await client.callTool({
      name: "submit_codex_security_dependency_scan",
      arguments: {
        dependencies: [
          {
            ecosystem: "npm",
            registry: "https://registry.npmjs.org",
            package: "@example/dependency",
            oldVersion: "1.161.9",
            newVersion: "1.161.12",
            repositoryPath: "/private/repository",
          },
        ],
      },
    });
    assert.equal(privateContext.isError, true);

    const unknownJob = await client.callTool({
      name: "get_codex_security_dependency_scan",
      arguments: { jobId: "dps_missing" },
    });
    assert.equal(unknownJob.isError, true);
    assert.match(unknownJob.content[0].text, /HTTP 404/);

    const directFull = await client.callTool({
      name: "start_codex_security_prompt_only_scan",
      arguments: {
        dependencyScanTarget: "malware-and-vulnerabilities",
        mode: "full_dependency",
        targetPath: target,
        scope: ".",
      },
      _meta: { "openai/threadId": "fixture-direct-full-dependency-thread" },
    });
    assert.equal(directFull.isError, undefined);
    assert.equal(directFull.structuredContent.scan.mode, "full_dependency");
    assert.equal(directFull.structuredContent.scan.scanDependencies, true);
    assert.equal(
      directFull.structuredContent.scan.dependencyScanTarget,
      "malware-and-vulnerabilities",
    );
    assert.equal(directFull.structuredContent.scan.diffTarget, null);

    const directUpdate = await client.callTool({
      name: "start_codex_security_prompt_only_scan",
      arguments: {
        mode: "dependency_update",
        targetPath: target,
        scope: ".",
        diffTarget: { kind: "range", baseRevision, headRevision },
      },
      _meta: { "openai/threadId": "fixture-direct-dependency-update-thread" },
    });
    assert.equal(directUpdate.isError, undefined);
    assert.equal(directUpdate.structuredContent.scan.mode, "dependency_update");
    assert.equal(directUpdate.structuredContent.scan.scanDependencies, true);
    assert.equal(
      directUpdate.structuredContent.scan.diffTarget.baseRevision,
      baseRevision,
    );
    assert.equal(
      directUpdate.structuredContent.scan.diffTarget.headRevision,
      headRevision,
    );

    const beforeScopedPromptOnly = requests.length;
    const scopedPromptOnly = await client.callTool({
      name: "start_codex_security_prompt_only_scan",
      arguments: {
        mode: "full_dependency",
        targetPath: target,
        scope: scopedDirectory,
      },
      _meta: {
        "openai/threadId": "fixture-scoped-prompt-only-full-dependency-thread",
      },
    });
    assert.equal(
      scopedPromptOnly.isError,
      undefined,
      `Full-dependency prompt-only scan should accept the authorized folder: ${scopedPromptOnly.content[0]?.text}`,
    );
    assert.equal(
      scopedPromptOnly.structuredContent.scan.mode,
      "full_dependency",
    );
    assert.equal(
      scopedPromptOnly.structuredContent.scan.scope,
      "packages/scoped",
    );
    for (const mode of ["diff", "dependency_update"]) {
      const rejectedScopedPromptOnly = await client.callTool({
        name: "start_codex_security_prompt_only_scan",
        arguments: {
          mode,
          targetPath: target,
          scope: "packages/scoped",
          diffTarget: { kind: "range", baseRevision, headRevision },
        },
        _meta: {
          "openai/threadId": `fixture-rejected-scoped-prompt-only-${mode}-thread`,
        },
      });
      assert.equal(rejectedScopedPromptOnly.isError, true);
      assert.match(rejectedScopedPromptOnly.content[0].text, /whole target/i);
    }
    assert.equal(requests.length, beforeScopedPromptOnly);

    const nativeThread = "fixture-native-continuation-thread";
    const nativeWorkspace = await client.callTool({
      name: "open_codex_security_workspace",
      arguments: {
        mode: "full_dependency",
        targetPath: target,
        scope: ".",
      },
    });
    assert.equal(nativeWorkspace.isError, undefined);
    const nativeWorkspaceId = nativeWorkspace.structuredContent.workspace.id;
    const nativeSaved = await client.callTool({
      name: "submit_codex_security_setup",
      arguments: {
        sessionId: nativeWorkspaceId,
        mode: "full_dependency",
        targetPath: target,
        scope: ".",
      },
    });
    assert.equal(nativeSaved.isError, undefined);
    const nativeStarted = await client.callTool({
      name: "start_codex_security_scan",
      arguments: { sessionId: nativeWorkspaceId },
    });
    assert.equal(nativeStarted.isError, undefined);
    const nativeScanId =
      nativeStarted.structuredContent.workspace.results.scanId;
    assert.equal(
      nativeStarted.structuredContent.workspace.results.continuationThreadId,
      null,
    );

    const nativeDependencies = [
      {
        ecosystem: "npm",
        registry: "https://registry.npmjs.org",
        package: "@example/dependency",
        oldVersion: "1.161.9",
        newVersion: "1.161.12",
      },
    ];
    const beforeNativeOwnership = requests.length;
    const unownedNative = await client.callTool({
      name: "submit_codex_security_dependency_scan",
      arguments: { scanId: nativeScanId, dependencies: nativeDependencies },
      _meta: { "openai/threadId": nativeThread },
    });
    assert.equal(unownedNative.isError, true);
    assert.equal(requests.length, beforeNativeOwnership);

    const nativeHandoffToken = randomUUID();
    const nativeClaimed = await client.callTool({
      name: "claim_codex_security_scan_handoff_delivery",
      arguments: { scanId: nativeScanId, claimToken: nativeHandoffToken },
    });
    assert.equal(nativeClaimed.isError, undefined);
    const nativeAttached = await client.callTool({
      name: "attach_codex_security_scan_continuation_thread",
      arguments: {
        scanId: nativeScanId,
        claimToken: nativeHandoffToken,
        threadId: nativeThread,
      },
    });
    assert.equal(nativeAttached.isError, undefined);
    assert.equal(
      nativeAttached.structuredContent.workspace.results.continuationThreadId,
      nativeThread,
    );
    const nativeContext = await client.callTool({
      name: "get_codex_security_scan_context",
      arguments: {
        scanId: nativeScanId,
        handoffClaimToken: nativeHandoffToken,
      },
      _meta: { "openai/threadId": nativeThread },
    });
    assert.equal(nativeContext.isError, undefined);
    assert.equal(
      nativeContext.structuredContent.scan.handoffStatus,
      "delivered",
    );
    assert.equal(
      nativeContext.structuredContent.scan.continuationThreadId,
      nativeThread,
    );

    const spoofedNative = await client.callTool({
      name: "submit_codex_security_dependency_scan",
      arguments: { scanId: nativeScanId, dependencies: nativeDependencies },
      _meta: { "openai/threadId": "fixture-spoofed-native-thread" },
    });
    assert.equal(spoofedNative.isError, true);
    assert.equal(requests.length, beforeNativeOwnership);

    const authPath = path.join(codexHome, "auth.json");
    const savedAuth = await readFile(authPath, "utf8");
    try {
      await writeFile(authPath, "{}");
      const withoutLogin = await client.callTool({
        name: "submit_codex_security_dependency_scan",
        arguments: { scanId: nativeScanId, dependencies: nativeDependencies },
        _meta: { "openai/threadId": nativeThread },
      });
      assert.equal(withoutLogin.isError, true);
      assert.match(withoutLogin.content[0].text, /existing ChatGPT login/);
      assert.equal(requests.length, beforeNativeOwnership);
    } finally {
      await writeFile(authPath, savedAuth);
    }

    const nativeBound = await client.callTool({
      name: "submit_codex_security_dependency_scan",
      arguments: { scanId: nativeScanId, dependencies: nativeDependencies },
      _meta: { "openai/threadId": nativeThread },
    });
    assert.equal(
      nativeBound.isError,
      undefined,
      `A failed local login check must leave submission retryable: ${nativeBound.content[0]?.text}`,
    );
    assert.equal(nativeBound.structuredContent.jobId, "dps_123");
    assert.equal(requests.length, beforeNativeOwnership + 1);
    const nativeProgress = await client.callTool({
      name: "get_codex_security_scan_dependency_progress",
      arguments: { scanId: nativeScanId },
    });
    assert.equal(nativeProgress.isError, undefined);
    assert.equal(nativeProgress.structuredContent.jobId, "dps_123");

    const ownerThread = "fixture-dependency-owning-thread";
    const selectedSettings = {
      acquisition: {
        model: "fixture-acquisition-model",
        reasoningEffort: "xhigh",
      },
      scan: { model: "fixture-acquisition-model", reasoningEffort: "xhigh" },
      verification: { model: "fixture-scan-model", reasoningEffort: "high" },
      history: { model: "fixture-acquisition-model", reasoningEffort: "xhigh" },
    };
    const opened = await client.callTool({
      name: "open_codex_security_workspace",
      arguments: {
        mode: "full_dependency",
        dependencyDepth: 2,
        dependencyScanTarget: "malware-and-vulnerabilities",
        targetPath: target,
        scope: ".",
        scanDependencies: true,
        modelSettings: selectedSettings,
      },
      _meta: { "openai/threadId": ownerThread },
    });
    assert.equal(opened.isError, undefined);
    assert.equal(opened.structuredContent.workspace.mode, "full_dependency");
    assert.equal(opened.structuredContent.workspace.scanDependencies, true);
    assert.equal(opened.structuredContent.workspace.dependencyDepth, 2);
    assert.equal(
      opened.structuredContent.workspace.dependencyScanTarget,
      "malware-and-vulnerabilities",
    );
    assert.deepEqual(
      opened.structuredContent.workspace.modelSettings,
      selectedSettings,
    );

    const saved = await client.callTool({
      name: "submit_codex_security_setup",
      arguments: {
        sessionId: opened.structuredContent.workspace.id,
        mode: "full_dependency",
        dependencyDepth: null,
        dependencyScanTarget: "malware",
        targetPath: target,
        scope: ".",
        scanDependencies: true,
        modelSettings: selectedSettings,
      },
    });
    assert.equal(saved.isError, undefined);
    assert.equal(saved.structuredContent.workspace.scanDependencies, true);
    assert.equal(saved.structuredContent.workspace.dependencyDepth, null);
    assert.equal(
      saved.structuredContent.workspace.dependencyScanTarget,
      "malware",
    );
    assert.deepEqual(
      saved.structuredContent.workspace.modelSettings,
      selectedSettings,
    );

    const started = await client.callTool({
      name: "start_codex_security_scan",
      arguments: { sessionId: opened.structuredContent.workspace.id },
    });
    assert.equal(started.isError, undefined);
    boundScanId = started.structuredContent.workspace.results.scanId;
    assert.equal(
      started.structuredContent.workspace.results.dependencyJobId,
      null,
    );
    assert.equal(
      started.structuredContent.workspace.results.dependencyDepth,
      null,
    );
    assert.equal(
      started.structuredContent.workspace.results.dependencyScanTarget,
      "malware",
    );
    assert.deepEqual(
      started.structuredContent.workspace.results.modelSettings,
      selectedSettings,
    );

    const beforeOwnerFailures = requests.length;
    const unboundProgress = await client.callTool({
      name: "get_codex_security_scan_dependency_progress",
      arguments: { scanId: boundScanId },
    });
    assert.equal(unboundProgress.isError, true);
    assert.match(
      unboundProgress.content[0].text,
      /no associated dependency scan job/i,
    );

    const missingOwner = await client.callTool({
      name: "submit_codex_security_dependency_scan",
      arguments: {
        scanId: boundScanId,
        dependencies: [
          {
            ecosystem: "npm",
            registry: "https://registry.npmjs.org",
            package: "@example/dependency",
            oldVersion: "1.161.9",
            newVersion: "1.161.12",
          },
        ],
      },
    });
    assert.equal(missingOwner.isError, true);
    assert.match(missingOwner.content[0].text, /owning Codex thread/i);

    const wrongOwner = await client.callTool({
      name: "submit_codex_security_dependency_scan",
      arguments: {
        scanId: boundScanId,
        dependencies: [
          {
            ecosystem: "npm",
            registry: "https://registry.npmjs.org",
            package: "@example/dependency",
            oldVersion: "1.161.9",
            newVersion: "1.161.12",
          },
        ],
      },
      _meta: { "openai/threadId": "fixture-other-thread" },
    });
    assert.equal(wrongOwner.isError, true);
    assert.equal(requests.length, beforeOwnerFailures);

    const bound = await client.callTool({
      name: "submit_codex_security_dependency_scan",
      arguments: {
        scanId: boundScanId,
        dependencyScanTarget: "malware-and-vulnerabilities",
        modelSettings: {
          scan: { model: "untrusted-model", reasoningEffort: "low" },
        },
        dependencies: [
          {
            ecosystem: "npm",
            registry: "https://registry.npmjs.org",
            package: "@example/dependency",
            oldVersion: "1.161.9",
            newVersion: "1.161.12",
          },
        ],
      },
      _meta: { "openai/threadId": ownerThread },
    });
    assert.equal(bound.isError, undefined);
    assert.equal(bound.structuredContent.jobId, "dps_123");
    assert.equal(requests.at(-1).body.dependency_scan_target, "malware");
    assert.deepEqual(requests.at(-1).body.model_settings, {
      acquisition: {
        model: "fixture-acquisition-model",
        reasoning_effort: "xhigh",
      },
      scan: { model: "fixture-acquisition-model", reasoning_effort: "xhigh" },
      verification: { model: "fixture-scan-model", reasoning_effort: "high" },
      history: {
        model: "fixture-acquisition-model",
        reasoning_effort: "xhigh",
      },
    });
    assert.equal(Object.hasOwn(requests.at(-1).body, "scanId"), false);
    assert.equal(Object.hasOwn(requests.at(-1).body, "scan_id"), false);
    assert.equal(JSON.stringify(requests.at(-1).body).includes(target), false);

    const localScan = await client.callTool({
      name: "get_codex_security_scan",
      arguments: { scanId: boundScanId },
    });
    assert.equal(localScan.structuredContent.scan.dependencyJobId, "dps_123");

    const appProgress = await client.callTool({
      name: "get_codex_security_scan_dependency_progress",
      arguments: { scanId: boundScanId },
    });
    assert.equal(appProgress.isError, undefined);
    assert.equal(appProgress.structuredContent.jobId, "dps_123");
    assert.equal(
      appProgress.structuredContent.packages[0].artifacts[0].cacheHit,
      true,
    );

    const submissionsBeforeResume = requests.filter(
      ({ method }) => method === "POST",
    ).length;
    const resumed = await client.callTool({
      name: "submit_codex_security_dependency_scan",
      arguments: {
        scanId: boundScanId,
        dependencies: [
          {
            ecosystem: "npm",
            registry: "https://registry.npmjs.org",
            package: "@example/dependency",
            oldVersion: "1.161.9",
            newVersion: "1.161.12",
          },
        ],
      },
      _meta: { "openai/threadId": ownerThread },
    });
    assert.equal(resumed.isError, undefined);
    assert.equal(resumed.structuredContent.jobId, "dps_123");
    assert.equal(
      requests.filter(({ method }) => method === "POST").length,
      submissionsBeforeResume,
    );

    const submissionsBeforeConcurrent = requests.filter(
      ({ method }) => method === "POST",
    ).length;
    const concurrentSubmission = {
      name: "submit_codex_security_dependency_scan",
      arguments: {
        scanId: directFull.structuredContent.scan.scanId,
        dependencies: [
          {
            ecosystem: "npm",
            registry: "https://registry.npmjs.org",
            package: "@example/dependency",
            oldVersion: "1.161.9",
            newVersion: "1.161.12",
          },
        ],
      },
      _meta: { "openai/threadId": "fixture-direct-full-dependency-thread" },
    };
    const concurrent = await Promise.all([
      client.callTool(concurrentSubmission),
      client.callTool(concurrentSubmission),
    ]);
    assert.deepEqual(
      concurrent.map((result) => result.structuredContent.jobId),
      ["dps_123", "dps_123"],
    );
    assert.equal(
      requests.filter(({ method }) => method === "POST").length,
      submissionsBeforeConcurrent + 1,
    );
    assert.equal(
      requests.filter(({ method }) => method === "POST").at(-1).body
        .dependency_scan_target,
      "malware-and-vulnerabilities",
    );
  } finally {
    await client.close();
  }

  const authoritativeSettings = {
    acquisition: {
      model: "fixture-acquisition-model",
      reasoningEffort: "xhigh",
    },
    scan: { model: "fixture-acquisition-model", reasoningEffort: "xhigh" },
    verification: { model: "fixture-scan-model", reasoningEffort: "high" },
    history: { model: "fixture-acquisition-model", reasoningEffort: "xhigh" },
  };
  const resumedClient = new Client({
    name: "codex-security-dependency-tools-resume-test",
    version: "1.0.0",
  });
  await resumedClient.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [runtimeBundle, "--stdio"],
      cwd: applicationRoot,
      env: {
        ...process.env,
        CODEX_HOME: codexHome,
        CODEX_SECURITY_AARDVARK_BASE_URL: baseUrl,
        CODEX_SECURITY_DEPENDENCY_MODEL_SETTINGS: JSON.stringify(
          authoritativeSettings,
        ),
        CODEX_SECURITY_SCAN_ROOT: scanRoot,
        CODEX_SECURITY_STATE_DIR: stateDir,
      },
    }),
  );
  try {
    const restartedProgress = await resumedClient.callTool({
      name: "get_codex_security_scan_dependency_progress",
      arguments: { scanId: boundScanId },
    });
    assert.equal(restartedProgress.isError, undefined);
    assert.equal(restartedProgress.structuredContent.jobId, "dps_123");

    const authoritative = await resumedClient.callTool({
      name: "submit_codex_security_dependency_scan",
      arguments: {
        dependencies: [
          {
            ecosystem: "npm",
            registry: "https://registry.npmjs.org",
            package: "@example/dependency",
            oldVersion: "1.161.9",
            newVersion: "1.161.12",
          },
        ],
        modelSettings: {
          scan: { model: "untrusted-model", reasoningEffort: "low" },
        },
      },
    });
    assert.equal(authoritative.isError, undefined);
    assert.deepEqual(requests.at(-1).body.model_settings, {
      acquisition: {
        model: "fixture-acquisition-model",
        reasoning_effort: "xhigh",
      },
      scan: { model: "fixture-acquisition-model", reasoning_effort: "xhigh" },
      verification: { model: "fixture-scan-model", reasoning_effort: "high" },
      history: {
        model: "fixture-acquisition-model",
        reasoning_effort: "xhigh",
      },
    });
  } finally {
    await resumedClient.close();
  }

  const invalidClient = new Client({
    name: "codex-security-dependency-tools-invalid-settings-test",
    version: "1.0.0",
  });
  await invalidClient.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [runtimeBundle, "--stdio"],
      cwd: applicationRoot,
      env: {
        ...process.env,
        CODEX_HOME: codexHome,
        CODEX_SECURITY_AARDVARK_BASE_URL: baseUrl,
        CODEX_SECURITY_DEPENDENCY_MODEL_SETTINGS: "{invalid-json",
        CODEX_SECURITY_SCAN_ROOT: scanRoot,
        CODEX_SECURITY_STATE_DIR: stateDir,
      },
    }),
  );
  try {
    const beforeInvalidSettings = requests.length;
    const invalidSettings = await invalidClient.callTool({
      name: "submit_codex_security_dependency_scan",
      arguments: {
        dependencies: [
          {
            ecosystem: "npm",
            registry: "https://registry.npmjs.org",
            package: "@example/dependency",
            oldVersion: "1.161.9",
            newVersion: "1.161.12",
          },
        ],
      },
    });
    assert.equal(invalidSettings.isError, true);
    assert.match(
      invalidSettings.content[0].text,
      /model settings are invalid/i,
    );
    assert.equal(requests.length, beforeInvalidSettings);
  } finally {
    await invalidClient.close();
  }
} finally {
  await new Promise((resolve) => server.close(resolve));
  await rm(temporaryRoot, { recursive: true, force: true });
}

console.log("Codex Security dependency scan MCP transport tests passed");
