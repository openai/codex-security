import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { build } from "esbuild";

await testDependencyAssessmentContract();
await testDependencyImportTools();

async function testDependencyAssessmentContract() {
  const bundle = await build({
    bundle: true,
    entryPoints: [
      fileURLToPath(
        new URL("../src/server/dependency-import-tools.ts", import.meta.url),
      ),
    ],
    format: "esm",
    platform: "node",
    write: false,
  });
  const { registerDependencyImportTools } = await import(
    `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
  );
  await testDependencyTargetContext(registerDependencyImportTools);
  const server = new McpServer({
    name: "dependency-contract-test",
    version: "1.0.0",
  });
  let writes = 0;
  registerDependencyImportTools(server, async (args) => {
    writes += 1;
    return {
      results: JSON.parse(
        await readFile(args[args.indexOf("--results-path") + 1], "utf8"),
      ),
    };
  });
  const client = new Client({
    name: "dependency-contract-test",
    version: "1.0.0",
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const assessment = {
      findingId: "11111111-1111-4111-8111-111111111111",
      verdict: "not_applicable",
      summary: "The advisory concerns a different package.",
      basis: "advisory_mismatch",
      versionBasis: null,
      packageVersion: null,
      resolution: null,
      applicability:
        "The public advisory names a different package coordinate.",
      advisoryEvidence: [
        {
          url: "https://advisories.example.invalid/CVE-2099-0001",
          explanation: "The advisory identifies a different package.",
        },
      ],
      limitations: ["The installed graph was not inspected."],
      externalEvidence: [],
      investigation: [
        {
          action: "Read the public advisory.",
          result: "It names a different package.",
        },
      ],
      attackPath: null,
      unknowns: [],
      codeEvidence: [],
    };
    const call = (result) =>
      client.callTool({
        name: "record_dependency_assessments",
        _meta: { "codex/sandbox-state-meta": { sandboxCwd: process.cwd() } },
        arguments: {
          assessmentId: "22222222-2222-4222-8222-222222222222",
          results: [result],
        },
      });
    const accepted = await call(assessment);
    assert.notEqual(accepted.isError, true);
    assert.deepEqual(accepted.structuredContent.results, [assessment]);
    assert.equal(writes, 1);
    for (const field of [
      "basis",
      "versionBasis",
      "limitations",
      "advisoryEvidence",
      "resolution",
      "externalEvidence",
      "investigation",
      "attackPath",
    ]) {
      const incomplete = { ...assessment };
      delete incomplete[field];
      assert.equal(
        (await call(incomplete)).isError,
        true,
        `${field} must be explicit on new writes`,
      );
    }
    for (const invalid of [
      { ...assessment, basis: "unsupported" },
      { ...assessment, versionBasis: "estimated" },
      {
        ...assessment,
        advisoryEvidence: [
          {
            url: "file:///private/advisory.json",
            explanation: "Not a public source URL.",
          },
        ],
      },
    ]) {
      assert.equal((await call(invalid)).isError, true);
    }
    assert.equal(
      writes,
      1,
      "Invalid assessment inputs must not reach persistence",
    );

    const manifest = '{\n  "name": "example",\n  "version": "1.0.0"\n}\n';
    const external = {
      url: "https://packages.example.invalid/example/1.0.0/package.json",
      revision: null,
      sha256: createHash("sha256").update(manifest).digest("hex"),
      kind: "manifest",
      package: { ecosystem: "npm", name: "example", version: "1.0.0" },
      excerpt: '  "version": "1.0.0"\n',
      explanation: "The fetched manifest identifies the package version.",
    };
    const artifact = {
      ...assessment,
      verdict: "affects_application",
      basis: "code_path",
      versionBasis: "artifact",
      packageVersion: "1.0.0",
      externalEvidence: [external],
      investigation: [
        {
          action: "Read the public package manifest.",
          result: "It identifies example@1.0.0.",
        },
      ],
      attackPath: {
        entryPoint: "The public request handler.",
        attackerControl: "An unauthenticated caller supplies request.body.",
        vulnerableOperation: "The handler passes request.body into parse.",
        prerequisites: "The handler is enabled with the affected parser.",
      },
      codeEvidence: [
        {
          path: "app.js",
          startLine: 1,
          explanation: "The handler passes untrusted input to parse.",
        },
      ],
    };
    const excluded = {
      ...assessment,
      basis: "execution_excluded",
      applicability: "Repository code excludes the required execution context.",
      codeEvidence: [
        {
          path: "workflow.yml",
          startLine: 1,
          explanation: "The workflow runs on a platform excluded by the claim.",
        },
      ],
    };
    for (const result of [artifact, excluded]) {
      const response = await call(result);
      assert.notEqual(response.isError, true);
      assert.deepEqual(response.structuredContent.results, [result]);
    }
    const validWrites = writes;
    for (const invalid of [
      {
        ...artifact,
        externalEvidence: [
          { ...external, sha256: external.sha256.toUpperCase() },
        ],
      },
      {
        ...artifact,
        externalEvidence: [
          { ...external, url: "file:///private/package.json" },
        ],
      },
      { ...artifact, externalEvidence: [{ ...external, excerpt: "  \n" }] },
      {
        ...artifact,
        externalEvidence: [{ ...external, kind: "unclassified" }],
      },
      {
        ...artifact,
        investigation: [{ action: "Read a manifest.", result: "" }],
      },
      {
        ...artifact,
        attackPath: { ...artifact.attackPath, attackerControl: "" },
      },
    ]) {
      assert.equal((await call(invalid)).isError, true);
    }
    assert.equal(
      writes,
      validWrites,
      "Invalid evidence must not reach persistence",
    );
  } finally {
    await Promise.allSettled([client.close(), server.close()]);
  }
}

async function testDependencyTargetContext(registerDependencyImportTools) {
  const directory = await realpath(
    await mkdtemp(path.join(tmpdir(), "dependency-context-")),
  );
  const target = path.join(directory, "target");
  const otherTarget = path.join(directory, "other");
  const alias = path.join(directory, "alias");
  const handlers = new Map();
  let calls = 0;
  registerDependencyImportTools(
    {
      registerTool(name, _config, handler) {
        handlers.set(name, handler);
      },
    },
    async (args) => {
      calls += 1;
      if (args[0] === "import-dependency-findings") {
        // Retarget the caller's alias before the workbench opens its target.
        await rm(alias);
        await symlink(otherTarget, alias, "junction");
        assert.equal(args[args.indexOf("--target-path") + 1], target);
      }
      return { args };
    },
  );
  const meta = (sandboxCwd) => ({ "codex/sandbox-state-meta": { sandboxCwd } });
  const read = handlers.get("get_dependency_report");
  const input = {
    reportId: "11111111-1111-4111-8111-111111111111",
    offset: 0,
    limit: 100,
  };
  try {
    await Promise.all([mkdir(target), mkdir(otherTarget)]);
    await symlink(target, alias, "junction");
    for (const extra of [
      { _meta: meta(target) },
      { requestInfo: { _meta: meta(target) } },
      { _meta: meta(target), requestInfo: { _meta: meta(target) } },
      { _meta: meta(pathToFileURL(target).href) },
      { _meta: meta(alias) },
    ]) {
      const response = await read(input, extra);
      assert.deepEqual(response.structuredContent.args.slice(-2), [
        "--target-path",
        target,
      ]);
    }
    const validCalls = calls;
    for (const extra of [
      {},
      { _meta: meta(undefined) },
      { _meta: meta("relative/path") },
      { _meta: meta(1) },
      { _meta: { "codex/sandbox-state-meta": [] } },
      { _meta: meta(target), requestInfo: { _meta: meta(otherTarget) } },
      {
        _meta: { "codex/sandbox-state-meta": null },
        requestInfo: { _meta: meta(target) },
      },
    ]) {
      await assert.rejects(() => read(input, extra));
    }
    assert.equal(
      calls,
      validCalls,
      "Invalid host context must not reach the workbench",
    );
    await handlers.get("import_dependency_findings")(
      {
        targetPath: alias,
        reportName: "report.json",
        vendor: "snyk",
        reportContent: "{}",
      },
      { _meta: meta(target) },
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function testDependencyImportTools() {
  const appRoot = fileURLToPath(new URL("..", import.meta.url));
  const pluginRoot =
    process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT ??
    fileURLToPath(
      new URL("../../../../sdk/typescript/_bundled_plugin", import.meta.url),
    );
  const serverPath = path.join(pluginRoot, "mcp", "server.mjs");
  const temporaryRoot = await realpath(
    await mkdtemp(path.join(tmpdir(), "dependency-import-tools-")),
  );
  const target = path.join(temporaryRoot, "target");
  const stateDir = path.join(temporaryRoot, "state");
  const codexHome = path.join(temporaryRoot, "codex-home");
  const clients = [];
  const source =
    "import { parse } from 'example';\nexport const handle = request => parse(request.body);\n";
  const sourceClaim = {
    id: "SNYK-JS-EXAMPLE-TEST",
    title: "Example dependency vulnerability",
    packageName: "example",
    version: "1.0.0",
    severity: "high",
    from: ["fixture@1.0.0", "example@1.0.0"],
    identifiers: { CVE: ["CVE-2099-0001"] },
    reachability: "reachable",
    fixedIn: ["1.0.1"],
  };
  const reportContent = JSON.stringify({
    packageManager: "npm",
    targetFile: "package.json",
    vulnerabilities: [
      sourceClaim,
      { ...sourceClaim, id: "SNYK-JS-EXAMPLE-OTHER" },
      { id: "license-only", type: "license", severity: "high" },
    ],
  });

  async function connect() {
    const client = new Client({
      name: "dependency-import-tools-test",
      version: "1.0.0",
    });
    clients.push(client);
    await client.connect(
      new StdioClientTransport({
        command: process.execPath,
        args: [serverPath, "--stdio"],
        cwd: appRoot,
        env: {
          ...process.env,
          CODEX_HOME: codexHome,
          CODEX_SECURITY_SCAN_ROOT: path.join(temporaryRoot, "scans"),
          CODEX_SECURITY_STATE_DIR: stateDir,
        },
        stderr: "inherit",
      }),
    );
    return client;
  }

  async function call(client, name, args) {
    const response = await client.callTool({
      name,
      arguments: args,
      _meta: { "codex/sandbox-state-meta": { sandboxCwd: target } },
    });
    assert.notEqual(
      response.isError,
      true,
      `${name}: ${JSON.stringify(response.content)}`,
    );
    assert.ok(
      response.structuredContent,
      `${name} must return structured Python workbench output`,
    );
    return response.structuredContent;
  }

  async function expectError(client, name, args, pattern) {
    const response = await client.callTool({
      name,
      arguments: args,
      _meta: { "codex/sandbox-state-meta": { sandboxCwd: target } },
    });
    assert.equal(response.isError, true, `${name} must reject this request`);
    assert.match(JSON.stringify(response.content), pattern);
    assert.doesNotMatch(
      JSON.stringify(response),
      /synthetic-other-target-detail/,
    );
  }

  try {
    await Promise.all([mkdir(target), mkdir(stateDir), mkdir(codexHome)]);
    await writeFile(path.join(target, "app.js"), source);
    await writeFile(
      path.join(target, "package.json"),
      JSON.stringify({
        name: "fixture",
        version: "1.0.0",
        dependencies: { example: "1.0.0" },
      }),
    );
    await writeFile(
      path.join(target, "package-lock.json"),
      JSON.stringify({
        name: "fixture",
        lockfileVersion: 3,
        packages: { "node_modules/example": { version: "1.0.0" } },
      }),
    );
    execFileSync("git", ["init", "-q", target]);
    execFileSync("git", ["-C", target, "add", "."]);
    execFileSync("git", [
      "-C",
      target,
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.invalid",
      "-c",
      "core.hooksPath=/dev/null",
      "commit",
      "-qm",
      "dependency import fixture",
    ]);

    const client = await connect();
    const imported = await call(client, "import_dependency_findings", {
      targetPath: target,
      reportName: "existing-findings.json",
      vendor: "snyk",
      reportContent,
    });
    const reportId = imported.report.id;
    assert.equal(imported.report.findingCount, 2);
    assert.equal(imported.report.vendor, "snyk");
    const otherTarget = path.join(temporaryRoot, "other-target");
    execFileSync("git", ["clone", "--quiet", "--local", target, otherTarget]);
    const otherImport = await call(
      client,
      "import_dependency_findings_from_app",
      {
        targetPath: otherTarget,
        reportName: "other-report.json",
        vendor: "snyk",
        reportContent: JSON.stringify({
          packageManager: "npm",
          vulnerabilities: [
            { ...sourceClaim, privateField: "synthetic-other-target-detail" },
          ],
        }),
      },
    );
    const otherReportId = otherImport.report.id;
    const otherPage = await call(client, "get_dependency_report_from_app", {
      reportId: otherReportId,
    });
    const otherFindingId = otherPage.findings[0].id;
    const otherAssessment = await call(
      client,
      "start_dependency_assessment_from_app",
      {
        reportId: otherReportId,
        findingIds: [otherFindingId],
      },
    );
    const tools = (await client.listTools()).tools;
    for (const name of [
      "list_dependency_reports",
      "claim_dependency_task_launch",
      "settle_dependency_task_launch",
      "get_dependency_task_launches",
      "import_dependency_findings_from_app",
      "get_dependency_report_from_app",
      "get_dependency_finding_from_app",
      "start_dependency_assessment_from_app",
      "get_dependency_assessment_from_app",
    ]) {
      assert.deepEqual(
        tools.find((tool) => tool.name === name)?._meta?.ui?.visibility,
        ["app"],
      );
    }
    assert.equal(
      (await call(client, "list_dependency_reports", {})).reports.length,
      2,
    );
    for (const [name, args] of [
      [
        "import_dependency_findings",
        {
          targetPath: otherTarget,
          reportName: "wrong.json",
          vendor: "snyk",
          reportContent,
        },
      ],
      ["get_dependency_report", { reportId: otherReportId }],
      [
        "get_dependency_finding",
        { reportId: otherReportId, findingId: otherFindingId },
      ],
      [
        "get_dependency_finding",
        {
          reportId: otherReportId,
          findingId: otherFindingId,
          requireCurrent: true,
        },
      ],
      [
        "start_dependency_assessment",
        { reportId: otherReportId, findingIds: [otherFindingId] },
      ],
      [
        "get_dependency_assessment",
        { assessmentId: otherAssessment.assessment.id },
      ],
    ]) {
      await expectError(client, name, args, /active repository/);
    }
    for (const sandboxCwd of [undefined, "", "relative/path", 1]) {
      const rejected = await client.callTool({
        name: "get_dependency_report",
        arguments: { reportId },
        _meta: { "codex/sandbox-state-meta": { sandboxCwd } },
      });
      assert.equal(
        rejected.isError,
        true,
        "A model read requires a valid host target",
      );
    }
    const withoutMetadata = await client.callTool({
      name: "get_dependency_report",
      arguments: { reportId },
    });
    assert.equal(withoutMetadata.isError, true);
    const fileUriRead = await client.callTool({
      name: "get_dependency_report",
      arguments: { reportId },
      _meta: {
        "codex/sandbox-state-meta": { sandboxCwd: pathToFileURL(target).href },
      },
    });
    assert.equal(fileUriRead.structuredContent.report.id, reportId);
    const listed = await call(client, "list_dependency_reports", {
      targetPath: target,
    });
    assert.deepEqual(
      listed.reports.map((report) => report.id),
      [reportId],
    );
    const pending = await call(client, "get_dependency_report", {
      reportId,
      verdict: "pending",
    });
    assert.equal(pending.total, 2);
    const findingId = pending.findings[0].id;
    const unselectedId = pending.findings[1].id;
    assert.equal(pending.findings[0].assessment, null);
    const original = await call(client, "get_dependency_finding", {
      reportId,
      findingId,
    });
    assert.deepEqual(original.finding.original, sourceClaim);

    const started = await call(client, "start_dependency_assessment", {
      reportId,
      findingIds: [findingId],
    });
    const assessmentId = started.assessment.id;
    const scope = { accountId: null, hostId: "local", reportId };
    const launchRequest = { ...scope, assessmentId, kind: "assessment" };
    const otherClient = await connect();
    const attempts = await Promise.all(
      [client, otherClient].map((current) =>
        call(current, "claim_dependency_task_launch", launchRequest),
      ),
    );
    assert.equal(attempts.filter((attempt) => attempt.claimed).length, 1);
    assert.deepEqual(attempts[0].launch, attempts[1].launch);
    const firstLaunch = attempts[0].launch;
    const recovered = await call(otherClient, "claim_dependency_task_launch", {
      ...launchRequest,
      retryAttemptId: firstLaunch.attemptId,
    });
    assert.equal(recovered.claimed, true);
    assert.notEqual(recovered.launch.attemptId, firstLaunch.attemptId);
    const settlement = {
      accountId: null,
      hostId: "local",
      launchId: firstLaunch.id,
      status: "settled",
      threadId: "saved-dependency-task",
    };
    await expectError(
      client,
      "settle_dependency_task_launch",
      {
        ...settlement,
        attemptId: firstLaunch.attemptId,
      },
      /stale/i,
    );
    await call(otherClient, "settle_dependency_task_launch", {
      ...settlement,
      attemptId: recovered.launch.attemptId,
      error: "The first turn outcome is unknown; check the saved task.",
    });
    const savedLaunches = await call(
      client,
      "get_dependency_task_launches",
      scope,
    );
    assert.equal(savedLaunches.assessments[0].id, assessmentId);
    assert.equal(savedLaunches.launches[0].threadId, settlement.threadId);
    assert.equal(savedLaunches.launches[0].status, "settled");
    assert.match(savedLaunches.launches[0].error, /first turn outcome/);
    const confirmedLaunch = await call(
      client,
      "settle_dependency_task_launch",
      {
        ...settlement,
        attemptId: recovered.launch.attemptId,
      },
    );
    assert.equal(confirmedLaunch.launch.threadId, settlement.threadId);
    assert.equal(confirmedLaunch.launch.error, null);
    const otherScope = await call(client, "get_dependency_task_launches", {
      ...scope,
      accountId: "different-account",
    });
    assert.deepEqual(otherScope.launches, []);
    assert.deepEqual(started.assessment.findingIds, [findingId]);
    assert.deepEqual(
      started.findings.map((finding) => finding.id),
      [findingId],
    );
    assert.deepEqual(started.findings[0].inputWarnings, []);
    const selected = await call(client, "get_dependency_assessment", {
      assessmentId,
    });
    assert.deepEqual(
      selected.findings.map((finding) => finding.id),
      [findingId],
    );
    const assessment = {
      findingId,
      verdict: "affects_application",
      summary:
        "The application passes request input to the reported dependency.",
      basis: "code_path",
      versionBasis: "resolved",
      limitations: [],
      advisoryEvidence: [],
      externalEvidence: [],
      investigation: [
        {
          action: "Read app.js and the native dependency tree.",
          result: "The request body reaches the selected parser.",
        },
      ],
      attackPath: {
        entryPoint: "The public request handler.",
        attackerControl: "An unauthenticated caller supplies request.body.",
        vulnerableOperation: "The handler passes request.body into parse.",
        prerequisites:
          "The request handler is exposed with the affected parser.",
      },
      packageVersion: "1.0.0",
      applicability:
        "The checked application handler calls the installed package with request data.",
      // Synthetic native output keeps this transport/persistence test hermetic.
      resolution: {
        argv: ["npm", "ls", "example", "--all", "--json", "--offline"],
        cwd: ".",
        exitCode: 0,
        stdout: JSON.stringify({
          dependencies: { example: { version: "1.0.0" } },
        }),
        stderr: "",
        package: { ecosystem: "npm", name: "example" },
        selectedVersions: ["1.0.0"],
        explanation:
          "The native installed tree selects this version for the fixture project.",
        inputFiles: [
          {
            path: "package.json",
            sha256: createHash("sha256")
              .update(await readFile(path.join(target, "package.json")))
              .digest("hex"),
          },
        ],
        issues: [],
      },
      unknowns: [],
      codeEvidence: [
        {
          path: "app.js",
          startLine: 1,
          endLine: 2,
          explanation: "The imported parser receives request.body.",
        },
      ],
    };
    await expectError(
      client,
      "record_dependency_assessments",
      {
        assessmentId,
        results: [{ ...assessment, findingId: unselectedId }],
      },
      /every selected finding exactly once/,
    );
    await expectError(
      client,
      "record_dependency_assessments",
      {
        assessmentId: otherAssessment.assessment.id,
        results: [{ ...assessment, findingId: otherFindingId }],
      },
      /active repository/,
    );
    const untouched = await call(client, "get_dependency_assessment_from_app", {
      assessmentId: otherAssessment.assessment.id,
    });
    assert.equal(untouched.assessment.state, "pending");
    assert.equal(untouched.results, null);
    const recorded = await call(client, "record_dependency_assessments", {
      assessmentId,
      results: [assessment],
    });
    assert.equal(recorded.assessment.state, "complete");
    assert.equal(recorded.results[0].codeEvidence[0].excerpt, source.trimEnd());
    assert.deepEqual(recorded.results[0].resolution, assessment.resolution);
    assert.equal(recorded.results[0].basis, assessment.basis);
    assert.equal(recorded.results[0].versionBasis, assessment.versionBasis);
    assert.deepEqual(
      recorded.results[0].investigation,
      assessment.investigation,
    );
    assert.deepEqual(recorded.results[0].attackPath, assessment.attackPath);

    // Restart the actual bundle: persisted results must come back through Python/SQLite.
    await client.close();
    const restarted = await connect();
    const assessed = await call(restarted, "get_dependency_report", {
      reportId,
      verdict: "affects_application",
    });
    assert.deepEqual(
      assessed.findings.map((finding) => finding.id),
      [findingId],
    );
    const remaining = await call(restarted, "get_dependency_report", {
      reportId,
      verdict: "pending",
    });
    assert.deepEqual(
      remaining.findings.map((finding) => finding.id),
      [unselectedId],
    );
    const current = await call(restarted, "get_dependency_finding", {
      reportId,
      findingId,
      requireCurrent: true,
    });
    assert.equal(current.finding.assessment.verdict, "affects_application");
    assert.deepEqual(current.finding.original, sourceClaim);
    assert.equal(current.finding.originalSeverity, "high");

    const mismatchRequest = await call(
      restarted,
      "start_dependency_assessment",
      {
        reportId,
        findingIds: [unselectedId],
      },
    );
    const mismatch = {
      ...assessment,
      findingId: unselectedId,
      verdict: "not_applicable",
      basis: "advisory_mismatch",
      summary: "The cited advisory identifies a different package.",
      applicability:
        "The advisory package coordinate differs from this imported claim.",
      versionBasis: null,
      packageVersion: null,
      resolution: null,
      attackPath: null,
      codeEvidence: [],
      advisoryEvidence: [
        {
          url: "https://advisories.example.invalid/CVE-2099-0001",
          explanation: "The advisory names a different package coordinate.",
        },
      ],
      limitations: ["The application dependency graph has not been resolved."],
    };
    const mismatchRecorded = await call(
      restarted,
      "record_dependency_assessments",
      {
        assessmentId: mismatchRequest.assessment.id,
        results: [mismatch],
      },
    );
    assert.equal(mismatchRecorded.assessment.state, "complete");
    for (const [field, value] of Object.entries(mismatch)) {
      assert.deepEqual(mismatchRecorded.results[0][field], value);
    }
    const mismatchSaved = await call(restarted, "get_dependency_finding", {
      reportId,
      findingId: unselectedId,
    });
    assert.deepEqual(
      mismatchSaved.finding.assessment.advisoryEvidence,
      mismatch.advisoryEvidence,
    );
    assert.equal(mismatchSaved.finding.package.version, sourceClaim.version);

    const artifactRequest = await call(
      restarted,
      "start_dependency_assessment",
      {
        reportId,
        findingIds: [unselectedId],
      },
    );
    // Synthetic fetched bytes keep this transport/persistence test offline.
    const manifest = '{\n  "name": "example",\n  "version": "1.0.0"\n}\n';
    const externalEvidence = [
      {
        url: "https://packages.example.invalid/example/1.0.0/package.json",
        revision: null,
        sha256: createHash("sha256").update(manifest).digest("hex"),
        kind: "manifest",
        package: { ecosystem: "npm", name: "example", version: "1.0.0" },
        excerpt: '  "version": "1.0.0"\n',
        explanation: "The fetched manifest identifies the package version.",
      },
    ];
    const artifact = {
      ...assessment,
      findingId: unselectedId,
      versionBasis: "artifact",
      resolution: null,
      externalEvidence,
      investigation: [
        {
          action: "Read the public manifest and app.js.",
          result:
            "The declared artifact identifies the parser called with request input.",
        },
      ],
    };
    const artifactRecorded = await call(
      restarted,
      "record_dependency_assessments",
      {
        assessmentId: artifactRequest.assessment.id,
        results: [artifact],
      },
    );
    assert.deepEqual(
      artifactRecorded.results[0].externalEvidence,
      externalEvidence,
    );
    const artifactSaved = await call(restarted, "get_dependency_finding", {
      reportId,
      findingId: unselectedId,
    });
    assert.equal(artifactSaved.finding.assessment.versionBasis, "artifact");
    assert.deepEqual(
      artifactSaved.finding.assessment.externalEvidence,
      externalEvidence,
    );
    assert.deepEqual(
      artifactSaved.finding.assessment.attackPath,
      artifact.attackPath,
    );

    await writeFile(
      path.join(target, "app.js"),
      `${source}// Application changed after assessment.\n`,
    );
    await expectError(
      restarted,
      "get_dependency_finding",
      {
        reportId,
        findingId,
        requireCurrent: true,
      },
      /repository changed since this assessment/i,
    );
    const historical = await call(restarted, "get_dependency_finding", {
      reportId,
      findingId,
    });
    assert.equal(historical.finding.assessment.verdict, "affects_application");

    const largeClaim = {
      ...sourceClaim,
      description: "x".repeat(5 * 1024 * 1024),
    };
    const largeReport = await call(restarted, "import_dependency_findings", {
      targetPath: target,
      reportName: "large-finding.json",
      vendor: "snyk",
      reportContent: JSON.stringify({
        packageManager: "npm",
        vulnerabilities: [largeClaim],
      }),
    });
    const largePage = await call(restarted, "get_dependency_report", {
      reportId: largeReport.report.id,
    });
    const largeFinding = await call(restarted, "get_dependency_finding", {
      reportId: largeReport.report.id,
      findingId: largePage.findings[0].id,
    });
    assert.equal(
      largeFinding.finding.original.description,
      largeClaim.description,
    );
    console.log("Dependency import MCP integration smoke passed.");
  } finally {
    await Promise.allSettled(clients.map((client) => client.close()));
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}
