import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  access,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const root = await mkdtemp(
  path.join(tmpdir(), "codex-security-dependency-agent-writer-"),
);
const mcpAppRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const bundle = path.join(root, "dependency-agent-writer.cjs");
const digestPattern = "^sha256:[0-9a-f]{64}$";

try {
  await build({
    bundle: true,
    define: { "import.meta.url": "__filename" },
    entryPoints: [path.join(mcpAppRoot, "main.ts")],
    external: ["fsevents"],
    format: "cjs",
    loader: { ".md": "text" },
    logLevel: "silent",
    outfile: bundle,
    platform: "node",
    target: "node20",
  });

  await testAcquisitionValidationAndSameRunRepair();
  await testHistoricalValidationAndSameRunRepair();
  await testInvalidHostBindingsFailClosed();
  console.log("dependency agent private stdio writer tests passed");
} finally {
  await rm(root, { recursive: true, force: true });
}

async function testAcquisitionValidationAndSameRunRepair() {
  const workspace = path.join(root, "acquisition");
  const downloads = path.join(workspace, "downloads");
  await mkdir(downloads, { recursive: true, mode: 0o700 });
  const oldContents = Buffer.from("inert old published artifact\n");
  const newContents = Buffer.from("inert new published artifact\n");
  await writeFile(path.join(downloads, "old.tgz"), oldContents);
  await writeFile(path.join(downloads, "new.tgz"), newContents);
  const external = path.join(root, "outside.tgz");
  await writeFile(external, "inert outside workspace\n");
  await symlink(external, path.join(downloads, "outside.tgz"));
  const resultPath = path.join(
    workspace,
    ".codex-security-dependency-result.json",
  );

  const server = await startServer({
    role: "acquisition",
    schema: acquisitionSchema(),
    resultPath,
    expectedVersions: ["1.0.0", "2.0.0"],
    expectedFindingIds: [],
  });

  try {
    assert.deepEqual(
      (await server.listTools()).map((tool) => tool.name),
      ["complete_dependency_acquisition"],
    );
    const oldArtifact = artifact("1.0.0", "downloads/old.tgz", oldContents);
    const newArtifact = artifact("2.0.0", "downloads/new.tgz", newContents);

    for (const [payload, expectedError] of [
      [
        { recipe: "resolve packages", artifacts: [newArtifact] },
        /1\.0\.0|missing/i,
      ],
      [
        {
          recipe: "resolve packages",
          artifacts: [oldArtifact, newArtifact, newArtifact],
        },
        /duplicate/i,
      ],
      [
        {
          recipe: "resolve packages",
          artifacts: [oldArtifact, { ...newArtifact, version: "3.0.0" }],
        },
        /2\.0\.0|3\.0\.0|requested/i,
      ],
      [
        {
          recipe: "resolve packages",
          artifacts: [oldArtifact, { ...newArtifact, path: "../outside.tgz" }],
        },
        /relative|path|workspace/i,
      ],
      [
        {
          recipe: "resolve packages",
          artifacts: [
            oldArtifact,
            { ...newArtifact, filename: "../outside.tgz" },
          ],
        },
        /filename|basename/i,
      ],
      [
        {
          recipe: "resolve packages",
          artifacts: [
            oldArtifact,
            { ...newArtifact, path: "downloads/outside.tgz" },
          ],
        },
        /symlink|workspace|regular/i,
      ],
      [
        {
          recipe: "resolve packages",
          artifacts: [
            oldArtifact,
            { ...newArtifact, digest: "sha256:" + "0".repeat(64) },
          ],
        },
        /digest|sha.?256/i,
      ],
      [
        {
          recipe: "resolve packages",
          artifacts: [
            oldArtifact,
            { ...newArtifact, privateSource: "/repository" },
          ],
        },
        /validation|unrecognized|additional|privateSource/i,
      ],
    ]) {
      const response = await server.call(
        "complete_dependency_acquisition",
        payload,
      );
      assert.equal(response.result?.isError, true, JSON.stringify(response));
      assert.match(response.result.content[0].text, expectedError);
      await assert.rejects(access(resultPath));
    }

    const accepted = {
      recipe: "Resolve official public package distributions.",
      artifacts: [oldArtifact, newArtifact],
    };
    const response = await server.call(
      "complete_dependency_acquisition",
      accepted,
    );
    assert.equal(response.error, undefined, response.error?.message);
    assert.equal(response.result?.isError, undefined, JSON.stringify(response));
    assert.deepEqual(response.result.structuredContent, {
      status: "completed",
    });
    assert.deepEqual(JSON.parse(await readFile(resultPath, "utf8")), accepted);
    assert.equal((await lstat(resultPath)).mode & 0o777, 0o600);

    const duplicate = await server.call(
      "complete_dependency_acquisition",
      accepted,
    );
    assert.equal(duplicate.result?.isError, true);
    assert.match(duplicate.result.content[0].text, /already accepted/i);
    assert.deepEqual(JSON.parse(await readFile(resultPath, "utf8")), accepted);
  } finally {
    await server.stop();
  }
}

async function testHistoricalValidationAndSameRunRepair() {
  const workspace = path.join(root, "history");
  await mkdir(workspace, { recursive: true, mode: 0o700 });
  const resultPath = path.join(
    workspace,
    ".codex-security-dependency-result.json",
  );
  const server = await startServer({
    role: "history",
    schema: historySchema(),
    resultPath,
    expectedVersions: [],
    expectedFindingIds: ["dep_one", "dep_two"],
  });

  const found = {
    upstreamFindingId: "dep_one",
    status: "found",
    introducedIn: {
      version: "0.8.0",
      artifactDigest: "sha256:" + "1".repeat(64),
      confidence: "high",
      evidence: [
        {
          path: "src/settings.js",
          startLine: 4,
          code: "security_control = disabled",
          explanation:
            "This published release first contains the same behavior.",
        },
      ],
    },
  };
  const unknown = {
    upstreamFindingId: "dep_two",
    status: "unknown",
    reason:
      "The published version history does not resolve the first affected release.",
  };

  try {
    assert.deepEqual(
      (await server.listTools()).map((tool) => tool.name),
      ["complete_dependency_history"],
    );
    for (const [payload, expectedError] of [
      [{ results: [found] }, /dep_two|missing/i],
      [
        { results: [found, { ...unknown, upstreamFindingId: "dep_one" }] },
        /duplicate/i,
      ],
      [
        {
          results: [
            found,
            unknown,
            { ...unknown, upstreamFindingId: "dep_three" },
          ],
        },
        /dep_three|unseeded/i,
      ],
      [
        {
          results: [{ upstreamFindingId: "dep_one", status: "found" }, unknown],
        },
        /introducedIn/i,
      ],
      [
        {
          results: [found, { upstreamFindingId: "dep_two", status: "unknown" }],
        },
        /reason/i,
      ],
      [
        { results: [found, { ...unknown, introducedIn: found.introducedIn }] },
        /introducedIn|unknown/i,
      ],
      [
        {
          results: [
            {
              ...found,
              introducedIn: { ...found.introducedIn, evidence: [] },
            },
            unknown,
          ],
        },
        /evidence|validation/i,
      ],
      [
        {
          results: [
            {
              ...found,
              introducedIn: {
                ...found.introducedIn,
                evidence: [{ path: "../private.js", code: "private" }],
              },
            },
            unknown,
          ],
        },
        /path|relative/i,
      ],
    ]) {
      const response = await server.call(
        "complete_dependency_history",
        payload,
      );
      assert.equal(response.result?.isError, true, JSON.stringify(response));
      assert.match(response.result.content[0].text, expectedError);
      await assert.rejects(access(resultPath));
    }

    const accepted = {
      results: [
        {
          ...found,
          introducedIn: {
            ...found.introducedIn,
            confidence: {
              level: "high",
              rationale:
                "Verified public release evidence supports the introduction.",
            },
          },
        },
        unknown,
      ],
    };
    const response = await server.call("complete_dependency_history", accepted);
    assert.equal(response.result?.isError, undefined, JSON.stringify(response));
    assert.deepEqual(response.result.structuredContent, {
      status: "completed",
    });
    assert.deepEqual(JSON.parse(await readFile(resultPath, "utf8")), accepted);
    assert.equal((await lstat(resultPath)).mode & 0o777, 0o600);
  } finally {
    await server.stop();
  }
}

async function testInvalidHostBindingsFailClosed() {
  const workspace = path.join(root, "invalid");
  await mkdir(workspace, { mode: 0o700 });
  for (const invalid of [
    { CODEX_SECURITY_DEPENDENCY_AGENT_ROLE: "public" },
    { CODEX_SECURITY_DEPENDENCY_COMPLETION_SCHEMA_JSON: "{" },
    { CODEX_SECURITY_DEPENDENCY_EXPECTED_VERSIONS_JSON: "{}" },
    { CODEX_SECURITY_DEPENDENCY_COMPLETION_PATH: "relative-result.json" },
  ]) {
    const environment = roleEnvironment({
      role: "acquisition",
      schema: acquisitionSchema(),
      resultPath: path.join(
        workspace,
        ".codex-security-dependency-result.json",
      ),
      expectedVersions: ["2.0.0"],
      expectedFindingIds: [],
    });
    Object.assign(environment, invalid);
    const child = spawn(
      process.execPath,
      [bundle, "--dependency-agent-writer", "--stdio"],
      {
        cwd: workspace,
        env: environment,
        stdio: ["ignore", "ignore", "pipe"],
      },
    );
    const stderr = [];
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    const code = await new Promise((resolve) => child.once("exit", resolve));
    assert.notEqual(
      code,
      0,
      `Expected invalid host binding to fail: ${JSON.stringify(invalid)}`,
    );
    assert.ok(Buffer.concat(stderr).length > 0);
  }
}

function artifact(version, relativePath, contents) {
  return {
    version,
    variant: "tgz",
    path: relativePath,
    filename: `${version}.tgz`,
    digest: "sha256:" + createHash("sha256").update(contents).digest("hex"),
  };
}

function acquisitionSchema() {
  return {
    type: "object",
    additionalProperties: false,
    required: ["recipe", "artifacts"],
    properties: {
      recipe: { type: "string", minLength: 1 },
      artifacts: {
        type: "array",
        minItems: 1,
        items: { $ref: "#/$defs/AcquiredDependencyArtifact" },
      },
    },
    $defs: {
      AcquiredDependencyArtifact: {
        type: "object",
        additionalProperties: false,
        required: ["version", "variant", "path", "filename", "digest"],
        properties: {
          version: { type: "string", minLength: 1 },
          variant: { type: "string", minLength: 1 },
          path: { type: "string", minLength: 1 },
          filename: { type: "string", minLength: 1 },
          digest: { type: "string", pattern: digestPattern },
          url: { anyOf: [{ type: "string", minLength: 1 }, { type: "null" }] },
          registry_integrity: {
            anyOf: [{ type: "string", minLength: 1 }, { type: "null" }],
          },
        },
      },
    },
  };
}

function historySchema() {
  return {
    type: "object",
    additionalProperties: false,
    required: ["results"],
    properties: {
      results: { type: "array", items: { $ref: "#/$defs/HistoryResult" } },
    },
    $defs: {
      HistoryResult: {
        type: "object",
        additionalProperties: false,
        required: ["upstreamFindingId", "status"],
        properties: {
          upstreamFindingId: { type: "string", minLength: 1 },
          status: { enum: ["found", "unknown"] },
          reason: {
            anyOf: [{ type: "string", minLength: 1 }, { type: "null" }],
          },
          introducedIn: {
            anyOf: [{ $ref: "#/$defs/Introduction" }, { type: "null" }],
          },
        },
      },
      Introduction: {
        type: "object",
        additionalProperties: false,
        required: ["version", "artifactDigest", "evidence"],
        properties: {
          version: { type: "string", minLength: 1 },
          artifactDigest: { type: "string", pattern: digestPattern },
          confidence: {
            anyOf: [
              { type: "string", minLength: 1 },
              {
                type: "object",
                additionalProperties: false,
                required: ["level"],
                properties: {
                  level: { type: "string", minLength: 1 },
                  rationale: { type: "string", minLength: 1 },
                },
              },
            ],
          },
          evidence: {
            type: "array",
            minItems: 1,
            items: { $ref: "#/$defs/Evidence" },
          },
        },
      },
      Evidence: {
        type: "object",
        additionalProperties: false,
        required: ["path", "code"],
        properties: {
          path: { type: "string", minLength: 1 },
          code: { type: "string", minLength: 1 },
          startLine: { type: "integer", minimum: 1 },
          explanation: { type: "string", minLength: 1 },
          rationale: { type: "string", minLength: 1 },
        },
      },
    },
  };
}

function roleEnvironment({
  role,
  schema,
  resultPath,
  expectedVersions,
  expectedFindingIds,
}) {
  return {
    PATH: process.env.PATH ?? "",
    CODEX_SECURITY_DEPENDENCY_AGENT_ROLE: role,
    CODEX_SECURITY_DEPENDENCY_COMPLETION_SCHEMA_JSON: JSON.stringify(schema),
    CODEX_SECURITY_DEPENDENCY_COMPLETION_PATH: resultPath,
    CODEX_SECURITY_DEPENDENCY_EXPECTED_VERSIONS_JSON:
      JSON.stringify(expectedVersions),
    CODEX_SECURITY_DEPENDENCY_EXPECTED_FINDING_IDS_JSON:
      JSON.stringify(expectedFindingIds),
  };
}

async function startServer({
  role,
  schema,
  resultPath,
  expectedVersions,
  expectedFindingIds,
}) {
  const child = spawn(
    process.execPath,
    [bundle, "--dependency-agent-writer", "--stdio"],
    {
      cwd: path.dirname(resultPath),
      env: roleEnvironment({
        role,
        schema,
        resultPath,
        expectedVersions,
        expectedFindingIds,
      }),
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  const waiting = new Map();
  const stderr = [];
  child.stderr.on("data", (chunk) => stderr.push(chunk));
  const lines = createInterface({ input: child.stdout });
  lines.on("line", (line) => {
    const response = JSON.parse(line);
    waiting.get(response.id)?.(response);
    waiting.delete(response.id);
  });
  let id = 0;

  const request = (method, params = {}) => {
    const requestId = ++id;
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        waiting.delete(requestId);
        reject(
          new Error(
            `Timed out waiting for ${method}: ${Buffer.concat(stderr).toString()}`,
          ),
        );
      }, 5000);
      waiting.set(requestId, (response) => {
        clearTimeout(timeout);
        resolve(response);
      });
      child.stdin.write(
        JSON.stringify({ jsonrpc: "2.0", id: requestId, method, params }) +
          "\n",
      );
    });
  };

  const initialized = await request("initialize", {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "private-dependency-agent-test", version: "1.0.0" },
  });
  assert.equal(initialized.error, undefined, initialized.error?.message);

  return {
    async listTools() {
      const response = await request("tools/list");
      assert.equal(response.error, undefined, response.error?.message);
      return response.result.tools;
    },
    call(name, args) {
      return request("tools/call", { name, arguments: args });
    },
    async stop() {
      if (child.exitCode !== null) return;
      const stopped = new Promise((resolve) => child.once("exit", resolve));
      child.stdin.end();
      await stopped;
      lines.close();
    },
  };
}
