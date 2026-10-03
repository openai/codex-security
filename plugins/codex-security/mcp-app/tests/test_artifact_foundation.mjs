import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { build } from "esbuild";

const compiled = await build({
  bundle: true,
  entryPoints: [
    new URL("../src/artifact-io.ts", import.meta.url).pathname,
    new URL("../src/artifact-context.ts", import.meta.url).pathname,
    new URL("../src/artifact-schema-loader.ts", import.meta.url).pathname,
  ],
  format: "esm",
  outdir: "codex-security-artifact-foundation",
  platform: "node",
  write: false,
});
const modules = new Map(
  compiled.outputFiles.map((file) => [
    path.basename(file.path),
    "data:text/javascript;base64," +
      Buffer.from(file.contents).toString("base64"),
  ]),
);
const io = await import(modules.get("artifact-io.js"));
const contextApi = await import(modules.get("artifact-context.js"));
const schemas = await import(modules.get("artifact-schema-loader.js"));
const fixture = await realpath(
  await mkdtemp(path.join(tmpdir(), "codex-security-artifact-foundation-")),
);

const context = {
  root: path.join(fixture, "scan"),
  repoRoot: path.join(fixture, "repository"),
  layout: "scan",
};
const components = ["artifacts", "02_discovery", "candidate_ledger.jsonl"];

try {
  await testSchemaSourceOfTruth();
  await testWorkerThreatModelSchema();
  await testScanContext();
  await testWorkerStandardLayout();
  await testSafeJsonAndJsonl();
  await testAtomicReplacement();
  await testBoundedPagination();
  await testUnsafeArtifacts();
} finally {
  await rm(fixture, { force: true, recursive: true });
}

console.log("Codex Security compact artifact foundation tests passed");

async function testWorkerThreatModelSchema() {
  const schema = JSON.parse(
    await readFile(
      new URL(
        "../../schemas/tools/worker-threat-model.schema.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(
    schema.$id,
    "codex-security://schemas/tools/worker-threat-model.schema.json",
  );
  const input = schema.$defs.recordWorkerThreatModelInput;
  assert.deepEqual(Object.keys(input.properties), ["content"]);
  assert.deepEqual(input.required, ["content"]);
  assert.equal(input.additionalProperties, false);
  assert.equal(input.properties.content.type, "string");
  assert.equal(input.properties.content.minLength, 1);
  assert.equal(input.properties.content.pattern, "\\S");
}

async function testSchemaSourceOfTruth() {
  const common = JSON.parse(
    await readFile(
      new URL(
        "../../schemas/definitions/artifact-common.schema.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  const fixtureDocument = {
    $id: "codex-security://schemas/tools/artifact-foundation-fixture.schema.json",
    $defs: {
      request: {
        type: "object",
        properties: {
          path: { $ref: common.$id + "#/$defs/repositoryPath" },
          candidateId: { $ref: common.$id + "#/$defs/candidateId" },
        },
        required: ["path", "candidateId"],
        additionalProperties: false,
      },
    },
  };
  const bundled = schemas.bundleArtifactSchema(
    [common, fixtureDocument],
    fixtureDocument.$id,
    "request",
  );
  assert.equal(JSON.stringify(bundled).includes("$ref"), false);
  assert.equal(bundled.properties.path.type, "string");
  assert.equal(bundled.properties.candidateId.type, "string");

  const validator = schemas.loadArtifactZodSchema(
    [common, fixtureDocument],
    fixtureDocument.$id,
    "request",
  );
  for (const repositoryPath of [
    "src/index.ts",
    "./src/index.ts",
    "scope with spaces/café.ts",
    ".hidden/config.ts",
  ]) {
    assert.equal(
      validator.safeParse({ path: repositoryPath, candidateId: "candidate-1" })
        .success,
      true,
      repositoryPath,
    );
  }
  for (const repositoryPath of [
    "/etc/passwd",
    "../outside.ts",
    "src/../outside.ts",
    "src/./outside.ts",
    "src//outside.ts",
    "C:\\outside.ts",
    "src/\0outside.ts",
  ]) {
    assert.equal(
      validator.safeParse({ path: repositoryPath, candidateId: "candidate-1" })
        .success,
      false,
      repositoryPath,
    );
  }
  for (const candidateId of [
    ".",
    "..",
    "../candidate",
    "a/b",
    "a\\b",
    "a\0b",
  ]) {
    assert.equal(
      validator.safeParse({ path: "src/index.ts", candidateId }).success,
      false,
      candidateId,
    );
  }
  assert.throws(
    () => schemas.bundleArtifactSchema([common], "missing", "request"),
    /Unknown Codex Security schema document/,
  );
  assert.throws(
    () =>
      schemas.bundleArtifactSchema(
        [common, common],
        common.$id,
        "repositoryPath",
      ),
    /Duplicate Codex Security schema document/,
  );
}

async function testScanContext() {
  const root = path.join(fixture, "scan");
  const repoRoot = path.join(fixture, "repository");
  await Promise.all([
    mkdir(root, { recursive: true }),
    mkdir(repoRoot, { recursive: true }),
  ]);
  const scanId = "61a20957-1be8-4ccf-8de8-eab4061e8cc3";
  const contract = {
    target: {
      allowedKinds: ["directory_snapshot"],
      targetId: "target-1",
      requiredSnapshotDigest: "sha256:fixture",
    },
    scope: {
      requiredIncludePaths: ["."],
      requiredExcludePaths: [],
    },
  };
  const calls = [];
  const runWorkbench = async (args) => {
    calls.push(args);
    return {
      scan: {
        scanId,
        scanDir: root,
        targetPath: repoRoot,
        scope: ".",
        mode: "deep",
        progress: { status: "running" },
        contract,
        handoffClaimToken: "fixture-claim",
      },
    };
  };
  const context = await contextApi.createScanArtifactContext(
    scanId,
    runWorkbench,
    {
      requireRunning: true,
      requireClaim: true,
      handoffClaimToken: "fixture-claim",
      pluginRoot: "/fixture/plugin",
      pythonCommand: "python3",
    },
  );
  assert.deepEqual(calls, [["get-scan", "--scan-id", scanId]]);
  assert.equal(context.root, await realpath(root));
  assert.equal(context.repoRoot, await realpath(repoRoot));
  assert.equal(context.layout, "scan");
  assert.equal(context.scope, ".");
  assert.equal(context.mode, "deep");
  assert.deepEqual(context.targetContract, contract);
  assert.equal(context.handoffClaimToken, "fixture-claim");
  assert.equal(context.pluginRoot, "/fixture/plugin");
  assert.equal(context.pythonCommand, "python3");

  await assert.rejects(
    contextApi.createScanArtifactContext(scanId, runWorkbench, {
      requireClaim: true,
      handoffClaimToken: "different-claim",
    }),
    /different continuation/,
  );
  await assert.rejects(
    contextApi.createScanArtifactContext(
      scanId,
      async () => ({
        scan: {
          scanId,
          scanDir: root,
          targetPath: repoRoot,
          progress: { status: "completed" },
        },
      }),
      { requireRunning: true },
    ),
    /not running/,
  );
  await assert.rejects(
    contextApi.createScanArtifactContext(scanId, async () => ({
      scan: { scanId: "different", scanDir: root, targetPath: repoRoot },
    })),
    /requested scan identity/,
  );
}

async function testWorkerStandardLayout() {
  const root = path.join(fixture, "worker", "output");
  const repoRoot = path.join(fixture, "repository");
  await mkdir(root, { recursive: true });
  const context = await contextApi.createWorkerArtifactContext({
    root,
    repoRoot,
    scope: ".",
    pluginRoot: "/fixture/plugin",
  });
  const inventory = await io.artifactDestination(
    context,
    ["artifacts", "02_discovery", "in_scope_files.txt"],
    "review_items",
  );
  const candidates = await io.artifactDestination(
    context,
    ["artifacts", "02_discovery", "candidate_ledger.jsonl"],
    "discovery_candidates",
  );
  assert.equal(
    inventory,
    path.join(
      await realpath(root),
      "artifacts",
      "02_discovery",
      "in_scope_files.txt",
    ),
  );
  assert.equal(
    candidates,
    path.join(
      await realpath(root),
      "artifacts",
      "02_discovery",
      "candidate_ledger.jsonl",
    ),
  );
  assert.equal(context.layout, "worker");
  assert.equal(context.scope, ".");

  await assert.rejects(
    contextApi.createWorkerArtifactContext({
      root,
      repoRoot,
      deepReducer: { scanRoot: root, claimedWorkers: [] },
    }),
    /reducer-bound context/,
  );
  const reducer = await contextApi.createWorkerArtifactContext({
    root,
    repoRoot,
    layout: "reducer",
    deepReducer: {
      scanRoot: root,
      claimedWorkers: [
        { id: "worker-1", resultPath: path.join(root, "worker-result.json") },
      ],
    },
  });
  assert.equal(reducer.layout, "reducer");
  assert.equal(reducer.deepReducer.claimedWorkers[0].id, "worker-1");
}

async function testSafeJsonAndJsonl() {
  const destination = await io.artifactDestination(
    context,
    components,
    "discovery_candidates",
  );
  await io.replaceArtifactJsonl(destination, [
    { candidate_id: "one", extension: "preserved" },
    { candidate_id: "two" },
  ]);
  const rowSchema = {
    safeParse(value) {
      return value && typeof value.candidate_id === "string"
        ? { success: true, data: value }
        : {
            success: false,
            error: {
              issues: [{ path: ["candidate_id"], message: "required" }],
            },
          };
    },
  };
  assert.deepEqual(
    await io.readArtifactJsonl(
      context,
      components,
      "discovery_candidates",
      rowSchema,
    ),
    [{ candidate_id: "one", extension: "preserved" }, { candidate_id: "two" }],
  );

  const manifestComponents = ["scan-manifest.json"];
  const manifest = await io.artifactDestination(
    context,
    manifestComponents,
    "scan_manifest",
  );
  await io.replaceArtifactJson(manifest, {
    scanId: "fixture",
    extension: true,
  });
  assert.deepEqual(
    await io.readArtifactJsonObject(
      context,
      manifestComponents,
      "scan_manifest",
    ),
    { scanId: "fixture", extension: true },
  );
  await io.replaceArtifactText(
    destination,
    '{"candidate_id":"valid"}\nnot-json\n',
  );
  await assert.rejects(
    io.readArtifactJsonl(
      context,
      components,
      "discovery_candidates",
      rowSchema,
    ),
    /row 2 is not valid JSON/,
  );
  await io.replaceArtifactText(destination, '{"other":"missing"}\n');
  await assert.rejects(
    io.readArtifactJsonl(
      context,
      components,
      "discovery_candidates",
      rowSchema,
    ),
    /row 1 does not match its artifact schema: candidate_id: required/,
  );
}

async function testAtomicReplacement() {
  const destination = await io.artifactDestination(
    context,
    components,
    "discovery_candidates",
  );
  await io.replaceArtifactJsonl(destination, []);
  assert.equal(await readFile(destination, "utf8"), "");

  const replacements = Array.from({ length: 12 }, (_, index) => ({
    candidate_id: "concurrent-" + index,
  }));
  await Promise.all(
    replacements.map((row) => io.replaceArtifactJsonl(destination, [row])),
  );
  const written = JSON.parse(await readFile(destination, "utf8"));
  assert.deepEqual(
    written,
    replacements.find((row) => row.candidate_id === written.candidate_id),
  );
  assert.deepEqual(await readdir(path.dirname(destination)), [
    "candidate_ledger.jsonl",
  ]);
}

async function testBoundedPagination() {
  const rows = [
    { path: "./src/first.ts" },
    { path: "scope with spaces/café.ts" },
    { path: "src/third.ts" },
  ];
  assert.deepEqual(
    io.paginateArtifactRows(rows, { limit: 2 }, "review_items"),
    {
      rows: rows.slice(0, 2),
      nextCursor: "2",
    },
  );
  assert.deepEqual(
    io.paginateArtifactRows(rows, { cursor: "2", limit: 2 }, "review_items"),
    { rows: rows.slice(2) },
  );
  assert.throws(
    () => io.paginateArtifactRows(rows, { cursor: "-1" }, "review_items"),
    /non-negative integer/,
  );
  assert.throws(
    () => io.paginateArtifactRows(rows, { cursor: "4" }, "review_items"),
    /outside the available rows/,
  );
  assert.throws(
    () => io.paginateArtifactRows(rows, { limit: 1001 }, "review_items"),
    /1 through 1000/,
  );
}

async function testUnsafeArtifacts() {
  for (const components of [
    [],
    ["..", "outside.json"],
    [".", "outside.json"],
    ["artifacts/02_discovery", "candidate_ledger.jsonl"],
    ["artifacts", "..", "outside.json"],
    ["artifacts", "bad\0name"],
  ]) {
    await assert.rejects(
      io.artifactDestination(context, components, "discovery_candidates"),
      /fixed artifact destination|unsafe/,
    );
  }

  const outside = path.join(fixture, "outside");
  await mkdir(outside, { recursive: true });
  const symlinkPath = path.join(context.root, "linked");
  await symlink(outside, symlinkPath);
  await assert.rejects(
    io.artifactDestination(
      context,
      ["linked", "candidate_ledger.jsonl"],
      "discovery_candidates",
    ),
    /not a regular directory/,
  );

  const linkedFile = path.join(context.root, "linked.json");
  await symlink(path.join(outside, "outside.json"), linkedFile);
  await assert.rejects(
    io.artifactDestination(context, ["linked.json"], "scan_manifest"),
    /not a regular file/,
  );

  const linkedRoot = path.join(fixture, "linked-root");
  await symlink(context.root, linkedRoot);
  await assert.rejects(
    io.artifactDestination(
      { ...context, root: linkedRoot },
      ["scan_manifest.json"],
      "scan_manifest",
    ),
    /safe regular directory|escaped|context/i,
  );
}
