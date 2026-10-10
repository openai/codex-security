import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import {
  chmod,
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
import { importSource } from "./import-module.ts";

const io = await importSource(
  path.join(import.meta.dirname, "../src/artifact-io.ts"),
);
const contextApi = await importSource(
  path.join(import.meta.dirname, "../src/artifact-context.ts"),
);
const schemas = await importSource(
  path.join(import.meta.dirname, "../src/artifact-schema-loader.ts"),
);
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
  await testScanContext();
  await testSafeJsonAndJsonl();
  await testAtomicReplacementAfterInterruptedWriter();
  await testAtomicReplacement();
  await testBoundedPagination();
  await testUnsafeArtifacts();
} finally {
  await rm(fixture, { force: true, recursive: true });
}

console.log("Codex Security compact artifact foundation tests passed");

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
  const calls: string[][] = [];
  const runWorkbench = async (args: string[]) => {
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

async function testAtomicReplacementAfterInterruptedWriter() {
  const destination = await io.artifactDestination(
    context,
    ["interrupted.json"],
    "interrupted artifact",
  );
  const child = spawn(process.execPath, [
    "-e",
    'require("node:fs").openSync(process.argv[1], "wx", 0o600); process.stdout.write("locked"); setInterval(() => {}, 1000);',
    destination + ".lock",
  ]);
  await once(child.stdout, "data");
  child.kill("SIGKILL");
  await once(child, "close");
  await io.replaceArtifactText(destination, "recovered\n");
  assert.equal(await readFile(destination, "utf8"), "recovered\n");
  const values = ["a", "b", "c"].map((value) => value.repeat(32_000));
  await Promise.all(
    values.map((value) => io.replaceArtifactText(destination, value)),
  );
  assert.ok(values.includes(await readFile(destination, "utf8")));
}

async function testSafeJsonAndJsonl() {
  const context = {
    root: path.join(fixture, "scan"),
    repoRoot: path.join(fixture, "repository"),
  };
  const components = ["artifacts", "02_discovery", "candidate_ledger.jsonl"];
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
    safeParse(value: { candidate_id?: unknown } | null) {
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
  await io.replaceArtifactText(
    manifest,
    JSON.stringify({ scanId: "fixture", extension: true }) + "\n",
  );
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
  if (process.platform !== "win32" && process.getuid?.() !== 0) {
    try {
      await chmod(destination, 0o000);
      for (const read of [
        io.readArtifactText,
        io.readArtifactTextWithMetadata,
      ]) {
        await assert.rejects(
          read(context, components, "discovery_candidates"),
          (error: Error & { cause?: NodeJS.ErrnoException }) => {
            assert.equal(error.cause?.code, "EACCES");
            assert.ok(error.message.includes("EACCES"));
            assert.ok(error.message.includes(destination));
            return true;
          },
        );
      }
    } finally {
      await chmod(destination, 0o600);
    }
  }
}

async function testAtomicReplacement() {
  const context = {
    root: path.join(fixture, "scan"),
    repoRoot: path.join(fixture, "repository"),
  };
  const components = ["artifacts", "02_discovery", "candidate_ledger.jsonl"];
  const destination = await io.artifactDestination(
    context,
    components,
    "discovery_candidates",
  );
  await io.replaceArtifactJsonl(destination, []);
  assert.equal(await readFile(destination, "utf8"), "");

  const versions = Array.from({ length: 12 }, (_, index) => [
    {
      candidate_id: "concurrent-" + index,
      evidence: String(index).repeat(8192),
    },
    { candidate_id: "tail-" + index },
  ]);
  const expected = new Set(versions.map((rows) => JSON.stringify(rows)));
  await Promise.all(
    versions.map(async (rows) => {
      await io.replaceArtifactJsonl(destination, rows);
      const observed = await io.readArtifactJsonl(
        context,
        components,
        "discovery_candidates",
        { safeParse: (value: unknown) => ({ success: true, data: value }) },
      );
      assert.ok(expected.has(JSON.stringify(observed)));
    }),
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
    () => io.paginateArtifactRows(rows, { cursor: "4" }, "review_items"),
    /outside the available rows/,
  );
}

async function testUnsafeArtifacts() {
  const context = {
    root: path.join(fixture, "scan"),
    repoRoot: path.join(fixture, "repository"),
  };
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
  const outsideFile = path.join(outside, "candidate_ledger.jsonl");
  await writeFile(outsideFile, "outside remains unchanged\n");
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

  assert.equal(
    await readFile(outsideFile, "utf8"),
    "outside remains unchanged\n",
  );
  const linkedFile = path.join(context.root, "linked.json");
  await symlink(outsideFile, linkedFile);
  await assert.rejects(
    io.artifactDestination(context, ["linked.json"], "scan_manifest"),
    /not a regular file/,
  );
  assert.equal(
    await readFile(outsideFile, "utf8"),
    "outside remains unchanged\n",
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
