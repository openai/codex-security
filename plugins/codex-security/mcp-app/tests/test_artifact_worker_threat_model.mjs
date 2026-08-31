import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  entryPoints: [new URL("../src/artifact-threat-model.ts", import.meta.url).pathname],
  format: "esm",
  platform: "node",
  write: false
});
const threatModel = await import(
  "data:text/javascript;base64,"
  + Buffer.from(bundle.outputFiles[0].contents).toString("base64")
);
const schema = JSON.parse(await readFile(
  new URL("../../schemas/tools/worker-threat-model.schema.json", import.meta.url),
  "utf8"
));
const fixtureRoot = await realpath(
  await mkdtemp(path.join(tmpdir(), "codex-security-worker-threat-model-"))
);
const repoRoot = path.join(fixtureRoot, "repository");

try {
  await mkdir(repoRoot, { recursive: true });
  await testCheckedInStrictSchema();
  await testExactContentAndAtomicReplacement();
  await testInvalidInputDoesNotWrite();
  await testOnlyDiscoveryWorkersCanWrite();
  await testSymlinkedContextDirectoryIsRejected();
  await testSymlinkedDestinationIsRejected();
  await testSymlinkedArtifactRootIsRejected();
} finally {
  await rm(fixtureRoot, { recursive: true, force: true });
}

console.log("Codex Security worker threat-model artifact tests passed");

async function testCheckedInStrictSchema() {
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(
    schema.$id,
    "codex-security://schemas/tools/worker-threat-model.schema.json"
  );

  const input = schema.$defs.recordWorkerThreatModelInput;
  assert.deepEqual(Object.keys(input.properties), ["content"]);
  assert.deepEqual(input.required, ["content"]);
  assert.equal(input.additionalProperties, false);
  assert.equal(input.properties.content.type, "string");
  assert.equal(input.properties.content.minLength, 1);
  assert.equal(input.properties.content.pattern, "\\S");

  const validator = threatModel.workerThreatModelInputSchema;
  assert.equal(validator.safeParse({ content: "# Worker threat model" }).success, true);
  for (const invalid of [
    {},
    { content: null },
    { content: 1 },
    { content: "" },
    { content: " \t\r\n " },
    { content: "# Threat model", scanId: "another-scan" },
    { content: "# Threat model", path: "outside.md" },
    { content: "# Threat model", artifactRoot: repoRoot },
    { content: "# Threat model", operation: "append" }
  ]) {
    assert.equal(
      validator.safeParse(invalid).success,
      false,
      `Worker threat-model schema unexpectedly accepted ${JSON.stringify(invalid)}.`
    );
  }
}

async function testExactContentAndAtomicReplacement() {
  const context = await createWorkerContext("exact-content");
  const destination = threatModelDestination(context);
  const original = [
    "# Worker threat model",
    "",
    "Trust boundary: independent source review.",
    "",
    "Repository: fixture/repository",
    "Version: sha256:original",
    ""
  ].join("\n");

  assert.deepEqual(
    await threatModel.recordCodexSecurityWorkerThreatModel(
      { content: original },
      context
    ),
    { operation: "replace" }
  );
  assert.equal(await readFile(destination, "utf8"), original);

  const replacement = [
    "# Updated worker threat model",
    "",
    "Trust boundary: café and preserved whitespace.  ",
    "",
    "Repository: fixture/repository",
    "Version: sha256:replacement",
    ""
  ].join("\n");

  assert.deepEqual(
    await threatModel.recordCodexSecurityWorkerThreatModel(
      { content: replacement },
      context
    ),
    { operation: "replace" }
  );
  assert.equal(await readFile(destination, "utf8"), replacement);
  assert.deepEqual(await readdir(path.dirname(destination)), ["threat_model.md"]);
}

async function testInvalidInputDoesNotWrite() {
  for (const [index, input] of [
    {},
    { content: "" },
    { content: "  \t\n " },
    { content: "# Threat model", path: "outside.md" },
    { content: "# Threat model", scanId: "another-scan" }
  ].entries()) {
    const context = await createWorkerContext(`invalid-${index}`);
    await assert.rejects(
      threatModel.recordCodexSecurityWorkerThreatModel(input, context)
    );
    await assert.rejects(
      readFile(threatModelDestination(context), "utf8"),
      { code: "ENOENT" }
    );
  }
}

async function testOnlyDiscoveryWorkersCanWrite() {
  for (const layout of ["scan", "reducer"]) {
    const worker = await createWorkerContext(`forbidden-${layout}`);
    const context = { ...worker, layout };
    await assert.rejects(
      threatModel.recordCodexSecurityWorkerThreatModel(
        { content: "# Threat model\n" },
        context
      ),
      /only a bound discovery worker/i
    );
    await assert.rejects(
      readFile(threatModelDestination(context), "utf8"),
      { code: "ENOENT" }
    );
  }
}

async function testSymlinkedContextDirectoryIsRejected() {
  const context = await createWorkerContext("linked-context");
  const outside = path.join(fixtureRoot, "outside-context");
  const outsideThreatModel = path.join(outside, "threat_model.md");
  await mkdir(path.join(context.root, "artifacts"), { recursive: true });
  await mkdir(outside, { recursive: true });
  await writeFile(outsideThreatModel, "outside remains unchanged\n");
  await symlink(
    outside,
    path.join(context.root, "artifacts", "01_context")
  );

  await assert.rejects(
    threatModel.recordCodexSecurityWorkerThreatModel(
      { content: "# Escaping threat model\n" },
      context
    ),
    /regular directory|escaped|safe/i
  );
  assert.equal(
    await readFile(outsideThreatModel, "utf8"),
    "outside remains unchanged\n"
  );
}

async function testSymlinkedDestinationIsRejected() {
  const context = await createWorkerContext("linked-destination");
  const destination = threatModelDestination(context);
  const outside = path.join(fixtureRoot, "outside-threat-model.md");
  await mkdir(path.dirname(destination), { recursive: true });
  await writeFile(outside, "outside remains unchanged\n");
  await symlink(outside, destination);

  await assert.rejects(
    threatModel.recordCodexSecurityWorkerThreatModel(
      { content: "# Escaping threat model\n" },
      context
    ),
    /regular file|escaped|safe/i
  );
  assert.equal(await readFile(outside, "utf8"), "outside remains unchanged\n");
}

async function testSymlinkedArtifactRootIsRejected() {
  const worker = await createWorkerContext("linked-root-target");
  const linkedRoot = path.join(fixtureRoot, "linked-worker-root");
  await symlink(worker.root, linkedRoot);
  const context = { ...worker, root: linkedRoot };

  await assert.rejects(
    threatModel.recordCodexSecurityWorkerThreatModel(
      { content: "# Escaping threat model\n" },
      context
    ),
    /safe regular directory|escaped|context/i
  );
  await assert.rejects(
    readFile(threatModelDestination(worker), "utf8"),
    { code: "ENOENT" }
  );
}

async function createWorkerContext(name) {
  const root = path.join(fixtureRoot, name, "output");
  await mkdir(root, { recursive: true });
  return {
    root: await realpath(root),
    repoRoot,
    layout: "worker"
  };
}

function threatModelDestination(context) {
  return path.join(
    context.root,
    "artifacts",
    "01_context",
    "threat_model.md"
  );
}
