import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { build } from "esbuild";

const applicationRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixture = await realpath(await mkdtemp(path.join(tmpdir(), "codex-security-storage-test-")));
const stateRoot = path.join(fixture, "state");
const repository = path.join(fixture, "repository");
const bundle = path.join(fixture, "server.cjs");
const temporaryDirectories = new Set();
let client;

try {
  await mkdir(repository);
  await writeFile(path.join(repository, "example.py"), "value = 1\n");
  await build({
    bundle: true,
    nodePaths: [fileURLToPath(new URL("../node_modules", import.meta.url))],
    define: { __dirname: JSON.stringify(applicationRoot), "import.meta.url": "__filename" },
    entryPoints: [path.join(applicationRoot, "main.ts")],
    external: ["fsevents"],
    format: "cjs",
    loader: { ".md": "text" },
    logLevel: "silent",
    outfile: bundle,
    platform: "node"
  });
  client = await connect();
  const started = await call("start_codex_security_standard_scan", { targetPath: repository });
  const { scanId, scanDir, handoffClaimToken } = started;
  assert.ok(scanDir.startsWith(path.join(stateRoot, "scans", "repository") + path.sep),
    `The default scan directory must be persistent, got ${scanDir}`);
  const identity = { scanId, handoffClaimToken };
  const scratch = await save({ ...identity, storage: "temporary" });
  temporaryDirectories.add(scratch.directory);
  assert.ok(scratch.directory.startsWith(await realpath(tmpdir()) + path.sep));
  assert.equal(scratch.directory.startsWith(scanDir + path.sep), false);

  const content = "# Threat model\n\nExact café bytes and trailing spaces.  \n";
  const relativePath = "artifacts/01_context/threat_model.md";
  const saved = await save({ ...identity, storage: "persistent", path: relativePath, content });
  assert.equal(saved.path, path.join(scanDir, ...relativePath.split("/")));
  assert.equal(await readFile(saved.path, "utf8"), content);
  await save({ ...identity, storage: "temporary", path: relativePath, content: "temporary\n" });
  assert.equal((await read({ ...identity, storage: "temporary", path: relativePath })).content, "temporary\n");
  assert.equal((await read({ ...identity, storage: "persistent", path: relativePath })).content, content);

  const binary = Buffer.from([0, 1, 127, 128, 255]);
  const sourcePath = path.join(scratch.directory, "poc.bin");
  await writeFile(sourcePath, binary);
  const imported = await save({
    ...identity, storage: "persistent", path: "artifacts/02_discovery/validation_artifacts/example/poc.bin",
    sourcePath
  });
  assert.deepEqual(await readFile(imported.path), binary);
  assert.equal((await read({ ...identity, storage: "persistent", path: imported.relativePath, encoding: "base64" })).content,
    binary.toString("base64"));

  const outside = path.join(fixture, "outside.txt");
  await writeFile(outside, "outside\n");
  await rejected(() => save({ ...identity, storage: "persistent", path: "artifacts/copied.txt", sourcePath: outside }));
  await symlink(outside, path.join(scratch.directory, "linked.txt"));
  await rejected(() => save({ ...identity, storage: "persistent", path: "artifacts/copied.txt", sourcePath: path.join(scratch.directory, "linked.txt") }));
  for (const unsafe of ["../outside.txt", "/outside.txt", "C:/outside.txt", "artifacts/file:stream", "artifacts/../outside.txt", "artifacts/CON", "artifacts/name.", "artifacts/name "]) {
    await rejected(() => save({ ...identity, storage: "persistent", path: unsafe, content: "bad" }));
  }
  for (const owned of ["scan-manifest.json", "findings.json", "coverage.json", "report.md", "drafts/checkpoint.json", "artifacts/deep_discovery/result.json", "artifacts/02_discovery/candidate_ledger.jsonl", "artifacts/02_discovery/CANDIDATE_LEDGER.JSONL", "artifacts/02_discovery/in_scope_files.txt"]) {
    await rejected(() => save({ ...identity, storage: "persistent", path: owned, content: "bad" }));
  }
  await rejected(() => save({ ...identity, handoffClaimToken: "00000000-0000-4000-8000-000000000000", storage: "persistent", path: relativePath, content: "bad" }));
  assert.equal(await readFile(saved.path, "utf8"), content);
  assert.equal(await readFile(outside, "utf8"), "outside\n");

  await client.close();
  client = await connect();
  assert.equal((await read({ ...identity, storage: "persistent", path: relativePath })).content, content);
  assert.equal((await read({ ...identity, storage: "temporary", path: relativePath })).content, "temporary\n");
  await rm(scratch.directory, { recursive: true, force: true });
  assert.equal((await read({ ...identity, storage: "persistent", path: relativePath })).content, content);
  assert.deepEqual(await readFile(imported.path), binary);

  const standalone = await save({ targetPath: repository, storage: "persistent", path: "threat_model.md", content });
  assert.ok(standalone.directory.startsWith(path.join(stateRoot, "scans") + path.sep));
  assert.equal(standalone.directory.startsWith(repository + path.sep), false);
  assert.equal((await read({ targetPath: repository, storage: "persistent", path: "threat_model.md" })).content, content);
  await rejected(() => save({ ...identity, targetPath: repository, storage: "persistent", path: relativePath, content }));

  const stateAlias = path.join(fixture, "state-alias");
  await symlink(stateRoot, stateAlias, process.platform === "win32" ? "junction" : "dir");
  await client.close();
  client = await connect({ CODEX_SECURITY_STATE_DIR: stateAlias });
  const standaloneScratch = await save({ targetPath: repository, storage: "temporary" });
  temporaryDirectories.add(standaloneScratch.directory);
  const standaloneInput = path.join(standaloneScratch.directory, "input.bin");
  await writeFile(standaloneInput, binary);
  const standaloneImport = await save({ targetPath: repository, storage: "persistent", path: "artifacts/input.bin", sourcePath: standaloneInput });
  assert.equal(standaloneImport.directory, standalone.directory);
  assert.deepEqual(await readFile(standaloneImport.path), binary);

  await call("record_codex_security_scan_draft", {
    ...identity, findings: [], threatModel: { summary: content },
    coverage: { completeness: "complete",
      surfaces: [{ id: "example", label: "Example source", disposition: "not_applicable", receiptRefs: [relativePath] }], explicitExclusions: [], deferred: [] }
  });
  execFileSync(process.env.PYTHON || "python3", [
    path.resolve(applicationRoot, "../scripts/workbench_db.py"), "prepare-scan-completion",
    "--scan-id", scanId, "--claim-token", handoffClaimToken
  ], { env: { ...process.env, CODEX_SECURITY_STATE_DIR: stateRoot } });
  // Preparation seals receipts before the database transitions to complete.
  await rejected(() => save({ ...identity, storage: "persistent", path: relativePath, content: "changed after seal" }));
  assert.equal(await readFile(saved.path, "utf8"), content);
  await call("complete_codex_security_scan", identity);
  await rejected(() => save({ ...identity, storage: "persistent", path: "findings/late/late.md", content: "late" }));
  assert.equal((await read({ ...identity, storage: "persistent", path: relativePath })).content, content);
  console.log("Persistent roots, temporary routing, exact file import, restart readback and artifact boundaries passed");
} finally {
  await client?.close();
  for (const directory of temporaryDirectories) await rm(directory, { recursive: true, force: true });
  await rm(fixture, { recursive: true, force: true });
}

async function connect(overrides = {}) {
  const result = new Client({ name: "artifact-storage-test", version: "1.0.0" });
  const env = { ...process.env, CODEX_SECURITY_STATE_DIR: stateRoot, CODEX_HOME: path.join(fixture, "home"), ...overrides };
  delete env.CODEX_SECURITY_SCAN_ROOT;
  await result.connect(new StdioClientTransport({ command: process.execPath, args: [bundle, "--stdio"], cwd: applicationRoot, env }));
  return result;
}

async function call(name, arguments_) {
  const result = await client.callTool({ name, arguments: arguments_, _meta: { "openai/threadId": "storage-test-owner" } });
  if (result.isError) throw new Error(JSON.stringify(result));
  return result.structuredContent;
}

function save(input) { return call("save_codex_security_artifact", input); }
function read(input) { return call("read_codex_security_artifact", input); }
async function rejected(action) { await assert.rejects(action); }
