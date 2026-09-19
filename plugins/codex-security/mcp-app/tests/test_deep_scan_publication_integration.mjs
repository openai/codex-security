import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { build } from "esbuild";

const execFileAsync = promisify(execFile);
const testsRoot = path.dirname(fileURLToPath(import.meta.url));
const mcpAppRoot = path.resolve(testsRoot, "..");
const pluginRoot = path.resolve(mcpAppRoot, "..");
const workbenchPath = path.join(pluginRoot, "scripts", "workbench_db.py");
const python = process.env.PYTHON?.trim() || "python3";
const owner = "publication-test-owner";
const coverage = { completeness: "complete", surfaces: [], explicitExclusions: [], deferred: [] };
const highId = "ffffffff-ffff-4fff-8fff-ffffffffffff";
const lowId = "00000000-0000-4000-8000-000000000001";
const bundleRoot = await mkdtemp(path.join(tmpdir(), "deep-publication-bundle-"));
after(() => rm(bundleRoot, { recursive: true, force: true }));
const serverPath = path.join(bundleRoot, "server.cjs");
await build({
  bundle: true,
  define: { __dirname: JSON.stringify(mcpAppRoot), "import.meta.url": "__filename" },
  entryPoints: [path.join(mcpAppRoot, "main.ts")],
  external: ["fsevents"],
  format: "cjs",
  loader: { ".md": "text" },
  logLevel: "silent",
  outfile: serverPath,
  platform: "node",
  target: "node20",
});
const hostBundle = await build({
  bundle: true,
  stdin: {
    contents: [
      'export { WorkbenchDeepScanStore } from "./src/deep-scan/store.ts";',
      'export { DeepScanCoordinator } from "./src/deep-scan/coordinator.ts";',
      'export { createScanArtifactContext } from "./src/artifact-context.ts";',
      'export { recordCodexSecurityScanDraftViaWorkbench } from "./src/artifact-scan-draft.ts";',
    ].join("\n"),
    resolveDir: mcpAppRoot,
  },
  format: "esm",
  loader: { ".md": "text" },
  platform: "node",
  write: false,
});
const {
  WorkbenchDeepScanStore, DeepScanCoordinator, createScanArtifactContext,
  recordCodexSecurityScanDraftViaWorkbench,
} = await import(`data:text/javascript;base64,${Buffer.from(hostBundle.outputFiles[0].contents).toString("base64")}`);

test("public partial drafts retain checkpoints after coordinator adoption", async (t) => {
  const fixture = await createFixture(t);
  const { run, store, call, runWorkbench } = fixture;
  assertSuccess(await call("record_codex_security_scan_draft", partial(run, "generation-one")));
  const first = await checkpoints(run);
  assert.equal(Object.keys(first).length, 1);
  const claim = await store.claimCoordinator({ scanId: run.scanId, threadId: owner });
  assert.equal(claim.acquired, true);
  assert.equal(claim.run.coordinatorGeneration, 2);

  assertSuccess(await call("record_codex_security_scan_draft", partial(run, "generation-two")));
  const retained = await checkpoints(run);
  assert.equal(Object.keys(retained).length, 2);
  for (const [name, bytes] of Object.entries(first)) assert.equal(retained[name], bytes);
  assert.deepEqual(new Set(Object.values(retained).flatMap((bytes) => (
    JSON.parse(bytes).coverage.deferred.map((item) => item.candidateId)
  ))), new Set(["generation-one", "generation-two"]));

  const before = await snapshot(run);
  assertToolError(await call("record_codex_security_scan_draft", {
    ...partial(run, "unfenced-final"), complete: true,
  }), /current coordinator lease/);
  const context = await createScanArtifactContext(run.scanId, runWorkbench, { requireRunning: true });
  await assert.rejects(recordCodexSecurityScanDraftViaWorkbench(
    context, partial(run, "stale-generation"), runWorkbench, undefined,
    { coordinatorGeneration: 1, resultPath: null },
  ), /newer generation/);
  assertToolError(await call("complete_codex_security_scan", { scanId: run.scanId }), /deep/i);
  assert.deepEqual(await snapshot(run), before);
  assert.deepEqual(await readdir(path.join(run.scanDir, "drafts")), []);
});

for (const [label, offsets, ids, paths, recoveryOnly] of [
  ["increasing timestamps", [1, 2], [highId, lowId]],
  ["equal timestamps and descending UUIDs", [1, 1], [highId, lowId]],
  ["decreasing timestamps", [2, 1], [lowId, highId]],
  ["equal timestamps and ascending UUIDs", [1, 1], [lowId, highId]],
  ["scan root collision, live publication", [1, 1], [highId, lowId], { scanRoot: "dedup-123/scans" }],
  ["scan root collision, recovery", [1, 1], [highId, lowId], { scanRoot: "dedup-123/scans" }, true],
  ["target name collision, live publication", [1, 1], [highId, lowId], { target: "dedup-456-target" }],
  ["target name collision, recovery", [1, 1], [highId, lowId], { target: "dedup-456-target" }, true],
]) {
  test(`selected reducer survives recovery and public completion: ${label}`, async (t) => {
    const fixture = await createFixture(t, paths);
    const { run, store, call, runWorkbench, instant } = fixture;
    assertSuccess(await call("record_codex_security_scan_draft", partial(run, "parent-checkpoint-only")));
    const parentCheckpoints = await checkpoints(run);
    assert.equal(Object.keys(parentCheckpoints).length, 1);
    const claimed = await store.claimCoordinator({ scanId: run.scanId, threadId: owner });
    assert.equal(claimed.run.coordinatorGeneration, 2);
    assert.equal(claimed.run.config.stopAfterNoNew, 4);
    const results = await commitReducers(fixture, offsets, ids);
    const persisted = await store.get(run.scanId, owner);
    assert.equal(persisted.noNewStreak, 4);
    assert.deepEqual(persisted.persistedWorkers.filter((worker) => worker.kind === "discovery")
      .map((worker) => worker.mergeState), Array(4).fill("merged"));
    const context = await createScanArtifactContext(run.scanId, runWorkbench, { requireRunning: true });
    const publish = async (index, coordinatorGeneration = 2) => (
      recordCodexSecurityScanDraftViaWorkbench(context, {
        ...JSON.parse(await readFile(results[index], "utf8")), coverage,
      }, runWorkbench, undefined, { coordinatorGeneration, resultPath: results[index] })
    );

    if (!recoveryOnly) {
      await publish(1);
      const selected = await snapshot(run);
      await assert.rejects(publish(0), /superseded publication selection/);
      await assert.rejects(publish(1, 1), /newer generation/);
      assert.deepEqual(await snapshot(run), selected);
    }

    const publications = [];
    const coordinator = new DeepScanCoordinator({
      run: persisted, store, pluginRoot,
      executor: { run() { throw new Error("Recovery must reuse the committed workers."); } },
      clock: { now: () => Date.parse(instant), sleep: async () => {} },
      onComplete: async (draft, signal, publication) => {
        publications.push(publication);
        await recordCodexSecurityScanDraftViaWorkbench(context, draft, runWorkbench, signal, publication);
      },
    });
    coordinator.start();
    const terminal = await coordinator.wait(undefined, 30_000);
    assert.equal(terminal?.status, "succeeded", terminal?.error);
    assert.deepEqual(publications, [{ coordinatorGeneration: 2, resultPath: results[1] }]);

    const beforeCompletion = await snapshot(run);
    const lateDraft = partial(run, "late-parent-checkpoint");
    assertToolError(await call("record_codex_security_scan_draft", lateDraft));
    assert.deepEqual(await snapshot(run), beforeCompletion);
    assertSuccess(await call("complete_codex_security_scan", { scanId: run.scanId }));
    const sealed = await snapshot(run);
    const manifest = JSON.parse(sealed.files["scan-manifest.json"]);
    assert.equal(manifest.scan.threatModel.summary, "dedup-0002");
    assert.ok(manifest.scan.sealedAt);
    assert.deepEqual(JSON.parse(sealed.files["findings.json"]).findings, []);
    assert.deepEqual(JSON.parse(sealed.files["coverage.json"]).deferred, []);
    assert.ok(sealed.files["report.md"]);
    for (const [name, bytes] of Object.entries(parentCheckpoints)) {
      assert.equal(sealed.checkpoints[name], bytes, "completion retains the immutable parent checkpoint");
    }
    assert.deepEqual(sealed.checkpoints, beforeCompletion.checkpoints);
    assertSuccess(await call("complete_codex_security_scan", { scanId: run.scanId }));
    assert.deepEqual(await snapshot(run), sealed, "completion replay is byte-stable");
    assertToolError(await call("record_codex_security_scan_draft", lateDraft));
    assert.deepEqual(await snapshot(run), sealed, "late writes cannot replace sealed results");
  });
}

async function createFixture(t, paths = {}) {
  const root = await mkdtemp(path.join(tmpdir(), "deep-publication-"));
  let client;
  t.after(async () => {
    await client?.close();
    await rm(root, { recursive: true, force: true });
  });
  const targetPath = path.join(root, paths.target ?? "target");
  await mkdir(targetPath);
  await writeFile(path.join(targetPath, "fixture.py"), "# Synthetic publication fixture\n");
  const environment = {
    ...process.env,
    CODEX_HOME: path.join(root, "home"),
    CODEX_SECURITY_STATE_DIR: path.join(root, "state"),
    CODEX_SECURITY_SCAN_ROOT: path.join(root, paths.scanRoot ?? "scans"),
  };
  delete environment.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
  const instant = new Date().toISOString();
  let now = instant;
  const runWorkbench = async (args, input) => {
    const child = execFileAsync(python, [path.join(testsRoot, "clock_workbench.py"), workbenchPath, ...args], {
      cwd: pluginRoot, env: { ...environment, TEST_WORKBENCH_NOW: now },
      timeout: 30_000, maxBuffer: 4 * 1024 * 1024,
    });
    child.child.stdin.end(input);
    return JSON.parse((await child).stdout);
  };
  const store = new WorkbenchDeepScanStore(runWorkbench);
  const { run } = await store.begin({ targetPath, scope: ".", threadId: owner, scanRoot: environment.CODEX_SECURITY_SCAN_ROOT });
  client = new Client({ name: "publication-integration", version: "1.0.0" });
  const transport = new StdioClientTransport({
    command: process.execPath, args: [serverPath, "--stdio"], cwd: mcpAppRoot,
    env: environment, stderr: "pipe",
  });
  transport.stderr?.resume();
  await client.connect(transport);
  return {
    run, store, runWorkbench, instant,
    setTime(offset) { now = new Date(Date.parse(instant) + offset * 1_000).toISOString(); },
    call(name, args) {
      return client.callTool({ name, arguments: args, _meta: { "openai/threadId": owner } });
    },
  };
}

async function commitReducers(fixture, offsets, ids) {
  const { run, store } = fixture;
  const results = [];
  for (let batch = 0; batch < 2; batch++) {
    const workerIds = [];
    for (let index = batch * 2 + 1; index <= batch * 2 + 2; index++) {
      const id = `10000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
      const label = `discovery-${String(index).padStart(4, "0")}`;
      const artifact = await workerArtifact(run, "workers", label);
      const update = { id, scanId: run.scanId, kind: "discovery", status: "running", attempt: 1, ...artifact };
      await store.updateWorker(update);
      const resultManifestPath = path.join(artifact.artifactDir, "result.json");
      await writeFile(resultManifestPath, JSON.stringify({ scanId: run.scanId, findings: [], coverage }));
      await store.updateWorker({ ...update, status: "succeeded", resultManifestPath });
      workerIds.push(id);
    }
    const label = `dedup-${String(batch + 1).padStart(4, "0")}`;
    const artifact = await workerArtifact(run, "dedup", label);
    const id = ids[batch];
    await store.claimDedup({ id, scanId: run.scanId, workerIds, ...artifact });
    await store.updateWorker({ id, scanId: run.scanId, kind: "dedup", status: "running", attempt: 1, ...artifact });
    const resultManifestPath = path.join(artifact.artifactDir, "result.json");
    await writeFile(resultManifestPath, JSON.stringify({ scanId: run.scanId, findings: [], threatModel: { summary: label } }));
    fixture.setTime(offsets[batch]);
    await store.commitDedup({ id, scanId: run.scanId, resultManifestPath, newFindings: 0 });
    fixture.setTime(0);
    results.push(resultManifestPath);
  }
  return results;
}

async function workerArtifact(run, kind, label) {
  const artifactDir = path.join(run.scanDir, "artifacts", "deep_discovery", kind, label, "output");
  const promptPath = path.join(path.dirname(artifactDir), "prompt.md");
  await mkdir(artifactDir, { recursive: true });
  await writeFile(promptPath, `Synthetic ${label}\n`);
  return { artifactDir, promptPath };
}

function partial(run, candidateId) {
  return {
    scanId: run.scanId, complete: false, findings: [],
    coverage: {
      ...coverage, completeness: "partial",
      deferred: [{ candidateId, reason: "Synthetic review remains pending.", paths: ["fixture.py"] }],
    },
  };
}

async function checkpoints(run) {
  const directory = path.join(run.scanDir, "checkpoints");
  const files = {};
  for (const name of await readdir(directory)) files[name] = await readFile(path.join(directory, name), "utf8");
  return files;
}

async function snapshot(run) {
  const files = {};
  for (const name of ["scan-manifest.json", "findings.json", "coverage.json", "report.md"]) {
    try { files[name] = await readFile(path.join(run.scanDir, name), "utf8"); }
    catch (error) { if (error.code !== "ENOENT") throw error; }
  }
  return { files, checkpoints: await checkpoints(run) };
}

function assertSuccess(result) {
  assert.notEqual(result.isError, true, JSON.stringify(result));
}

function assertToolError(result, pattern) {
  assert.equal(result.isError, true, JSON.stringify(result));
  if (pattern) assert.match(JSON.stringify(result), pattern);
}
