import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const app = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const plugin = path.resolve(app, "..");
const bundle = await build({
  bundle: true, format: "esm", platform: "node", write: false,
  loader: { ".md": "text" },
  stdin: { resolveDir: app, contents: [
    'export { WorkbenchDeepScanStore } from "./src/deep-scan/store.ts";',
    'export { DeepScanWorkerRunner } from "./src/deep-scan/worker-runner.ts";',
    'export { DeepScanCoordinator } from "./src/deep-scan/coordinator.ts";',
    'export { createDeepScanArtifacts, ensureDeepScanDirectories } from "./src/deep-scan/artifacts.ts";'
  ].join("\n") }
});
const { WorkbenchDeepScanStore, DeepScanWorkerRunner, DeepScanCoordinator, createDeepScanArtifacts, ensureDeepScanDirectories } =
  await import(`data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`);
const execute = promisify(execFile);
for (const responseLosses of [3, 1]) await testResponseLoss(responseLosses);

async function testResponseLoss(responseLosses) {
  const root = await mkdtemp(path.join(tmpdir(), "deep-attempt-receipt-"));
  const target = path.join(root, "target");
  const environment = { ...process.env, CODEX_HOME: path.join(root, "home"), CODEX_SECURITY_STATE_DIR: path.join(root, "state") };
  const counts = new Map();
  const receipts = new Map();
  const raw = async (args) => {
    const { stdout } = await execute(process.env.PYTHON || "python3", [path.join(plugin, "scripts/workbench_db.py"), ...args], {
      env: environment, timeout: 30_000, maxBuffer: 4 * 1024 * 1024
    });
    return JSON.parse(stdout);
  };
  const store = new WorkbenchDeepScanStore(async (args) => {
    const result = await raw(args);
    const key = args[0] === "commit-deep-scan-dedup" ? "merge"
      : args[0] === "upsert-deep-scan-worker" && args[args.indexOf("--status") + 1] === "succeeded" ? "acceptance" : null;
    const operation = key === "acceptance" ? `${key}:${args[args.indexOf("--worker-id") + 1]}` : key;
    if (key) {
      counts.set(key, (counts.get(key) ?? 0) + 1);
      const receipt = key === "acceptance" ? result.deepScan.workerReceipt : result.deepScan.committedMerge;
      if (!receipts.has(operation)) receipts.set(operation, receipt);
      else assert.deepEqual(receipt, receipts.get(operation), "replay returns the original operation receipt");
      if (counts.get(key) <= responseLosses) {
        const error = new Error("fixture response lost after committed write");
        error.code = "ETIMEDOUT";
        throw error;
      }
    }
    return result;
  });
  try {
    await mkdir(target);
    await writeFile(path.join(target, "fixture.py"), "print('fixture')\n");
    const { run } = await store.begin({ targetPath: target, scope: ".", threadId: "fixture-owner", scanRoot: path.join(root, "scans") });
    const artifacts = createDeepScanArtifacts(run.scanDir);
    await ensureDeepScanDirectories(artifacts);
    let executions = 0;
    const runner = new DeepScanWorkerRunner({
      run, store, artifacts, pluginRoot: plugin, signal: new AbortController().signal,
      random: () => 0.5, log: () => {}, retryDelaysMs: [],
      clock: { now: () => Date.now(), sleep: async () => {} },
      executor: { async run(request) {
        executions++;
        if (request.kind === "dedup") {
          const workers = request.artifactContext.deepReducer.claimedWorkers;
          const prompt = await readFile(request.promptPath, "utf8");
          const configuration = JSON.parse(prompt.match(/```json\n([\s\S]*?)\n```/)[1]);
          assert.deepEqual(configuration.claimedWorkerIds, workers.map(worker => worker.id));
          assert.equal(workers.every(worker => worker.resultPath.includes("checkpoints")), true);
          assert.deepEqual(workers.map(worker => worker.attempt), [1, 1], "execution uses the immutable claim attempts");
        }
        await request.onThreadStarted?.(`fixture-session-${executions}`);
        const draft = { scanId: run.scanId, findings: [], threatModel: { summary: "Synthetic fixture." } };
        if (request.kind === "discovery") draft.coverage = {
          completeness: "complete", surfaces: [{ label: "Fixture", disposition: "no_issue_found" }], explicitExclusions: [], deferred: []
        };
        await writeFile(path.join(request.artifactContext.root, "result.json"), JSON.stringify(draft));
        return { threadId: `fixture-session-${executions}` };
      } }
    });
    if (responseLosses === 3) {
      const outcome = await runner.runDiscoveryWorker(randomUUID(), "discovery-1").catch((error) => error);
      assert.equal(counts.get("acceptance"), 3, "the runner must not multiply the store's retry policy");
      assert.match(outcome.message, /response lost/);
      assert.equal(executions, 1);
      return;
    }
    const discovery = await runner.runDiscoveryWorker(randomUUID(), "discovery-1");
    assert.equal(discovery.status, "succeeded");
    assert.match(discovery.worker.resultPath, /checkpoints/);
    const second = await runner.runDiscoveryWorker(randomUUID(), "discovery-2");
    // Acceptance receipts are operation-specific, so only the first discovery loses a response.
    await rm(path.join(discovery.worker.artifactDir, "result.json"));
    const merged = await runner.runReducer({
      id: randomUUID(), label: "dedup-1",
      consumed: [discovery.worker, second.worker].map(worker => ({
        ...worker, resultPath: path.join(worker.artifactDir, "result.json"), attempt: 99
      }))
    });
    assert.equal(merged.error, undefined, merged.error?.stack);
    assert.match(merged.resultPath, /checkpoints/);
    assert.equal(merged.newFindings, 0);
    assert.equal(merged.run.persistedDedupInputs.filter((input) => input.dedupWorkerId === merged.id).length, 2);
    assert.equal(counts.get("merge"), 2);
    assert.equal(executions, 3);
    assert.deepEqual(JSON.parse(await readFile(merged.resultPath, "utf8")), merged.result);
    const snapshot = await store.get(run.scanId, "fixture-owner");
    const resumed = new DeepScanCoordinator({
      run: snapshot, store, pluginRoot: plugin,
      executor: { run: async () => assert.fail("accepted recovery must not execute another model") },
    });
    const beforeRecovery = await readFile(merged.resultPath, "utf8");
    const recovered = await resumed.recoverAcceptedDiscoveries();
    assert.deepEqual(recovered.map(worker => worker.resultPath), [discovery.worker.resultPath, second.worker.resultPath]);
    await rm(path.join(path.dirname(merged.resultPath), "..", "result.json"));
    const reducers = await resumed.recoverCompletedReducers(recovered);
    assert.equal(reducers.reducers[0].resultPath, merged.resultPath);
    assert.deepEqual(reducers.result, merged.result);
    assert.equal(await readFile(merged.resultPath, "utf8"), beforeRecovery, "recovery cannot rewrite accepted bytes");

  } finally {
    await rm(root, { recursive: true, force: true });
  }
}
