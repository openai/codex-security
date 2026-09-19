import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { build } from "esbuild";

const bundle = await build({
  entryPoints: [path.resolve(import.meta.dirname, "../src/deep-scan/coordinator.ts")],
  loader: { ".md": "text" },
  bundle: true, format: "esm", platform: "node", write: false,
  footer: { js: "//# sourceURL=deep-scan-selected-replay.js" },
});
const { DeepScanCoordinator } = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`,
);

for (const terminalReason of ["saturated", "capped"]) {
  test(`restart publishes the selected ${terminalReason} result after an output failure`, async () => {
    const scanDir = await realpath(await mkdtemp(path.join(tmpdir(), "selected-replay-")));
    try {
      const scanId = "4e7b4acb-ac80-4d68-98cd-3d5ac5581cd1";
      const draft = {
        scanId, complete: true, findings: [],
        coverage: { completeness: "partial", surfaces: [], explicitExclusions: [],
          deferred: [{ id: "review", reason: "A dependency remains unreviewed." }] },
      };
      const { coverage, ...reduction } = draft;
      const bytes = JSON.stringify({ ...reduction, sourceCoverage: coverage });
      const digest = createHash("sha256").update(bytes).digest("hex");
      const resultPath = `artifacts/deep_discovery/dedup/dedup-0001/output/checkpoints/${digest}.json`;
      await mkdir(path.dirname(path.join(scanDir, resultPath)), { recursive: true });
      await writeFile(path.join(scanDir, resultPath), bytes);
      const selection = { version: 1, resultPath, resultSha256: digest, terminalReason,
        omittedWorkerIds: [], selectedAt: "2026-01-01T00:00:00Z" };
      let run = {
        scanId, scanDir, targetPath: scanDir, scope: ".", workflowVersion: "deep-security-scan/v2",
        status: "running", phase: "terminal", coordinatorGeneration: 3,
        finalizationInput: selection, terminalReason, createdAt: "2026-01-01T00:00:00Z",
        config: { workers: 2, subagents: 0, stopAfterNoNew: 2, stopAfterConsecutiveErrors: 2,
          maxDiscoveryRuns: 4, maxTimeHours: 1 },
        dispatchedCount: 4, noNewStreak: 2, consecutiveErrors: 0,
      };
      const mutations = [];
      const store = new Proxy({
        get: async () => structuredClone(run),
        finish: async (input) => {
          mutations.push("finish");
          assert.equal(input.reason, terminalReason);
          assert.deepEqual(input.omittedWorkerIds, selection.omittedWorkerIds);
          run = { ...run, status: "succeeded", manifestPath: input.manifestPath };
          return structuredClone(run);
        },
        fail: async () => { mutations.push("fail"); run = { ...run, status: "failed" }; return run; },
      }, { get: (target, key) => key in target ? target[key] : async () => {
        mutations.push(key); throw new Error(`Unexpected scheduler operation: ${String(key)}`);
      } });
      let executions = 0;
      let publications = 0;
      const options = {
        store, executor: { run: async () => { executions++; throw new Error("Unexpected model work"); } },
        pluginRoot: scanDir, threadId: "original-result-conversation", retryDelaysMs: [],
        // Already expired: replay must not start a discovery deadline timer.
        discoveryTimeoutMs: 1,
        onComplete: async (actual, _signal, publication) => {
          publications++;
          assert.deepEqual(actual, draft);
          assert.equal(publication.coordinatorGeneration, 3);
          assert.equal(publication.resultPath, path.join(scanDir, resultPath));
          if (publications === 1) throw new Error("Synthetic publication write failure");
        },
      };
      const first = new DeepScanCoordinator({ ...options, run: structuredClone(run) });
      first.start();
      await assert.rejects(first.wait(), /Synthetic publication write failure/);
      assert.equal(run.status, "running");
      assert.equal(run.terminalReason, terminalReason);
      assert.deepEqual(run.finalizationInput, selection);
      const restarted = new DeepScanCoordinator({ ...options, run: structuredClone(run) });
      restarted.start();
      const completed = await restarted.wait();
      assert.equal(completed.status, "succeeded");
      assert.equal(completed.terminalReason, terminalReason);
      assert.equal(executions, 0);
      assert.deepEqual(mutations, ["finish"]);
      assert.equal(publications, 2);
    } finally {
      await rm(scanDir, { recursive: true, force: true });
    }
  });
}
