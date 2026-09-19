import assert from "node:assert/strict";
import path from "node:path";
import { test } from "node:test";
import { build } from "esbuild";

const bundle = await build({
  entryPoints: [path.resolve(import.meta.dirname, "../src/deep-scan/store.ts")],
  bundle: true, format: "esm", platform: "node", write: false,
  footer: { js: "//# sourceURL=deep-scan-selection-store.js" },
});
const { WorkbenchDeepScanStore } = await import(`data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`);

test("selection uses the dedicated function bridge and the store's existing replay policy", async () => {
  const scanId = "ed8ff2da-01d9-4338-aeba-8bcfd4b530a9";
  const selection = {
    version: 1, resultPath: "artifacts/merge/checkpoints/aggregate.json", resultSha256: "a".repeat(64),
    terminalReason: "saturated", omittedWorkerIds: [], selectedAt: "2026-01-01T00:00:00Z",
  };
  const response = { deepScan: {
    scanId, targetPath: "/target", scope: ".", scanDir: "/scan", status: "running",
    schemaVersion: 1, workflowVersion: "deep-security-scan/v2", coordinatorGeneration: 2,
    config: { workers: 2, subagents: 0, stopAfterNoNew: 2, stopAfterConsecutiveErrors: 2, maxDiscoveryRuns: 4 },
    dispatchedCount: 2, noNewStreak: 2, consecutiveErrors: 0, finalizationInput: selection,
  } };
  const calls = [];
  const store = new WorkbenchDeepScanStore(async (...args) => {
    calls.push(structuredClone(args));
    if (calls.length === 1) throw Object.assign(new Error("Synthetic lost selection response"), { code: "ETIMEDOUT" });
    return response;
  });
  const result = await store.selectFinalization({
    scanId, coordinatorGeneration: 2, reason: "saturated", manifestPath: "/scan/scan-manifest.json",
    resultPath: "/scan/artifacts/merge/checkpoints/aggregate.json", omittedWorkerIds: [],
  });
  assert.deepEqual(result.finalizationInput, selection);
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[1], calls[0]);
  assert.deepEqual(calls[0], [[
    "finish-deep-scan", "--scan-id", scanId, "--coordinator-generation", "2",
    "--terminal-reason", "saturated", "--manifest-path", "/scan/scan-manifest.json",
  ], JSON.stringify({ resultPath: "/scan/artifacts/merge/checkpoints/aggregate.json" }), true]);
});
