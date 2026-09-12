import assert from "node:assert/strict";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  entryPoints: [new URL("../src/deep-scan/registry.ts", import.meta.url).pathname],
  format: "esm",
  loader: { ".md": "text" },
  platform: "node",
  write: false
});
const { startOrJoinDeepScanCoordinator } = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);

await testUnsupportedWorkflowDoesNotAcquireOwnership();

async function testUnsupportedWorkflowDoesNotAcquireOwnership() {
  for (const version of [
    { schemaVersion: 99, workflowVersion: "deep-scan-mcp/v1" },
    { schemaVersion: 1, workflowVersion: "future/v99" }
  ]) {
    let mutations = 0;
    await assert.rejects(startOrJoinDeepScanCoordinator({
      begin: { run: { scanId: "fixture", ...version }, shouldStart: false },
      registry: {
        get: () => undefined,
        start: () => { mutations += 1; }
      },
      options: {
        threadId: "fixture-thread",
        store: { claimCoordinator: async () => { mutations += 1; } }
      }
    }), /unsupported workflow or schema version/);
    assert.equal(mutations, 0);
  }
}

