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
const { startOrJoinDeepScanCoordinator, DeepScanRemoteCoordinator } = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);

await testUnsupportedWorkflowDoesNotAcquireOwnership();
await testUnsupportedSelectionDoesNotAcquireOwnership();

async function testUnsupportedSelectionDoesNotAcquireOwnership() {
  for (const selection of [
    { workflowVersion: "deep-security-scan/v1", finalizationInput: { version: 1 } },
    { workflowVersion: "deep-security-scan/v2", finalizationInput: { version: 99 } }
  ]) {
    await assert.rejects(startOrJoinDeepScanCoordinator({
      begin: { run: { scanId: "fixture", schemaVersion: 1, ...selection }, shouldStart: false },
      registry: {
        get: () => assert.fail("unsupported selection inspected a live coordinator"),
        start: () => assert.fail("unsupported selection started a coordinator")
      },
      options: {
        threadId: "fixture-thread",
        prepareExecutor: async () => assert.fail("unsupported selection resolved settings"),
        store: { claimCoordinator: async () => assert.fail("unsupported selection acquired ownership") }
      }
    }), /finalization input version/);
  }
}

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


// A joining client must not resolve or replace the live executor's settings.
for (const workflowVersion of ["deep-scan-mcp/v1", "deep-security-scan/v1", "deep-security-scan/v2"]) {
  for (const local of [true, false]) {
    let preparations = 0;
    const run = { scanId: "fixture", status: "running", workflowVersion };
    const options = {
      threadId: "fixture-thread",
      executor: { marker: "observer" },
      prepareExecutor: async () => { preparations += 1; return {}; },
      store: { claimCoordinator: async () => ({ run, acquired: false }) }
    };
    await startOrJoinDeepScanCoordinator({
      begin: { run, shouldStart: false },
      registry: { get: () => local ? {} : undefined, start: () => assert.fail("observer started") },
      options
    });
    assert.equal(preparations, 0);
  }
}

// Selected publication has no worker launch and must not need current settings.
for (const selected of [false, true]) {
  const run = {
    scanId: "fixture", status: "running", workflowVersion: "deep-security-scan/v2",
    ...(selected ? { finalizationInput: { version: 1 } } : {})
  };
  let preparations = 0;
  const fallback = {};
  const restored = {};
  await startOrJoinDeepScanCoordinator({
    begin: { run, shouldStart: false },
    registry: {
      get: () => undefined,
      start: (options) => {
        assert.equal(options.executor, selected ? fallback : restored);
        assert.equal(options.run, run);
        return {};
      }
    },
    options: {
      threadId: "fixture-thread",
      executor: fallback,
      prepareExecutor: async () => { preparations += 1; return restored; },
      store: { claimCoordinator: async () => ({ run, acquired: true }) }
    }
  });
  assert.equal(preparations, selected ? 0 : 1);
}

const originalNow = Date.now;
try {
  let now = 0;
  Date.now = () => now;
  const run = { scanId: "fixture", status: "running", updatedAt: "1970-01-01T00:00:00Z" };
  const acquired = { ...run, model: "original-model", coordinatorGeneration: 3 };
  let preparations = 0;
  const executor = { marker: "restored" };
  const registry = {
    get: () => undefined,
    start: (options) => {
      assert.equal(options.run, acquired);
      assert.equal(options.executor, executor);
      return { wait: async () => ({ ...acquired, status: "succeeded" }) };
    }
  };
  const options = {
    threadId: "fixture-thread",
    executor: { marker: "observer" },
    prepareExecutor: async (state) => {
      assert.equal(state, acquired);
      preparations += 1;
      return executor;
    },
    store: {
      get: async () => run,
      claimCoordinator: async () => ({ run: acquired, acquired: true })
    }
  };
  await startOrJoinDeepScanCoordinator({ begin: { run, shouldStart: true }, registry, options });
  assert.equal(preparations, 1);
  const remote = new DeepScanRemoteCoordinator({ run, registry, options });
  now = 60_000;
  assert.equal((await remote.wait(undefined, 1_000)).status, "succeeded");
  assert.equal(preparations, 2, "takeover resolves settings from the newly acquired run");
} finally {
  Date.now = originalNow;
}
