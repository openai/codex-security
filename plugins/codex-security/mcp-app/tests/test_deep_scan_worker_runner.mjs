import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  entryPoints: [new URL("../src/deep-scan/worker-runner.ts", import.meta.url).pathname],
  format: "esm",
  loader: { ".md": "text" },
  platform: "node",
  write: false
});
const { DeepScanWorkerRunner } = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);

test("retry and terminal failures retain each attempt's observed thread", async (t) => {
  const fixture = await runnerFixture(t);
  fixture.execute = async (request) => {
    const threadId = `thread-attempt-${fixture.requests.length}`;
    await request.onThreadStarted(threadId);
    throw new Error(`execution failed in ${threadId}`);
  };

  const outcome = await fixture.runDiscovery();

  assert.equal(outcome.status, "failed");
  assert.deepEqual(fixture.requests.map((request) => request.resumeThreadId), [
    undefined,
    "thread-attempt-1"
  ]);
  assert.deepEqual(fixture.updates.filter((update) => update.error).map((update) => ({
    attempt: update.attempt,
    threadId: update.threadId,
    status: update.status
  })), [
    { attempt: 1, threadId: "thread-attempt-1", status: "running" },
    { attempt: 2, threadId: "thread-attempt-2", status: "canceled" }
  ]);
});

test("cancellation after retry sleep resolves retains the completed attempt", async (t) => {
  const fixture = await runnerFixture(t);
  fixture.execute = async (request) => {
    await request.onThreadStarted("thread-before-cancellation");
    throw new Error("retryable execution failure");
  };
  fixture.sleep = async () => fixture.controller.abort("fixture cancellation");

  const outcome = await fixture.runDiscovery();

  assert.equal(outcome.status, "canceled");
  assert.equal(fixture.requests.length, 1);
  assert.equal(fixture.updates.every((update) => update.attempt === 1), true);
  const cancellation = fixture.updates.at(-1);
  assert.equal(cancellation.status, "canceled");
  assert.equal(cancellation.threadId, "thread-before-cancellation");
});

test("an unstarted fresh thread does not inherit the preceding attempt's thread", async (t) => {
  const fixture = await runnerFixture(t, [0, 0]);
  fixture.execute = async (request) => {
    if (fixture.requests.length === 1) {
      await request.onThreadStarted("thread-invalid-artifacts");
      await writeFile(path.join(request.artifactContext.root, "result.json"), "{}\n");
      return { threadId: "thread-invalid-artifacts" };
    }
    throw new Error("execution failed before starting a fresh thread");
  };
  fixture.sleep = async () => {
    if (fixture.requests.length === 2) fixture.controller.abort("fixture cancellation");
  };

  const outcome = await fixture.runDiscovery();

  assert.equal(outcome.status, "canceled");
  assert.deepEqual(fixture.requests.map((request) => request.resumeThreadId), [undefined, undefined]);
  const cancellation = fixture.updates.at(-1);
  assert.equal(cancellation.attempt, 2);
  assert.equal(cancellation.threadId, undefined);
  assert.equal(fixture.updates.some((update) => update.attempt === 3), false);
});

test("a returned thread is persisted and resumed when validation fails without a callback", async (t) => {
  const fixture = await runnerFixture(t);
  fixture.execute = async (request) => {
    if (fixture.requests.length === 2) await fixture.writeResult(request);
    return { threadId: "thread-returned-without-callback" };
  };

  const outcome = await fixture.runDiscovery();

  assert.equal(outcome.status, "succeeded");
  assert.deepEqual(fixture.requests.map((request) => request.resumeThreadId), [
    undefined,
    "thread-returned-without-callback"
  ]);
  assert.equal(fixture.updates.find((update) => update.error).threadId,
    "thread-returned-without-callback");
  assert.equal(outcome.worker.threadId, "thread-returned-without-callback");
});

test("a reducer's returned thread is persisted before committing its result", async (t) => {
  const fixture = await runnerFixture(t);
  fixture.execute = async (request) => {
    await fixture.writeResult(request);
    return { threadId: `thread-${request.kind}-without-callback` };
  };
  const discovery = await fixture.runDiscovery();
  assert.equal(discovery.status, "succeeded");

  const outcome = await fixture.runner.runReducer({
    id: randomUUID(),
    label: "dedup-0001",
    consumed: [discovery.worker]
  });

  assert.equal(outcome.threadId, "thread-dedup-without-callback");
  assert.deepEqual(fixture.committedThreads, ["thread-dedup-without-callback"]);
});

async function runnerFixture(t, retryDelaysMs = [0]) {
  const root = await realpath(await mkdtemp(path.join(tmpdir(), "deep-scan-worker-runner-")));
  t.after(async () => await rm(root, { recursive: true, force: true }));
  const scanDir = path.join(root, "scan");
  const targetPath = path.join(root, "target");
  const pluginRoot = path.join(root, "plugin");
  await Promise.all([mkdir(scanDir), mkdir(targetPath), mkdir(pluginRoot)]);
  const deepRoot = path.join(scanDir, "artifacts", "deep_discovery");
  const run = {
    scanId: randomUUID(),
    status: "running",
    targetPath,
    scope: ".",
    scanDir,
    config: { subagents: 0 }
  };
  const workers = new Map();
  const fixture = {
    controller: new AbortController(),
    requests: [],
    updates: [],
    committedThreads: [],
    execute: async () => { throw new Error("Missing fixture execution"); },
    sleep: async () => {},
    writeResult: async (request) => await writeFile(
      path.join(request.artifactContext.root, "result.json"),
      JSON.stringify({
        scanId: run.scanId,
        findings: [],
        coverage: {
          completeness: "complete",
          surfaces: [],
          explicitExclusions: [],
          deferred: []
        }
      })
    )
  };
  fixture.runner = new DeepScanWorkerRunner({
    run,
    artifacts: {
      scanDir,
      deepRoot,
      workersRoot: path.join(deepRoot, "workers"),
      dedupRoot: path.join(deepRoot, "dedup")
    },
    pluginRoot,
    store: {
      updateWorker: async (update) => {
        fixture.updates.push(structuredClone(update));
        const worker = {
          ...workers.get(update.id),
          ...update,
          ...(update.status === "succeeded" ? { completionSequence: 1 } : {})
        };
        workers.set(update.id, worker);
        return worker;
      },
      claimDedup: async () => {},
      commitDedup: async (commit) => {
        fixture.committedThreads.push(workers.get(commit.id)?.threadId);
        return run;
      }
    },
    executor: {
      run: async (request) => {
        fixture.requests.push(request);
        return await fixture.execute(request);
      }
    },
    clock: { now: () => 0, sleep: async () => await fixture.sleep() },
    random: () => 0,
    log: () => {},
    retryDelaysMs,
    signal: fixture.controller.signal
  });
  fixture.runDiscovery = async () => await fixture.runner.runDiscoveryWorker(
    randomUUID(), "discovery-0001"
  );
  return fixture;
}
