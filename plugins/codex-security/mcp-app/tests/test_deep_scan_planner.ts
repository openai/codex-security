import assert from "node:assert/strict";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import test, { after } from "node:test";
import type { CodexWorkerRequest } from "../src/deep-scan/types.js";
import {
  coordinatorFixture,
  createCoordinator,
  eventually,
  FakeExecutor,
  promptContext,
  runCoordinator,
  temporaryDirectories,
} from "./deep_scan_coordinator_fixture.ts";

const workItems = [
  {
    title: "Public upload endpoint",
    objective:
      "Trace the upload handler through authorization and file creation.",
    startingPoints: ["api/upload.ts"],
  },
  {
    title: "Queued import",
    objective: "Trace queued import requests to command execution.",
    startingPoints: ["jobs/import.ts"],
  },
];

after(() => temporaryDirectories.cleanup());

test("Deep discovery gives concurrent workers distinct planned entrypoints inside the original scope and keeps them on retry", async () => {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    maxDiscoveryRuns: 2,
  });
  const includePaths = ["api", "jobs"];
  fixture.run.includePaths = includePaths;
  fixture.run.userContext = "Authenticated tenant requests.";
  const workers = new FakeExecutor({ invalidDiscoveryAttempts: 1 });
  let planCalls = 0;
  const executor = {
    async plan(request: CodexWorkerRequest) {
      planCalls++;
      assert.equal(request.kind, "setup");
      assert.equal(request.subagents, 0);
      const prompt = await readFile(request.promptPath, "utf8");
      assert.ok(prompt.includes(fixture.run.targetPath));
      assert.ok(prompt.includes(fixture.run.userContext!));
      for (const entry of includePaths) assert.ok(prompt.includes(entry));
      return {
        workItems: [
          ...workItems,
          {
            title: "Unscoped service",
            objective: "Trace a separate service.",
            startingPoints: ["other/entry.ts"],
          },
        ],
      };
    },
    run: workers.run.bind(workers),
  };
  const terminal = await runCoordinator(fixture, store, executor, {
    retryDelaysMs: [0],
  });
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(planCalls, 1);
  const setup = [...store.workers.values()].find(
    (worker) => worker.kind === "setup",
  );
  assert.ok(setup?.resultManifestPath);
  assert.deepEqual(
    JSON.parse(await readFile(setup.resultManifestPath, "utf8")),
    { workItems },
  );
  assert.deepEqual([...workers.discoveryAttempts.values()].sort(), [1, 2]);
  for (const [index, item] of workItems.entries()) {
    const label = `discovery-000${index + 1}`;
    const promptPaths = workers.discoveryPromptPaths.get(label);
    assert.ok(promptPaths?.size);
    for (const promptPath of promptPaths) {
      const context = await promptContext(promptPath);
      assert.deepEqual(context.assignment, item);
      assert.deepEqual(context.includePaths, includePaths);
      assert.equal(context.userContext, fixture.run.userContext);
    }
  }
});

test("a worker without a distinct planned entrypoint can investigate alongside an assigned peer", async () => {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    maxDiscoveryRuns: 2,
  });
  const release = Promise.withResolvers<void>();
  const workers = new FakeExecutor({
    discoveryGates: {
      "discovery-0001": release.promise,
      "discovery-0002": release.promise,
    },
  });
  const executor = {
    plan: async () => ({ workItems: [workItems[0]] }),
    run: workers.run.bind(workers),
  };
  const coordinator = createCoordinator(fixture, store, executor);
  coordinator.start();
  try {
    await eventually(() => workers.runningDiscovery === 2);
  } finally {
    release.resolve();
  }
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  const [promptPath] = workers.discoveryPromptPaths.get("discovery-0002")!;
  const scout = await promptContext(promptPath);
  assert.equal(scout.assignment, undefined);
  assert.deepEqual(scout.peerAssignments, [workItems[0]]);
});

test("a replacement coordinator reuses the saved plan and assigns the entrypoint left unfinished", async () => {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    maxDiscoveryRuns: 2,
  });
  const workers = new FakeExecutor();
  const originalExecutor = {
    plan: async () => ({ workItems }),
    async run(request: CodexWorkerRequest) {
      if (
        request.kind === "discovery" &&
        (await promptContext(request.promptPath)).workerLabel ===
          "discovery-0001"
      ) {
        if (!request.signal.aborted) await once(request.signal, "abort");
        throw new DOMException("coordinator shutdown", "AbortError");
      }
      return workers.run(request);
    },
  };
  const original = createCoordinator(fixture, store, originalExecutor);
  original.start();
  await eventually(() =>
    [...store.workers.values()].some(
      (worker) => worker.kind === "discovery" && worker.status === "succeeded",
    ),
  );
  original.cancel("mcp server process restarted");
  await original.wait(undefined, 5_000);

  // The workbench refunds the interrupted discovery slot on coordinator takeover.
  const recovered = await store.get();
  recovered.dispatchedCount = 1;
  const replacement = new FakeExecutor();
  let replans = 0;
  const executor = {
    async plan() {
      replans++;
      return { workItems: [] };
    },
    run: replacement.run.bind(replacement),
  };
  const terminal = await runCoordinator(fixture, store, executor, {
    run: recovered,
  });
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(replans, 0);
  assert.deepEqual(
    [...replacement.discoveryAttempts.keys()],
    ["discovery-0003"],
  );
  const [promptPath] = replacement.discoveryPromptPaths.get("discovery-0003")!;
  assert.deepEqual((await promptContext(promptPath)).assignment, workItems[0]);
});
