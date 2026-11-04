import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { promises as filesystem, rmdirSync, writeFileSync } from "node:fs";
import { mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { basename, dirname, join } from "node:path";
import { after, test } from "node:test";
import type { CoordinatorOptions } from "../src/deep-scan/coordinator.js";
import {
  DeepScanCoordinatorRegistry,
  FakeExecutor,
  coordinatorFixture,
  createCoordinator,
  fixtureRun,
  runCoordinator,
  standardScanDraft,
  temporaryDirectories,
  type TestWorker,
} from "./deep_scan_coordinator_fixture.ts";
import { importSource } from "./import-module.ts";
import { writeJson } from "./support/json.ts";

const options = {
  define: {
    "import.meta.url": JSON.stringify(
      new URL(
        "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
        import.meta.url,
      ).href,
    ),
  },
};
const { checkSelectedTargets } = await importSource(
  "src/deep-scan/target-admission.ts",
  options,
);
const { startDeepScanEngine } = await importSource("src/deep-scan/engine.ts", {
  ...options,
  loader: { ".md": "text" },
});
const signal = new AbortController().signal;
after(() => temporaryDirectories.cleanup());

test("a fresh scan rejects an empty target before dispatch", async () => {
  const { fixture, store } = await coordinatorFixture();
  const executor = new FakeExecutor();
  const registry = new DeepScanCoordinatorRegistry();
  const start = registry.start.bind(registry);
  registry.start = (options: CoordinatorOptions) =>
    start({ ...options, executor });
  await mkdir(fixture.run.targetPath);
  const parent = dirname(fixture.run.targetPath);
  execFileSync("git", ["init", "-q", parent]);
  await writeFile(join(parent, "outside.py"), "");
  const { coordinator } = await startDeepScanEngine({
    run: store.run,
    store,
    registry,
    runWorkbench: async () => ({}),
    pluginRoot: fixture.pluginRoot,
    pythonCommand: "fixture-python",
    parentSandbox: { filesystemDenies: [] },
    threadId: "fixture-owner",
  });
  const result = await coordinator.wait(undefined, 5_000);
  assert.equal(result?.status, "failed", result?.error);
  assert.match(result.error, /target is empty.*no security audit/iu);
  assert.equal(executor.discoveryCalls, 0);
});

test("admission tests only the registered selections and accepts any directory entry or regular file", async () => {
  const { run } = await fixtureRun();
  run.includePaths = ["left", "right"];
  const left = join(run.targetPath, "left");
  const right = join(run.targetPath, "right");
  await mkdir(left, { recursive: true });
  await mkdir(right);
  await writeFile(join(run.targetPath, "outside.py"), "");
  await assert.rejects(checkSelectedTargets(run, signal), /target is empty/iu);
  await writeFile(join(right, ".gitignore"), "");
  await checkSelectedTargets(run, signal);
  run.includePaths.reverse();
  await checkSelectedTargets(run, signal);
  await assert.rejects(
    checkSelectedTargets({ ...run, filePaths: ["left"] }, signal),
    /regular file/iu,
  );
  await rm(left, { recursive: true });
  await writeFile(left, "");
  run.includePaths = ["left"];
  await checkSelectedTargets({ ...run, filePaths: ["left"] }, signal);
});

test("a viable file cannot mask a missing or escaping sibling", async () => {
  const { run } = await fixtureRun();
  await mkdir(run.targetPath);
  await writeFile(join(run.targetPath, "source.py"), "");
  const outside = join(dirname(run.targetPath), "outside");
  await mkdir(outside);
  await symlink(
    outside,
    join(run.targetPath, "link"),
    process.platform === "win32" ? "junction" : "dir",
  );
  for (const [member, error] of [
    ["gone", /ENOENT|not found|Windows filesystem error/iu],
    ["../outside", /inside repo|outside/iu],
    ["link", /symbolic links|inside repo/iu],
  ] as const) {
    await assert.rejects(
      checkSelectedTargets(
        {
          ...run,
          includePaths: ["source.py", member],
          filePaths: ["source.py"],
        },
        signal,
      ),
      error,
    );
  }
});

test("a directory lost after validation preserves a viable sibling or its original diagnostic", async (t) => {
  const { run } = await fixtureRun();
  const first = join(run.targetPath, "first");
  const lost = join(run.targetPath, "lost");
  await mkdir(first, { recursive: true });
  await writeFile(join(run.targetPath, "source.py"), "");
  const open = filesystem.opendir;
  const opener = t.mock.method(
    filesystem,
    "opendir",
    async (...args: Parameters<typeof open>) => {
      if (basename(String(args[0])) === "first")
        await rm(lost, { recursive: true });
      return open(...args);
    },
  );
  syncBuiltinESMExports();
  try {
    await mkdir(lost);
    run.includePaths = ["first", "lost"];
    await assert.rejects(
      checkSelectedTargets(run, signal),
      /ENOENT|not found|Windows filesystem error/iu,
    );
    await mkdir(lost);
    run.includePaths.push("source.py");
    await checkSelectedTargets(run, signal);
  } finally {
    opener.mock.restore();
    syncBuiltinESMExports();
  }
});

test("admission rechecks a repository replaced after initial validation", async () => {
  const { run } = await fixtureRun();
  await mkdir(run.targetPath);
  const checking = checkSelectedTargets(run, signal);
  setImmediate(() => {
    rmdirSync(run.targetPath);
    writeFileSync(run.targetPath, "replacement");
  });
  await assert.rejects(checking, /not a directory|no longer a directory/iu);
});

test("cancellation interrupts validation between registered files", async () => {
  const { run } = await fixtureRun();
  await mkdir(run.targetPath);
  const controller = new AbortController();
  run.includePaths = ["first", "missing"];
  run.filePaths = run.includePaths;
  await writeFile(join(run.targetPath, "first"), "");
  const checking = checkSelectedTargets(run, controller.signal);
  setImmediate(() => controller.abort(new Error("canceled")));
  await assert.rejects(checking, /canceled/u);
});

test("a slow directory read checks one raw entry and closes on cancellation", async (t) => {
  const { run } = await fixtureRun();
  await mkdir(run.targetPath);
  const controller = new AbortController();
  const read = t.mock.fn(async () => {
    controller.abort(new Error("canceled"));
    return {};
  });
  const close = t.mock.fn(async () => {});
  const opener = t.mock.method(
    filesystem,
    "opendir",
    async (_path: unknown, opts: unknown) => {
      assert.deepEqual(opts, { encoding: "buffer", bufferSize: 1 });
      return { read, close };
    },
  );
  syncBuiltinESMExports();
  try {
    await assert.rejects(
      checkSelectedTargets(run, controller.signal),
      /canceled/u,
    );
    assert.equal(read.mock.callCount(), 1);
    assert.equal(close.mock.callCount(), 1);
  } finally {
    opener.mock.restore();
    syncBuiltinESMExports();
  }
});

test(
  "POSIX directory selections preserve raw name bytes",
  { skip: process.platform === "win32" },
  async () => {
    const { run } = await fixtureRun();
    const { decodePosixBytes } = await importSource(
      "src/helpers/posix-path.ts",
    );
    const name =
      process.platform === "darwin" ? Buffer.from("雪") : Buffer.from([0xff]);
    const selected = Buffer.concat([Buffer.from(run.targetPath + "/"), name]);
    await mkdir(selected, { recursive: true });
    await writeFile(Buffer.concat([selected, Buffer.from("/entry")]), "");
    await checkSelectedTargets(
      { ...run, includePaths: [decodePosixBytes(name)] },
      signal,
    );
  },
);

test(
  "Windows directory selection distinguishes lone surrogates from replacement characters",
  { skip: process.platform !== "win32" },
  async () => {
    const { run } = await fixtureRun();
    const { windowsFiles } = await importSource(
      "src/helpers/resolve-security-md.ts",
      options,
    );
    const files = windowsFiles();
    const selected = "selected-\ud800";
    const replacement = join(run.targetPath, "selected-\ufffd");
    await mkdir(replacement, { recursive: true });
    await writeFile(join(replacement, "entry"), "");
    const wide = Buffer.from(join(run.targetPath, selected), "utf16le");
    const entry = Buffer.from(
      join(run.targetPath, selected, "entry"),
      "utf16le",
    );
    files.mkdir(wide);
    try {
      run.includePaths = [selected];
      await assert.rejects(
        checkSelectedTargets(run, signal),
        /target is empty/iu,
      );
      files.writeFile(entry, [Buffer.from("source")]);
      try {
        await checkSelectedTargets(run, signal);
      } finally {
        files.unlink(entry);
      }
    } finally {
      files.unlink(wide);
    }
  },
);

for (const checkpoint of ["discovery phase", "dispatched worker"]) {
  test(`resume after a persisted ${checkpoint} skips fresh admission`, async () => {
    const { fixture, store } = await coordinatorFixture({
      maxDiscoveryRuns: 2,
    });
    fixture.run.discoveryStarted = checkpoint === "discovery phase";
    fixture.run.dispatchedCount = checkpoint === "dispatched worker" ? 1 : 0;
    const executor = new FakeExecutor();
    const result = await runCoordinator(fixture, store, executor, {
      checkTarget: checkSelectedTargets,
    });
    assert.equal(result?.status, "succeeded", result?.error);
    assert.equal(executor.discoveryCalls, 1);
  });
}

test("resume merges accepted discovery even when the target is gone", async () => {
  const { fixture, store } = await coordinatorFixture();
  const dir = join(
    fixture.run.scanDir,
    "artifacts/deep_discovery/workers/discovery-0001",
  );
  const artifactDir = join(dir, "output");
  const resultManifestPath = join(artifactDir, "result.json");
  await mkdir(artifactDir, { recursive: true });
  await writeJson(
    resultManifestPath,
    standardScanDraft(fixture.run.scanId, undefined, "discovery-0001"),
  );
  const worker: TestWorker = {
    id: "accepted-discovery",
    kind: "discovery",
    status: "succeeded",
    mergeState: "buffered",
    promptPath: join(dir, "prompt.md"),
    artifactDir,
    resultManifestPath,
    attempt: 1,
    completionSequence: 1,
  };
  store.workers.set(worker.id, worker);
  fixture.run.persistedWorkers = [worker];
  const executor = new FakeExecutor();
  const result = await runCoordinator(fixture, store, executor, {
    checkTarget: checkSelectedTargets,
  });
  assert.equal(result?.status, "succeeded", result?.error);
  assert.deepEqual(store.iterations[0]?.workerIds, [worker.id]);
  assert.equal(executor.discoveryCalls, 0);
});

for (const stop of ["cancellation", "deadline"]) {
  test(`${stop} interrupts admission before any worker starts`, async (t) => {
    const { fixture, store } = await coordinatorFixture();
    const executor = new FakeExecutor();
    const entered = Promise.withResolvers<AbortSignal>();
    const release = Promise.withResolvers<void>();
    const deadline = stop === "deadline";
    if (deadline) t.mock.timers.enable({ apis: ["setTimeout"] });
    const coordinator = createCoordinator(fixture, store, executor, {
      discoveryTimeoutMs: 500,
      checkTarget: async (_run, signal) => {
        entered.resolve(signal);
        await release.promise;
      },
    });
    coordinator.start();
    try {
      const checking = await entered.promise;
      if (deadline) {
        t.mock.timers.tick(500);
        t.mock.timers.reset();
      } else coordinator.cancel("cancel admission");
      const result = await coordinator.wait(undefined, 5_000);
      assert.equal(checking.aborted, true);
      assert.equal(
        result?.status,
        deadline ? "succeeded" : "canceled",
        result?.error,
      );
      if (deadline) assert.equal(result?.terminalReason, "capped");
      assert.equal(executor.discoveryCalls, 0);
    } finally {
      release.resolve();
    }
  });
}
