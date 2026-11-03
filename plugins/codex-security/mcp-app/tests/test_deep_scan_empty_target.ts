import assert from "node:assert/strict";
import { execFile as nodeExecFile } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { after, mock, test } from "node:test";
import {
  promises as filesystem,
  chmodSync,
  existsSync,
  mkdirSync,
  rmdirSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
  type Dir,
} from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { promisify } from "node:util";
import type { CoordinatorOptions } from "../src/deep-scan/coordinator.js";
import {
  DeepScanCoordinatorRegistry,
  FakeExecutor,
  FakeStore,
  coordinatorFixture,
  createCoordinator,
  fixtureRun,
  immediateClock,
  runCoordinator,
  standardScanDraft,
  temporaryDirectories,
  type TestWorker,
} from "./deep_scan_coordinator_fixture.ts";
import { importSource } from "./import-module.ts";
import { writeJson } from "./support/json.ts";

const execFile = promisify(nodeExecFile);
const { decodePosixBytes } = await importSource("src/helpers/posix-path.ts");
const helperOptions = {
  define: {
    "import.meta.url": JSON.stringify(
      new URL(
        "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
        import.meta.url,
      ).href,
    ),
  },
};
const { windowsFiles } = await importSource(
  "src/helpers/resolve-security-md.ts",
  helperOptions,
);
const { checkSelectedTargets } = await importSource(
  "src/deep-scan/target-admission.ts",
  helperOptions,
);
const { startDeepScanEngine } = await importSource("src/deep-scan/engine.ts", {
  ...helperOptions,
  loader: { ".md": "text" },
});
after(() => temporaryDirectories.cleanup());

for (const cancel of [false, true]) {
  test(`admission consumes one entry and closes its handle, cancel=${cancel}`, async () => {
    const fixture = await fixtureRun();
    await mkdir(fixture.run.targetPath, { recursive: true });
    const controller = new AbortController();
    let reads = 0,
      closes = 0;
    const handle = {
      async read() {
        reads++;
        if (cancel) controller.abort("Canceled directory read");
        return { name: "source.py" };
      },
      async close() {
        closes++;
      },
    };
    const opener = mock.method(
      filesystem,
      "opendir",
      async (_path: unknown, options: unknown) => {
        assert.deepEqual(options, { encoding: "buffer", bufferSize: 1 });
        return handle as unknown as Dir;
      },
    );
    syncBuiltinESMExports();
    try {
      if (cancel)
        await assert.rejects(
          checkSelectedTargets(fixture.run, controller.signal),
          (error) => error === "Canceled directory read",
        );
      else await checkSelectedTargets(fixture.run, controller.signal);
      assert.equal(reads, 1);
      assert.equal(closes, 1);
    } finally {
      opener.mock.restore();
      syncBuiltinESMExports();
    }
  });
}

test("cancellation interrupts validation between registered files", async () => {
  const { run } = await fixtureRun();
  await mkdir(run.targetPath);
  run.includePaths = ["first.py", "second.py"];
  run.filePaths = run.includePaths;
  await writeFile(path.join(run.targetPath, "first.py"), "");
  await mkdir(path.join(run.targetPath, "second.py"));
  const controller = new AbortController();
  const checking = checkSelectedTargets(run, controller.signal);
  setImmediate(() => controller.abort(new Error("canceled")));
  await assert.rejects(checking, /canceled/u);
});

test("a registered file replaced by a directory while yielding fails admission", async () => {
  const { run } = await fixtureRun();
  await mkdir(path.join(run.targetPath, "empty"), { recursive: true });
  const file = path.join(run.targetPath, "source.py");
  await writeFile(file, "pass");
  run.includePaths = ["source.py", "empty"];
  run.filePaths = ["source.py"];
  const checking = checkSelectedTargets(run, new AbortController().signal);
  setImmediate(() => {
    unlinkSync(file);
    mkdirSync(file);
  });
  await assert.rejects(checking, /Selected file is no longer a regular file/u);
});

for (const fileSibling of [false, true]) {
  test(`a selected directory replaced by an external link is rejected, file sibling=${fileSibling}`, async () => {
    const { run } = await fixtureRun();
    run.includePaths = ["left", "right"];
    run.filePaths = fileSibling ? ["right"] : [];
    const left = path.join(run.targetPath, "left");
    const right = path.join(run.targetPath, "right");
    const outside = path.join(path.dirname(run.targetPath), "outside");
    await mkdir(left, { recursive: true });
    await mkdir(right);
    await mkdir(outside);
    await writeFile(path.join(outside, "source.py"), "pass");
    const checking = checkSelectedTargets(run, new AbortController().signal);
    setImmediate(() => {
      rmdirSync(left);
      symlinkSync(
        outside,
        left,
        process.platform === "win32" ? "junction" : "dir",
      );
      if (fileSibling) {
        rmdirSync(right);
        writeFileSync(right, "pass");
      }
    });
    await assert.rejects(checking, /symbolic links|inside repo/u);
  });
}

test("an absent selection fails validation despite a usable sibling", async () => {
  const { run } = await fixtureRun();
  await mkdir(run.targetPath);
  await writeFile(path.join(run.targetPath, "live.py"), "pass");
  run.includePaths = ["live.py", "gone"];
  await assert.rejects(
    checkSelectedTargets(run, new AbortController().signal),
    /ENOENT|not found|Windows filesystem error/iu,
  );
});

for (const unavailable of ["missing", "fifo", "inaccessible"]) {
  test(
    `a validated directory becoming ${unavailable} leaves a viable sibling`,
    {
      skip:
        (unavailable !== "missing" && process.platform === "win32") ||
        (unavailable === "inaccessible" && process.getuid?.() === 0),
    },
    async () => {
      const { run } = await fixtureRun();
      run.includePaths = ["empty", "parent/gone", "live"];
      for (const name of run.includePaths)
        await mkdir(path.join(run.targetPath, name), { recursive: true });
      await writeFile(path.join(run.targetPath, "live/source.py"), "pass");
      const parent = path.join(run.targetPath, "parent");
      const gone = path.join(parent, "gone");
      const open = filesystem.opendir;
      const opener = mock.method(
        filesystem,
        "opendir",
        async (...args: Parameters<typeof open>) => {
          if (path.basename(String(args[0])) === "empty") {
            if (unavailable === "inaccessible") chmodSync(parent, 0);
            else {
              rmdirSync(gone);
              if (unavailable === "fifo") await execFile("mkfifo", [gone]);
            }
          }
          return open(...args);
        },
      );
      syncBuiltinESMExports();
      try {
        await checkSelectedTargets(run, new AbortController().signal);
        assert.equal(opener.mock.calls.length, 2);
      } finally {
        if (unavailable === "inaccessible") chmodSync(parent, 0o700);
        opener.mock.restore();
        syncBuiltinESMExports();
      }
    },
  );
}

test("a repository replaced with a regular file while yielding fails admission", async () => {
  const { run } = await fixtureRun();
  await mkdir(run.targetPath);
  const checking = checkSelectedTargets(run, new AbortController().signal);
  setImmediate(() => {
    const alternateCase = path.join(
      path.dirname(run.targetPath),
      path.basename(run.targetPath).toUpperCase(),
    );
    const replacement =
      process.platform === "win32" && existsSync(alternateCase)
        ? alternateCase
        : run.targetPath;
    rmdirSync(run.targetPath);
    writeFileSync(replacement, "replaced");
  });
  await assert.rejects(checking, /not a directory|no longer a directory/iu);
});

for (const nonempty of [false, true]) {
  test(
    `Windows directory selection preserves lone surrogates, nonempty=${nonempty}`,
    { skip: process.platform !== "win32" },
    async () => {
      const fixture = await fixtureRun();
      await mkdir(fixture.run.targetPath, { recursive: true });
      const name = "selected-\ud800",
        selected = path.join(fixture.run.targetPath, name),
        replacement = path.join(fixture.run.targetPath, "selected-\ufffd");
      const files = windowsFiles(),
        wide = Buffer.from(selected, "utf16le"),
        source = Buffer.from(path.join(selected, "source.py"), "utf16le");
      files.mkdir(wide);
      await mkdir(replacement);
      if (nonempty) files.writeFile(source, [Buffer.from("pass\n")]);
      else await writeFile(path.join(replacement, "source.py"), "pass\n");
      fixture.run.includePaths = [name];
      try {
        const { coordinator, executor } = await startFixture(fixture);
        if (nonempty) await assertDiscoveryThenCancel(coordinator, executor);
        else {
          const terminal = await coordinator.wait(undefined, 5_000);
          assert.equal(terminal?.status, "failed");
          assert.match(terminal?.error ?? "", /target is empty/iu);
          assert.equal(executor.discoveryCalls, 0);
        }
      } finally {
        if (nonempty) files.unlink(source);
        files.unlink(wide);
      }
    },
  );
}

for (const checkpoint of ["persisted phase", "dispatched worker"]) {
  test(`resumed ${checkpoint} preserves admission before any accepted result`, async () => {
    const fixture = await fixtureRun({ maxDiscoveryRuns: 2 });
    fixture.run.discoveryStarted = checkpoint === "persisted phase";
    fixture.run.dispatchedCount = checkpoint === "dispatched worker" ? 1 : 0;
    const store = new FakeStore(fixture.run),
      executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
    let checks = 0;
    const coordinator = createCoordinator(fixture, store, executor, {
      checkTarget: async () => {
        checks++;
        throw new Error("Admission must not repeat");
      },
    });
    coordinator.start();
    await assertDiscoveryThenCancel(coordinator, executor);
    assert.equal(checks, 0);
  });
}

test(
  "POSIX encoded directories retain their filesystem bytes",
  { skip: process.platform === "win32" },
  async () => {
    const fixture = await fixtureRun();
    const name =
      process.platform === "darwin"
        ? Buffer.from("selected-雪")
        : Buffer.from([115, 101, 108, 101, 99, 116, 101, 100, 45, 255]);
    const selected = Buffer.concat([
      Buffer.from(fixture.run.targetPath + path.sep),
      name,
    ]);
    await mkdir(selected, { recursive: true });
    await writeFile(
      Buffer.concat([selected, Buffer.from("/source.py")]),
      "pass\n",
    );
    fixture.run.includePaths = [decodePosixBytes(name)];
    const { coordinator, executor } = await startFixture(fixture);
    await assertDiscoveryThenCancel(coordinator, executor);
  },
);

test("an empty child of a nonempty Git repository dispatches no workers", async () => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  const parent = path.dirname(fixture.run.targetPath);
  await writeFile(path.join(parent, "outside.ts"), "export {};\n");
  await execFile("git", ["init", "-q"], { cwd: parent });
  const { coordinator, executor } = await startFixture(fixture);
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "failed");
  assert.match(terminal?.error ?? "", /target is empty.*no security audit/iu);
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(executor.dedupCalls, 0);
});

for (const selection of [
  "file",
  "replaced file",
  "directory",
  "joining empty directory",
]) {
  test(`the engine preserves a registered ${selection} selection`, async () => {
    const fixture = await fixtureRun();
    fixture.run.includePaths = ["selected"];
    fixture.run.filePaths = ["file", "replaced file"].includes(selection)
      ? ["selected"]
      : [];
    await mkdir(fixture.run.targetPath, { recursive: true });
    const selected = path.join(fixture.run.targetPath, "selected");
    if (selection === "file") await writeFile(selected, "");
    else {
      await mkdir(selected);
      if (selection !== "joining empty directory")
        await writeFile(path.join(selected, "source.ts"), "export {};\n");
    }
    const { coordinator, executor, claim } = await startFixture(
      fixture,
      selection === "joining empty directory",
    );
    if (
      selection === "replaced file" ||
      selection === "joining empty directory"
    ) {
      const terminal = await coordinator.wait(undefined, 5_000);
      assert.equal(terminal?.status, "failed");
      assert.match(
        terminal?.error ?? "",
        selection === "replaced file"
          ? /selected file.*regular file/iu
          : /target is empty/iu,
      );
      assert.equal(claim.mock.callCount(), 1);
      assert.equal(executor.discoveryCalls, 0);
    } else await assertDiscoveryThenCancel(coordinator, executor);
  });
}

test("physical nonemptiness preserves the existing ignore interpretation", async () => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  await writeFile(path.join(fixture.run.targetPath, ".gitignore"), "*.py\n");
  await writeFile(path.join(fixture.run.targetPath, "ignored.py"), "pass\n");
  const { coordinator, executor } = await startFixture(fixture);
  await assertDiscoveryThenCancel(coordinator, executor);
});

for (const selected of [undefined, "left", "right"]) {
  test(`multiple selections retain a nonempty ${selected ?? "neither"} side`, async () => {
    const fixture = await fixtureRun();
    fixture.run.includePaths = ["left", "right"];
    await mkdir(path.join(fixture.run.targetPath, "left"), { recursive: true });
    await mkdir(path.join(fixture.run.targetPath, "right"));
    await writeFile(
      path.join(fixture.run.targetPath, "outside.ts"),
      "export {};\n",
    );
    if (selected)
      await writeFile(
        path.join(fixture.run.targetPath, selected, "source.ts"),
        "export {};\n",
      );
    const checking = checkSelectedTargets(
      fixture.run,
      new AbortController().signal,
    );
    if (selected) await checking;
    else await assert.rejects(checking, /target is empty/iu);
  });
}

test("an escaping authoritative selection is rejected before dispatch", async () => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  fixture.run.includePaths = ["../outside"];
  const { coordinator, executor } = await startFixture(fixture);
  const terminal = await coordinator.wait(undefined, 5_000);
  assert.equal(terminal?.status, "failed");
  assert.match(terminal?.error ?? "", /scope.*inside|outside/iu);
  assert.equal(executor.discoveryCalls, 0);
});

test("a discovery preparation error retains its diagnostic", async () => {
  const { fixture, store } = await coordinatorFixture();
  const executor = new FakeExecutor();
  const terminal = await runCoordinator(fixture, store, executor, {
    checkTarget: async () => {
      throw new Error("Synthetic directory read failure");
    },
  });
  assert.equal(terminal?.status, "failed");
  assert.equal(terminal?.error, "Synthetic directory read failure");
  assert.equal(executor.discoveryCalls, 0);
});

test("cancellation before preparation launches no check", async () => {
  const { fixture, store } = await coordinatorFixture();
  const executor = new FakeExecutor();
  let calls = 0;
  const coordinator = createCoordinator(fixture, store, executor, {
    checkTarget: async () => {
      calls++;
    },
  });
  coordinator.cancel("cancel before preparation");
  coordinator.start();
  assert.equal((await coordinator.wait(undefined, 5_000))?.status, "canceled");
  assert.equal(calls, 0);
  assert.equal(executor.discoveryCalls, 0);
});

test("cancellation reaches pending preparation", async () => {
  const { fixture, store } = await coordinatorFixture();
  const executor = new FakeExecutor();
  const entered = Promise.withResolvers<void>();
  let received: AbortSignal | undefined;
  const coordinator = createCoordinator(fixture, store, executor, {
    checkTarget: async (_run, signal) => {
      received = signal;
      entered.resolve();
      await new Promise<void>((resolve) =>
        signal.addEventListener("abort", () => resolve(), { once: true }),
      );
      signal.throwIfAborted();
    },
  });
  coordinator.start();
  await entered.promise;
  coordinator.cancel("cancel preparation");
  assert.equal((await coordinator.wait(undefined, 5_000))?.status, "canceled");
  assert.equal(received?.aborted, true);
  assert.equal(executor.discoveryCalls, 0);
});

test("an already expired run preserves its capped result", async () => {
  const fixture = await fixtureRun({ maxTimeHours: 1 });
  fixture.run.createdAt = new Date(
    immediateClock.now() - 7_200_000,
  ).toISOString();
  const store = new FakeStore(fixture.run),
    executor = new FakeExecutor();
  let calls = 0,
    published = false;
  const terminal = await runCoordinator(fixture, store, executor, {
    checkTarget: async () => {
      calls++;
    },
    onComplete: async (draft) => {
      assert.match(JSON.stringify(draft.reviewState), /time limit elapsed/iu);
      published = true;
    },
  });
  assert.equal(terminal?.status, "succeeded");
  assert.equal(terminal?.terminalReason, "capped");
  assert.equal(calls, 0);
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(executor.dedupCalls, 0);
  assert.equal(published, true);
});
for (const empty of [false, true]) {
  test(`a deadline stops outstanding preparation and preserves its capped result, empty=${empty}`, async () => {
    const { fixture, store } = await coordinatorFixture();
    const executor = new FakeExecutor();
    const release = Promise.withResolvers<void>(),
      finished = Promise.withResolvers<void>();
    let calls = 0,
      received: AbortSignal | undefined;
    const coordinator = createCoordinator(fixture, store, executor, {
      discoveryTimeoutMs: 500,
      checkTarget: async (_run, signal) => {
        calls++;
        received = signal;
        try {
          await release.promise;
          if (empty) throw new Error("empty");
        } finally {
          finished.resolve();
        }
      },
      onComplete: async (draft) => {
        assert.match(JSON.stringify(draft.reviewState), /time limit elapsed/iu);
      },
    });
    coordinator.start();
    try {
      const terminal = await coordinator.wait(undefined, 5_000);
      assert.equal(terminal?.status, "succeeded");
      assert.equal(terminal?.terminalReason, "capped");
      assert.equal(calls, 1);
      assert.equal(received?.aborted, true);
      assert.equal(executor.discoveryCalls, 0);
      assert.equal(executor.dedupCalls, 0);
    } finally {
      release.resolve();
      await finished.promise;
    }
  });
}

test("resume preserves accepted work without replacing the source inventory", async () => {
  const fixture = await fixtureRun();
  const workerDir = path.join(
    fixture.run.scanDir,
    "artifacts/deep_discovery/workers/discovery-0001",
  );
  const artifactDir = path.join(workerDir, "output");
  const resultPath = path.join(artifactDir, "result.json");
  await mkdir(artifactDir, { recursive: true });
  await writeJson(
    resultPath,
    standardScanDraft(fixture.run.scanId, undefined, "discovery-0001"),
  );
  const worker: TestWorker = {
    id: "accepted-discovery",
    kind: "discovery",
    status: "succeeded",
    mergeState: "buffered",
    promptPath: path.join(workerDir, "prompt.md"),
    artifactDir,
    attempt: 1,
    resultManifestPath: resultPath,
    completionSequence: 1,
  };
  fixture.run.persistedWorkers = [worker];
  fixture.run.dispatchedCount = 1;
  const store = new FakeStore(fixture.run);
  store.workers.set(worker.id, worker);
  store.completionSequence = 1;
  const executor = new FakeExecutor();
  let preflightCalls = 0;

  const terminal = await runCoordinator(fixture, store, executor, {
    checkTarget: async () => {
      preflightCalls += 1;
      throw new Error("Unexpected admission check");
    },
  });

  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(preflightCalls, 0);
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(executor.dedupCalls, 1);
  assert.equal(store.dedupClaims[0]?.workerIds.includes(worker.id), true);
});

async function startFixture(
  fixture: Awaited<ReturnType<typeof fixtureRun>>,
  joining = false,
) {
  const store = new FakeStore(fixture.run),
    executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
  const claim = mock.method(store, "claimCoordinator");
  const registry = new DeepScanCoordinatorRegistry(),
    start = registry.start.bind(registry);
  registry.start = (options: CoordinatorOptions) =>
    start({ ...options, executor });
  const started = await startDeepScanEngine({
    run: joining ? await store.get() : store.run,
    store,
    registry,
    runWorkbench: async (args: string[]) => {
      assert.equal(args[0], "preserve-scan-results");
      return {};
    },
    pluginRoot: fixture.pluginRoot,
    pythonCommand: "fixture-python",
    parentSandbox: { filesystemDenies: [] },
    threadId: "fixture-owner",
  });
  return { ...started, executor, claim };
}

async function assertDiscoveryThenCancel(
  coordinator: {
    wait(signal: undefined, timeout: number): Promise<unknown>;
    cancel(reason: string): void;
  },
  executor: FakeExecutor,
) {
  try {
    const started = await Promise.race([
      executor.discoveryStarted.promise.then(() => true),
      coordinator.wait(undefined, 5_000).then(() => false),
    ]);
    assert.equal(started, true);
    assert.equal(executor.discoveryCalls, 1);
  } finally {
    coordinator.cancel("fixture complete");
    await coordinator.wait(undefined, 5_000);
  }
}
