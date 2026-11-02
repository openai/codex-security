import assert from "node:assert/strict";
import { execFile as nodeExecFile } from "node:child_process";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { after, test } from "node:test";
import { promisify } from "node:util";
import type { CoordinatorOptions } from "../src/deep-scan/coordinator.js";
import {
  DeepScanCoordinatorRegistry,
  FakeExecutor,
  FakeStore,
  assertNoPublishedCandidates,
  fixtureRun,
  runCoordinator,
  temporaryDirectories,
} from "./deep_scan_coordinator_fixture.ts";
import { importSource } from "./import-module.ts";

const execFile = promisify(nodeExecFile);
const { startDeepScanEngine } = await importSource("src/deep-scan/engine.ts", {
  loader: { ".md": "text" },
  define: {
    "import.meta.url": JSON.stringify(
      new URL("../src/deep-scan/engine.ts", import.meta.url).href,
    ),
  },
});

after(() => temporaryDirectories.cleanup());

test("an empty directory beneath a Git repository starts no workers", async () => {
  const fixture = await fixtureRun();
  const repository = path.dirname(fixture.run.targetPath);
  await mkdir(fixture.run.targetPath, { recursive: true });
  await writeFile(path.join(repository, "parent-source.ts"), "export {};\n");
  await runGit(repository, "init", "-q");
  await runGit(repository, "add", "parent-source.ts");
  await runGit(repository, "commit", "-qm", "parent source");
  assert.match(
    await runGit(repository, "rev-parse", "--verify", "HEAD"),
    /^[0-9a-f]+$/u,
  );

  const { coordinator, executor, store } = await startFixture(fixture);
  const terminal = await coordinator.wait(undefined, 10_000);

  assert.equal(terminal?.status, "failed");
  assert.match(
    terminal?.error ?? "",
    /target is empty.*no security audit was performed/iu,
  );
  assert.equal(executor.discoveryCalls, 0);
  assert.equal(executor.dedupCalls, 0);
  assert.deepEqual(store.workerUpdates, []);
  assert.deepEqual(store.finishCalls, []);
  await assertNoPublishedCandidates(fixture.run.scanDir);
});

test("a nonempty directory retains ordinary discovery", async () => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  await writeFile(
    path.join(fixture.run.targetPath, "source.ts"),
    "export {};\n",
  );

  const { coordinator, executor } = await startFixture(
    fixture,
    new FakeExecutor({ blockDiscoveryAfterCalls: 0 }),
  );
  await executor.discoveryStarted.promise;
  assert.equal(executor.discoveryCalls, 1);

  coordinator.cancel("fixture complete");
  assert.equal((await coordinator.wait(undefined, 10_000))?.status, "canceled");
});

test("a physically nonempty target is not reinterpreted through ignore rules", async () => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  await writeFile(path.join(fixture.run.targetPath, ".gitignore"), "*.py\n");
  await writeFile(path.join(fixture.run.targetPath, "generated.py"), "pass\n");

  const { coordinator, executor } = await startFixture(
    fixture,
    new FakeExecutor({ blockDiscoveryAfterCalls: 0 }),
  );
  await executor.discoveryStarted.promise;
  assert.equal(executor.discoveryCalls, 1);
  coordinator.cancel("fixture complete");
  await coordinator.wait(undefined, 10_000);
});

test("multiple selected paths are empty only when every path is empty", async () => {
  const emptyFixture = await fixtureRun();
  emptyFixture.run.includePaths = ["left", "right"];
  await mkdir(path.join(emptyFixture.run.targetPath, "left"), {
    recursive: true,
  });
  await mkdir(path.join(emptyFixture.run.targetPath, "right"));

  const empty = await startFixture(emptyFixture);
  const emptyTerminal = await empty.coordinator.wait(undefined, 10_000);
  assert.equal(emptyTerminal?.status, "failed");
  assert.match(emptyTerminal?.error ?? "", /target is empty/iu);
  assert.equal(empty.executor.discoveryCalls, 0);

  const nonemptyFixture = await fixtureRun();
  nonemptyFixture.run.includePaths = ["left", "right"];
  await mkdir(path.join(nonemptyFixture.run.targetPath, "left"), {
    recursive: true,
  });
  await mkdir(path.join(nonemptyFixture.run.targetPath, "right"));
  await writeFile(
    path.join(nonemptyFixture.run.targetPath, "right", "ok.py"),
    "pass\n",
  );
  const nonempty = await startFixture(
    nonemptyFixture,
    new FakeExecutor({ blockDiscoveryAfterCalls: 0 }),
  );
  await nonempty.executor.discoveryStarted.promise;
  assert.equal(nonempty.executor.discoveryCalls, 1);
  nonempty.coordinator.cancel("fixture complete");
  await nonempty.coordinator.wait(undefined, 10_000);
});

for (const replacement of ["file", "directory"] as const) {
  test(`an exact-file selection remains eligible when it is a ${replacement}`, async () => {
    const fixture = await fixtureRun();
    fixture.run.includePaths = ["selected.py"];
    fixture.run.filePaths = ["selected.py"];
    await mkdir(fixture.run.targetPath, { recursive: true });
    const selected = path.join(fixture.run.targetPath, "selected.py");
    if (replacement === "file") await writeFile(selected, "");
    else await mkdir(selected);

    const { coordinator, executor } = await startFixture(
      fixture,
      new FakeExecutor({ blockDiscoveryAfterCalls: 0 }),
    );
    await executor.discoveryStarted.promise;
    assert.equal(executor.discoveryCalls, 1);
    coordinator.cancel("fixture complete");
    await coordinator.wait(undefined, 10_000);
  });
}

test(
  "an unreadable selected directory retains its filesystem diagnostic",
  { skip: process.platform === "win32" },
  async () => {
    const fixture = await fixtureRun();
    await mkdir(fixture.run.targetPath, { recursive: true });
    await chmod(fixture.run.targetPath, 0);
    try {
      const { coordinator, executor } = await startFixture(fixture);
      const terminal = await coordinator.wait(undefined, 10_000);
      assert.equal(terminal?.status, "failed");
      assert.match(terminal?.error ?? "", /EACCES|permission denied/iu);
      assert.doesNotMatch(terminal?.error ?? "", /target is empty/iu);
      assert.equal(executor.discoveryCalls, 0);
      assert.equal(executor.dedupCalls, 0);
    } finally {
      await chmod(fixture.run.targetPath, 0o700);
    }
  },
);

test(
  "an unreadable selected directory does not hide another usable selection",
  { skip: process.platform === "win32" },
  async () => {
    const fixture = await fixtureRun();
    fixture.run.includePaths = ["left", "right"];
    const left = path.join(fixture.run.targetPath, "left");
    await mkdir(left, { recursive: true });
    await mkdir(path.join(fixture.run.targetPath, "right"));
    await writeFile(
      path.join(fixture.run.targetPath, "right", "ok.py"),
      "pass\n",
    );
    await chmod(left, 0);
    try {
      const { coordinator, executor } = await startFixture(
        fixture,
        new FakeExecutor({ blockDiscoveryAfterCalls: 0 }),
      );
      await executor.discoveryStarted.promise;
      assert.equal(executor.discoveryCalls, 1);
      coordinator.cancel("fixture complete");
      await coordinator.wait(undefined, 10_000);
    } finally {
      await chmod(left, 0o700);
    }
  },
);

test("prior dispatch history bypasses the fresh-target check", async () => {
  const fixture = await fixtureRun({ maxDiscoveryRuns: 1 });
  fixture.run.dispatchedCount = 1;
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor();
  let checks = 0;

  const terminal = await runCoordinator(fixture, store, executor, {
    checkFreshTarget: async () => {
      checks += 1;
      throw new Error("fresh-target check should not run");
    },
  });

  assert.equal(checks, 0);
  assert.equal(terminal?.status, "failed");
  assert.match(
    terminal?.error ?? "",
    /ended without a successfully reduced Standard scan/iu,
  );
  assert.doesNotMatch(terminal?.error ?? "", /target is empty/iu);
});

test("a joined run with no dispatch history preserves the resume path", async () => {
  const fixture = await fixtureRun();
  await mkdir(fixture.run.targetPath, { recursive: true });
  const { coordinator, executor } = await startFixture(
    fixture,
    new FakeExecutor({ blockDiscoveryAfterCalls: 0 }),
    false,
  );

  await executor.discoveryStarted.promise;
  assert.equal(executor.discoveryCalls, 1);
  coordinator.cancel("fixture complete");
  await coordinator.wait(undefined, 10_000);
});

async function startFixture(
  fixture: Awaited<ReturnType<typeof fixtureRun>>,
  executor = new FakeExecutor(),
  freshStart = true,
) {
  const store = new FakeStore(fixture.run);
  store.freshStart = freshStart;
  const registry = new DeepScanCoordinatorRegistry();
  const start = registry.start.bind(registry);
  registry.start = (options: CoordinatorOptions) =>
    start({ ...options, executor });
  const started = await startDeepScanEngine({
    run: store.run,
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
  return { ...started, executor, store };
}

async function runGit(repository: string, ...arguments_: string[]) {
  const { stdout } = await execFile(
    "git",
    [
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.com",
      ...arguments_,
    ],
    { cwd: repository, encoding: "utf8" },
  );
  return stdout.trim();
}
