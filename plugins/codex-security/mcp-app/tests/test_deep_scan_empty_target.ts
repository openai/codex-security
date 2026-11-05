import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmod, mkdir, rm, symlink, watch, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { after, test } from "node:test";
import type { DeepScanRunState } from "../src/deep-scan/types.js";
import {
  createCoordinator,
  eventually,
  FakeExecutor,
  FakeStore,
  fixtureRun,
  runCoordinator,
  temporaryDirectories,
} from "./deep_scan_coordinator_fixture.ts";
import { importSource } from "./import-module.ts";

const python = process.env.PYTHON?.trim() || "python3";
const pluginRoot = resolve(import.meta.dirname, "../..");
const { checkFreshTarget } = await importSource("src/deep-scan/engine.ts", {
  loader: { ".md": "text" },
});

function inspect(run: DeepScanRunState) {
  return checkFreshTarget(
    run,
    new AbortController().signal,
    python,
    pluginRoot,
  );
}

after(() => temporaryDirectories.cleanup());

test("only registered paths determine whether the target is empty", async () => {
  const { run } = await fixtureRun();
  run.includePaths = ["left", "right"];
  const left = join(run.targetPath, "left");
  const right = join(run.targetPath, "right");
  await mkdir(left, { recursive: true });
  await mkdir(right);
  await writeFile(join(run.targetPath, "outside.py"), "");
  const git = (...args: string[]) =>
    execFileSync("git", ["-C", run.targetPath, ...args], { stdio: "pipe" });
  git("init", "-q");
  git("add", "outside.py");
  git(
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.com",
    "-c",
    "commit.gpgsign=false",
    "commit",
    "-qm",
    "outside selection",
  );
  await assert.rejects(
    inspect({ ...run, targetPath: left, includePaths: undefined }),
    /target is empty.*no security audit/iu,
  );
  await assert.rejects(inspect(run), /target is empty.*no security audit/iu);

  // Any entry counts, even if normal source inventory would ignore it.
  await writeFile(join(right, ".gitignore"), "*");
  await inspect(run);
  run.includePaths.reverse();
  await inspect(run);

  await rm(left, { recursive: true });
  await writeFile(left, "");
  run.includePaths = ["left"];
  run.filePaths = ["left"];
  await inspect(run);
});

test("a usable selection cannot mask a replaced file or an unsafe sibling", async () => {
  const { run } = await fixtureRun();
  await mkdir(run.targetPath);
  await writeFile(join(run.targetPath, "first"), "");
  const external = join(dirname(run.targetPath), "external");
  await mkdir(external);
  await writeFile(join(external, "source.py"), "");
  await symlink(
    external,
    join(run.targetPath, "link"),
    process.platform === "win32" ? "junction" : "dir",
  );
  await mkdir(join(run.targetPath, "was-file"));
  for (const [sibling, error] of [
    ["missing", /no such file|not found|cannot find/iu],
    ["link", /symbolic link|outside|reparse|symlink/iu],
    ["../external", /inside|outside|relative|escapes/iu],
    ["was-file", /regular file/iu],
  ] as const) {
    run.includePaths = ["first", sibling];
    run.filePaths = sibling === "was-file" ? ["first", sibling] : ["first"];
    await assert.rejects(inspect(run), error);
  }
});

test(
  "an unreadable directory preserves its diagnostic unless a sibling can be scanned",
  { skip: process.platform === "win32" || process.getuid?.() === 0 },
  async () => {
    const { run } = await fixtureRun();
    const denied = join(run.targetPath, "denied");
    await mkdir(denied, { recursive: true });
    await writeFile(join(run.targetPath, "ok"), "");
    await chmod(denied, 0);
    try {
      run.includePaths = ["denied"];
      await assert.rejects(inspect(run), /permission denied|EACCES/iu);
      run.includePaths.push("ok");
      await inspect(run);
    } finally {
      await chmod(denied, 0o700);
    }
  },
);

test(
  "a POSIX directory and entry retain their original filesystem bytes",
  { skip: process.platform === "win32" },
  async () => {
    const { run } = await fixtureRun();
    const { decodePosixBytes } = await importSource(
      "src/helpers/posix-path.ts",
    );
    const name =
      process.platform === "darwin" ? Buffer.from("雪") : Buffer.from([0xff]);
    const directory = Buffer.concat([Buffer.from(run.targetPath + "/"), name]);
    await mkdir(directory, { recursive: true });
    await writeFile(Buffer.concat([directory, Buffer.from("/"), name]), "");
    run.includePaths = [decodePosixBytes(name)];
    await inspect(run);
  },
);

test(
  "Windows distinguishes a lone surrogate from its replacement character",
  { skip: process.platform !== "win32" },
  async () => {
    const { run } = await fixtureRun();
    await mkdir(run.targetPath);
    run.includePaths = ["selected-\ud800"];
    const selected = join(run.targetPath, run.includePaths[0]!);
    // Create the unpaired UTF-16 name through Python; Node string paths replace it.
    const changeDirectory = (operation: "mkdir" | "rmdir") =>
      execFileSync(python, [
        "-I",
        "-c",
        `import os, sys; os.${operation}(bytes.fromhex(sys.argv[1]).decode('utf-16-le','surrogatepass'))`,
        Buffer.from(selected, "utf16le").toString("hex"),
      ]);
    changeDirectory("mkdir");
    const replacement = join(run.targetPath, "selected-\ufffd");
    await mkdir(replacement);
    await writeFile(join(replacement, "source.py"), "");
    try {
      await assert.rejects(inspect(run), /target is empty/iu);
    } finally {
      changeDirectory("rmdir");
    }
  },
);

for (const stop of ["cancellation", "deadline"]) {
  test(
    `a blocked directory read cannot delay ${stop}`,
    { timeout: 15_000 },
    async (t) => {
      const fixture = await fixtureRun();
      const { run } = fixture;
      await mkdir(run.targetPath);
      const scripts = join(fixture.pluginRoot, "scripts");
      await mkdir(scripts, { recursive: true });
      const markerDir = join(dirname(run.targetPath), "ready");
      await mkdir(markerDir);
      const scriptName = "check_deep_scan_target.py";
      // Stop the real helper inside enumeration. The marker arms the interruption
      // only once the child owns the request, even on slow hosts.
      await writeFile(
        join(scripts, scriptName),
        `
import os, runpy, sys, time
from pathlib import Path
real_scan = os.scandir
def blocked(path):
    if os.fsdecode(path) == ${JSON.stringify(run.targetPath)}:
        Path(${JSON.stringify(markerDir)}, str(os.getpid())).touch()
        time.sleep(30)
    return real_scan(path)
os.scandir = blocked
sys.path.insert(0, ${JSON.stringify(join(pluginRoot, "scripts"))})
runpy.run_path(${JSON.stringify(join(pluginRoot, "scripts", scriptName))}, run_name="__main__")
`,
      );
      const executor = new FakeExecutor();
      const coordinator = createCoordinator(
        fixture,
        new FakeStore(run),
        executor,
        {
          discoveryTimeoutMs: 60_000,
          checkFreshTarget: (state, signal) =>
            checkFreshTarget(state, signal, python, fixture.pluginRoot),
        },
      );
      const watcher = watch(markerDir, { signal: t.signal });
      const ready = watcher.next();
      if (stop === "deadline") t.mock.timers.enable({ apis: ["setTimeout"] });
      coordinator.start();
      try {
        const marker = await Promise.race([
          ready,
          coordinator
            .settled()
            .then((result: DeepScanRunState) =>
              assert.fail(
                result.error ?? "coordinator settled before enumeration",
              ),
            ),
        ]);
        assert.ok(!marker.done && marker.value.filename);
        const pid = Number(marker.value.filename);
        assert.ok(Number.isSafeInteger(pid) && pid > 0);
        if (stop === "deadline") {
          t.mock.timers.tick(60_000);
          t.mock.timers.reset();
        } else coordinator.cancel("fixture cancellation");
        const result = await coordinator.wait(undefined, 5_000);
        assert.equal(
          result?.status,
          stop === "deadline" ? "succeeded" : "canceled",
          result?.error,
        );
        assert.equal(
          result.terminalReason,
          stop === "deadline" ? "capped" : undefined,
        );
        assert.equal(executor.discoveryCalls, 0);
        await eventually(() => {
          try {
            process.kill(pid, 0);
            return false;
          } catch (error) {
            return (error as NodeJS.ErrnoException).code === "ESRCH";
          }
        });
      } finally {
        t.mock.timers.reset();
        coordinator.cancel("fixture cleanup");
        await watcher.return?.();
      }
    },
  );
}

test("legacy setup workers still require admission before the first discovery", async () => {
  const fixture = await fixtureRun();
  const { run } = fixture;
  await mkdir(run.targetPath);
  run.persistedWorkers = [
    {
      id: "setup-1",
      kind: "setup",
      status: "succeeded",
      mergeState: "none",
      attempt: 0,
      promptPath: join(run.scanDir, "setup.md"),
      artifactDir: join(run.scanDir, "setup"),
    },
  ];
  const executor = new FakeExecutor();
  const result = await runCoordinator(fixture, new FakeStore(run), executor, {
    checkFreshTarget: inspect,
  });
  assert.equal(result?.status, "failed");
  assert.match(result.error, /target is empty/iu);
  assert.equal(executor.discoveryCalls, 0);
});

test("a zero-dispatch resume is re-admitted after its only file is removed", async () => {
  const fixture = await fixtureRun();
  const { run } = fixture;
  await mkdir(run.targetPath, { recursive: true });
  const only = join(run.targetPath, "source.py");
  await writeFile(only, "x = 1\n");
  // The run persisted its discovery phase but never dispatched a worker, and
  // its only source file was removed before the lease expired.
  run.discoveryStarted = true;
  await rm(only);
  let admissionCalls = 0;
  const executor = new FakeExecutor();
  const result = await runCoordinator(fixture, new FakeStore(run), executor, {
    checkFreshTarget: async (state) => {
      admissionCalls += 1;
      await inspect(state);
    },
  });
  assert.equal(admissionCalls, 1);
  assert.equal(result?.status, "failed");
  assert.match(result.error, /target is empty.*no security audit/iu);
  assert.equal(executor.discoveryCalls, 0);
});

test("prior dispatch history bypasses fresh admission", async () => {
  const fixture = await fixtureRun({ maxDiscoveryRuns: 2 });
  fixture.run.dispatchedCount = 1;
  const store = new FakeStore(fixture.run);
  const executor = new FakeExecutor();
  const result = await runCoordinator(fixture, store, executor, {
    checkFreshTarget: async () => {
      assert.fail("re-entered admission after prior dispatch");
    },
  });
  assert.equal(result?.status, "succeeded", result?.error);
  assert.equal(executor.discoveryCalls, 1);
});

test("a target holding only an empty subdirectory has no inventory to scan", async () => {
  const fixture = await fixtureRun();
  const { run } = fixture;
  await mkdir(join(run.targetPath, "sub"), { recursive: true });
  // The physical probe admits this target (the subdirectory is an entry),
  // but the registered scope inventory counted zero regular files.
  run.scopeFileCount = 0;
  const executor = new FakeExecutor();
  const result = await runCoordinator(fixture, new FakeStore(run), executor, {
    checkFreshTarget: inspect,
  });
  assert.equal(result?.status, "failed");
  assert.match(result.error, /target is empty.*no security audit/iu);
  assert.equal(executor.discoveryCalls, 0);
});

test("a target holding only a Git-ignored file has no inventory to scan", async () => {
  const fixture = await fixtureRun();
  const { run } = fixture;
  const child = join(run.targetPath, "child");
  await mkdir(child, { recursive: true });
  await writeFile(join(run.targetPath, ".gitignore"), "child/\n");
  await writeFile(join(child, "ignored.py"), "x = 1\n");
  const git = (...args: string[]) =>
    execFileSync("git", ["-C", run.targetPath, ...args], {
      encoding: "utf8",
      stdio: "pipe",
    });
  git("init", "-q");
  // The scan's own inventory excludes the ignored file from the scope.
  assert.equal(
    git(
      "ls-files",
      "--cached",
      "--others",
      "--exclude-standard",
      "--",
      "child",
    ).trim(),
    "",
  );
  run.scope = "child";
  run.includePaths = ["child"];
  run.scopeFileCount = 0;
  const executor = new FakeExecutor();
  const result = await runCoordinator(fixture, new FakeStore(run), executor, {
    checkFreshTarget: inspect,
  });
  assert.equal(result?.status, "failed");
  assert.match(result.error, /target is empty.*no security audit/iu);
  assert.equal(executor.discoveryCalls, 0);
});

test("an explicitly selected Git-ignored file is not gated by its directory inventory", async () => {
  const fixture = await fixtureRun();
  const { run } = fixture;
  const child = join(run.targetPath, "child");
  await mkdir(child, { recursive: true });
  await writeFile(join(run.targetPath, ".gitignore"), "child/\n");
  await writeFile(join(child, "ignored.py"), "x = 1\n");
  const git = (...args: string[]) =>
    execFileSync("git", ["-C", run.targetPath, ...args], { stdio: "pipe" });
  git("init", "-q");
  run.scope = "child";
  run.includePaths = ["child/ignored.py"];
  run.filePaths = ["child/ignored.py"];
  // Registration counts an explicitly selected file itself, so the
  // registered inventory for this selection is one, not zero.
  run.scopeFileCount = 1;
  const executor = new FakeExecutor();
  const result = await runCoordinator(fixture, new FakeStore(run), executor, {
    checkFreshTarget: inspect,
  });
  assert.equal(result?.status, "succeeded", result?.error);
  assert.equal(executor.discoveryCalls, 1);
});
