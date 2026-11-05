import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
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

  await writeFile(join(right, "source.py"), "");
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
    await chmod(denied, 0);
    try {
      run.includePaths = ["denied"];
      await assert.rejects(inspect(run), /permission denied|EACCES/iu);
      const nested = join(run.targetPath, "nested");
      await mkdir(nested);
      run.includePaths = ["."];
      await assert.rejects(inspect(run), /permission denied|EACCES/iu);
      await writeFile(join(nested, "source.py"), "");
      await inspect(run);
      run.includePaths = ["denied", "nested"];
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

for (const [stop, blockedOperation] of [
  ["cancellation", "directory read"],
  ["deadline", "directory read"],
  ["cancellation", "Git inventory"],
]) {
  test(
    `a blocked ${blockedOperation} cannot delay ${stop}`,
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
      await writeFile(join(run.targetPath, "source.py"), "");
      // Stop the real helper inside enumeration. The marker arms the interruption
      // only once the child owns the request, even on slow hosts.
      await writeFile(
        join(scripts, scriptName),
        `
import os, runpy, subprocess, sys, time
from pathlib import Path
marker_dir = ${JSON.stringify(markerDir)}
real_scan = os.scandir
def blocked(path):
    if ${JSON.stringify(blockedOperation)} == "directory read" and os.fsdecode(path) == ${JSON.stringify(run.targetPath)}:
        Path(marker_dir, str(os.getpid())).touch()
        time.sleep(30)
    return real_scan(path)
os.scandir = blocked
if ${JSON.stringify(blockedOperation)} == "Git inventory":
    real_run = subprocess.run
    def slow_git(command, **kwargs):
        assert "rev-parse" in command
        script = "import os, sys, time; from pathlib import Path; Path(sys.argv[1], str(os.getpid())).touch(); time.sleep(10)"
        return real_run([sys.executable, "-c", script, marker_dir], **kwargs)
    subprocess.run = slow_git
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
            // A container's init may defer reaping the killed Git grandchild.
            return (
              process.platform === "linux" &&
              /^State:\s+Z/m.test(readFileSync(`/proc/${pid}/status`, "utf8"))
            );
          } catch (error) {
            return ["ESRCH", "ENOENT"].includes(
              (error as NodeJS.ErrnoException).code ?? "",
            );
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

test("a target holding only a Git-ignored file has no inventory to scan", async () => {
  const fixture = await fixtureRun();
  const { run } = fixture;
  const child = join(run.targetPath, "child");
  await mkdir(child, { recursive: true });
  await writeFile(join(run.targetPath, ".gitignore"), "child/\n");
  await writeFile(join(child, "ignored.py"), "x = 1\n");
  execFileSync("git", ["-C", run.targetPath, "init", "-q"]);
  run.scope = "child";
  run.includePaths = ["child"];
  await assert.rejects(inspect(run), /target is empty.*no security audit/iu);

  // Registration treats an explicitly selected file as in scope even if Git ignores it.
  run.includePaths = ["child/ignored.py"];
  run.filePaths = ["child/ignored.py"];
  await inspect(run);
});
