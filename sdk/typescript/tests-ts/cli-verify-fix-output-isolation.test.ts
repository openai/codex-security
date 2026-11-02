import { afterEach, expect, test } from "bun:test";
import { copyFile, mkdir, symlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createApiTestFixtures } from "./support/temporary-directories.js";

interface HarnessResult {
  scenario: string;
  exit: number;
  blocked: boolean;
  stdout: string;
  stderr: string;
  events: Array<Record<string, unknown>>;
  drained?: number;
  workerPid?: number | null;
  workerAlive?: boolean;
  firstSignal?: string;
  secondSignal?: string;
}

const sdkRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = join(
  sdkRoot,
  "tests-ts",
  "fixtures",
  "verify-fix-stderr-isolation.ts",
);
const harness = join(
  sdkRoot,
  "tests-ts",
  "fixtures",
  "verify_fix_stderr_harness.py",
);
const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "verify-fix-output-isolation-",
);
afterEach(cleanup);

const result = (results: HarnessResult[], scenario: string) =>
  results.find((entry) => entry.scenario === scenario)!;

const completeEvent = (entry: HarnessResult) =>
  entry.events.find((event) => event["event"] === "complete")!;

async function bounded<T>(
  promise: Promise<T>,
  timeoutMs: number,
  message: string,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(message)), timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

async function runHarness(
  command: string[],
  options: {
    timeoutMs?: number;
    terminationGraceMs?: number;
    onSpawn?: (pid: number) => void;
  } = {},
): Promise<readonly [string, string, number]> {
  const child = Bun.spawn(command, { stdout: "pipe", stderr: "pipe" });
  options.onSpawn?.(child.pid);
  const completed = Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ] as const);
  // A timed-out reader may settle after termination; always consume rejection.
  void completed.catch(() => undefined);
  const timeout = options.timeoutMs ?? 22_000;
  try {
    return await bounded(
      completed,
      timeout,
      `Harness timed out after ${timeout}ms.`,
    );
  } finally {
    const grace = options.terminationGraceMs ?? 3_000;
    if (child.exitCode === null && child.signalCode === null)
      child.kill("SIGTERM");
    try {
      await bounded(child.exited, grace, "Harness did not exit after SIGTERM.");
    } catch {
      if (child.exitCode === null && child.signalCode === null)
        child.kill("SIGKILL");
      await bounded(child.exited, grace, "Harness did not exit after SIGKILL.");
    }
  }
}

test.skipIf(process.platform === "win32")(
  "bounds and reaps a hung output-isolation harness",
  async () => {
    const python = Bun.which("python3");
    expect(python).not.toBeNull();
    let pid = 0;
    const started = Date.now();
    await expect(
      runHarness(
        [
          python!,
          "-c",
          "import signal,time; signal.signal(signal.SIGTERM, lambda *_: None); time.sleep(60)",
        ],
        {
          timeoutMs: 100,
          terminationGraceMs: 100,
          onSpawn: (childPid) => {
            pid = childPid;
          },
        },
      ),
    ).rejects.toThrow("Harness timed out after 100ms.");
    expect(Date.now() - started).toBeLessThan(2_000);
    expect(pid).toBeGreaterThan(0);
    expect(() => process.kill(pid, 0)).toThrow();
  },
);

test.skipIf(process.platform === "win32")(
  "isolates multi-batch verification from disconnected and backpressured stderr",
  async () => {
    const runtime = await temporaryDirectory();
    const source = join(runtime, "src");
    await mkdir(source);
    await copyFile(
      join(sdkRoot, "package.json"),
      join(runtime, "package.json"),
    );
    await symlink(join(sdkRoot, "node_modules"), join(runtime, "node_modules"));
    await symlink(
      join(sdkRoot, "_bundled_plugin"),
      join(runtime, "_bundled_plugin"),
    );
    const build = await Bun.build({
      entrypoints: [fixture],
      outdir: source,
      target: "node",
      format: "esm",
      packages: "external",
    });
    expect(build.logs).toEqual([]);
    expect(build.success).toBe(true);
    const bundledFixture = build.outputs[0]!.path;
    const node = Bun.which("node");
    const python = Bun.which("python3");
    expect(node).not.toBeNull();
    expect(python).not.toBeNull();
    const [stdout, stderr, exitCode] = await runHarness([
      python!,
      harness,
      node!,
      bundledFixture,
      sdkRoot,
      runtime,
    ]);
    expect(exitCode, stderr).toBe(0);
    const results = JSON.parse(stdout) as HarnessResult[];
    expect(results).toHaveLength(17);
    expect(results.every((entry) => entry.blocked === false)).toBe(true);
    for (const entry of results.filter(
      ({ scenario }) => !scenario.startsWith("single-saved-progress"),
    )) {
      expect(completeEvent(entry)).toMatchObject({
        sigintListeners: 0,
        sigtermListeners: 0,
        stderrErrorListeners: 1,
      });
    }

    for (const scenario of [
      "pipe-quiet-success",
      "pipe-progress-success",
      "pty-disconnected",
      "pty-backpressure-success",
    ]) {
      const entry = result(results, scenario);
      expect(entry.exit).toBe(0);
      expect(
        JSON.parse(entry.stdout).results.map(({ id }: { id: string }) => id),
      ).toEqual(["occ_0", "occ_1", "occ_2"]);
    }

    const failure = result(results, "pipe-worker-failure");
    expect(failure.exit).toBe(2);
    expect(JSON.parse(failure.stdout)).toEqual({
      status: "failed",
      code: "VERIFICATION_FAILED",
      message: "Second worker original diagnostic.",
    });

    const unrelated = result(results, "pipe-unrelated-stderr-error");
    expect(unrelated.exit).toBe(2);
    expect(JSON.parse(unrelated.stdout)).toMatchObject({
      status: "failed",
      code: "VERIFICATION_FAILED",
      message: "Synthetic unrelated error.",
    });
    expect(unrelated.stderr).toContain("Synthetic unrelated error.");

    for (const [scenario, expectedExit] of [
      ["pty-backpressure-sigint", 130],
      ["pty-backpressure-sigterm", 143],
    ] as const) {
      const entry = result(results, scenario);
      expect(entry.exit).toBe(expectedExit);
      expect(entry.stdout).toBe("");
      expect(entry.drained).toBe(0);
      expect(typeof entry.workerPid).toBe("number");
      expect(entry.workerAlive).toBe(false);
    }

    const pausedFailure = result(results, "pty-backpressure-worker-failure");
    expect(pausedFailure.exit).toBe(2);
    expect(pausedFailure.workerAlive).toBe(false);
    expect(JSON.parse(pausedFailure.stdout)).toEqual({
      status: "failed",
      code: "VERIFICATION_FAILED",
      message: "Second worker original diagnostic.",
    });

    for (const [scenario, expectedExit] of [
      ["pty-backpressure-mixed-sigint-sigterm", 143],
      ["pty-backpressure-mixed-sigterm-sigint", 130],
    ] as const) {
      const entry = result(results, scenario);
      expect(entry.exit).toBe(expectedExit);
      expect(entry.stdout).toBe("");
      expect(typeof entry.workerPid).toBe("number");
      expect(entry.workerAlive).toBe(false);
    }

    const cleanupSignal = result(results, "pty-cleanup-sigwinch");
    expect(cleanupSignal.exit).toBe(0);
    expect(
      cleanupSignal.events
        .filter((event) => event["event"] === "invocation-complete")
        .map((event) => ({
          invocation: event["invocation"],
          exitCode: event["exitCode"],
          stderrErrorListeners: event["stderrErrorListeners"],
        })),
    ).toEqual([
      { invocation: 1, exitCode: 0, stderrErrorListeners: 1 },
      { invocation: 2, exitCode: 0, stderrErrorListeners: 1 },
      { invocation: 3, exitCode: 0, stderrErrorListeners: 1 },
    ]);
    expect(
      cleanupSignal.events.find(
        (event) => event["event"] === "single-request-progress",
      ),
    ).toMatchObject({ hasOnEvent: true });
    expect(
      cleanupSignal.events.some(
        (event) => event["event"] === "post-cleanup-sigwinch",
      ),
    ).toBe(true);
    expect(
      JSON.parse(cleanupSignal.stdout).results.map(
        ({ id }: { id: string }) => id,
      ),
    ).toEqual(["occ_0", "occ_1", "occ_2"]);

    for (const scenario of ["missing-id", "wrong-id"]) {
      const entry = result(results, scenario);
      expect(entry.exit).toBe(2);
      expect(JSON.parse(entry.stdout)).toMatchObject({
        status: "failed",
        code: "VERIFICATION_FAILED",
      });
      expect(JSON.parse(entry.stdout).results).toBeUndefined();
    }

    const interactive = result(results, "single-saved-progress-interactive");
    const noninteractive = result(results, "single-saved-progress-ci");
    for (const entry of [interactive, noninteractive]) {
      expect(entry.exit).toBe(0);
      expect(JSON.parse(entry.stdout).results).toHaveLength(3);
      expect(completeEvent(entry)).toMatchObject({
        sigintListeners: 0,
        sigtermListeners: 0,
        stderrErrorListeners: 0,
      });
      expect(
        entry.events.find(
          (event) => event["event"] === "single-request-progress",
        ),
      ).toMatchObject({ hasOnEvent: true });
    }
    expect(interactive.stderr).toContain("\u001B[?1049h");
    expect(noninteractive.stderr).not.toContain("\u001B[?1049h");
    expect(noninteractive.stderr).toContain("rg authorization src/guard.ts");

    const repeated = result(results, "repeated-main");
    expect(repeated.exit).toBe(0);
    expect(
      repeated.events.find((event) => event["event"] === "invocation-complete"),
    ).toMatchObject({
      invocation: 1,
      exitCode: 0,
      stderrErrorListeners: 1,
    });
    expect(completeEvent(repeated)).toMatchObject({
      exitCode: 0,
      stderrErrorListeners: 1,
    });
    expect(repeated.stdout.match(/"scanId": "scan"/gu)).toHaveLength(2);
  },
  60_000,
);
