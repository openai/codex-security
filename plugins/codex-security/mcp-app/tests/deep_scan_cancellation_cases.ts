import assert from "node:assert/strict";
import childProcess, {
  type ChildProcess,
  type SpawnOptions,
} from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import path from "node:path";
import { createInterface } from "node:readline";
import type { DeepScanWorkerKind } from "../src/deep-scan/types.js";
import { assertFlagPair } from "./assertions.ts";
import { readJson } from "./support/json.ts";
import type { CodexSdkWorkerExecutor as WorkerExecutor } from "../src/deep-scan/executor.js";
import type { DeepWorkerParentSandbox } from "../src/deep-scan/parent-sandbox.js";

import { restoreEnv } from "./support/fake-codex-source.ts";

export function mockWorkerSpawn(
  executablePath: string,
  onExec?: (
    child: ChildProcess,
    args: readonly string[],
    options: SpawnOptions,
  ) => void,
) {
  const previousPath = process.env.CODEX_CLI_PATH;
  process.env.CODEX_CLI_PATH = process.execPath;
  const originalSpawn = childProcess.spawn;
  childProcess.spawn = ((
    command: string,
    args: readonly string[] = [],
    options: SpawnOptions = {},
  ) => {
    const child = originalSpawn(
      command,
      command === process.execPath ||
        command === path.toNamespacedPath(process.execPath)
        ? [executablePath, ...args]
        : args,
      options,
    );
    if (args[0] === "exec") onExec?.(child, args, options);
    return child;
  }) as typeof childProcess.spawn;
  syncBuiltinESMExports();
  return () => {
    restoreEnv("CODEX_CLI_PATH", previousPath);
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
  };
}

interface WorkerFixtures {
  CodexSdkWorkerExecutor: typeof WorkerExecutor;
  fakeCodexFixture: () => Promise<{
    root: string;
    executablePath: string;
    preflightMarkerPath: string;
    markerPath: string;
  }>;
  trustedParentSandbox: DeepWorkerParentSandbox;
}

export async function testWorkerCancellation({
  CodexSdkWorkerExecutor,
  fakeCodexFixture,
  trustedParentSandbox,
}: WorkerFixtures) {
  const fixture = await fakeCodexFixture();
  let worker: ChildProcess | undefined;
  let workerSignal: AbortSignal | undefined;
  let cancelDuringCleanup: (() => void) | undefined;
  let timeout: NodeJS.Timeout | undefined;
  const restoreSpawn = mockWorkerSpawn(
    fixture.executablePath,
    (child, args, options) => {
      assertFlagPair(args, "--thread-source", "security_scan");
      worker = child;
      workerSignal = options.signal;
      const kill = child.kill;
      child.kill = function (...args: Parameters<ChildProcess["kill"]>) {
        cancelDuringCleanup?.();
        return kill.apply(this, args);
      };
    },
  );
  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    const executor = new CodexSdkWorkerExecutor({
      parentSandbox: trustedParentSandbox,
      artifactContext: {
        pluginRoot: fixture.root,
        repoRoot: fixture.root,
        scanId: randomUUID(),
        includePaths: ["api"],
      },
    });
    const run = (controller: AbortController, onThreadStarted?: () => void) =>
      executor.run({
        kind: "discovery",
        promptPath,
        workingDirectory,
        subagents: 0,
        signal: controller.signal,
        onThreadStarted,
        artifactContext: { root: workingDirectory, layout: "worker" },
      });
    const preAborted = new AbortController();
    const beforeStartup = new Error(
      "coordinator canceled before worker startup",
    );
    preAborted.abort(beforeStartup);
    await assert.rejects(
      run(preAborted),
      (error: Error) => error === beforeStartup,
    );
    assert.equal(worker, undefined);
    assert.equal(
      (await readdir(fixture.root)).some((name) => name.startsWith("scope-")),
      false,
    );
    await assert.rejects(readFile(fixture.preflightMarkerPath), {
      code: "ENOENT",
    });
    await assert.rejects(readFile(fixture.markerPath), { code: "ENOENT" });

    for (const prompt of [
      "BLOCK_AFTER_START",
      "COMPLETE_THEN_HANG",
      "FAIL_THEN_HANG",
    ]) {
      await writeFile(promptPath, `${prompt}\n`);
      const controller = new AbortController();
      const cancellation = new Error(
        "coordinator canceled its remaining workers",
      );
      // Exercise cancellation inside the real SDK's iterator cleanup, before kill returns.
      cancelDuringCleanup =
        prompt === "COMPLETE_THEN_HANG"
          ? () => controller.abort(cancellation)
          : undefined;
      const deadline = new Promise<never>((_, reject) => {
        timeout = setTimeout(
          () => reject(new Error(`${prompt} worker did not settle`)),
          10_000,
        );
      });
      const execution = Promise.race([
        run(controller, () => {
          if (prompt === "BLOCK_AFTER_START") controller.abort(cancellation);
        }),
        deadline,
      ]);
      if (prompt === "BLOCK_AFTER_START") {
        await assert.rejects(
          execution,
          (error: Error) =>
            error?.name === "AbortError" ||
            /abort|SIGTERM/i.test(error?.message ?? ""),
        );
        assert(workerSignal);
        assert.equal(workerSignal.aborted, true);
        assert.equal(workerSignal.reason, cancellation);
      } else {
        if (prompt === "FAIL_THEN_HANG") {
          await assert.rejects(execution, /fixture worker failed/);
          controller.abort(cancellation);
        } else {
          const result = await execution;
          assert.equal(result.threadId, "fixture-thread-id");
        }
        assert.equal(controller.signal.aborted, true);
        assert(workerSignal);
        assert.equal(workerSignal.aborted, false);
      }
      assert.equal(
        (await readdir(fixture.root)).some((name) => name.startsWith("scope-")),
        false,
      );
      assert.notEqual(workerSignal, controller.signal);
      const currentWorker = worker as ChildProcess | undefined;
      assert(currentWorker);
      assert.equal(currentWorker.killed, true);
      if (
        currentWorker.exitCode === null &&
        currentWorker.signalCode === null
      ) {
        await Promise.race([
          new Promise<void>((resolve) =>
            worker!.once("close", () => resolve()),
          ),
          deadline,
        ]);
      }
      clearTimeout(timeout);
      cancelDuringCleanup = undefined;
    }
  } finally {
    clearTimeout(timeout);
    cancelDuringCleanup = undefined;
    if (worker && worker.exitCode === null && worker.signalCode === null)
      worker.kill("SIGKILL");
    restoreSpawn();
  }
}

export async function testAbortPropagation(
  { CodexSdkWorkerExecutor, trustedParentSandbox }: WorkerFixtures,
  promptPath: string,
  workingDirectory: string,
) {
  await writeFile(promptPath, "BLOCK_AFTER_START\n");
  const abortController = new AbortController();
  const execution = new CodexSdkWorkerExecutor({
    parentSandbox: trustedParentSandbox,
  }).run({
    kind: "discovery",
    promptPath,
    workingDirectory,
    subagents: 0,
    signal: abortController.signal,
    onThreadStarted: () => abortController.abort("fixture cancellation"),
  });
  await assert.rejects(
    execution,
    (error: NodeJS.ErrnoException & { cause?: NodeJS.ErrnoException }) =>
      error?.name === "AbortError" ||
      /abort|SIGTERM/i.test(error?.message ?? ""),
  );
}

export async function testCompletedWorkerSettlesWithoutWaitingForProcessExit(
  fixtures: WorkerFixtures,
) {
  await completedWorkerSettlesWithoutWaitingForProcessExit(fixtures);
  for (const resumed of [false, true]) {
    await completedWorkerSettlesWithoutWaitingForProcessExit(
      fixtures,
      "discovery",
      resumed,
    );
  }
}

async function completedWorkerSettlesWithoutWaitingForProcessExit(
  {
    CodexSdkWorkerExecutor,
    fakeCodexFixture,
    trustedParentSandbox,
  }: WorkerFixtures,
  kind?: "discovery",
  resumed = false,
) {
  const fixture = await fakeCodexFixture();
  const saved = [
    "CODEX_HOME",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
  ].map((name) => [name, process.env[name]] as const);
  const deadline = Promise.withResolvers<never>();
  let timeout: NodeJS.Timeout | undefined;
  function armDeadline(ms: number, message: string) {
    clearTimeout(timeout);
    timeout = setTimeout(() => deadline.reject(new Error(message)), ms);
  }
  let worker: ChildProcess | undefined;
  const restoreSpawn = mockWorkerSpawn(fixture.executablePath, (child) => {
    worker = child;
    createInterface({ input: child.stdout! }).on("line", (line) => {
      if (JSON.parse(line).type === "turn.completed")
        armDeadline(
          1_000,
          "completed worker did not settle after turn.completed",
        );
    });
  });
  if (kind !== undefined) {
    const home = path.join(fixture.root, "private profile home");
    await mkdir(home);
    const configPath = path.join(fixture.root, "preflight.toml");
    const workerConfigPath = path.join(home, "deep-scan-config.toml");
    await writeFile(configPath, "");
    await writeFile(
      workerConfigPath,
      '[worker_runtime]\nnative_profile = "completion_fixture"\n',
    );
    await writeFile(
      path.join(home, "completion_fixture.config.toml"),
      'model_provider = "openai"\n',
    );
    Object.assign(process.env, {
      CODEX_HOME: home,
      CODEX_SECURITY_CONFIG_PATH: configPath,
      CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: workerConfigPath,
    });
  }
  const controller = new AbortController();
  const unexpectedErrors: unknown[] = [];
  const captureUnexpectedError = (error: NodeJS.ErrnoException) =>
    unexpectedErrors.push(error);
  let execution;

  process.on("uncaughtException", captureUnexpectedError);
  try {
    const promptPath = path.join(fixture.root, "prompt.md");
    const workingDirectory = path.join(fixture.root, "artifacts");
    await mkdir(workingDirectory);
    await writeFile(
      promptPath,
      kind === undefined
        ? "COMPLETE_THEN_HANG\n"
        : "COMPLETE_THEN_HANG_IGNORE_TERMINATION\n",
    );
    armDeadline(10_000, "worker did not emit turn.completed");
    execution = new CodexSdkWorkerExecutor({
      parentSandbox: trustedParentSandbox,
    }).run({
      kind: kind ?? "discovery",
      promptPath,
      workingDirectory,
      subagents: 0,
      signal: controller.signal,
      ...(resumed ? { resumeThreadId: "fixture-resumed-thread-id" } : {}),
    });

    const result = await Promise.race([execution, deadline.promise]);
    clearTimeout(timeout);
    assert.equal(
      result.threadId,
      resumed ? "fixture-resumed-thread-id" : "fixture-thread-id",
    );
    const invocation = await readJson(fixture.markerPath);
    assert.equal(invocation.argv.includes("--profile"), kind !== undefined);
    assert.equal(invocation.argv.includes("resume"), resumed);

    controller.abort("coordinator immediately canceled its remaining workers");
    await new Promise((resolve) => setTimeout(resolve, 250));

    assert.deepEqual(unexpectedErrors, []);
    assert.throws(() => process.kill(worker!.pid!, 0), { code: "ESRCH" });
  } finally {
    clearTimeout(timeout);
    controller.abort("completed worker fixture cleanup");
    worker?.kill("SIGKILL");
    await execution?.catch(() => {});
    process.removeListener("uncaughtException", captureUnexpectedError);
    restoreSpawn();
    for (const [name, value] of saved) restoreEnv(name, value);
  }
}
