import assert from "node:assert/strict";
import childProcess, {
  type ChildProcess,
  type SpawnOptions,
} from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import path from "node:path";
import { assertFlagPair } from "./assertions.ts";
import type { CodexSdkWorkerExecutor as WorkerExecutor } from "../src/deep-scan/executor.js";
import type { DeepWorkerParentSandbox } from "../src/deep-scan/parent-sandbox.js";

export async function testWorkerCancellation({
  CodexSdkWorkerExecutor,
  fakeCodexFixture,
  trustedParentSandbox,
  restoreEnv,
}: {
  CodexSdkWorkerExecutor: typeof WorkerExecutor;
  fakeCodexFixture: () => Promise<{
    root: string;
    executablePath: string;
    preflightMarkerPath: string;
    markerPath: string;
  }>;
  trustedParentSandbox: DeepWorkerParentSandbox;
  restoreEnv: (name: string, value: string | undefined) => void;
}) {
  const fixture = await fakeCodexFixture();
  const previousPath = process.env.CODEX_CLI_PATH;
  const originalSpawn = childProcess.spawn;
  let worker: ChildProcess | undefined;
  let workerSignal: AbortSignal | undefined;
  let cancelDuringCleanup: (() => void) | undefined;
  let timeout: NodeJS.Timeout | undefined;
  childProcess.spawn = ((
    command: string,
    args: readonly string[] = [],
    options: SpawnOptions = {},
  ) => {
    const child = originalSpawn(
      command,
      command === process.execPath ||
        command === path.toNamespacedPath(process.execPath)
        ? [fixture.executablePath, ...args]
        : args,
      options,
    );
    if (args[0] === "exec") {
      assertFlagPair(args, "--thread-source", "security_scan");
      worker = child;
      workerSignal = options.signal;
      const kill = child.kill;
      child.kill = function (...args: Parameters<ChildProcess["kill"]>) {
        cancelDuringCleanup?.();
        return kill.apply(this, args);
      };
    }
    return child;
  }) as typeof childProcess.spawn;
  syncBuiltinESMExports();
  process.env.CODEX_CLI_PATH = process.execPath;
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
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    restoreEnv("CODEX_CLI_PATH", previousPath);
  }
}
