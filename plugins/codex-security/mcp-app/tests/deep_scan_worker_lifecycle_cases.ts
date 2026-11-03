import assert from "node:assert/strict";
import childProcess, { type SpawnOptions } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import path from "node:path";
import { mock } from "node:test";
import { assertFlagPair } from "./assertions.ts";
import { readJson } from "./support/json.ts";
import type { createFakeCodexFixture } from "./deep_scan_native_fixture.ts";
import type { CodexSdkWorkerExecutor as WorkerExecutor } from "../src/deep-scan/executor.js";
import type { DeepWorkerParentSandbox } from "../src/deep-scan/parent-sandbox.js";
import type {
  CodexWorkerRequest,
  DeepScanWorkerKind,
} from "../src/deep-scan/types.js";

type WorkerFixture = Awaited<ReturnType<typeof createFakeCodexFixture>>;

export function createWorkerLifecycleCases({
  runWorker,
  CodexSdkWorkerExecutor,
  fakeCodexFixture,
  trustedParentSandbox,
  withWorkerFixture,
  restoreEnv,
}: {
  runWorker: (
    prompt: string,
    cwd: string,
    options: Partial<CodexWorkerRequest>,
  ) => ReturnType<WorkerExecutor["run"]>;
  CodexSdkWorkerExecutor: typeof WorkerExecutor;
  fakeCodexFixture: () => Promise<WorkerFixture>;
  trustedParentSandbox: DeepWorkerParentSandbox;
  withWorkerFixture: <Result>(
    action: (
      fixture: WorkerFixture,
      promptPath: string,
      workingDirectory: string,
    ) => Promise<Result>,
  ) => Promise<Result>;
  restoreEnv: (name: string, value: string | undefined) => void;
}) {
  return {
    testCancellationBeforeAcceptedTurnHasNoOwnership,
    testOwnershipRegistrationSettlesBeforeWorker,
    testCompletedWorkerDrainPreservesCancellation,
    testCancelCompletedWorkerDrain,
    testCompletedWorkerFlushesBeforeSettling,
    testCompletedWorkerClosesIdleServer,
    testWorkerTerminalEvents,
  };

  async function testCompletedWorkerDrainPreservesCancellation() {
    await completedWorkerDrainPreservesCancellation();
    for (const kind of ["discovery", "dedup"] as const) {
      for (const resumed of [false, true]) {
        await completedWorkerDrainPreservesCancellation(kind, resumed);
        await completedWorkerDrainPreservesCancellation(kind, resumed, true);
      }
    }
  }

  async function completedWorkerDrainPreservesCancellation(
    kind?: DeepScanWorkerKind,
    resumed = false,
    pendingStart = false,
  ) {
    const fixture = await fakeCodexFixture();
    const saved = [
      "CODEX_CLI_PATH",
      "CODEX_HOME",
      "CODEX_SECURITY_CONFIG_PATH",
      "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    ].map((name) => [name, process.env[name]] as const);
    process.env.CODEX_CLI_PATH = process.execPath;
    const originalSpawn = childProcess.spawn;
    childProcess.spawn = ((
      command: string,
      args: readonly string[] = [],
      options: SpawnOptions = {},
    ) =>
      originalSpawn(
        command,
        command === process.execPath ||
          command === path.win32.toNamespacedPath(process.execPath)
          ? [fixture.executablePath, ...args]
          : args,
        options,
      )) as typeof childProcess.spawn;
    syncBuiltinESMExports();
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
    let timeout;
    let childPid!: number;
    let registrations = 0;

    process.on("uncaughtException", captureUnexpectedError);
    try {
      const promptPath = path.join(fixture.root, "prompt.md");
      const workingDirectory = path.join(fixture.root, "artifacts");
      await mkdir(workingDirectory);
      await writeFile(
        promptPath,
        kind === undefined
          ? "COMPLETE_THEN_FLUSH\n"
          : pendingStart
            ? "DELAY_TURN_START\n"
            : "BLOCK_AFTER_START\n",
      );
      execution = new CodexSdkWorkerExecutor({
        parentSandbox: trustedParentSandbox,
      }).run({
        kind: kind ?? "discovery",
        promptPath,
        workingDirectory,
        subagents: 0,
        signal: controller.signal,
        ...(resumed ? { resumeThreadId: "fixture-resumed-thread-id" } : {}),
        onThreadStarted: async (threadId: string) => {
          registrations++;
          assert.equal(
            threadId,
            resumed ? "fixture-resumed-thread-id" : "fixture-thread-id",
          );
          childPid = (await readJson(fixture.markerPath)).pid;
        },
      });

      await Promise.race([
        (async () => {
          while (
            !controller.signal.aborted &&
            (await readFile(fixture.completionMarkerPath, "utf8").catch(
              () => "",
            )) !==
              (kind === undefined
                ? "completed\n"
                : pendingStart
                  ? "starting\n"
                  : "active\n")
          ) {
            await new Promise((resolve) => setTimeout(resolve, 10));
          }
        })(),
        new Promise((_, reject) => {
          timeout = setTimeout(() => {
            controller.abort("completed worker fixture timed out");
            reject(new Error("worker did not publish its completed turn"));
          }, 1_000);
        }),
      ]);
      clearTimeout(timeout);
      const invocation = await readJson(fixture.markerPath);
      childPid ??= invocation.pid;
      if (kind === undefined)
        assert.equal(invocation.argv.includes("--profile"), false);
      else assertFlagPair(invocation.argv, "--profile", "completion_fixture");
      assert.equal(invocation.thread.method === "thread/resume", resumed);

      controller.abort("coordinator canceled its worker");
      await assert.rejects(execution, /abort|coordinator canceled/i);
      assert.equal(registrations, pendingStart ? 0 : 1);
      const settled = await readJson(fixture.markerPath);
      assert.equal(
        await readFile(fixture.completionMarkerPath, "utf8"),
        "flushed\n",
      );
      assert.ok(
        settled.sequence.indexOf("eof") < settled.sequence.indexOf("flushed"),
      );
      if (kind !== undefined) {
        assert.ok(settled.sequence.indexOf("interrupt") >= 0);
        if (pendingStart) {
          assert.equal(settled.sequence.includes("active"), false);
          assert.equal(
            settled.sequence.includes("terminal:interrupted"),
            false,
          );
          assert.ok(
            settled.sequence.indexOf("interrupt") <
              settled.sequence.indexOf("eof"),
          );
        } else {
          assert.ok(
            settled.sequence.indexOf("interrupt") <
              settled.sequence.indexOf("terminal:interrupted"),
          );
          assert.ok(
            settled.sequence.indexOf("terminal:interrupted") <
              settled.sequence.indexOf("eof"),
          );
        }
        const interrupted = settled.rpc.find(
          (message: { method: string }) => message.method === "turn/interrupt",
        );
        assert.deepEqual(interrupted.params, {
          threadId: resumed ? "fixture-resumed-thread-id" : "fixture-thread-id",
          turnId: pendingStart ? "" : "fixture-turn-id",
        });
      } else {
        assert.ok(
          settled.sequence.indexOf("terminal:completed") <
            settled.sequence.indexOf("eof"),
        );
      }
      await new Promise((resolve) => setTimeout(resolve, 250));
      assert.deepEqual(unexpectedErrors, []);
      assert.throws(() => process.kill(childPid, 0), { code: "ESRCH" });
    } finally {
      clearTimeout(timeout);
      controller.abort("completed worker fixture cleanup");
      if (childPid) {
        try {
          process.kill(childPid, "SIGKILL");
        } catch {}
      }
      await execution?.catch(() => {});
      process.removeListener("uncaughtException", captureUnexpectedError);
      childProcess.spawn = originalSpawn;
      syncBuiltinESMExports();
      for (const [name, value] of saved) restoreEnv(name, value);
    }
  }

  async function testCancelCompletedWorkerDrain() {
    const fixture = await fakeCodexFixture();
    const previousPath = process.env.CODEX_CLI_PATH;
    process.env.CODEX_CLI_PATH = fixture.executablePath;
    const controller = new AbortController();
    let childPid: number | undefined;
    let execution: Promise<{ threadId?: string }> | undefined;
    let timeout: NodeJS.Timeout | undefined;
    try {
      const promptPath = path.join(fixture.root, "prompt.md"),
        workingDirectory = path.join(fixture.root, "artifacts");
      await mkdir(workingDirectory);
      await writeFile(promptPath, "COMPLETE_THEN_FLUSH\n");
      execution = new CodexSdkWorkerExecutor({
        parentSandbox: trustedParentSandbox,
      }).run({
        kind: "discovery",
        promptPath,
        workingDirectory,
        subagents: 0,
        signal: controller.signal,
      });
      while (true) {
        try {
          if (
            (await readFile(fixture.completionMarkerPath, "utf8")) ===
            "completed\n"
          )
            break;
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
        }
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      childPid = JSON.parse(await readFile(fixture.markerPath, "utf8")).pid;
      controller.abort("coordinator canceled completed worker drain");
      await assert.rejects(
        Promise.race([
          execution,
          new Promise<never>((_, reject) => {
            timeout = setTimeout(
              () =>
                reject(
                  new Error("completed worker drain ignored cancellation"),
                ),
              1000,
            );
          }),
        ]),
        /abort|SIGTERM/i,
      );
    } finally {
      clearTimeout(timeout);
      controller.abort("fixture cleanup");
      if (childPid)
        try {
          process.kill(childPid, "SIGKILL");
        } catch {}
      await execution?.catch(() => {});
      restoreEnv("CODEX_CLI_PATH", previousPath);
    }
  }

  async function testCompletedWorkerFlushesBeforeSettling() {
    const fixture = await fakeCodexFixture();
    const previousPath = process.env.CODEX_CLI_PATH;
    process.env.CODEX_CLI_PATH = fixture.executablePath;
    const controller = new AbortController();
    const unexpectedErrors: Error[] = [];
    const captureUnexpectedError = (error: Error) =>
      unexpectedErrors.push(error);
    let execution: Promise<{ threadId?: string }> | undefined;
    let timeout: NodeJS.Timeout | undefined;
    let childPid: number | undefined;

    process.on("uncaughtException", captureUnexpectedError);
    try {
      const promptPath = path.join(fixture.root, "prompt.md");
      const workingDirectory = path.join(fixture.root, "artifacts");
      await mkdir(workingDirectory);
      await writeFile(promptPath, "COMPLETE_THEN_FLUSH\n");
      execution = new CodexSdkWorkerExecutor({
        parentSandbox: trustedParentSandbox,
      }).run({
        kind: "discovery",
        promptPath,
        workingDirectory,
        subagents: 0,
        signal: controller.signal,
      });

      const result = await Promise.race([
        execution,
        new Promise<never>((_, reject) => {
          timeout = setTimeout(() => {
            controller.abort("completed worker fixture timed out");
            reject(
              new Error("completed worker did not settle after flushing usage"),
            );
          }, 1_000);
        }),
      ]);
      clearTimeout(timeout);
      assert.ok(result);
      assert.equal(result.threadId, "fixture-thread-id");
      childPid = JSON.parse(await readFile(fixture.markerPath, "utf8")).pid;
      assert.equal(
        await readFile(fixture.completionMarkerPath, "utf8"),
        "flushed\n",
      );

      controller.abort(
        "coordinator immediately canceled its remaining workers",
      );
      await new Promise((resolve) => setTimeout(resolve, 250));

      assert.deepEqual(unexpectedErrors, []);
      assert.throws(() => process.kill(childPid!, 0), { code: "ESRCH" });
    } finally {
      clearTimeout(timeout);
      if (!controller.signal.aborted)
        controller.abort("completed worker fixture cleanup");
      await execution?.catch(() => {});
      if (childPid) {
        try {
          process.kill(childPid, "SIGKILL");
        } catch {}
      }
      process.removeListener("uncaughtException", captureUnexpectedError);
      restoreEnv("CODEX_CLI_PATH", previousPath);
    }
  }

  async function testCompletedWorkerClosesIdleServer() {
    for (const kind of ["discovery", "dedup"] as const) {
      for (const resumed of [false, true]) {
        await withWorkerFixture(
          async (fixture, promptPath, workingDirectory) => {
            await writeFile(promptPath, "COMPLETE_THEN_HANG\n");
            const originalSpawn = childProcess.spawn;
            const previousPath = process.env.CODEX_CLI_PATH;
            process.env.CODEX_CLI_PATH = process.execPath;
            childProcess.spawn = ((
              command: string,
              args: readonly string[] = [],
              options: SpawnOptions = {},
            ) =>
              originalSpawn(
                command,
                command === process.execPath ||
                  command === path.win32.toNamespacedPath(process.execPath)
                  ? [fixture.executablePath, ...args]
                  : args,
                options,
              )) as typeof childProcess.spawn;
            syncBuiltinESMExports();
            const controller = new AbortController();
            let childPid: number | undefined;
            let timeout: NodeJS.Timeout | undefined;
            const execution = new CodexSdkWorkerExecutor({
              parentSandbox: trustedParentSandbox,
            }).run({
              kind,
              promptPath,
              workingDirectory,
              subagents: 0,
              signal: controller.signal,
              ...(resumed
                ? { resumeThreadId: "fixture-resumed-thread-id" }
                : {}),
              onThreadStarted: async () => {
                childPid = (await readJson(fixture.markerPath)).pid;
              },
            });
            try {
              const result = await Promise.race([
                execution,
                new Promise<never>((_, reject) => {
                  timeout = setTimeout(() => {
                    controller.abort("fixture completion bound");
                    reject(
                      new Error(
                        "completed worker did not close its idle app-server",
                      ),
                    );
                  }, 5_000);
                }),
              ]);
              assert.equal(
                result.threadId,
                resumed ? "fixture-resumed-thread-id" : "fixture-thread-id",
              );
              assert.equal(controller.signal.aborted, false);
            } finally {
              clearTimeout(timeout);
              controller.abort("fixture cleanup");
              if (childPid)
                try {
                  process.kill(childPid, "SIGKILL");
                } catch {}
              await execution.catch(() => {});
              childProcess.spawn = originalSpawn;
              syncBuiltinESMExports();
              restoreEnv("CODEX_CLI_PATH", previousPath);
            }
          },
        );
      }
    }
  }

  async function testWorkerTerminalEvents() {
    const fixture = await fakeCodexFixture();
    const previousPath = process.env.CODEX_CLI_PATH;
    const originalSpawn = childProcess.spawn;
    childProcess.spawn = ((
      command: string,
      args: readonly string[] = [],
      options: SpawnOptions = {},
    ) =>
      originalSpawn(
        command,
        command === process.execPath ||
          command === path.toNamespacedPath(process.execPath)
          ? [fixture.executablePath, ...args]
          : args,
        options,
      )) as typeof childProcess.spawn;
    syncBuiltinESMExports();
    process.env.CODEX_CLI_PATH = process.execPath;
    try {
      const promptPath = path.join(fixture.root, "prompt.md");
      const quotaMessage =
        "Quota exceeded. Check your plan and billing details.";
      for (const event of [
        undefined,
        { type: "turn.failed", error: { message: quotaMessage } },
        { type: "turn.failed", error: { message: "429 Too Many Requests" } },
        { type: "error", message: quotaMessage },
        {
          type: "item.completed",
          item: { id: "quota-text", type: "agent_message", text: quotaMessage },
        },
      ] as const) {
        await writeFile(
          promptPath,
          event
            ? `IPC_DIAGNOSTIC_EVENT\n${JSON.stringify(event)}\n`
            : "NULL_USAGE\n",
        );
        for (const kind of ["discovery", "dedup"] as const) {
          for (const resumeThreadId of [undefined, "fixture-resumed-thread"]) {
            const onNonRetryableError = mock.fn();
            const execution = new CodexSdkWorkerExecutor({
              parentSandbox: trustedParentSandbox,
            }).run({
              kind,
              promptPath,
              workingDirectory: fixture.root,
              subagents: 0,
              resumeThreadId,
              signal: new AbortController().signal,
              onNonRetryableError,
            });
            if (event?.type === "turn.failed") {
              const isQuota = event.error.message === quotaMessage;
              await assert.rejects(execution, {
                name: isQuota ? "DeepScanNonRetryableError" : "Error",
                message: event.error.message,
              });
              assert.deepEqual(
                onNonRetryableError.mock.calls.map(
                  ({ arguments: [error] }) => error.message,
                ),
                isQuota ? [quotaMessage] : [],
              );
              continue;
            }
            const result = await execution;
            assert.equal(onNonRetryableError.mock.callCount(), 0);
            assert.equal(
              result.threadId,
              resumeThreadId ?? "fixture-thread-id",
            );
          }
        }
      }
    } finally {
      childProcess.spawn = originalSpawn;
      syncBuiltinESMExports();
      restoreEnv("CODEX_CLI_PATH", previousPath);
    }
  }
  async function waitForWorkerFixture(predicate: () => Promise<boolean>) {
    const deadline = Date.now() + 3_000;
    while (!(await predicate())) {
      assert.ok(
        Date.now() < deadline,
        "worker fixture did not reach its boundary",
      );
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }

  async function testCancellationBeforeAcceptedTurnHasNoOwnership() {
    for (const kind of ["discovery", "dedup"] as const) {
      for (const resumed of [false, true]) {
        await withWorkerFixture(
          async (fixture, promptPath, workingDirectory) => {
            await writeFile(promptPath, "unsubmitted fixture prompt\n");
            const previous = process.env.FAKE_CODEX_HOLD_THREAD_START;
            process.env.FAKE_CODEX_HOLD_THREAD_START = "true";
            const controller = new AbortController();
            const registered = mock.fn();
            const execution = runWorker(promptPath, workingDirectory, {
              kind,
              signal: controller.signal,
              ...(resumed ? { resumeThreadId: "fixture-existing-thread" } : {}),
              onThreadStarted: registered,
            });
            void execution.catch(() => {});
            try {
              await waitForWorkerFixture(
                async () =>
                  (await readFile(fixture.completionMarkerPath, "utf8").catch(
                    () => "",
                  )) === "thread-pending\n",
              );
              controller.abort("canceled before turn acceptance");
              await assert.rejects(
                execution,
                (error: Error) =>
                  error.name === "AbortError" &&
                  error.cause === "canceled before turn acceptance",
              );
              const invocation = await readJson(fixture.markerPath);
              assert.equal(registered.mock.callCount(), 0);
              assert.equal(invocation.turn, undefined);
              assert.equal(
                invocation.rpc.some(
                  (message: { method: string }) =>
                    message.method === "turn/start",
                ),
                false,
              );
              assert.deepEqual(invocation.sequence, [
                "thread-pending",
                "eof",
                "flushed",
              ]);
              assert.equal(
                invocation.thread.method,
                resumed ? "thread/resume" : "thread/start",
              );
            } finally {
              controller.abort("fixture cleanup");
              await execution.catch(() => {});
              restoreEnv("FAKE_CODEX_HOLD_THREAD_START", previous);
            }
          },
        );
      }
    }
  }

  async function testOwnershipRegistrationSettlesBeforeWorker() {
    for (const kind of ["discovery", "dedup"] as const) {
      for (const resumed of [false, true]) {
        for (const outcome of ["success", "abort", "failure"] as const) {
          await withWorkerFixture(
            async (fixture, promptPath, workingDirectory) => {
              await writeFile(
                promptPath,
                outcome === "abort"
                  ? "BLOCK_AFTER_START\n"
                  : "COMPLETE_THEN_FLUSH\n",
              );
              const controller = new AbortController();
              const registration = Promise.withResolvers<void>();
              let callbacks = 0;
              let callbackStarted = false;
              let callbackFinished = false;
              let settled = false;
              const registrationFailure = new Error(
                "synthetic ownership registration failed",
              );
              const execution = runWorker(promptPath, workingDirectory, {
                kind,
                signal: controller.signal,
                ...(resumed
                  ? { resumeThreadId: "fixture-existing-thread" }
                  : {}),
                onThreadStarted: async (threadId) => {
                  callbacks++;
                  assert.equal(
                    threadId,
                    resumed ? "fixture-existing-thread" : "fixture-thread-id",
                  );
                  callbackStarted = true;
                  await registration.promise;
                  callbackFinished = true;
                  if (outcome === "failure") throw registrationFailure;
                },
              });
              const observed = execution.finally(() => {
                settled = true;
              });
              void observed.catch(() => {});
              try {
                await waitForWorkerFixture(async () => callbackStarted);
                if (outcome === "abort")
                  controller.abort("canceled while saving accepted ownership");
                await waitForWorkerFixture(
                  async () =>
                    (await readFile(fixture.completionMarkerPath, "utf8").catch(
                      () => "",
                    )) === "flushed\n",
                );
                const invocation = await readJson(fixture.markerPath);
                await waitForWorkerFixture(async () => {
                  try {
                    process.kill(invocation.pid, 0);
                    return false;
                  } catch (error) {
                    return (error as NodeJS.ErrnoException).code === "ESRCH";
                  }
                });
                await new Promise((resolve) => setImmediate(resolve));
                assert.equal(callbackFinished, false);
                assert.equal(
                  settled,
                  false,
                  "worker settled before its accepted turn ownership was saved",
                );
                registration.resolve();
                if (outcome === "failure") {
                  await assert.rejects(
                    observed,
                    (error: Error) => error === registrationFailure,
                  );
                } else if (outcome === "abort") {
                  await assert.rejects(
                    observed,
                    (error: Error) =>
                      error.name === "AbortError" &&
                      error.cause ===
                        "canceled while saving accepted ownership",
                  );
                } else {
                  assert.equal(
                    (await observed).threadId,
                    resumed ? "fixture-existing-thread" : "fixture-thread-id",
                  );
                }
                assert.equal(callbackFinished, true);
                assert.equal(callbacks, 1);
              } finally {
                registration.resolve();
                controller.abort("fixture cleanup");
                await observed.catch(() => {});
              }
            },
          );
        }
      }
    }
  }
}
