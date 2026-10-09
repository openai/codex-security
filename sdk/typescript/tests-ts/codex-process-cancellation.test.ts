import {
  execFileSync,
  spawn,
  type ChildProcessWithoutNullStreams,
  type SpawnOptions,
} from "node:child_process";
import { getEventListeners } from "node:events";
import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  setImmediate as nextTurn,
  setTimeout as delay,
} from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { CodexReviewRunner } from "../src/deduplication/codex-review.js";
import { resolveSourceMcp } from "../src/deduplication/source-mcp.js";
import { sendFeedback } from "../src/feedback.js";
import { nodeCommand } from "./support/shell.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);
const fixture = fileURLToPath(
  new URL("fixtures/inherited-codex-pipes.mjs", import.meta.url),
);
const node = nodeCommand().command;

for (const surface of [
  "review",
  "source-review",
  "source-config",
  "feedback",
] as const) {
  for (const mode of surface === "source-review"
    ? ["abandoned", "late", "late-stderr"]
    : surface === "source-config"
      ? ["abandoned", "late", "late-stderr", "active", "spawn-error", "success"]
      : [
          "abandoned",
          "success",
          "error",
          "unterminated",
          "late",
          "active",
          "spawn-error",
        ]) {
    test.skipIf(mode === "active" && process.platform === "win32")(
      `${surface} settles inherited pipes: ${mode}`,
      async () => {
        const root = await temporaryDirectory();
        const repository = join(root, "repository");
        await mkdir(repository);
        const release = join(root, "release");
        const environment = {
          PATH: process.env["PATH"],
          SystemRoot: process.env["SystemRoot"],
          CODEX_HOME: join(root, "home"),
          CODEX_SECURITY_STATE_DIR: join(root, "state"),
          OPENAI_API_KEY: "synthetic-review-key",
        };
        await mkdir(environment.CODEX_HOME, { mode: 0o700 });
        if (surface === "source-review") {
          execFileSync("git", ["init", "-q", repository]);
          execFileSync("git", [
            "-C",
            repository,
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "--allow-empty",
            "-qm",
            "source fixture",
          ]);
          execFileSync("git", [
            "-C",
            repository,
            "remote",
            "add",
            "origin",
            "https://git.example.com/team/repo.git",
          ]);
        }
        const controller = new AbortController();
        const reason = mode === "active" ? "synthetic interruption" : { mode };
        const ready = Promise.withResolvers<void>();
        const ignored = Promise.withResolvers<void>();
        const exited = Promise.withResolvers<void>();
        const stdoutEnded = Promise.withResolvers<void>();
        let child: ChildProcessWithoutNullStreams | undefined;
        let holderStarted = false;
        let holderPid: number | undefined;
        let nativeSpawnOptions: SpawnOptions | undefined;
        let starts = 0;
        let retries = 0;
        let retryDiagnostic: string | undefined;
        const start: NonNullable<Parameters<typeof sendFeedback>[1]> = (
          _command,
          _args,
          options,
        ) => {
          starts++;
          nativeSpawnOptions = {
            ...options,
            stdio: ["pipe", "pipe", "pipe", "ipc"],
          };
          child = spawn(
            mode === "spawn-error" ? join(root, "missing-codex") : node,
            [fixture, mode, release],
            nativeSpawnOptions,
          ) as ChildProcessWithoutNullStreams;
          child.stdout.once("end", () => stdoutEnded.resolve());
          child.on("message", (message) => {
            if (
              message &&
              typeof message === "object" &&
              "holderPid" in message
            )
              holderPid = message.holderPid as number;
            if (message === "ready") {
              holderStarted = true;
              ready.resolve();
            }
            if (message === "ignored-term") ignored.resolve();
          });
          if (mode !== "spawn-error")
            child.once("exit", () => {
              exited.resolve();
              if (!mode.startsWith("late") && mode !== "active")
                controller.abort(reason);
            });
          return child;
        };
        const task =
          surface === "feedback"
            ? sendFeedback(
                {
                  reason: "Synthetic feedback",
                  includeLogs: false,
                  environment,
                  workingDirectory: repository,
                  signal: controller.signal,
                },
                start,
              )
            : surface === "source-config"
              ? resolveSourceMcp(
                  "source",
                  environment,
                  controller.signal,
                  repository,
                  start,
                )
              : new CodexReviewRunner(
                  environment,
                  start,
                  controller.signal,
                  repository,
                  {
                    wait: async () => {
                      retries++;
                      throw new Error("Stop the synthetic transport retry");
                    },
                  },
                  (event) => {
                    if (event.event === "review.retry")
                      retryDiagnostic = event.message;
                  },
                  undefined,
                  surface === "source-review"
                    ? {
                        name: "source",
                        configPath: join(environment.CODEX_HOME, "config.toml"),
                        server: {},
                        environment: {},
                        credentialNames: [],
                      }
                    : undefined,
                ).run({
                  stage: "pair-review",
                  model: "synthetic-model",
                  effort: "high",
                  prompt: "Review synthetic findings.",
                  schema: { type: "object" },
                  validate: (value) => value,
                });
        let settled = false;
        const result = task.then(
          (value) => ({ value, error: undefined }),
          (error: unknown) => ({ value: undefined, error }),
        );
        void result.then(() => {
          settled = true;
        });
        const deadline = new AbortController();
        const bounded = <T>(operation: Promise<T>, phase: string): Promise<T> =>
          Promise.race([
            operation,
            delay(5000, undefined, { signal: deadline.signal }).then(() => {
              throw new Error(`${phase} did not settle before holder release`);
            }),
          ]);
        let primaryFailure: unknown;
        try {
          if (mode !== "spawn-error") {
            await bounded(
              Promise.race([
                ready.promise,
                result.then((outcome) => {
                  throw outcome.error ?? new Error("Fixture did not start");
                }),
              ]),
              "fixture readiness",
            );
            if (mode === "active") {
              controller.abort(reason);
              await bounded(ignored.promise, "SIGTERM observation");
              expect(child!.exitCode).toBeNull();
              expect(child!.signalCode).toBeNull();
              expect(child!.stdout.destroyed).toBe(false);
              expect(child!.stderr.destroyed).toBe(false);
              if (surface === "review") child!.kill("SIGKILL");
            }
            await bounded(exited.promise, "direct child exit");
            if (mode === "active" && surface !== "review")
              expect(child!.signalCode).toBe("SIGKILL");
          }
          if (mode.startsWith("late")) {
            if (mode === "late-stderr")
              await bounded(stdoutEnded.promise, "stdout EOF");
            await nextTurn();
            expect(settled).toBe(false);
            if (mode === "late") expect(child!.stdout.destroyed).toBe(false);
            expect(child!.stderr.destroyed).toBe(false);
            await writeFile(release, "released");
          }
          const outcome = await bounded(result, "operation completion");
          if (mode === "success" && surface === "source-config") {
            expect((outcome.error as Error).message).toContain(
              'Source MCP server "source" is disabled.',
            );
          } else if (mode === "success") {
            expect(outcome).toMatchObject({
              value:
                surface === "feedback"
                  ? { feedbackId: "synthetic-feedback" }
                  : { decision: "SAME" },
              error: undefined,
            });
          } else if (mode.startsWith("late")) {
            expect(
              surface === "feedback" || surface === "source-config"
                ? (outcome.error as Error).message
                : retryDiagnostic,
            ).toContain("late café 日本語 😀");
          } else if (mode !== "spawn-error") {
            expect(outcome.error).toBe(reason);
          }
          expect(starts).toBe(1);
          expect(retries).toBe(
            mode.startsWith("late") &&
              ["review", "source-review"].includes(surface)
              ? 1
              : 0,
          );
          const remaining = getEventListeners(controller.signal, "abort");
          if (mode === "spawn-error") {
            // Compare native ownership without depending on its callback identities.
            const controlAbort = new AbortController();
            let control: ReturnType<typeof spawn> | undefined;
            let controlError: unknown;
            try {
              control = spawn(
                join(root, "missing-codex"),
                [fixture, mode, release],
                { ...nativeSpawnOptions, signal: controlAbort.signal },
              );
              control.once("error", (error: Error) => {
                controlError = error;
              });
              await new Promise<void>((resolve) =>
                control!.once("close", resolve),
              );
            } catch (error) {
              controlError = error;
            }
            expect(controlError).toBeInstanceOf(Error);
            expect((outcome.error as Error).message).toContain(
              (controlError as Error).message,
            );
            expect(remaining).toHaveLength(
              getEventListeners(controlAbort.signal, "abort").length,
            );
            expect(child?.listenerCount("exit") ?? 0).toBe(
              control?.listenerCount("exit") ?? 0,
            );
          } else {
            expect(remaining).toHaveLength(0);
            expect(child!.listenerCount("exit")).toBe(0);
          }
        } catch (error) {
          primaryFailure = error;
          throw error;
        } finally {
          try {
            await writeFile(release, "released");
            if (child?.exitCode === null && child.signalCode === null)
              child.kill("SIGKILL");
            await result;
            if (holderStarted)
              await bounded(
                (async () => {
                  while (!existsSync(`${release}.done`))
                    await delay(10, undefined, { signal: deadline.signal });
                })(),
                "holder cleanup",
              );
          } catch (error) {
            let holderStatus = "not announced";
            if (holderPid !== undefined) {
              try {
                process.kill(holderPid, 0);
                holderStatus = "alive";
              } catch (probeError) {
                holderStatus =
                  (probeError as NodeJS.ErrnoException).code ??
                  String(probeError);
              }
            }
            const cleanupError = new Error(
              `Holder cleanup failed (holder ${holderPid ?? "unknown"}: ${holderStatus}; completion marker: ${existsSync(`${release}.done`)})`,
              { cause: error },
            );
            if (primaryFailure !== undefined)
              throw new AggregateError(
                [primaryFailure, cleanupError],
                "The cancellation test and holder cleanup both failed",
              );
            throw cleanupError;
          } finally {
            deadline.abort();
          }
        }
      },
    );
  }
}
