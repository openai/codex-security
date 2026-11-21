import { hash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { ThreadEvent } from "@openai/codex-sdk";
import { afterEach, expect, test } from "bun:test";
import type { JsonObject } from "../src/config.js";
import { copyCompletedScan } from "./plugin-root.js";
import { mockWorkbench, TestClient } from "./support/api-client.js";
import {
  codexFactory,
  completedEvents,
  scanRuntimeDependencies,
} from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { writeSession } from "./support/usage-rollout.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
afterEach(cleanup);

test.each(["pending", "finalized", "unavailable", "standard"] as const)(
  "finalizes saved completion-turn usage when accounting is %s",
  async (scenario) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const scanDir = join(root, "scan");
    await Promise.all(
      [repository, codexHome, scanDir].map((path) => mkdir(path)),
    );
    const commands: Array<readonly string[]> = [];
    const warnings: string[] = [];
    const observerErrors: string[] = [];
    const accountingFailure = "Synthetic usage storage failure: token=fixture";
    const completionWarning = "Synthetic saved scan warning";
    let turnFinished = false;
    const client = TestClient.withDependencies({
      ...scanRuntimeDependencies(codexHome, scanDir),
      canRunDirectDeepScan: () => false,
      runWorkbench: async (_options, args, input) => {
        commands.push(args);
        if (args[0] === "complete-scan") {
          return {
            scan: {
              warnings: [completionWarning],
              ...(scenario === "standard"
                ? {}
                : {
                    usage: {
                      completion: {
                        threadId: "completion-thread",
                        turnId: "completion-turn",
                        finalized: scenario === "finalized",
                      },
                    },
                  }),
            },
          };
        }
        if (args[0] === "finalize-scan-usage") {
          expect(turnFinished).toBe(true);
          if (scenario === "unavailable") throw new Error(accountingFailure);
          return {};
        }
        return mockWorkbench(args, input);
      },
      createCodex: codexFactory(async () => {
        await copyCompletedScan(root);
        if (scenario !== "standard") {
          const coveragePath = join(scanDir, "coverage.json");
          const coverage = JSON.parse(await readFile(coveragePath, "utf8"));
          coverage.mode = "deep_repository";
          const coverageBytes = `${JSON.stringify(coverage)}\n`;
          await writeFile(coveragePath, coverageBytes);
          const manifestPath = join(scanDir, "scan-manifest.json");
          const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
          manifest.scan.artifacts.find(
            (artifact: { path: string }) => artifact.path === "coverage.json",
          ).sha256 = hash("sha256", coverageBytes);
          await writeFile(manifestPath, `${JSON.stringify(manifest)}\n`);
        }
        async function* events() {
          yield* completedEvents();
          turnFinished = true;
        }
        return { events: events() };
      }),
    });
    try {
      const result = await client.run(repository, {
        mode: scenario === "standard" ? "standard" : "deep",
        onWarning: (warning) => {
          warnings.push(warning);
          if (warning.includes(accountingFailure))
            throw new Error("Synthetic warning observer failure");
        },
        onObserverError: (observer) => observerErrors.push(observer),
      });
      expect(result).toMatchObject({ scanDir, threadId: "thread-1" });
      const finalization = commands.filter(
        (args) => args[0] === "finalize-scan-usage",
      );
      if (scenario === "pending" || scenario === "unavailable") {
        expect(finalization).toEqual([
          [
            "finalize-scan-usage",
            "--scan-id",
            "scan_example_001",
            "--thread-id",
            "completion-thread",
            "--turn-id",
            "completion-turn",
            "--turn-status",
            "completed",
          ],
        ]);
        expect(commands.indexOf(finalization[0]!)).toBeGreaterThan(
          commands.findIndex((args) => args[0] === "complete-scan"),
        );
      } else {
        expect(finalization).toEqual([]);
      }
      expect(warnings).toEqual([
        ...(scenario === "unavailable"
          ? [`Could not finalize scan token usage: ${accountingFailure}`]
          : []),
        completionWarning,
      ]);
      expect(observerErrors).toEqual(
        scenario === "unavailable" ? ["onWarning"] : [],
      );
      expect(commands.some((args) => args[0] === "fail-scan")).toBe(false);
    } finally {
      await client.close();
    }
  },
);

test.each([
  "failed",
  "interrupted",
  "post-turn-error",
  "post-turn-cancel",
  "transport-error",
  "resumed",
  "accounting-error",
] as const)(
  "preserves a sealed scan and its %s outcome while finalizing usage",
  async (scenario) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const scanDir = join(root, "scan");
    await Promise.all(
      [repository, codexHome, scanDir].map((path) =>
        mkdir(path, { mode: 0o700 }),
      ),
    );
    const report = "# Sealed scan report\n";
    await writeFile(join(scanDir, "report.md"), report);
    if (scenario === "resumed")
      await writeSession(codexHome, "thread-1", {}, { cwd: scanDir });
    const controller = new AbortController();
    const commands: Array<readonly string[]> = [];
    const warnings: string[] = [];
    const originalFailure = new Error("Synthetic scan turn failure");
    const accountingFailure = "Synthetic accounting failure: token=fixture";
    let turnExited = false;
    async function* events(): AsyncGenerator<ThreadEvent> {
      try {
        if (scenario === "post-turn-error" || scenario === "post-turn-cancel") {
          yield* completedEvents();
          if (scenario === "post-turn-cancel")
            controller.abort(originalFailure);
          return;
        }
        yield { type: "thread.started", thread_id: "thread-1" };
        yield { type: "turn.started" };
        if (scenario === "interrupted") {
          controller.abort(originalFailure);
          throw originalFailure;
        }
        if (scenario === "transport-error") throw originalFailure;
        yield {
          type: "turn.failed",
          error: { message: originalFailure.message },
        };
      } finally {
        turnExited = true;
      }
    }
    const client = TestClient.withDependencies({
      ...scanRuntimeDependencies(codexHome, scanDir),
      canRunDirectDeepScan: () => false,
      createCodex: () => ({
        startThread: () => ({
          id: null,
          runStreamed: async () => ({ events: events() }),
        }),
        resumeThread: (threadId) => ({
          id: threadId,
          runStreamed: async () => ({ events: events() }),
        }),
      }),
      runWorkbench: async (options, args, input): Promise<JsonObject> => {
        commands.push(args);
        if (args[0] === "get-cli-scan-resume") {
          return {
            scanId: "scan_example_001",
            scanDir,
            targetId: "target_sha256_example",
            targetRevision: "deadbeef",
            threadId: "thread-1",
            recipe: { repository, target: { kind: "repository", paths: [] } },
            contract: { target: { allowedKinds: ["git_revision"] } },
          };
        }
        if (args[0] === "prepare-scan-completion") throw originalFailure;
        if (args[0] === "get-scan") {
          if (turnExited && scenario !== "post-turn-error")
            expect(options.signal).toBeUndefined();
          return {
            scan: {
              progress: { status: "complete" },
              usage: {
                completion: {
                  threadId: "completion-thread",
                  turnId: "completion-turn",
                  finalized: false,
                },
              },
            },
          };
        }
        if (args[0] === "finalize-scan-usage") {
          expect(turnExited).toBe(true);
          expect(options.signal).toBeUndefined();
          if (scenario === "accounting-error")
            throw new Error(accountingFailure);
        }
        return mockWorkbench(args, input);
      },
    });
    try {
      const failure = await client
        .run(repository, {
          mode: "deep",
          ...(scenario === "resumed"
            ? { resumeScanId: "scan_example_001", outputDir: scanDir }
            : {}),
          signal: controller.signal,
          onWarning: (warning) => {
            warnings.push(warning);
            throw new Error("Synthetic warning observer failure");
          },
        })
        .then(
          () => {
            throw new Error("Expected the original scan failure");
          },
          (error: unknown) => error,
        );
      if (scenario === "interrupted" || scenario === "post-turn-cancel") {
        expect(failure).toMatchObject({ name: "ScanInterruptedError" });
      } else if (
        scenario === "post-turn-error" ||
        scenario === "transport-error"
      ) {
        expect(failure).toBe(originalFailure);
      } else {
        expect(failure).toMatchObject({ message: originalFailure.message });
      }
      const finalization = commands.filter(
        (args) => args[0] === "finalize-scan-usage",
      );
      expect(finalization).toEqual(
        scenario === "transport-error"
          ? []
          : [
              [
                "finalize-scan-usage",
                "--scan-id",
                "scan_example_001",
                "--thread-id",
                "completion-thread",
                "--turn-id",
                "completion-turn",
                "--turn-status",
                scenario === "post-turn-error" ||
                scenario === "post-turn-cancel"
                  ? "completed"
                  : scenario === "interrupted"
                    ? "interrupted"
                    : "failed",
              ],
            ],
      );
      expect(commands.some((args) => args[0] === "fail-scan")).toBe(false);
      expect(warnings).toEqual(
        scenario === "accounting-error"
          ? [`Could not finalize scan token usage: ${accountingFailure}`]
          : [],
      );
      expect(await readFile(join(scanDir, "report.md"), "utf8")).toBe(report);
    } finally {
      await client.close();
    }
  },
);
