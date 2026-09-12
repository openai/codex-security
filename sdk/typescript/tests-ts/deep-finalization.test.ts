import { execFileSync } from "node:child_process";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, test } from "bun:test";
import type { ThreadEvent } from "@openai/codex-sdk";
import {
  prepareScanArtifactRestorer,
  runWorkbench,
  type WorkbenchCommandOptions,
} from "../src/runtime.js";
import { TestClient } from "./support/api-client.js";
import {
  completedEvents,
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);
const threadId = "1af317a1-c9ed-4c73-b428-cb0d160cf8e8";
const followUp = "Explain the selected finding.";

for (const outcome of [
  "failed",
  "completed",
  "restart",
  "canceled-before-publication",
  "canceled-during-publication",
  "published-before-cancellation",
  "closed-during-publication",
  "budget-during-publication",
  "budget-after-deep-finish",
  "budget-during-resumed-publication",
  "closed-during-resumed-publication",
  "followup-canceled",
] as const) {
  const resumedStop = outcome.includes("-resumed-");
  const restart = outcome === "restart" || resumedStop;
  const closed = outcome.startsWith("closed-");
  const budgeted = outcome.startsWith("budget-");
  const name =
    outcome === "followup-canceled"
      ? "SDK preserves a selected aggregate when its follow-up is canceled"
      : `SDK handles selected aggregate: ${outcome}`;
  const runCase = async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const scanDir = join(root, "scan");
    const codexHome = join(root, "codex-home");
    const stateDir = join(root, "state");
    await Promise.all([
      mkdir(repository),
      mkdir(scanDir, { mode: 0o700 }),
      mkdir(codexHome),
    ]);
    await writeFile(join(repository, "extract.py"), "# Synthetic source\n");
    const environment = {
      ...process.env,
      CODEX_HOME: codexHome,
      CODEX_SECURITY_STATE_DIR: stateDir,
    };
    const cancellation = new AbortController();
    let scanId = "";
    let workbenchOptions: WorkbenchCommandOptions;
    let publicationFails = restart;
    let acceptedReport = "";
    const modelInputs: string[] = [];
    const commands: string[] = [];
    const usagePath = join(
      codexHome,
      "sessions",
      "2026",
      "01",
      "01",
      `rollout-${threadId}.jsonl`,
    );
    let closePromise: Promise<void> | undefined;
    const makeClient = () =>
      new TestClient(
        {},
        {
          environment,
          prepareScanArtifactRestorer,
          prepareRuntime: async () => {
            const runtime = preparedRuntime(codexHome);
            const manifest = JSON.parse(
              await readFile(
                join(PLUGIN_ROOT, ".codex-plugin/plugin.json"),
                "utf8",
              ),
            );
            return {
              ...runtime,
              environment,
              persistentCredentialHome: true,
              plugin: { ...runtime.plugin, version: manifest.version },
            };
          },
          resolvePluginPython: async () => "python3",
          prepareOutputDir: async () => scanDir,
          runWorkbench: async (options, args, input) => {
            workbenchOptions = options;
            commands.push(args[0]!);
            if (args[0] === "write-scan-draft" && publicationFails) {
              publicationFails = false;
              throw new Error("Synthetic publication write failure");
            }
            const result = await runWorkbench(options, args, input);
            if (
              (args[0] === "write-scan-draft" &&
                (outcome === "budget-during-publication" ||
                  outcome === "budget-during-resumed-publication")) ||
              (args[0] === "finish-deep-scan" &&
                outcome === "budget-after-deep-finish")
            ) {
              await appendFile(
                usagePath,
                JSON.stringify({
                  timestamp: new Date().toISOString(),
                  type: "turn_context",
                  payload: {
                    turn_id: "synthetic-scan-turn",
                    model: "gpt-5.6-sol",
                  },
                }) +
                  "\n" +
                  JSON.stringify({
                    timestamp: new Date().toISOString(),
                    type: "event_msg",
                    payload: {
                      type: "token_count",
                      info: {
                        total_token_usage: {
                          input_tokens: 1_250,
                          cached_input_tokens: 200,
                          output_tokens: 30,
                        },
                      },
                    },
                  }) +
                  "\n",
              );
              await new Promise<void>((resolve) => {
                if (options.signal?.aborted) resolve();
                else
                  options.signal!.addEventListener("abort", () => resolve(), {
                    once: true,
                  });
              });
            }
            if (args[0] === "write-scan-draft" && closed) {
              closePromise = client.close();
            }
            if (
              args[0] === "write-scan-draft" &&
              outcome === "canceled-during-publication"
            ) {
              cancellation.abort("Synthetic user cancellation");
            }
            if (
              args[0] === "complete-scan" &&
              outcome === "published-before-cancellation"
            ) {
              cancellation.abort(
                "Synthetic user cancellation after completion",
              );
            }
            if (args[0] === "register-cli-scan")
              scanId = result["scanId"] as string;
            return result;
          },
          createCodex: () => {
            const thread = {
              id: threadId,
              async runStreamed(input: string) {
                modelInputs.push(input);
                if (input === followUp) {
                  if (outcome === "followup-canceled") {
                    const reportPath = join(scanDir, "report.md");
                    acceptedReport = await readFile(reportPath, "utf8");
                    expect(acceptedReport).toContain(
                      "Validate the resolved destination",
                    );
                    await writeFile(
                      reportPath,
                      "Incomplete follow-up report.\n",
                    );
                    cancellation.abort(
                      "Synthetic cancellation during follow-up",
                    );
                  }
                  return { events: completedEvents(threadId) };
                }
                expect(modelInputs.length).toBe(1);
                async function* events(): AsyncGenerator<ThreadEvent> {
                  yield { type: "thread.started", thread_id: threadId };
                  await runWorkbench(workbenchOptions, [
                    "begin-deep-scan",
                    "--scan-id",
                    scanId,
                    "--thread-id",
                    threadId,
                  ]);
                  const draft = {
                    scanId,
                    complete: true,
                    findings: [
                      {
                        ruleId: "path-traversal.archive",
                        title: "Unsafe archive extraction",
                        summary:
                          "An untrusted entry reaches a filesystem write.",
                        severity: { level: "high" },
                        confidence: {
                          level: "high",
                          rationale: "Source evidence.",
                        },
                        taxonomy: {
                          category: "path-traversal",
                          cwe: ["CWE-22"],
                        },
                        locations: [{ path: "extract.py", startLine: 1 }],
                        remediation:
                          "Validate the resolved destination before writing.",
                        provenance: {
                          source: "local_plugin",
                          candidateId: "archive-entry",
                        },
                      },
                    ],
                    coverage: {
                      completeness: "partial",
                      surfaces: [],
                      explicitExclusions: [],
                      deferred: [
                        {
                          id: "dependency",
                          reason: "A dependency remains unreviewed.",
                        },
                      ],
                    },
                  };
                  const seeded = JSON.parse(
                    execFileSync(
                      "python3",
                      [
                        fileURLToPath(
                          new URL(
                            "./fixtures/selected-deep-scan.py",
                            import.meta.url,
                          ),
                        ),
                      ],
                      {
                        input: JSON.stringify({
                          scanId,
                          scanDir,
                          database: join(stateDir, "workbench.sqlite3"),
                          draft,
                        }),
                        encoding: "utf8",
                        env: environment,
                      },
                    ),
                  );
                  // Exercise the dedicated function bridge, without extending CLI arguments.
                  execFileSync(
                    "python3",
                    [
                      "-c",
                      "import runpy, sys; script = sys.argv.pop(1); runpy.run_path(script)['main'](select_finalization=True)",
                      join(PLUGIN_ROOT, "scripts/workbench_db.py"),
                      "finish-deep-scan",
                      "--scan-id",
                      scanId,
                      "--coordinator-generation",
                      "2",
                      "--terminal-reason",
                      "saturated",
                      "--manifest-path",
                      join(scanDir, "scan-manifest.json"),
                    ],
                    {
                      input: JSON.stringify({ resultPath: seeded.resultPath }),
                      encoding: "utf8",
                      env: environment,
                    },
                  );
                  const sessions = join(
                    codexHome,
                    "sessions",
                    "2026",
                    "01",
                    "01",
                  );
                  await mkdir(sessions, { recursive: true });
                  await writeFile(
                    join(sessions, `rollout-${threadId}.jsonl`),
                    JSON.stringify({
                      timestamp: new Date().toISOString(),
                      type: "session_meta",
                      payload: { id: threadId, cwd: scanDir },
                    }) + "\n",
                  );
                  if (outcome === "canceled-before-publication")
                    cancellation.abort("Synthetic user cancellation");
                  if (outcome === "completed") {
                    yield {
                      type: "turn.completed",
                      usage: {
                        input_tokens: 0,
                        cached_input_tokens: 0,
                        cache_write_input_tokens: 0,
                        reasoning_output_tokens: 0,
                        output_tokens: 0,
                      },
                    };
                  } else {
                    throw new Error(
                      "Parent turn ended before its final completion tool call",
                    );
                  }
                }
                return { events: events() };
              },
            };
            return {
              startThread: () => thread,
              resumeThread: (id: string) => {
                expect(id).toBe(threadId);
                return thread;
              },
            };
          },
        },
      );
    let client = makeClient();
    // Native usage polling is unref'ed; the transport double has no child process.
    const keepAlive = setTimeout(() => {}, 30_000);
    try {
      if (restart) {
        await expect(
          client.run(repository, {
            mode: "deep",
            postScanPrompt: resumedStop ? undefined : followUp,
            ...(budgeted ? { maxCostUsd: 0.004 } : {}),
          }),
        ).rejects.toThrow("Synthetic publication write failure");
        const pending = await runWorkbench(workbenchOptions!, [
          "get-deep-scan",
          "--scan-id",
          scanId,
          "--thread-id",
          threadId,
        ]);
        expect(pending["deepScan"]).toMatchObject({
          status: "running",
          terminalReason: "saturated",
        });
        expect(commands).not.toContain("fail-scan");
        await client.close();
        client = makeClient();
      }
      if (budgeted || closed) {
        const running = client.run(repository, {
          mode: "deep",
          ...(budgeted ? { maxCostUsd: 0.004 } : {}),
          ...(resumedStop ? { resumeScanId: scanId, outputDir: scanDir } : {}),
          postScanPrompt: followUp,
        });
        if (outcome === "budget-after-deep-finish") {
          const result = await running;
          expect(result.coverage.completeness).toBe("partial");
          expect(JSON.stringify(result.coverage)).toContain("cost limit");
          expect(result.cost?.estimatedUsd).toBeGreaterThan(0.004);
          expect(result.threadId).toBe(threadId);
          expect(modelInputs).toHaveLength(1);
          expect(commands).toContain("complete-budget-exhausted-scan");
          expect(commands).not.toContain("fail-scan");
          return;
        }
        await expect(running).rejects.toThrow(
          budgeted ? /estimated cost.*exceeded/ : /closed/,
        );
        await closePromise;
        const stopped = await runWorkbench(
          { ...workbenchOptions!, signal: undefined },
          ["get-scan", "--scan-id", scanId],
        );
        const deep = await runWorkbench(
          { ...workbenchOptions!, signal: undefined },
          ["get-deep-scan", "--scan-id", scanId, "--thread-id", threadId],
        );
        expect(stopped["scan"]).toMatchObject({
          progress: { status: "failed" },
          findingCount: 1,
          reportAvailable: true,
        });
        expect(deep["deepScan"]).toMatchObject({
          status: "failed",
          finalizationInput: { terminalReason: "saturated" },
        });
        expect(await readFile(join(scanDir, "report.md"), "utf8")).toContain(
          "Validate the resolved destination",
        );
        expect(
          JSON.parse(await readFile(join(scanDir, "coverage.json"), "utf8"))
            .completeness,
        ).toBe("partial");
        expect(commands).toContain("fail-scan");
        expect(modelInputs).toHaveLength(1);
        await client.close();
        client = makeClient();
        await expect(
          client.run(repository, {
            mode: "deep",
            resumeScanId: scanId,
            outputDir: scanDir,
          }),
        ).rejects.toThrow();
        expect(modelInputs).toHaveLength(1);
        return;
      }
      if (outcome.startsWith("canceled-")) {
        await expect(
          client.run(repository, { mode: "deep", signal: cancellation.signal }),
        ).rejects.toThrow(/interrupted/);
        const stopped = await runWorkbench(
          { ...workbenchOptions!, signal: undefined },
          ["get-scan", "--scan-id", scanId],
        );
        const deep = await runWorkbench(
          { ...workbenchOptions!, signal: undefined },
          ["get-deep-scan", "--scan-id", scanId, "--thread-id", threadId],
        );
        expect(stopped["scan"]).toMatchObject({
          progress: { status: "canceled" },
          findingCount: 1,
          reportAvailable: true,
        });
        expect(
          JSON.parse(await readFile(join(scanDir, "coverage.json"), "utf8"))
            .completeness,
        ).toBe("partial");
        expect(await readFile(join(scanDir, "report.md"), "utf8")).toContain(
          "Validate the resolved destination",
        );
        expect(deep["deepScan"]).toMatchObject({
          status: "canceled",
          finalizationInput: { terminalReason: "saturated" },
        });
        expect(commands).toContain("cancel-scan");
        expect(commands).not.toContain("fail-scan");
        expect(modelInputs.length).toBe(1);
        await expect(
          client.run(repository, {
            mode: "deep",
            resumeScanId: scanId,
            outputDir: scanDir,
          }),
        ).rejects.toThrow();
        expect(modelInputs.length).toBe(1);
        return;
      }
      if (outcome === "followup-canceled") {
        await expect(
          client.run(repository, {
            mode: "deep",
            signal: cancellation.signal,
            postScanPrompt: followUp,
          }),
        ).rejects.toThrow(/interrupted/);
        const completed = await runWorkbench(
          { ...workbenchOptions!, signal: undefined },
          ["get-scan", "--scan-id", scanId],
        );
        expect(completed["scan"]).toMatchObject({
          progress: { status: "complete" },
          findingCount: 1,
          reportAvailable: true,
        });
        expect(modelInputs.length).toBe(2);
        expect(modelInputs[1]).toBe(followUp);
        expect(commands).not.toContain("cancel-scan");
        expect(commands).not.toContain("fail-scan");
        expect(await readFile(join(scanDir, "report.md"), "utf8")).toBe(
          acceptedReport,
        );
        return;
      }
      const result = await client.run(repository, {
        mode: "deep",
        signal: cancellation.signal,
        postScanPrompt:
          outcome === "published-before-cancellation" ? undefined : followUp,
        ...(restart ? { resumeScanId: scanId, outputDir: scanDir } : {}),
      });
      expect(result.threadId).toBe(threadId);
      // The synthetic accepted workers have no native usage receipts.
      expect(result.cost).toBeNull();
      expect(result.coverage.completeness).toBe("partial");
      expect(result.findings.findings[0]?.remediation).toBe(
        "Validate the resolved destination before writing.",
      );
      // postScanPrompt retains its existing behavior on each caller invocation.
      expect(modelInputs.filter((input) => input !== followUp).length).toBe(1);
      expect(modelInputs.filter((input) => input === followUp).length).toBe(
        outcome === "published-before-cancellation" ? 0 : restart ? 2 : 1,
      );
      const completed = await runWorkbench(
        { ...workbenchOptions!, signal: undefined },
        ["get-scan", "--scan-id", scanId],
      );
      expect(completed["scan"]).toMatchObject({
        progress: { status: "complete" },
      });
      expect(await readFile(join(scanDir, "report.md"), "utf8")).toContain(
        "Validate the resolved destination",
      );
      expect(commands).not.toContain("fail-scan");
    } finally {
      clearTimeout(keepAlive);
      await client.close();
    }
  };
  test(name, runCase, 30_000);
}
