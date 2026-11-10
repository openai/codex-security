import assert from "node:assert/strict";
import { existsSync, promises as fs } from "node:fs";
import { cp, mkdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { join, relative } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { temporaryDirectory } from "../../plugins/codex-security/mcp-app/tests/support/temporary-directories.ts";
import type { ThreadEvent } from "../../sdk/typescript/node_modules/@openai/codex-sdk/dist/index.js";
import type { JsonObject } from "../../sdk/typescript/src/config.js";
import * as sdk from "../../sdk/typescript/dist/api.js";
import { createIsolatedHome } from "../../sdk/typescript/dist/runtime.js";
import { withEvalState } from "../secret-discovery/runtime.mts";
import { hashText, runComparison } from "./experiment.mts";
import {
  createStandardRunner,
  preflightStandardEval,
  snapshotCodexExecutable,
} from "./production.mts";
import { prepareStandardEval } from "./fixtures.mts";
import { summarizeRuns } from "./summary.mts";

const { CodexSecurity } =
  sdk as unknown as typeof import("../../sdk/typescript/src/api.js");

test("executable provenance follows the configured binary and its actual bytes", async (context) => {
  const root = await temporaryDirectory("time-budget-executable-");
  context.after(() => rm(root, { recursive: true, force: true }));
  const first = join(root, "first.exe");
  const second = join(root, "second.exe");
  await writeFile(first, "synthetic executable one");
  await writeFile(second, "synthetic executable two");
  const snapshot = await snapshotCodexExecutable({ CODEX_CLI_PATH: first });
  assert.deepEqual(snapshot, {
    command: first,
    files: [
      {
        path: await realpath(first),
        sha256: hashText("synthetic executable one"),
      },
    ],
  });
  assert.deepEqual(await snapshotCodexExecutable({ CODEX_CLI_PATH: second }), {
    command: second,
    files: [
      {
        path: await realpath(second),
        sha256: hashText("synthetic executable two"),
      },
    ],
  });
  await writeFile(first, "replaced executable");
  const replaced = await snapshotCodexExecutable({ CODEX_CLI_PATH: first });
  assert.equal(replaced.command, snapshot.command);
  assert.equal(replaced.files[0]!.sha256, hashText("replaced executable"));
  assert.notEqual(replaced.files[0]!.sha256, snapshot.files[0]!.sha256);
});

test("state cleanup failure saves the attempt and stops before the paired arm", async (context) => {
  const root = await temporaryDirectory("time-budget-cleanup-");
  const originalRm = fs.rm;
  context.after(async () => {
    context.mock.restoreAll();
    syncBuiltinESMExports();
    await originalRm(root, { recursive: true, force: true });
  });
  const prepared = await prepareStandardEval(root, "/synthetic/plugin");
  const outputRoot = join(root, "results");
  const states: string[] = [];
  const saved: Awaited<ReturnType<typeof runComparison>> = [];
  context.mock.method(fs, "rm", async (...args: Parameters<typeof fs.rm>) => {
    if (states.includes(String(args[0]))) {
      throw new Error("Synthetic state removal failure");
    }
    return originalRm(...args);
  });
  syncBuiltinESMExports();
  await assert.rejects(
    runComparison({
      prepared,
      config: { model: "eval-model", pairs: 2, budgetMinutes: 5 },
      run: createStandardRunner({
        stateRoot: join(root, "states"),
        outputRoot,
        createClient: (_config, dependencies) => {
          states.push(dependencies.environment["CODEX_SECURITY_STATE_DIR"]!);
          return {
            run: async (_target, options) => {
              await writeFile(join(options!.outputDir!, "partial.json"), "{}");
              throw new Error("Synthetic scan failure");
            },
            close: async () => {
              throw new Error("Synthetic client close failure");
            },
          };
        },
      }),
      onResult: async (record) => {
        saved.push(record);
      },
    }),
    /Synthetic state removal failure/,
  );
  assert.equal(states.length, 1);
  assert.equal(saved.length, 1);
  assert.equal(saved[0]!.status, "failed");
  assert.match(saved[0]!.error!, /Synthetic scan failure/);
  assert.match(saved[0]!.error!, /Synthetic client close failure/);
  assert.match(saved[0]!.error!, /Synthetic state removal failure/);
  assert.equal(existsSync(states[0]!), true);
  assert.equal(
    await readFile(
      join(outputRoot, "pair-1-baseline", "scan", "partial.json"),
      "utf8",
    ),
    "{}",
  );
});

test("the developer eval preflights API-key authentication and the production budget before staging", async () => {
  assert.throws(
    () => preflightStandardEval({}, 5),
    /requires OPENAI_API_KEY or CODEX_API_KEY/,
  );
  for (const name of ["OPENAI_API_KEY", "CODEX_API_KEY"]) {
    preflightStandardEval({ [name]: "synthetic-environment" }, 0.25);
  }
  assert.throws(
    () =>
      preflightStandardEval({ OPENAI_API_KEY: "synthetic-environment" }, 1e12),
    /deadline within the supported date range/,
  );
  await withEvalState(createIsolatedHome, undefined, async ({ home }) => {
    assert.equal(existsSync(join(home, "auth.json")), false);
  });
});

async function writeUsageSession(
  home: string,
  threadId: string,
  usage: Record<string, number>,
  parent?: string,
) {
  const directory = join(home, "sessions", "2026", "01", "01");
  await mkdir(directory, { recursive: true });
  await writeFile(
    join(directory, `rollout-${threadId}.jsonl`),
    [
      JSON.stringify({
        type: "session_meta",
        payload: {
          id: threadId,
          ...(parent === undefined ? {} : { parent_thread_id: parent }),
        },
      }),
      JSON.stringify({
        type: "event_msg",
        payload: {
          type: "token_count",
          info: { total_token_usage: usage },
        },
      }),
      "",
    ].join("\n"),
  );
}

test("the paired evaluator preserves aggregate usage across production completion and failure", async (context) => {
  const root = await temporaryDirectory("time-budget-production-");
  context.after(() => rm(root, { recursive: true, force: true }));
  const pluginRoot = fileURLToPath(
    new URL("../../plugins/codex-security/", import.meta.url),
  );
  const prepared = await prepareStandardEval(root, pluginRoot);
  const outputRoot = join(root, "results");
  await mkdir(outputRoot);
  await writeFile(
    join(outputRoot, "fixture.json"),
    JSON.stringify(prepared.fixture),
  );
  const states: string[] = [];
  const commands: string[] = [];
  const prompts: string[] = [];
  const records = await runComparison({
    prepared,
    config: { model: "gpt-5.6-sol", pairs: 2, budgetMinutes: 5 },
    run: createStandardRunner({
      stateRoot: join(root, "states"),
      outputRoot,
      environment: { OPENAI_API_KEY: "synthetic-environment" },
      createClient: (config, dependencies) => {
        const home = dependencies.environment["CODEX_SECURITY_STATE_DIR"]!;
        states.push(home);
        const client = new CodexSecurity(
          config,
          {
            ...dependencies,
            now: () => Date.UTC(2026, 0, 1),
            probeCodexSandbox: async () => {},
            prepareScanArtifactRestorer: async () => ({
              restore: async () => {},
            }),
            prepareRuntime: async () => ({
              codexHome: home,
              plugin: {
                pluginRoot,
                marketplaceRoot: pluginRoot,
                installedRoot: pluginRoot,
                marketplaceName: "codex-security-sdk",
                name: "codex-security",
                version: "0.1.0",
              },
              environment: {},
              credentialsAvailable: true,
            }),
            resolvePluginPython: async () => "/managed/python",
            repositoryRevision: async () => "deadbeef",
            runWorkbench: async (_options, args): Promise<JsonObject> => {
              commands.push(args[0]!);
              if (
                args[0] === "prepare-scan-completion" &&
                states.length === 1
              ) {
                throw new Error(
                  "Synthetic completion failure after model usage",
                );
              }
              if (args[0] === "register-cli-scan") {
                return {
                  scanId: "scan_example_001",
                  targetId: "target_sha256_example",
                  targetRevision: "deadbeef",
                  scanDir: args[args.indexOf("--scan-dir") + 1]!,
                  contract: { target: { allowedKinds: ["git_revision"] } },
                };
              }
              if (args[0] === "get-scan-feedback") {
                return {
                  scanId: "scan_example_001",
                  targetId: "target_sha256_example",
                  falsePositives: [],
                };
              }
              return {};
            },
          },
          { surface: "sdk" },
        );
        return {
          run: client.run.bind(client),
          close: async () => {
            await client.close();
            if (states.length <= 2)
              throw new Error("Synthetic cleanup failure");
          },
        };
      },
      createCodex: async (options) => ({
        startThread: (threadOptions) => ({
          id: "thread-1",
          runStreamed: async (prompt) => {
            prompts.push(prompt);
            const scanDir = options.env!["CODEX_SECURITY_SCAN_DIR"]!;
            const home = options.env!["CODEX_HOME"]!;
            const nearby = join(scanDir, "..", "..");
            assert.equal(threadOptions?.workingDirectory, scanDir);
            for (const path of [
              scanDir,
              home,
              options.env!["CODEX_SECURITY_STATE_DIR"]!,
            ]) {
              assert.doesNotMatch(relative(root, path), /baseline|time-aware/u);
            }
            assert.equal(existsSync(join(nearby, "fixture.json")), false);
            assert.equal(
              existsSync(join(nearby, "pair-1-time-aware", "result.json")),
              false,
            );
            for (const previous of states.slice(0, -1)) {
              assert.equal(existsSync(previous), false);
            }
            await writeUsageSession(home, "thread-1", {
              input_tokens: 100,
              output_tokens: 20,
            });
            await writeUsageSession(
              home,
              "worker-thread",
              { input_tokens: 50, output_tokens: 7 },
              "thread-1",
            );
            await cp(join(pluginRoot, "examples", "completed-scan"), scanDir, {
              recursive: true,
            });
            await writeFile(
              join(scanDir, "report.md"),
              "# Finalized synthetic report\n",
            );
            async function* events(): AsyncGenerator<ThreadEvent> {
              yield { type: "thread.started", thread_id: "thread-1" };
              yield { type: "turn.started" };
              yield {
                type: "turn.completed",
                usage: {
                  input_tokens: 10,
                  cached_input_tokens: 2,
                  cache_write_input_tokens: 0,
                  output_tokens: 3,
                  reasoning_output_tokens: 1,
                },
              };
            }
            return { events: events() };
          },
        }),
      }),
    }),
    onResult: async (record, result) => {
      assert.equal(existsSync(states.at(-1)!), false);
      if (result !== undefined) {
        await writeFile(
          join(
            outputRoot,
            `pair-${record.pair}-${record.variant}`,
            "result.json",
          ),
          JSON.stringify(result),
        );
      }
    },
  });
  assert.equal(new Set(states).size, 4);
  assert.equal(prompts.length, 4, JSON.stringify(records));
  assert.ok(!prompts[0].includes("# Investigation time allowance"));
  assert.ok(prompts[1].includes("2026-01-01T00:05:00.000Z"));
  assert.deepEqual(
    records.map((record) => record.status),
    ["failed", "failed", "completed", "completed"],
    JSON.stringify(records),
  );
  assert.match(
    records[0].error!,
    /Synthetic completion failure after model usage/,
  );
  assert.match(records[0].error!, /Synthetic cleanup failure/);
  assert.equal(records[1].error, "Synthetic cleanup failure");
  assert.equal(
    commands.filter((command) => command === "prepare-scan-completion").length,
    4,
  );
  assert.equal(
    commands.filter((command) => command === "complete-scan").length,
    3,
  );
  for (const [index, record] of records.entries()) {
    assert.partialDeepStrictEqual(record.usage, {
      input_tokens: 150,
      output_tokens: 27,
    });
    const archivedReport = join(
      outputRoot,
      `pair-${record.pair}-${record.variant}`,
      "scan",
      "report.md",
    );
    assert.match(
      await readFile(archivedReport, "utf8"),
      /Finalized synthetic report/,
    );
    if (record.status === "completed")
      assert.equal(record.report.reportPath, archivedReport);
    assert.equal(record.promptSha256, hashText(prompts[index]));
  }
  const summary = summarizeRuns(records);
  assert.equal(summary.arms.baseline.usage.total_tokens, 354);
  assert.equal(summary.paired.completedPairs, 1);
  assert.equal(summary.paired.excludedPairs, 1);
});
