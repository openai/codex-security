import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseToml } from "smol-toml";
import { importModule } from "./import-module.ts";
import type { WorkbenchDeepScanStore as Store } from "../src/deep-scan/store.js";
import type { DeepScanWorkerRunner as Runner } from "../src/deep-scan/worker-runner.js";
import type { createDeepScanArtifacts as Artifacts } from "../src/deep-scan/artifacts.js";
import type { DeepWorkerParentSandbox } from "../src/deep-scan/parent-sandbox.js";
import type { CodexSdkWorkerExecutor as WorkerExecutor } from "../src/deep-scan/executor.js";
import type {
  CodexWorkerRequest,
  DeepScanWorkerKind,
  DeepScanRunState,
} from "../src/deep-scan/types.js";

export async function testDeepScanContextSnapshots({
  CodexSdkWorkerExecutor,
  fakeCodexFixture,
  parentSandbox,
}: {
  CodexSdkWorkerExecutor: typeof WorkerExecutor;
  fakeCodexFixture: () => Promise<{ root: string; executablePath: string }>;
  parentSandbox: DeepWorkerParentSandbox;
}) {
  const pluginRoot = fileURLToPath(new URL("../../", import.meta.url));
  const {
    WorkbenchDeepScanStore,
    DeepScanWorkerRunner,
    createDeepScanArtifacts,
  } = (await importModule({
    stdin: {
      contents: [
        'export { WorkbenchDeepScanStore } from "./store.ts";',
        'export { DeepScanWorkerRunner } from "./worker-runner.ts";',
        'export { createDeepScanArtifacts } from "./artifacts.ts";',
      ].join("\n"),
      resolveDir: path.join(pluginRoot, "mcp-app/src/deep-scan"),
    },
    loader: { ".md": "text" },
  })) as {
    WorkbenchDeepScanStore: typeof Store;
    DeepScanWorkerRunner: typeof Runner;
    createDeepScanArtifacts: typeof Artifacts;
  };
  const fixture = await fakeCodexFixture();
  // Concurrent children record their input in their own working directories.
  await writeFile(
    fixture.executablePath,
    (await readFile(fixture.executablePath, "utf8"))
      .replace(
        "process.env.FAKE_CODEX_MARKER",
        "process.argv[process.argv.indexOf('--cd') + 1] + '/invocation.json'",
      )
      .replace(
        "'RUNNER_TRACKING_ID'",
        "'RUNNER_TRACKING_ID', 'CODEX_SECURITY_ENABLE_REMOTE_SEVERITY_RUBRIC'",
      ),
  );
  const previousPath = process.env.CODEX_CLI_PATH;
  const previousDeepConfig = process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
  const rubricSetting = "CODEX_SECURITY_ENABLE_REMOTE_SEVERITY_RUBRIC";
  const previousRubricSetting = process.env[rubricSetting];
  process.env.CODEX_CLI_PATH = fixture.executablePath;
  const environment = {
    ...process.env,
    CODEX_HOME: path.join(fixture.root, "home"),
    CODEX_SECURITY_STATE_DIR: path.join(fixture.root, "state"),
  };
  try {
    const contexts: {
      userContext?: string;
      severityRubric?: DeepScanRunState["severityRubric"];
      initialRemoteRubricSetting?: "1" | "0";
    }[] = [{ userContext: "Review authentication only." }, {}];
    for (const { initialRemoteRubricSetting, markdown, revision } of [
      {
        initialRemoteRubricSetting: "1",
        markdown: "# Hosted policy\n",
        revision: 17,
      },
      {
        initialRemoteRubricSetting: "0",
        markdown: "# Bundled policy\n",
        revision: 1,
      },
    ] as const) {
      contexts.push({
        userContext: "Instructions edited before the first worker starts.",
        severityRubric: {
          markdown,
          revision,
          sha256: createHash("sha256").update(markdown).digest("hex"),
        },
        initialRemoteRubricSetting,
      });
    }
    const targetPath = path.join(fixture.root, "target");
    await mkdir(targetPath);
    await writeFile(path.join(targetPath, "fixture.py"), "print('fixture')\n");
    const outcomes = await Promise.allSettled(
      contexts.map(
        async (
          { userContext, severityRubric, initialRemoteRubricSetting },
          index,
        ) => {
          const deepConfig = path.join(fixture.root, `deep-${index}.toml`);
          const maxTimeHours = 1.5 + index;
          await writeFile(deepConfig, `[deep_scan]\nmax_time_hours = 48\n`);
          const command = async (args: string[], input?: string) => {
            const execution = promisify(execFile)(
              process.env.PYTHON?.trim() || "python3",
              [path.join(pluginRoot, "scripts/workbench_db.py"), ...args],
              {
                env: {
                  ...environment,
                  CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: deepConfig,
                },
              },
            );
            execution.child.stdin!.on("error", () => {});
            execution.child.stdin!.end(input);
            return JSON.parse((await execution).stdout);
          };
          const threadId = `context-owner-${index}`;
          const projectConfigPath = path.join(
            fixture.root,
            `selected-${index}.json`,
          );
          await writeFile(
            projectConfigPath,
            JSON.stringify({
              scan: {
                deep: {
                  max_time_hours: maxTimeHours,
                  subagents_per_worker: index,
                },
              },
            }),
          );
          let store = new WorkbenchDeepScanStore(command);
          let start:
            { scanId: string } | { targetPath: string; userContext?: string } =
            {
              targetPath,
              userContext,
            };
          if (severityRubric) {
            assert.ok(userContext);
            await writeFile(
              deepConfig,
              `[deep_scan]\nmax_time_hours = ${maxTimeHours}\nsubagents = ${index}\n`,
            );
            const scanDir = path.join(fixture.root, `registered-${index}`);
            await mkdir(scanDir, { mode: 0o700 });
            const { scanId } = await command(
              [
                "register-cli-scan",
                "--repository",
                targetPath,
                "--scan-dir",
                scanDir,
                "--registration-json-stdin",
              ],
              JSON.stringify({
                recipe: {
                  repository: targetPath,
                  mode: "deep",
                  target: { kind: "repository", paths: [] },
                  config: {},
                  severityRubric,
                },
                userContext: "Original user instructions.",
              }),
            );
            await command([
              "set-scan-thread",
              "--scan-id",
              scanId,
              "--thread-id",
              threadId,
            ]);
            await command([
              "update-scan-context",
              "--scan-id",
              scanId,
              "--thread-id",
              threadId,
              "--user-context",
              userContext,
            ]);
            start = { scanId };
          }
          let run = await store.begin({
            ...start,
            threadId,
            projectConfigPath: severityRubric ? undefined : projectConfigPath,
            scanRoot: path.join(fixture.root, "scans"),
          });
          const createdAt = run.createdAt;
          assert.ok(createdAt);
          assert.equal(run.config.maxTimeHours, maxTimeHours);
          assert.equal(run.config.subagents, index);
          const invocations: {
            kind: DeepScanWorkerKind;
            invocation: {
              argv: string[];
              stdin: string;
              deepConfig: string;
              runtimeEnvironment: Record<string, string | undefined>;
            };
          }[] = [];
          let sdk = new CodexSdkWorkerExecutor({
            parentSandbox,
            deepScanConfig: run.config,
          });
          const executor = {
            async run(request: CodexWorkerRequest) {
              process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH = deepConfig;
              if (initialRemoteRubricSetting !== undefined)
                process.env[rubricSetting] = request.resumeThreadId
                  ? initialRemoteRubricSetting
                  : initialRemoteRubricSetting === "1"
                    ? "0"
                    : "1";
              const result = await sdk.run(request);
              invocations.push({
                kind: request.kind,
                invocation: JSON.parse(
                  await readFile(
                    path.join(request.workingDirectory, "invocation.json"),
                    "utf8",
                  ),
                ),
              });
              // A missing result exercises the runner's real SDK resume path.
              if (request.resumeThreadId) {
                await writeFile(
                  path.join(request.artifactContext!.root, "result.json"),
                  JSON.stringify({
                    scanId: run.scanId,
                    findings: [],
                    ...(request.kind === "discovery"
                      ? {
                          reviewState: {
                            surfaces: [],
                            explicitExclusions: [],
                            deferred: [],
                          },
                        }
                      : {}),
                  }),
                );
              }
              return result;
            },
          };
          const runner = () =>
            new DeepScanWorkerRunner({
              run,
              store,
              executor,
              artifacts: createDeepScanArtifacts(run.scanDir),
              pluginRoot,
              clock: { now: Date.now, sleep: async () => {} },
              random: () => 0,
              log: () => {},
              retryDelaysMs: [0],
              signal: new AbortController().signal,
            });
          const first = await runner().runDiscoveryWorker(
            randomUUID(),
            "before-edit",
          );
          assert.ok(first.status === "succeeded");
          const editedContext = `Updated instructions for later phases ${index}.`;
          await command([
            "update-scan-context",
            "--scan-id",
            run.scanId,
            "--thread-id",
            threadId,
            "--user-context",
            editedContext,
          ]);
          // Reload through a new store to model a coordinator restart after editing.
          store = new WorkbenchDeepScanStore(command);
          run = await store.begin({
            scanId: run.scanId,
            threadId,
            scanRoot: path.join(fixture.root, "scans"),
          });
          assert.equal(run.config.maxTimeHours, maxTimeHours);
          assert.equal(run.createdAt, createdAt);
          sdk = new CodexSdkWorkerExecutor({
            parentSandbox,
            deepScanConfig: run.config,
          });
          const second = await runner().runDiscoveryWorker(
            randomUUID(),
            "after-edit",
          );
          assert.ok(second.status === "succeeded");
          const reducerId = randomUUID();
          const reduced = await runner().runReducer({
            id: reducerId,
            label: "reducer",
            consumed: [first.worker, second.worker],
          });
          assert.ok(!("status" in reduced), "Reducer did not succeed");
          assert.equal(
            reduced.run.persistedWorkers?.find(
              (worker) => worker.id === reducerId,
            )?.attempt,
            2,
          );
          assert.equal(invocations.length, 6);
          for (let offset = 0; offset < invocations.length; offset += 2) {
            const fresh = invocations[offset]!;
            const resumed = invocations[offset + 1]!;
            assert.equal(fresh.invocation.argv.includes("resume"), false);
            assert.equal(resumed.invocation.argv.includes("resume"), true);
            if (initialRemoteRubricSetting !== undefined) {
              assert.equal(
                fresh.invocation.runtimeEnvironment[rubricSetting],
                initialRemoteRubricSetting === "1" ? "0" : "1",
              );
              assert.equal(
                resumed.invocation.runtimeEnvironment[rubricSetting],
                initialRemoteRubricSetting,
              );
            }
            for (const { invocation } of [fresh, resumed]) {
              assert.deepEqual(
                { ...(parseToml(invocation.deepConfig).deep_scan as object) },
                {
                  workers: run.config.workers,
                  subagents: index,
                  stop_after_no_new: run.config.stopAfterNoNew,
                  stop_after_consecutive_errors:
                    run.config.stopAfterConsecutiveErrors,
                  max_discovery_runs: run.config.maxDiscoveryRuns,
                  max_time_hours: maxTimeHours,
                },
              );
            }
            const context = JSON.parse(
              fresh.invocation.stdin.match(/```json\n([\s\S]*?)\n```/)![1],
            );
            assert.deepEqual(context.severityRubric, severityRubric);
            if (severityRubric) {
              assert.ok(
                resumed.invocation.stdin.includes(
                  JSON.stringify({ severityRubric }),
                ),
              );
              assert.equal(
                fresh.invocation.stdin.includes("Original user instructions."),
                false,
              );
            }
            if (fresh.kind === "discovery") {
              assert.equal(context.userContext, userContext ?? null);
              assert.equal(context.scanId, run.scanId);
            } else {
              assert.equal(Object.hasOwn(context, "userContext"), false);
              assert.deepEqual(context.claimedWorkerIds, [
                first.worker.id,
                second.worker.id,
              ]);
            }
            assert.equal(fresh.invocation.stdin.includes(editedContext), false);
            assert.equal(
              resumed.invocation.stdin.includes(editedContext),
              false,
            );
            assert.match(resumed.invocation.stdin, /record_codex_security_/);
          }
          await writeFile(deepConfig, "[deep_scan]\nmax_time_hours = 48\n");
          const restarted = await new WorkbenchDeepScanStore(command).begin({
            scanId: run.scanId,
            threadId,
            scanRoot: path.join(fixture.root, "scans"),
          });
          assert.equal(restarted.config.maxTimeHours, maxTimeHours);
          assert.equal(restarted.createdAt, createdAt);
          const current = await command(["get-scan", "--scan-id", run.scanId]);
          assert.equal(current.scan.userContext, editedContext);
        },
      ),
    );
    for (const outcome of outcomes) {
      if (outcome.status === "rejected") throw outcome.reason;
    }
  } finally {
    if (previousRubricSetting === undefined) delete process.env[rubricSetting];
    else process.env[rubricSetting] = previousRubricSetting;
    if (previousPath === undefined) delete process.env.CODEX_CLI_PATH;
    else process.env.CODEX_CLI_PATH = previousPath;
    if (previousDeepConfig === undefined)
      delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
    else process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH = previousDeepConfig;
  }
}
