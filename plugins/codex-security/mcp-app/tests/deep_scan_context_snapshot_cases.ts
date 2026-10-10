import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { importModule } from "./import-module.ts";
import type { WorkbenchDeepScanStore as Store } from "../src/deep-scan/store.js";
import type { DeepScanWorkerRunner as Runner } from "../src/deep-scan/worker-runner.js";
import type { createDeepScanArtifacts as Artifacts } from "../src/deep-scan/artifacts.js";
import type { DeepWorkerParentSandbox } from "../src/deep-scan/parent-sandbox.js";
import type { CodexSdkWorkerExecutor as WorkerExecutor } from "../src/deep-scan/executor.js";
import type {
  CodexWorkerRequest,
  DeepScanWorkerKind,
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
    (await readFile(fixture.executablePath, "utf8")).replace(
      "process.env.FAKE_CODEX_MARKER",
      "process.argv[process.argv.indexOf('--cd') + 1] + '/invocation.json'",
    ),
  );
  const previousPath = process.env.CODEX_CLI_PATH;
  process.env.CODEX_CLI_PATH = fixture.executablePath;
  const environment = {
    ...process.env,
    CODEX_HOME: path.join(fixture.root, "home"),
    CODEX_SECURITY_STATE_DIR: path.join(fixture.root, "state"),
  };
  const command = async (args: string[], input?: string) => {
    const result = spawnSync(
      process.env.PYTHON?.trim() || "python3",
      [path.join(pluginRoot, "scripts/workbench_db.py"), ...args],
      { env: environment, input, encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(result.stdout);
  };
  try {
    const targetPath = path.join(fixture.root, "target");
    await mkdir(targetPath);
    await writeFile(path.join(targetPath, "fixture.py"), "print('fixture')\n");
    await Promise.all(
      ["Review authentication only.", undefined].map(
        async (userContext, index) => {
          const threadId = `context-owner-${index}`;
          let store = new WorkbenchDeepScanStore(command);
          let run = await store.begin({
            targetPath,
            scope: ".",
            threadId,
            userContext,
            scanRoot: path.join(fixture.root, "scans"),
          });
          const invocations: {
            kind: DeepScanWorkerKind;
            invocation: { argv: string[]; stdin: string };
          }[] = [];
          const sdk = new CodexSdkWorkerExecutor({ parentSandbox });
          const executor = {
            async run(request: CodexWorkerRequest) {
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
                          coverage: {
                            completeness: "complete",
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
            const context = JSON.parse(
              fresh.invocation.stdin.match(/```json\n([\s\S]*?)\n```/)![1],
            );
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
          const current = await command(["get-scan", "--scan-id", run.scanId]);
          assert.equal(current.scan.userContext, editedContext);
        },
      ),
    );
  } finally {
    if (previousPath === undefined) delete process.env.CODEX_CLI_PATH;
    else process.env.CODEX_CLI_PATH = previousPath;
  }
}
