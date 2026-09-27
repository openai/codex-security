import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

export async function testDeepScanContextSnapshots({
  CodexSdkWorkerExecutor,
  fakeCodexFixture,
  parentSandbox,
}) {
  const pluginRoot = fileURLToPath(new URL("../../", import.meta.url));
  const bundle = await build({
    bundle: true,
    stdin: {
      contents: [
        'export { WorkbenchDeepScanStore } from "./store.ts";',
        'export { DeepScanWorkerRunner } from "./worker-runner.ts";',
        'export { createDeepScanArtifacts } from "./artifacts.ts";',
      ].join("\n"),
      resolveDir: path.join(pluginRoot, "mcp-app/src/deep-scan"),
    },
    loader: { ".md": "text" },
    format: "esm",
    platform: "node",
    write: false,
  });
  const {
    WorkbenchDeepScanStore,
    DeepScanWorkerRunner,
    createDeepScanArtifacts,
  } = await import(
    `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
  );
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
  const command = async (args, input) => {
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
          const begun = await store.begin({
            targetPath,
            scope: ".",
            threadId,
            userContext,
            scanRoot: path.join(fixture.root, "scans"),
          });
          let run = begun.run;
          const invocations = [];
          const sdk = new CodexSdkWorkerExecutor({ parentSandbox });
          const executor = {
            async run(request) {
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
                  path.join(request.artifactContext.root, "result.json"),
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
              clock: { sleep: async () => {} },
              random: () => 0,
              log: () => {},
              retryDelaysMs: [0],
              signal: new AbortController().signal,
            });
          const first = await runner().runDiscoveryWorker(
            randomUUID(),
            "before-edit",
          );
          assert.equal(first.status, "succeeded", first.error?.message);
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
          run = (await store.begin({ scanId: run.scanId, threadId })).run;
          const second = await runner().runDiscoveryWorker(
            randomUUID(),
            "after-edit",
          );
          assert.equal(second.status, "succeeded", second.error?.message);
          const reduced = await runner().runReducer({
            id: randomUUID(),
            label: "reducer",
            consumed: [first.worker, second.worker],
          });
          assert.equal(reduced.status, undefined, reduced.error?.message);
          assert.equal(reduced.attempt, 2);
          assert.equal(invocations.length, 6);
          for (let offset = 0; offset < invocations.length; offset += 2) {
            const fresh = invocations[offset];
            const resumed = invocations[offset + 1];
            assert.equal(fresh.invocation.argv.includes("resume"), false);
            assert.equal(resumed.invocation.argv.includes("resume"), true);
            const context = JSON.parse(
              fresh.invocation.stdin.match(/```json\n([\s\S]*?)\n```/)[1],
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
