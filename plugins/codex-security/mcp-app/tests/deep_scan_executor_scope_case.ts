import assert from "node:assert/strict";
import childProcess, { type SpawnOptions } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { CodexWorkerRequest } from "../src/deep-scan/types.js";
import { assertFlagPair, nativeConfigOverrides } from "./assertions.ts";
import { trustedParentSandbox } from "./support/fake-codex-fixture.ts";
import { importModule } from "./import-module.ts";
import { readJson } from "./support/json.ts";

export async function testLargeScopeTransport({
  fakeCodexFixture,
  captureDeepScanExecutionSettings,
  workerRequest,
  restoreEnv,
}: {
  fakeCodexFixture: () => Promise<{ root: string; executablePath: string }>;
  captureDeepScanExecutionSettings: typeof import("../src/deep-scan/recovery-settings.js").captureDeepScanExecutionSettings;
  workerRequest: (
    promptPath: string,
    workingDirectory: string,
    overrides?: Partial<CodexWorkerRequest>,
  ) => CodexWorkerRequest;
  restoreEnv: (name: string, value: string | undefined) => void;
}) {
  const engineSource = new URL("../src/deep-scan/engine.ts", import.meta.url);
  const { startDeepScanEngine } = await importModule({
    entryPoints: [fileURLToPath(engineSource)],
    loader: { ".md": "text" },
    define: { "import.meta.url": JSON.stringify(engineSource.href) },
    banner: {
      js: `import { createRequire as engineScopeRequire } from "node:module"; const require = engineScopeRequire(${JSON.stringify(engineSource.href)});`,
    },
    plugins: [
      {
        name: "capture-coordinator-options",
        setup(build) {
          build.onLoad({ filter: /[/\\]registry\.ts$/ }, () => ({
            contents:
              "export function startOrJoinDeepScanCoordinator(options) { return options; }",
            loader: "js",
          }));
        },
      },
    ],
  });
  const names = [
    "CODEX_CLI_PATH",
    "CODEX_HOME",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    "FAKE_CODEX_MARKER",
  ];
  const saved = names.map((name) => [name, process.env[name]] as const);
  const originalSpawn = childProcess.spawn;
  const fixture = await fakeCodexFixture();
  const scanIds = [randomUUID(), randomUUID()];
  try {
    process.env.CODEX_CLI_PATH = process.execPath;
    process.env.CODEX_HOME = fixture.root;
    delete process.env.CODEX_SECURITY_CONFIG_PATH;
    delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
    await mkdir(path.join(fixture.root, "sessions"));
    for (const index of [0, 1]) {
      await writeFile(
        path.join(fixture.root, "sessions", `parent-${index}.jsonl`),
        [
          {
            type: "session_meta",
            timestamp: "2026-01-01T00:00:00Z",
            payload: { id: `scope-parent-${index}` },
          },
          {
            type: "turn_context",
            timestamp: "2026-01-01T00:00:01Z",
            payload: {
              turn_id: "original-turn",
              cyber_access_program: index === 0 ? "standard" : "daybreak_blue",
            },
          },
          {
            type: "turn_context",
            timestamp: "2026-01-01T00:00:30Z",
            payload: {
              turn_id: "later-turn",
              cyber_access_program: "daybreak_red",
            },
          },
        ]
          .map((event) => JSON.stringify(event))
          .join("\n") + "\n",
      );
    }
    childProcess.spawn = ((
      command: string,
      args: readonly string[],
      options: SpawnOptions,
    ) =>
      originalSpawn(command, [fixture.executablePath, ...args], {
        ...options,
        env: {
          ...options.env,
          FAKE_CODEX_MARKER: path.join(
            String(options.cwd ?? args[args.indexOf("--cd") + 1]),
            "invocation.json",
          ),
          FAKE_CODEX_PREFLIGHT_MARKER: path.join(
            String(options.cwd),
            "preflight.json",
          ),
        },
      })) as typeof childProcess.spawn;
    syncBuiltinESMExports();
    for (const kind of ["discovery", "dedup"] as const) {
      for (const resumed of [false, true]) {
        let control: number[] = [];
        for (const count of [2, 16384]) {
          const sizes = await Promise.all(
            scanIds.map(async (scanId, index) => {
              const workerRoot = path.join(
                fixture.root,
                `scan-${index} café`,
                `${kind}-${resumed}`,
              );
              const output = path.join(workerRoot, "output");
              const prompt = path.join(workerRoot, "prompt.md");
              await mkdir(output, { recursive: true });
              await writeFile(prompt, "CAPTURE_SCOPE_INPUT");
              const includePaths = Array.from(
                { length: count },
                (_, row) =>
                  `scan-${index}/background jobs/café-${row}-${"a".repeat(110)}`,
              );
              const run = {
                scanId,
                scanDir: workerRoot,
                targetPath: fixture.root,
                scope: ".",
                includePaths,
                filePaths: includePaths.filter((_, index) => index % 2 === 0),
                startDisposition: resumed ? "resumed" : "created",
                createdAt: "2026-01-01T00:01:00Z",
                usageOwner: {
                  threadId: `scope-parent-${index}`,
                  turnId: "original-turn",
                  startedAt: "2026-01-01T00:01:00Z",
                },
                executionSettings: {
                  version: 1,
                  settings: await captureDeepScanExecutionSettings(
                    {
                      usageOwner: {
                        threadId: `scope-parent-${index}`,
                        turnId: "original-turn",
                        startedAt: "2026-01-01T00:01:00Z",
                      },
                    },
                    trustedParentSandbox,
                  ),
                },
              };
              const captured = startDeepScanEngine({
                run,
                store: {},
                registry: {},
                runWorkbench: async () => ({}),
                pluginRoot: fixture.root,
                pythonCommand: process.env.PYTHON || "python3",
                parentSandbox: trustedParentSandbox,
                threadId: `scope-parent-${index}`,
                parentTurn: {
                  threadId: `scope-parent-${index}`,
                  turnId: "original-turn",
                },
              });
              const executor = await captured.options.prepareExecutor(run);
              await executor.run(
                workerRequest(prompt, output, {
                  kind,
                  ...(resumed
                    ? { resumeThreadId: `scope-thread-${index}` }
                    : {}),
                  artifactContext: {
                    root: output,
                    layout: kind === "dedup" ? "reducer" : "worker",
                    ...(kind === "dedup"
                      ? {
                          deepReducer: {
                            scanRoot: workerRoot,
                            claimedWorkers: [
                              {
                                id: "source-worker",
                                resultPath: path.join(
                                  workerRoot,
                                  "accepted.json",
                                ),
                              },
                            ],
                          },
                        }
                      : {}),
                  },
                }),
              );
              const invocation = await readJson(output, "invocation.json");
              assertFlagPair(
                invocation.argv,
                "--cyber-access-program",
                index === 0 ? "standard" : "daybreak_blue",
              );
              assert.deepEqual(invocation.scopeInput.paths, includePaths);
              assert.deepEqual(
                invocation.scopeInput.filePaths,
                includePaths.filter((_, index) => index % 2 === 0),
              );
              assert.equal(path.isAbsolute(invocation.scopeInput.file), true);
              await assert.rejects(readFile(invocation.scopeInput.file), {
                code: "ENOENT",
              });
              assert.equal(invocation.argv.includes("resume"), resumed);
              const argument = nativeConfigOverrides(invocation.argv).find(
                (value) => value.startsWith("mcp_servers="),
              )!;
              assert.ok(argument);
              return Buffer.byteLength(argument);
            }),
          );
          if (count === 2) control = sizes;
          else
            assert.deepEqual(
              sizes,
              control,
              "scope size must not increase the native command arguments",
            );
        }
      }
    }
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    for (const [name, value] of saved) restoreEnv(name, value);
  }
}
