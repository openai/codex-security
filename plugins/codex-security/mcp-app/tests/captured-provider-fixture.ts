import { importSource } from "./import-module.ts";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import childProcess, { type SpawnOptions } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import path from "node:path";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import { assertConfigOverrides } from "./assertions.ts";
import type { DeepWorkerParentSandbox } from "../src/deep-scan/parent-sandbox.js";

export async function testCapturedCustomProviderSettings({
  fakeCodexFixture,
  captureDeepScanExecutionSettings,
  loadDeepScanExecutionSettings,
  restoredDeepScanWorkerSettings,
  trustedParentSandbox,
  CodexSdkWorkerExecutor,
}: {
  fakeCodexFixture(): Promise<{
    root: string;
    markerPath: string;
    executablePath: string;
  }>;
  captureDeepScanExecutionSettings: typeof import("../src/deep-scan/recovery-settings.js").captureDeepScanExecutionSettings;
  loadDeepScanExecutionSettings: typeof import("../src/deep-scan/recovery-settings.js").loadDeepScanExecutionSettings;
  restoredDeepScanWorkerSettings: typeof import("../src/deep-scan/recovery-settings.js").restoredDeepScanWorkerSettings;
  trustedParentSandbox: DeepWorkerParentSandbox;
  CodexSdkWorkerExecutor: typeof import("../src/deep-scan/executor.js").CodexSdkWorkerExecutor;
}) {
  const { projectWorkerSettings } = await importSource(
    fileURLToPath(
      new URL("../src/deep-scan/worker-settings.ts", import.meta.url),
    ),
  );
  const originalSpawn = childProcess.spawn;
  const scans = await Promise.all(
    ["openrouter", "fireworks"]
      .flatMap((provider) =>
        ["current", "current-private", "legacy-recipe", "legacy-native"].map(
          (mode) => ({
            provider,
            mode,
          }),
        ),
      )
      .map(async ({ provider, mode }, index) => {
        const fixture = await fakeCodexFixture();
        const codexHome = path.join(fixture.root, "provider-home");
        await mkdir(codexHome, { mode: 0o700 });
        const configPath = path.join(codexHome, "config.toml");
        const definition = {
          name: "Synthetic provider",
          base_url: `http://127.0.0.1:9/scan-${index}/v1`,
          env_key: `SYNTHETIC_PROVIDER_${index}_KEY`,
          wire_api: "responses",
        };
        await writeFile(
          configPath,
          `model_provider = "${provider}"\n[model_providers.${provider}]\n` +
            Object.entries(definition)
              .map(([k, v]) => `${k} = ${JSON.stringify(v)}\n`)
              .join(""),
        );
        const environment = {
          ...process.env,
          CODEX_HOME: codexHome,
          CODEX_CLI_PATH: process.execPath,
          CODEX_SECURITY_CONFIG_PATH: configPath,
          FAKE_CODEX_MARKER: fixture.markerPath,
        };
        if (mode === "current-private") {
          const nativeProfile = { name: `codex_security_fixture_${index}` };
          await writeFile(
            path.join(codexHome, `${nativeProfile.name}.config.toml`),
            stringifyToml({ model_providers: { [provider]: definition } }),
            { mode: 0o600 },
          );
          await writeFile(
            configPath,
            stringifyToml(projectWorkerSettings({ model_provider: provider })),
          );
          const workerConfigPath = path.join(codexHome, "worker-runtime.toml");
          await writeFile(
            workerConfigPath,
            stringifyToml({
              worker_runtime: { native_profile: nativeProfile.name },
            }),
          );
          Object.assign(environment, {
            CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: workerConfigPath,
          });
        }
        const threadId = `legacy-provider-${index}`;
        await mkdir(path.join(codexHome, "sessions"));
        await writeFile(
          path.join(codexHome, "sessions", "owner.jsonl"),
          JSON.stringify({
            type: "session_meta",
            timestamp: "2026-01-01T00:00:00Z",
            payload: { id: threadId, model_provider: provider },
          }) + "\n",
        );
        const saved = mode.startsWith("current")
          ? await captureDeepScanExecutionSettings(
              { model: `fixture-${index}`, usageOwner: null },
              trustedParentSandbox,
              environment,
            )
          : await loadDeepScanExecutionSettings(
              codexHome,
              {
                workflowVersion: "deep-security-scan/v1",
                usageOwner:
                  mode === "legacy-native"
                    ? {
                        threadId,
                        turnId: null,
                        startedAt: "2026-01-01T00:00:01Z",
                      }
                    : undefined,
                createdAt: "2026-01-01T00:00:01Z",
              },
              async () => ({
                config:
                  mode === "legacy-recipe"
                    ? {
                        model_provider: provider,
                        model_providers: { [provider]: definition },
                      }
                    : {},
              }),
              environment,
            );
        const restored = restoredDeepScanWorkerSettings(
          saved,
          trustedParentSandbox,
          () => environment,
        );
        const promptPath = path.join(fixture.root, "prompt.md");
        await writeFile(promptPath, "Synthetic captured provider worker.");
        return {
          fixture,
          configPath,
          definition,
          provider,
          mode,
          codexHome,
          promptPath,
          executor: new CodexSdkWorkerExecutor(restored),
        };
      }),
  );
  childProcess.spawn = ((
    command: string,
    args: readonly string[] = [],
    options: SpawnOptions = {},
  ) => {
    const scan = scans.find(
      (s) => options.env?.FAKE_CODEX_MARKER === s.fixture.markerPath,
    );
    return originalSpawn(
      command,
      scan ? [scan.fixture.executablePath, ...args] : args,
      options,
    );
  }) as unknown as typeof childProcess.spawn;
  syncBuiltinESMExports();
  try {
    for (const resume of [false, true]) {
      for (const kind of ["discovery", "dedup"] as const) {
        const results = await Promise.allSettled(
          scans.map(async (scan) => {
            await scan.executor.run({
              kind,
              promptPath: scan.promptPath,
              workingDirectory: scan.fixture.root,
              subagents: 0,
              resumeThreadId: resume ? "fixture-resumed-thread" : undefined,
              signal: new AbortController().signal,
            });
            const invocation = JSON.parse(
              await readFile(scan.fixture.markerPath, "utf8"),
            );
            assert.equal(invocation.argv.includes("resume"), resume);
            assert.equal(invocation.codexHome, scan.codexHome);
            assertConfigOverrides(invocation.argv, {
              model_provider: scan.provider,
            });
            const providers = parseToml(
              invocation.argv
                .filter((arg: string) => /^model_providers[.=]/u.test(arg))
                .join("\n"),
            ).model_providers;
            if (scan.mode === "current-private") {
              assert.equal(
                providers,
                undefined,
                "preflight defaults must not override the private provider profile",
              );
              const profileIndex = invocation.argv.indexOf("--profile");
              assert.notEqual(profileIndex, -1);
              const profile = parseToml(
                await readFile(
                  path.join(
                    scan.codexHome,
                    `${invocation.argv[profileIndex + 1]}.config.toml`,
                  ),
                  "utf8",
                ),
              );
              assert.deepEqual(
                JSON.parse(JSON.stringify(profile.model_providers)),
                {
                  [scan.provider]: scan.definition,
                },
              );
            } else if (scan.mode === "legacy-native") {
              assert.equal(
                providers,
                undefined,
                "home-owned routing is resolved by native without a generated override",
              );
              const nativeConfig = parseToml(
                await readFile(scan.configPath, "utf8"),
              );
              assert.equal(nativeConfig.model_provider, scan.provider);
            } else {
              assert.deepEqual(JSON.parse(JSON.stringify(providers)), {
                [scan.provider]: scan.definition,
              });
            }
          }),
        );
        const failures = results.flatMap((result) =>
          result.status === "rejected" ? [result.reason] : [],
        );
        assert.equal(
          failures.length,
          0,
          failures.map((error) => error.stack ?? error.message).join("\n"),
        );
      }
      for (const scan of scans.filter(
        (scan) => !["legacy-native", "current-private"].includes(scan.mode),
      ))
        await writeFile(scan.configPath, 'model_provider = "openai"\n');
    }
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
  }
}
