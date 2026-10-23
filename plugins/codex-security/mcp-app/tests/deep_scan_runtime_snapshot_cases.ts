import assert from "node:assert/strict";
import childProcess, { type SpawnOptions } from "node:child_process";
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import path from "node:path";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import {
  assertConfigOverrides,
  workerPermissionProfileOverride,
} from "./assertions.ts";
import { readJson } from "./support/json.ts";
import type { DeepWorkerParentSandbox } from "../src/deep-scan/parent-sandbox.js";
import type { CodexWorkerRequest } from "../src/deep-scan/types.js";
import type { createFakeCodexFixture } from "./support/fake-codex-fixture.ts";

interface Dependencies {
  CodexSdkWorkerExecutor: typeof import("../src/deep-scan/executor.js").CodexSdkWorkerExecutor;
  captureDeepScanExecutionSettings: typeof import("../src/deep-scan/recovery-settings.js").captureDeepScanExecutionSettings;
  restoredDeepScanWorkerSettings: typeof import("../src/deep-scan/recovery-settings.js").restoredDeepScanWorkerSettings;
  fakeCodexFixture: () => ReturnType<typeof createFakeCodexFixture>;
  parentSandbox: DeepWorkerParentSandbox;
}

export async function testDurableWorkerRuntimeSnapshots({
  CodexSdkWorkerExecutor,
  captureDeepScanExecutionSettings,
  restoredDeepScanWorkerSettings,
  fakeCodexFixture,
  parentSandbox,
}: Dependencies) {
  async function prepareOwner(
    name: string,
    context: number,
    search: string,
    protectedHome = true,
  ) {
    const fixture = await fakeCodexFixture();
    const home = path.join(fixture.root, "home");
    const originalRuntime = path.join(home, "original-runtime");
    await mkdir(originalRuntime, { recursive: true });
    const configPath = path.join(originalRuntime, "config.toml");
    const snapshotPath = path.join(originalRuntime, "workers.toml");
    const currentConfigPath = path.join(fixture.root, "current.toml");
    const currentSnapshotPath = path.join(fixture.root, "current-workers.toml");
    const promptPath = path.join(fixture.root, "prompt.md");
    const instructionsPath = path.join(fixture.root, "instructions.md");
    await writeFile(promptPath, "NULL_USAGE fixture worker\n");
    await writeFile(instructionsPath, `Original ${name} file instructions.\n`);
    const config = {
      model: "fixture-model",
      features: { api_key_cyber_access_programs: false },
    };
    await writeFile(configPath, stringifyToml(config));
    await writeFile(currentConfigPath, stringifyToml(config));
    const workerConfig = {
      web_search: search,
      model_context_window: context,
      developer_instructions: `Original ${name} instructions.`,
      model_instructions_file: instructionsPath,
      otel: {
        exporter: {
          "otlp-http": {
            endpoint: "https://telemetry.example.invalid/v1/traces",
            headers: { Authorization: `synthetic-${name}-telemetry` },
          },
        },
      },
    };
    await writeFile(
      snapshotPath,
      stringifyToml({
        worker_runtime: {
          ...workerConfig,
          environment: { SYNTHETIC_GATEWAY_KEY: `synthetic-${name}-old` },
        },
      }),
    );
    await writeFile(
      currentSnapshotPath,
      stringifyToml({
        worker_runtime: {
          web_search: "live",
          model_context_window: 9000,
          developer_instructions: "Continuation instructions.",
          environment: { SYNTHETIC_GATEWAY_KEY: `synthetic-${name}-new` },
        },
      }),
    );
    const sandbox = {
      ...parentSandbox,
      filesystemDenies: [
        ...parentSandbox.filesystemDenies,
        ...(protectedHome ? [home] : [configPath, snapshotPath]),
      ],
    };
    const expectedProfile = {
      extends: ":read-only",
      filesystem: {
        ":root": "read",
        ...Object.fromEntries(
          sandbox.filesystemDenies.map((value) => [value, "deny"]),
        ),
      },
      network: { enabled: false },
    };
    const environment = {
      ...process.env,
      CODEX_HOME: home,
      CODEX_CLI_PATH: process.execPath,
      CODEX_SECURITY_CONFIG_PATH: configPath,
      CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: snapshotPath,
      CODEX_API_KEY: "synthetic-worker-key",
      FAKE_CODEX_MARKER: fixture.markerPath,
      FAKE_CODEX_PREFLIGHT_PROFILE: JSON.stringify(expectedProfile),
    };
    const captureEnvironment = protectedHome
      ? environment
      : {
          ...environment,
          CODEX_SECURITY_CONFIG_PATH: path.relative(process.cwd(), configPath),
          CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: path.relative(
            process.cwd(),
            snapshotPath,
          ),
        };
    const saved = await captureDeepScanExecutionSettings(
      {},
      sandbox,
      captureEnvironment,
    );
    const repeated = await captureDeepScanExecutionSettings(
      {},
      sandbox,
      captureEnvironment,
    );
    assert.equal(saved.runtimeConfigPath, repeated.runtimeConfigPath);
    const serialized = JSON.stringify(saved);
    assert.equal(serialized.includes("synthetic-"), false);
    assert.equal(
      serialized.includes(workerConfig.developer_instructions),
      false,
    );
    if (protectedHome) assert.ok(saved.runtimeConfigPath);
    else {
      assert.equal(saved.runtimeConfigPath, undefined);
      assert.ok(saved.runtimeConfigSource);
      await assert.rejects(
        stat(path.join(home, "codex-security-worker-settings")),
        { code: "ENOENT" },
      );
    }
    if (saved.runtimeConfigPath && process.platform !== "win32") {
      assert.equal((await stat(saved.runtimeConfigPath)).mode & 0o777, 0o600);
      assert.equal(
        (await stat(path.dirname(saved.runtimeConfigPath))).mode & 0o777,
        0o700,
      );
    }
    const currentEnvironment = {
      ...environment,
      CODEX_SECURITY_CONFIG_PATH: currentConfigPath,
      CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: currentSnapshotPath,
    };
    return {
      ...fixture,
      name,
      home,
      sandbox,
      expectedProfile,
      snapshotPath,
      protectedHome,
      workerConfig,
      promptPath,
      originalRuntime,
      saved,
      currentEnvironment,
      fresh: new CodexSdkWorkerExecutor({
        parentSandbox: sandbox,
        codexOptions: { codexPathOverride: process.execPath, env: environment },
      }),
    };
  }
  const owners = await Promise.all([
    prepareOwner("first", 1000, "disabled"),
    prepareOwner("second", 2000, "cached"),
    prepareOwner("referenced", 3000, "disabled", false),
  ]);
  assert.notEqual(
    owners[0]!.saved.runtimeConfigPath,
    owners[1]!.saved.runtimeConfigPath,
  );
  const originalSpawn = childProcess.spawn;
  let spawned = 0;
  childProcess.spawn = ((
    command: string,
    args: readonly string[] = [],
    options: SpawnOptions = {},
  ) => {
    const owner = owners.find((item) => item.home === options.env?.CODEX_HOME);
    assert.ok(owner);
    spawned += 1;
    return originalSpawn(command, [owner.executablePath, ...args], options);
  }) as typeof childProcess.spawn;
  syncBuiltinESMExports();
  const request = (
    owner: (typeof owners)[number],
    kind: "discovery" | "dedup",
    resumed = false,
  ): CodexWorkerRequest => ({
    kind,
    promptPath: owner.promptPath,
    workingDirectory: owner.root,
    subagents: 0,
    signal: new AbortController().signal,
    ...(resumed ? { resumeThreadId: `fixture-${owner.name}-${kind}` } : {}),
  });
  try {
    for (const restored of [false, true]) {
      if (restored) {
        await Promise.all(
          owners
            .filter((owner) => owner.protectedHome)
            .map((owner) => rm(owner.originalRuntime, { recursive: true })),
        );
      }
      for (const kind of ["discovery", "dedup"] as const) {
        await Promise.all(
          owners.map(async (owner) => {
            const executor = restored
              ? new CodexSdkWorkerExecutor(
                  restoredDeepScanWorkerSettings(
                    JSON.parse(JSON.stringify(owner.saved)),
                    owner.sandbox,
                    () => owner.currentEnvironment,
                  ),
                )
              : owner.fresh;
            await executor.run(request(owner, kind, restored));
            const child = await readJson(owner.markerPath);
            const profile = parseToml(
              workerPermissionProfileOverride(child.argv),
            ).permissions as Record<string, unknown>;
            assert.deepEqual(
              JSON.parse(
                JSON.stringify(profile.codex_security_deep_scan_worker),
              ),
              owner.expectedProfile,
            );
            assertConfigOverrides(child.argv, {
              web_search: owner.workerConfig.web_search,
              model_context_window: owner.workerConfig.model_context_window,
              developer_instructions: owner.workerConfig.developer_instructions,
              model_instructions_file:
                owner.workerConfig.model_instructions_file,
              "otel.exporter.otlp-http.headers.Authorization": `synthetic-${owner.name}-telemetry`,
            });
            assert.equal(
              child.providerKey,
              `synthetic-${owner.name}-${restored ? "new" : "old"}`,
            );
            assert.match(
              await readFile(
                owner.workerConfig.model_instructions_file,
                "utf8",
              ),
              /Original/,
            );
          }),
        );
      }
    }
    const referenced = owners[2]!;
    await writeFile(
      referenced.snapshotPath,
      stringifyToml({
        worker_runtime: {
          ...Object.fromEntries(
            Object.entries(referenced.workerConfig).reverse(),
          ),
          environment: { SYNTHETIC_GATEWAY_KEY: "synthetic-rotated-original" },
          native_profile: "already-removed-original-profile",
        },
      }),
    );
    const executor = new CodexSdkWorkerExecutor(
      restoredDeepScanWorkerSettings(
        referenced.saved,
        referenced.sandbox,
        () => referenced.currentEnvironment,
      ),
    );
    const previousCwd = process.cwd();
    try {
      process.chdir(referenced.root);
      await executor.run(request(referenced, "dedup", true));
    } finally {
      process.chdir(previousCwd);
    }
    assert.equal(
      (await readJson(referenced.markerPath)).providerKey,
      "synthetic-referenced-new",
    );
    await writeFile(
      referenced.snapshotPath,
      stringifyToml({
        worker_runtime: {
          ...referenced.workerConfig,
          model_context_window: 9999,
        },
      }),
    );
    for (const missing of [false, true]) {
      if (missing) await rm(referenced.snapshotPath);
      const before = spawned;
      const changed = new CodexSdkWorkerExecutor(
        restoredDeepScanWorkerSettings(
          referenced.saved,
          referenced.sandbox,
          () => referenced.currentEnvironment,
        ),
      );
      await assert.rejects(
        changed.run(request(referenced, "discovery")),
        /could not be restored/,
      );
      assert.equal(spawned, before);
    }
    const owner = owners[0]!;
    for (const invalid of [false, true]) {
      const snapshot = owner.saved.runtimeConfigPath!;
      if (invalid) await writeFile(snapshot, "invalid = [");
      else await rm(snapshot);
      const before = spawned;
      const executor = new CodexSdkWorkerExecutor(
        restoredDeepScanWorkerSettings(
          owner.saved,
          owner.sandbox,
          () => owner.currentEnvironment,
        ),
      );
      await assert.rejects(executor.run(request(owner, "discovery")));
      assert.equal(
        spawned,
        before,
        "unavailable saved settings must fail before launch",
      );
    }
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
  }
}
