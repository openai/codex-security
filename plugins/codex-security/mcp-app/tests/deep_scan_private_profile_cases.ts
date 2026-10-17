import assert from "node:assert/strict";
import childProcess, { type SpawnOptions } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import { assertConfigOverrides } from "./assertions.ts";
import { importModule } from "./import-module.ts";
import { readJson } from "./support/json.ts";
import type { CodexWorkerRequest } from "../src/deep-scan/types.js";
import type { fakeCodexFixture as createFixture } from "./test_deep_scan_executor.ts";

interface Dependencies {
  CodexSdkWorkerExecutor: typeof import("../src/deep-scan/executor.js").CodexSdkWorkerExecutor;
  captureDeepScanExecutionSettings: typeof import("../src/deep-scan/recovery-settings.js").captureDeepScanExecutionSettings;
  restoredDeepScanWorkerSettings: typeof import("../src/deep-scan/recovery-settings.js").restoredDeepScanWorkerSettings;
  fakeCodexFixture: typeof createFixture;
  workerRequest: (
    promptPath: string,
    workingDirectory: string,
    options?: Partial<CodexWorkerRequest>,
  ) => CodexWorkerRequest;
  emptyWorkerPermissionProfile: NonNullable<
    Parameters<typeof createFixture>[0]
  >;
}

export async function testRestoredPrivateProfileHomes({
  CodexSdkWorkerExecutor,
  captureDeepScanExecutionSettings,
  restoredDeepScanWorkerSettings,
  fakeCodexFixture,
  workerRequest,
  emptyWorkerPermissionProfile,
}: Dependencies) {
  const providerSource = new URL(
    "../../../../sdk/typescript/src/provider-profile.ts",
    import.meta.url,
  );
  const { createProviderProfile } = await importModule({
    entryPoints: [fileURLToPath(providerSource)],
    define: { "import.meta.url": JSON.stringify(providerSource.href) },
    banner: {
      js: `import { createRequire as profileRequire } from "node:module"; const require = profileRequire(${JSON.stringify(providerSource.href)});`,
    },
  });
  const fixture = await fakeCodexFixture();
  const owners = [];
  for (const name of ["same", "first", "second"]) {
    const originalHome = path.join(fixture.root, name, "original");
    const currentHome =
      name === "same" ? originalHome : path.join(fixture.root, name, "current");
    await mkdir(originalHome, { recursive: true });
    await mkdir(currentHome, { recursive: true });
    const provider =
      name === "first"
        ? "openrouter"
        : name === "second"
          ? "fireworks"
          : "fixture-provider";
    const config = {
      model: "fixture-model",
      model_provider: provider,
      model_providers: {
        [provider]: {
          name: "Fixture",
          base_url: `https://${name}.example.invalid/v1`,
          env_key: `SYNTHETIC_${name.toUpperCase()}_KEY`,
          wire_api: "responses",
          requires_openai_auth: true,
          http_headers: { Authorization: `synthetic-${name}-profile-header` },
        },
      },
    };
    const configPath = path.join(originalHome, "config.toml");
    await writeFile(configPath, stringifyToml(config));
    const sandbox = {
      filesystemDenies: [...new Set([originalHome, currentHome])],
    };
    const saved = await captureDeepScanExecutionSettings(
      { model: config.model },
      sandbox,
      {
        CODEX_HOME: originalHome,
        CODEX_CLI_PATH: process.execPath,
      },
    );
    const current = await createProviderProfile(currentHome, config);
    const workerConfigPath = path.join(currentHome, "workers.toml");
    await writeFile(
      workerConfigPath,
      stringifyToml({ worker_runtime: { native_profile: current.name } }),
    );
    const promptPath = path.join(fixture.root, name, "prompt.md");
    await writeFile(
      promptPath,
      "NULL_USAGE CAPTURE_SYNTHETIC_OPENAI_AUTH fixture worker\n",
    );
    const markerPath = path.join(fixture.root, name, "invocation.json");
    const environment = {
      ...process.env,
      CODEX_HOME: currentHome,
      CODEX_SECURITY_CONFIG_PATH: configPath,
      CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: workerConfigPath,
      CODEX_CLI_PATH: process.execPath,
      CODEX_API_KEY: `synthetic-${name}-worker-key`,
      FAKE_CODEX_MARKER: markerPath,
      FAKE_CODEX_PREFLIGHT_MARKER: path.join(
        fixture.root,
        name,
        "preflight.json",
      ),
      FAKE_CODEX_PREFLIGHT_PROFILE: JSON.stringify({
        extends: ":read-only",
        filesystem: Object.fromEntries([
          [":root", "read"],
          ...sandbox.filesystemDenies.map((value) => [value, "deny"]),
        ]),
        network: { enabled: false },
      }),
    };
    const recreated: {
      name: string;
      path: string;
      cleanup(): Promise<void>;
    }[] = [];
    const executor = new CodexSdkWorkerExecutor({
      ...restoredDeepScanWorkerSettings(saved, sandbox, () => environment),
      createProviderProfile: async (
        home: string,
        profileConfig: Record<string, unknown>,
      ) => {
        const profile = await createProviderProfile(home, profileConfig);
        recreated.push(profile);
        return profile;
      },
    });
    owners.push({
      name,
      provider,
      config,
      originalHome,
      currentHome,
      current,
      promptPath,
      markerPath,
      environment,
      recreated,
      executor,
    });
  }
  const originalSpawn = childProcess.spawn;
  childProcess.spawn = ((
    command: string,
    args: readonly string[] = [],
    options: SpawnOptions = {},
  ) =>
    originalSpawn(
      command,
      command === process.execPath ||
        command === path.win32.toNamespacedPath(process.execPath)
        ? [fixture.executablePath, ...args]
        : args,
      options,
    )) as typeof childProcess.spawn;
  syncBuiltinESMExports();
  try {
    for (const kind of ["discovery", "dedup"] as const) {
      const launches: PromiseSettledResult<void>[] = await Promise.allSettled(
        owners.map(async (owner) => {
          const request = workerRequest(owner.promptPath, fixture.root, {
            kind,
            ...(kind === "dedup"
              ? { resumeThreadId: `fixture-resumed-${owner.name}` }
              : {}),
          });
          const result = await owner.executor.run(request);
          assert.equal(
            result.threadId,
            kind === "dedup"
              ? `fixture-resumed-${owner.name}`
              : "fixture-thread-id",
          );
          const child = await readJson(owner.markerPath);
          assert.equal(child.codexHome, owner.originalHome);
          const profile = parseToml(child.profileContents);
          assert.deepEqual(
            JSON.parse(JSON.stringify(profile.model_providers)),
            owner.config.model_providers,
          );
          const preflight = await readJson(
            owner.environment.FAKE_CODEX_PREFLIGHT_MARKER,
          );
          assertConfigOverrides(child.argv, {
            [`model_providers.${owner.provider}.base_url`]: undefined,
            [`model_providers.${owner.provider}.env_key`]: undefined,
          });
          assertConfigOverrides(preflight.argv, {
            [`model_providers.${owner.provider}.base_url`]: undefined,
            [`model_providers.${owner.provider}.env_key`]: undefined,
          });
          assert.match(
            child.profileContents,
            new RegExp(`synthetic-${owner.name}-profile-header`),
          );
          assert.equal(
            child.argv
              .join(" ")
              .includes(`synthetic-${owner.name}-profile-header`),
            false,
          );
          assert.equal(
            child.openaiAuthentication.CODEX_API_KEY,
            `synthetic-${owner.name}-worker-key`,
          );
          for (const profile of owner.recreated)
            await assert.rejects(readFile(profile.path), { code: "ENOENT" });
          await readFile(owner.current.path);
        }),
      );
      assert.deepEqual(
        launches.flatMap((launch) =>
          launch.status === "rejected" ? [String(launch.reason)] : [],
        ),
        [],
        `native provider selections survive ${kind} child launches`,
      );
    }
    assert.equal(owners[0].recreated.length, 0);
    assert.equal(
      new Set(
        owners.flatMap((owner) =>
          owner.recreated.map((profile) => profile.name),
        ),
      ).size,
      4,
    );
    const owner = owners[1];
    const acceptedProfile = owner.environment.FAKE_CODEX_PREFLIGHT_PROFILE;
    owner.environment.FAKE_CODEX_PREFLIGHT_PROFILE = JSON.stringify({
      ...emptyWorkerPermissionProfile,
      network: { enabled: true },
    });
    await assert.rejects(
      owner.executor.run(workerRequest(owner.promptPath, fixture.root)),
    );
    for (const profile of owner.recreated)
      await assert.rejects(readFile(profile.path), { code: "ENOENT" });
    owner.environment.FAKE_CODEX_PREFLIGHT_PROFILE = acceptedProfile;
    await writeFile(owner.promptPath, "CONFIG_ERROR\n");
    await assert.rejects(
      owner.executor.run(workerRequest(owner.promptPath, fixture.root)),
    );
    for (const profile of owner.recreated)
      await assert.rejects(readFile(profile.path), { code: "ENOENT" });
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    await Promise.all(owners.map((owner) => owner.current.cleanup()));
  }
}
