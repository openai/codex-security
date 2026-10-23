import assert from "node:assert/strict";
import childProcess, { spawnSync, type SpawnOptions } from "node:child_process";
import {
  copyFile,
  mkdir,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseToml } from "smol-toml";
import {
  assertConfigOverrides,
  assertFlagPair,
  assertReadOnlyWorkerPolicy,
  assertWorkerSubagentPolicy,
  workerPermissionProfileOverride,
} from "./assertions.ts";
import type { DeepWorkerParentSandbox } from "../src/deep-scan/parent-sandbox.js";
import type { fakeCodexFixture as createFixture } from "./test_deep_scan_executor.ts";

interface Dependencies {
  CodexSdkWorkerExecutor: typeof import("../src/deep-scan/executor.js").CodexSdkWorkerExecutor;
  WorkbenchDeepScanStore: typeof import("../src/deep-scan/store.js").WorkbenchDeepScanStore;
  captureDeepScanExecutionSettings: typeof import("../src/deep-scan/recovery-settings.js").captureDeepScanExecutionSettings;
  loadDeepScanExecutionSettings: typeof import("../src/deep-scan/recovery-settings.js").loadDeepScanExecutionSettings;
  restoredDeepScanWorkerSettings: typeof import("../src/deep-scan/recovery-settings.js").restoredDeepScanWorkerSettings;
  fakeCodexFixture: typeof createFixture;
  trustedParentSandboxWithDenials: DeepWorkerParentSandbox;
  deniedWorkerPermissionProfile: NonNullable<
    Parameters<typeof createFixture>[0]
  >;
  restoreEnv: (name: string, value: string | undefined) => void;
}

export async function testReconstructedWorkers({
  CodexSdkWorkerExecutor,
  WorkbenchDeepScanStore,
  captureDeepScanExecutionSettings,
  loadDeepScanExecutionSettings,
  restoredDeepScanWorkerSettings,
  fakeCodexFixture,
  trustedParentSandboxWithDenials,
  deniedWorkerPermissionProfile,
  restoreEnv,
}: Dependencies) {
  const launchFailures: string[] = [];
  const previousMarker = process.env.FAKE_CODEX_MARKER;
  const originalSpawn = childProcess.spawn;
  const scans: Awaited<ReturnType<typeof prepareReconstructedScan>>[] = [];
  async function prepareReconstructedScan(name: string) {
    const uncappedSandbox = {
      filesystemDenies: trustedParentSandboxWithDenials.filesystemDenies,
      literalFilesystemDenies:
        trustedParentSandboxWithDenials.literalFilesystemDenies,
    };
    const currentParentSandbox =
      name === "first" ? uncappedSandbox : trustedParentSandboxWithDenials;
    const filesystem = { ...deniedWorkerPermissionProfile.filesystem };
    delete filesystem["glob_scan_max_depth"];
    const fixture = await fakeCodexFixture({
      ...deniedWorkerPermissionProfile,
      filesystem,
    });
    const codexHome = path.join(fixture.root, "home");
    const configPath = path.join(fixture.root, "scan config.toml");
    const promptPath = path.join(fixture.root, "prompt.md");
    await mkdir(codexHome);
    const config: Record<string, string> = {
      model: `fixture-${name}-inherited`,
      model_provider: name === "first" ? "openrouter" : "amazon-bedrock",
      model_reasoning_effort: "medium",
      model_reasoning_summary: "concise",
      service_tier: name === "first" ? "default" : "fast",
    };
    await writeFile(
      configPath,
      (name === "second"
        ? 'model_provider = "openai"\nprofile = "cloud.production"\n'
        : "") +
        Object.entries(config)
          .filter(
            ([key]) =>
              (name !== "second" || key !== "model_provider") &&
              (name !== "first" ||
                ![
                  "model_provider",
                  "model_reasoning_summary",
                  "service_tier",
                ].includes(key)),
          )
          .map(([key, value]) => `${key} = ${JSON.stringify(value)}\n`)
          .join("") +
        (name === "second"
          ? '[profiles."cloud.production"]\nmodel_provider = "amazon-bedrock"\n[model_providers.amazon-bedrock.aws]\nregion = "us-west-2"\nprofile = "fixture-profile"\n'
          : "") +
        `[codex_security]\ncyber_access_program = "${name === "first" ? "daybreak_blue" : "standard"}"\n[features]\napi_key_cyber_access_programs = ${name === "first"}\napi_key_model_discovery = ${name !== "first"}\n`,
    );
    const providerKeys =
      name === "first"
        ? ["OPENROUTER_API_KEY"]
        : ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"];
    await writeFile(
      promptPath,
      "CAPTURE_SYNTHETIC_OPENAI_AUTH CAPTURE_SYNTHETIC_PROVIDER_AUTH NULL_USAGE\n",
    );
    const executable = path.join(
      fixture.root,
      process.platform === "win32" ? "node.exe" : "node",
    );
    // Keep dynamically linked Node beside its libraries on Unix. Each scan
    // still selects a distinct executable path at the spawn boundary.
    if (process.platform === "win32")
      await copyFile(process.execPath, executable);
    else await symlink(process.execPath, executable);
    const codexOptions = {
      codexPathOverride: executable,
      baseUrl: `https://${name}.example.invalid/v1`,
      env: {
        PATH: path.dirname(process.execPath),
        ...(process.env.SystemRoot
          ? { SystemRoot: process.env.SystemRoot }
          : {}),
        CODEX_HOME: codexHome,
        CODEX_SECURITY_CONFIG_PATH: configPath,
        CODEX_API_KEY: `synthetic-${name}-credential`,
        FAKE_CODEX_MARKER: fixture.markerPath,
        FAKE_CODEX_PROVIDER_ENV_KEYS: JSON.stringify(providerKeys),
        FAKE_CODEX_SCAN_VALUE: name,
      },
    };
    const settings = {
      codexOptions,
      model: `fixture-${name}-override`,
      reasoningEffort: "ultra",
      usageOwner: {
        threadId: `fixture-${name}-owner`,
        turnId: "original-turn",
        startedAt: "2026-01-01T00:00:00Z",
      },
      parentSandbox:
        name === "first" ? trustedParentSandboxWithDenials : uncappedSandbox,
    };
    await mkdir(path.join(codexHome, "sessions"));
    await writeFile(
      path.join(codexHome, "sessions", "owner.jsonl"),
      [
        {
          type: "session_meta",
          timestamp: "2026-01-01T00:00:00Z",
          payload: {
            id: `fixture-${name}-owner`,
            model_provider: config.model_provider,
          },
        },
        {
          type: "event_msg",
          timestamp: "2026-01-01T00:00:00Z",
          payload: {
            type: "thread_settings_applied",
            thread_id: `fixture-${name}-owner`,
            thread_settings: {
              model: "native-parent-model",
              model_provider_id: config.model_provider,
              reasoning_effort: "medium",
              reasoning_summary: config.model_reasoning_summary,
            },
          },
        },
        {
          type: "turn_context",
          timestamp: "2026-01-01T00:00:01Z",
          payload: {
            turn_id: "original-turn",
            model: "native-parent-model",
            effort: "medium",
            summary: "none",
          },
        },
        {
          type: "turn_context",
          timestamp: "2026-01-01T00:02:00Z",
          payload: {
            turn_id: "later-turn",
            model: "later-parent-model",
            effort: "low",
            summary: "detailed",
          },
        },
      ]
        .map((value) => JSON.stringify(value))
        .join("\n") + "\n",
    );
    await writeFile(
      path.join(codexHome, "sessions", "observer.jsonl"),
      JSON.stringify({
        type: "session_meta",
        timestamp: "2026-01-01T00:00:00Z",
        payload: {
          id: `fixture-${name}-observer`,
          model_provider: "observer-provider",
        },
      }) + "\n",
    );
    const saved = await captureDeepScanExecutionSettings(
      settings,
      settings.parentSandbox,
      { ...codexOptions.env, CODEX_CLI_PATH: executable },
      {
        threadId: `fixture-${name}-observer`,
        startedAt: "2026-01-01T00:01:00Z",
      },
    );
    assert.equal(
      saved.nativeServiceTierAbsent,
      name === "first" ? true : undefined,
    );
    const targetPath = path.join(fixture.root, "target");
    await mkdir(targetPath);
    const workbenchPath = fileURLToPath(
      new URL("../../scripts/workbench_db.py", import.meta.url),
    );
    const runWorkbench = async (
      args: string[],
      input?: string,
      _selectFinalization?: boolean,
      withExecutionSettings?: boolean,
    ) => {
      const pythonArgs = withExecutionSettings
        ? [
            "-c",
            "import runpy, sys; script = sys.argv.pop(1); runpy.run_path(script)['main'](with_execution_settings=True)",
            workbenchPath,
            ...args,
          ]
        : [workbenchPath, ...args];
      const result = spawnSync(
        process.env.PYTHON?.trim() || "python3",
        pythonArgs,
        {
          env: {
            ...process.env,
            CODEX_HOME: codexHome,
            CODEX_SECURITY_STATE_DIR: path.join(fixture.root, "state"),
          },
          input,
          encoding: "utf8",
          timeout: 30_000,
        },
      );
      assert.equal(result.status, 0, result.stderr);
      return JSON.parse(result.stdout);
    };
    const store = new WorkbenchDeepScanStore(runWorkbench);
    const beginInput = {
      targetPath,
      threadId: settings.usageOwner.threadId,
      model: settings.model,
      reasoningEffort: settings.reasoningEffort,
      scanRoot: path.join(fixture.root, "scans"),
    };
    const run: import("../src/deep-scan/types.js").DeepScanRunState =
      await store.begin({ ...beginInput, executionSettings: saved });
    const recordedScanDir = run.scanDir;
    const snapshotPath = path.join(
      recordedScanDir,
      "artifacts",
      "deep_discovery",
      "execution-settings.json",
    );
    assert.equal(run.workflowVersion, "deep-security-scan/v2");
    assert.deepEqual(run.executionSettings, { version: 1, settings: saved });
    const snapshot = await readFile(snapshotPath, "utf8");
    const expectedProvider =
      name === "first"
        ? undefined
        : {
            "amazon-bedrock": {
              aws: { region: "us-west-2", profile: "fixture-profile" },
            },
          };
    assert.deepEqual(
      JSON.parse(snapshot).settings.providerConfig,
      expectedProvider,
      "recorded provider selections need no persisted catalog definitions",
    );
    const claim = await store.claimCoordinator({
      scanId: run.scanId,
      threadId: beginInput.threadId,
    });
    assert.equal(claim.acquired, true);
    assert.deepEqual(
      await loadDeepScanExecutionSettings(recordedScanDir, claim.run),
      saved,
    );
    assert.deepEqual(
      (await store.get(run.scanId, beginInput.threadId)).executionSettings,
      run.executionSettings,
    );
    const observer = await new WorkbenchDeepScanStore(runWorkbench).begin({
      ...beginInput,
      executionSettings: null,
      model: "observer-model",
      reasoningEffort: "low",
    });
    assert.equal(observer.startDisposition, "joined");
    assert.equal(await readFile(snapshotPath, "utf8"), snapshot);
    assert.deepEqual(observer.executionSettings, run.executionSettings);
    assert.equal(observer.model, settings.model);
    assert.equal(snapshot.includes("synthetic-"), false);
    const runtimeEnvironment: NodeJS.ProcessEnv = { ...codexOptions.env };
    const restored = restoredDeepScanWorkerSettings(
      saved,
      currentParentSandbox,
      () => runtimeEnvironment,
    );
    restored.codexOptions.baseUrl = codexOptions.baseUrl;
    return {
      name,
      fixture,
      run,
      readRun: async (): Promise<
        import("../src/deep-scan/types.js").DeepScanRunState
      > =>
        (
          await new WorkbenchDeepScanStore(runWorkbench).claimCoordinator({
            scanId: run.scanId,
            threadId: beginInput.threadId,
          })
        ).run,
      recordedScanDir,
      currentParentSandbox,
      config,
      configPath,
      promptPath,
      settings,
      runtimeEnvironment,
      snapshotPath,
      snapshot,
      providerKeys,
      expectedProvider,
      executor: new CodexSdkWorkerExecutor(restored),
    };
  }
  try {
    for (const name of ["first", "second"])
      scans.push(await prepareReconstructedScan(name));
    childProcess.spawn = ((
      command: string,
      args: readonly string[] = [],
      options: SpawnOptions = {},
    ) => {
      const scan = scans.find(
        (scan) => options?.env?.FAKE_CODEX_MARKER === scan.fixture.markerPath,
      );
      return originalSpawn(
        command,
        scan ? [scan.fixture.executablePath, ...args] : args,
        options,
      );
    }) as unknown as typeof childProcess.spawn;
    syncBuiltinESMExports();

    for (const phase of [
      "fresh",
      "resume",
      "reconstructed-fresh",
      "reconstructed",
      "incomplete",
    ]) {
      if (phase.startsWith("reconstructed") || phase === "incomplete") {
        for (const scan of scans) {
          scan.run = await scan.readRun();
          if (phase === "reconstructed-fresh") await rm(scan.configPath);
          if (phase.startsWith("reconstructed")) {
            const rewritten = JSON.parse(scan.snapshot);
            rewritten.settings.codexPath = process.execPath;
            rewritten.settings.codexHome = scans.find(
              (other) => other !== scan,
            )!.settings.codexOptions.env.CODEX_HOME;
            await writeFile(scan.snapshotPath, JSON.stringify(rewritten));
          }
          if (phase === "incomplete") {
            const saved = JSON.parse(scan.snapshot);
            for (const key of ["model", "reasoningEffort", "reasoningSummary"])
              delete saved.settings[key];
            if (scan.name === "first") delete saved.settings.modelProvider;
            if (scan.name === "first") delete saved.settings.serviceTier;
            await writeFile(scan.snapshotPath, JSON.stringify(saved));
            // Emulate an older trusted record with missing optional selections.
            scan.run.executionSettings = saved;
          }
          const snapshotBeforeRead = await readFile(scan.snapshotPath, "utf8");
          const recorded = await loadDeepScanExecutionSettings(
            scan.recordedScanDir,
            {
              ...scan.run,
              ...scan.settings,
              createdAt: "2026-01-01T00:01:00Z",
            },
          );
          const restored = restoredDeepScanWorkerSettings(
            recorded,
            scan.currentParentSandbox,
            () => scan.runtimeEnvironment,
          );
          restored.codexOptions.baseUrl = scan.settings.codexOptions.baseUrl;
          scan.executor = new CodexSdkWorkerExecutor(restored);
          assert.equal(
            await readFile(scan.snapshotPath, "utf8"),
            snapshotBeforeRead,
            "restoring original worker selections must not rewrite saved settings",
          );
        }
      }
      for (const scan of scans) {
        scan.runtimeEnvironment.CODEX_API_KEY = `synthetic-${scan.name}-${phase}`;
        for (const key of scan.providerKeys)
          scan.runtimeEnvironment[key] =
            `synthetic-${scan.name}-${phase}-${key}`;
        scan.runtimeEnvironment.FAKE_CODEX_SCAN_VALUE = `${scan.name}-${phase}`;
        scan.runtimeEnvironment.CODEX_HOME = path.join(
          scan.fixture.root,
          "observer-home",
        );
        scan.runtimeEnvironment.CODEX_CLI_PATH = path.join(
          scan.fixture.root,
          "observer-codex",
        );
      }
      for (const kind of ["discovery", "dedup"] as const) {
        const launches = await Promise.allSettled(
          scans.map(async (scan) => {
            const resumeThreadId = ["fresh", "reconstructed-fresh"].includes(
              phase,
            )
              ? undefined
              : `fixture-${scan.name}-resumed`;
            const result = await scan.executor.run({
              kind,
              promptPath: scan.promptPath,
              workingDirectory: scan.fixture.root,
              subagents: scan.name === "first" ? 0 : 2,
              resumeThreadId,
              continuationPrompt:
                "CAPTURE_SYNTHETIC_OPENAI_AUTH CAPTURE_SYNTHETIC_PROVIDER_AUTH NULL_USAGE continuation",
              signal: new AbortController().signal,
            });
            assert.equal(
              result.threadId,
              resumeThreadId ?? "fixture-thread-id",
            );
            const child = JSON.parse(
              await readFile(scan.fixture.markerPath, "utf8"),
            );
            const preflight = JSON.parse(
              await readFile(scan.fixture.preflightMarkerPath, "utf8"),
            );
            assert.equal(
              await realpath(child.executable),
              await realpath(scan.settings.codexOptions.codexPathOverride),
            );
            assert.equal(
              child.codexCliPath,
              scan.settings.codexOptions.codexPathOverride,
            );
            assert.equal(
              child.codexHome,
              scan.settings.codexOptions.env.CODEX_HOME,
            );
            assert.equal(preflight.codexHome, child.codexHome);
            assert.equal(child.scanValue, `${scan.name}-${phase}`);
            assert.equal(
              child.configPath,
              scan.runtimeEnvironment.CODEX_SECURITY_CONFIG_PATH,
            );
            assert.deepEqual(child.openaiAuthentication, {
              CODEX_API_KEY: `synthetic-${scan.name}-${phase}`,
            });
            assert.deepEqual(
              child.providerAuthentication,
              Object.fromEntries(
                scan.providerKeys.map((key) => [
                  key,
                  `synthetic-${scan.name}-${phase}-${key}`,
                ]),
              ),
            );
            assertFlagPair(child.argv, "--model", scan.settings.model);
            assertFlagPair(
              child.argv,
              "--cyber-access-program",
              scan.name === "first" ? "daybreak_blue" : "standard",
            );
            assertConfigOverrides(child.argv, {
              "features.api_key_cyber_access_programs": scan.name === "first",
              "features.api_key_model_discovery": scan.name !== "first",
            });
            for (const key of [
              "model_provider",
              "model_reasoning_summary",
              "service_tier",
            ]) {
              const override = `${key}=${JSON.stringify(scan.config[key])}`;
              assert.equal(child.argv.includes(override), true, override);
              assert.equal(preflight.argv.includes(override), true, override);
            }
            assert.equal(
              child.argv.includes('model_reasoning_effort="ultra"'),
              true,
            );
            assert.equal(
              preflight.argv.includes('model_reasoning_effort="ultra"'),
              true,
            );
            assert.equal(
              preflight.argv.includes(
                `model=${JSON.stringify(scan.settings.model)}`,
              ),
              true,
            );
            const baseUrl = `openai_base_url=${JSON.stringify(scan.settings.codexOptions.baseUrl)}`;
            assert.equal(child.argv.includes(baseUrl), true);
            assert.equal(preflight.argv.includes(baseUrl), true);
            for (const launch of [child, preflight]) {
              const provider = launch.argv.filter((argument: string) =>
                /^model_providers[.=]/u.test(argument),
              );
              if (scan.expectedProvider) {
                const providers = parseToml(provider.join("\n"))
                  .model_providers as Record<string, Record<string, unknown>>;
                assert.deepEqual(
                  JSON.parse(JSON.stringify(providers)),
                  scan.expectedProvider,
                );
              } else {
                assert.deepEqual(
                  provider,
                  [],
                  "restored external providers inherit the recorded native home",
                );
              }
              assert.equal(
                workerPermissionProfileOverride(launch.argv).includes(
                  "glob_scan_max_depth",
                ),
                false,
                "a resumed bounded cap must not truncate an original uncapped deny glob, in either order",
              );
            }
            assertReadOnlyWorkerPolicy(child.argv);
            assertWorkerSubagentPolicy(
              child.argv,
              scan.name === "first" ? 0 : 2,
            );
            assert.equal(
              (
                parseToml(workerPermissionProfileOverride(child.argv))
                  .permissions as Record<
                  string,
                  { filesystem: Record<string, unknown> }
                >
              ).codex_security_deep_scan_worker.filesystem["/repo/.env"],
              "deny",
            );
            assert.equal(
              child.argv.includes("resume"),
              resumeThreadId !== undefined,
            );
            assert.equal(
              child.stdin.includes("continuation"),
              resumeThreadId !== undefined,
            );
          }),
        );
        for (const [index, launch] of launches.entries()) {
          if (launch.status === "rejected") {
            launchFailures.push(
              `${scans[index].name}/${phase}/${kind}: ${launch.reason.message}`,
            );
          }
        }
      }
      if (phase === "fresh") {
        for (const scan of scans) {
          const replacementConfig = path.join(
            scan.fixture.root,
            "replacement config.toml",
          );
          await writeFile(
            replacementConfig,
            'model_provider = "changed-provider"\nmodel_reasoning_summary = "detailed"\n[codex_security]\ncyber_access_program = "daybreak_red"\n[features]\napi_key_cyber_access_programs = false\napi_key_model_discovery = false\n',
          );
          scan.runtimeEnvironment.CODEX_SECURITY_CONFIG_PATH =
            replacementConfig;
        }
      }
    }
    assert.deepEqual(
      launchFailures,
      [],
      "every actual preflight and worker must retain the original launch selection",
    );
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    restoreEnv("FAKE_CODEX_MARKER", previousMarker);
  }
}
