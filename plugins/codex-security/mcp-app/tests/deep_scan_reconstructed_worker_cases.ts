import assert from "node:assert/strict";
import childProcess, { spawnSync, type SpawnOptions } from "node:child_process";
import {
  copyFile,
  mkdir,
  readFile,
  realpath,
  symlink,
  writeFile,
} from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseToml } from "smol-toml";
import { assertFlagPair, assertConfigOverrides } from "./assertions.ts";
import type { DeepWorkerParentSandbox } from "../src/deep-scan/parent-sandbox.js";
type PermissionProfile = {
  extends: string;
  filesystem: { ":root": string; [key: string]: unknown };
  network: { enabled: boolean };
};
export function reconstructedWorkerCases({
  CodexSdkWorkerExecutor,
  WorkbenchDeepScanStore,
  captureDeepScanExecutionSettings,
  retainDeepScanExecutionSettings,
  loadDeepScanExecutionSettings,
  restoredDeepScanWorkerSettings,
  fakeCodexFixture,
  trustedParentSandbox,
  trustedParentSandboxWithDenials,
  deniedWorkerPermissionProfile,
  assertReadOnlyWorkerPolicy,
  assertWorkerSubagentPolicy,
  workerPermissionProfileOverride,
  restoreEnv,
}: {
  CodexSdkWorkerExecutor: typeof import("../src/deep-scan/executor.js").CodexSdkWorkerExecutor;
  WorkbenchDeepScanStore: typeof import("../src/deep-scan/store.js").WorkbenchDeepScanStore;
  captureDeepScanExecutionSettings: typeof import("../src/deep-scan/recovery-settings.js").captureDeepScanExecutionSettings;
  retainDeepScanExecutionSettings: typeof import("../src/deep-scan/recovery-settings.js").retainDeepScanExecutionSettings;
  loadDeepScanExecutionSettings: typeof import("../src/deep-scan/recovery-settings.js").loadDeepScanExecutionSettings;
  restoredDeepScanWorkerSettings: typeof import("../src/deep-scan/recovery-settings.js").restoredDeepScanWorkerSettings;
  fakeCodexFixture: (profile?: PermissionProfile) => Promise<{
    root: string;
    executablePath: string;
    markerPath: string;
    preflightMarkerPath: string;
  }>;
  trustedParentSandbox: DeepWorkerParentSandbox;
  trustedParentSandboxWithDenials: DeepWorkerParentSandbox;
  deniedWorkerPermissionProfile: PermissionProfile;
  assertReadOnlyWorkerPolicy: (args: readonly string[]) => void;
  assertWorkerSubagentPolicy: (
    args: readonly string[],
    subagents: number,
  ) => void;
  workerPermissionProfileOverride: (args: readonly string[]) => string;
  restoreEnv: (name: string, value: string | undefined) => void;
}) {
  return {
    testIsolatedReconstructedWorkers,
    testReducerCoveragePersistenceBinding,
  };
  async function testIsolatedReconstructedWorkers() {
    const launchFailures: string[] = [];
    const previousMarker = process.env.FAKE_CODEX_MARKER;
    const originalSpawn = childProcess.spawn;
    const scans: Awaited<ReturnType<typeof prepareReconstructedScan>>[] = [];
    async function prepareReconstructedScan(name: string) {
      const uncappedSandbox = {
        filesystemDenies: trustedParentSandboxWithDenials.filesystemDenies,
      };
      const originalLiteralDenial = `/repo/${name} [original]`;
      const currentLiteralDenial = `/repo/${name} [current]`;
      const currentParentSandbox = {
        ...(name === "first"
          ? uncappedSandbox
          : trustedParentSandboxWithDenials),
        literalFilesystemDenies: [currentLiteralDenial],
      };
      const expectedProfile = {
        ...structuredClone(deniedWorkerPermissionProfile),
        filesystem: {
          ":root": "read",
          "/repo/.env": "deny",
          "/repo/**/*.pem": "deny",
          "/repo/**/.secret": "deny",
          "/repo/temp[1]": "deny",
          "/repo/secret[1]": "deny",
          [originalLiteralDenial]: { ".": "deny" },
          [currentLiteralDenial]: { ".": "deny" },
        },
      };
      const fixture = await fakeCodexFixture(expectedProfile);
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
      const accessProgram = "daybreak_blue";
      const apiFeatures = {
        api_key_cyber_access_programs: name === "first",
        api_key_model_discovery: name !== "first",
      };
      await writeFile(
        configPath,
        Object.entries(config)
          .filter(
            ([key]) =>
              name !== "first" ||
              ![
                "model_provider",
                "model_reasoning_summary",
                "service_tier",
              ].includes(key),
          )
          .map(([key, value]) => `${key} = ${JSON.stringify(value)}\n`)
          .join("") +
          (name === "second"
            ? '[model_providers.amazon-bedrock.aws]\nregion = "us-west-2"\nprofile = "fixture-profile"\n'
            : "") +
          `\n[codex_security]\ncyber_access_program = "${accessProgram}"\n[features]\napi_key_cyber_access_programs = ${apiFeatures.api_key_cyber_access_programs}\napi_key_model_discovery = ${apiFeatures.api_key_model_discovery}\n`,
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
        parentSandbox: {
          ...(name === "first"
            ? trustedParentSandboxWithDenials
            : uncappedSandbox),
          literalFilesystemDenies: [originalLiteralDenial],
        },
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
      assert.deepEqual(
        saved.parentSandbox?.literalFilesystemDenies,
        [originalLiteralDenial],
        "capture retains literal parent denial paths",
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
        await store.begin(beginInput);
      const recordedScanDir = run.scanDir;
      const snapshotPath = path.join(
        recordedScanDir,
        "artifacts",
        "deep_discovery",
        "execution-settings.json",
      );
      await assert.rejects(readFile(snapshotPath), { code: "ENOENT" });
      assert.equal(run.workflowVersion, "deep-security-scan/v1");
      // Import the eventual writer's row and projection; this release must not create them.
      const envelope = { version: 1, settings: saved };
      const imported = spawnSync(
        process.env.PYTHON?.trim() || "python3",
        [
          "-c",
          'import json, sqlite3, sys; c=sqlite3.connect(sys.argv[1]); c.execute("UPDATE deep_scan_runs SET execution_settings_json = ? WHERE scan_id = ?", (sys.argv[3], sys.argv[2])); c.commit()',
          path.join(fixture.root, "state", "workbench.sqlite3"),
          run.scanId,
          JSON.stringify(envelope),
        ],
        { encoding: "utf8" },
      );
      assert.equal(imported.status, 0, imported.stderr);
      await mkdir(path.dirname(snapshotPath), { recursive: true });
      await writeFile(snapshotPath, JSON.stringify(envelope) + "\n");
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
      const observer = await new WorkbenchDeepScanStore(runWorkbench).begin({
        ...beginInput,
        model: "observer-model",
        reasoningEffort: "low",
      });
      assert.equal(observer.startDisposition, "joined");
      assert.equal(await readFile(snapshotPath, "utf8"), snapshot);
      assert.equal(observer.model, settings.model);
      assert.equal(snapshot.includes("synthetic-"), false);
      const retainedCapture = retainDeepScanExecutionSettings(
        async () =>
          await captureDeepScanExecutionSettings(
            settings,
            settings.parentSandbox,
            { ...codexOptions.env, CODEX_CLI_PATH: executable },
            {
              threadId: `fixture-${name}-observer`,
              startedAt: "2026-01-01T00:01:00Z",
            },
          ),
      );
      assert.deepEqual(await retainedCapture(run), saved);
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
        expectedFilesystem: expectedProfile.filesystem,
        retainedCapture,
        accessProgram,
        apiFeatures,
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
        "readopted-fresh",
        "readopted",
        "reconstructed-fresh",
        "reconstructed",
        "incomplete",
      ]) {
        if (phase.startsWith("readopted")) {
          for (const scan of scans) {
            const retained = await scan.retainedCapture({
              ...scan.run,
              coordinatorGeneration: 2,
            });
            const restored = restoredDeepScanWorkerSettings(
              retained,
              scan.currentParentSandbox,
              () => scan.runtimeEnvironment,
            );
            restored.codexOptions.baseUrl = scan.settings.codexOptions.baseUrl;
            scan.executor = new CodexSdkWorkerExecutor(restored);
          }
        }
        if (phase.startsWith("reconstructed") || phase === "incomplete") {
          for (const scan of scans) {
            scan.run = await scan.readRun();
            // Resume supplies current configuration while restoring recorded
            // launch selections; credentials remain in the selected home/env.
            if (phase.startsWith("reconstructed")) {
              // The managed parent can edit its output files. Neither a substituted
              // executable/home nor other settings in that file are launch authority.
              const rewritten = JSON.parse(scan.snapshot);
              rewritten.settings.codexPath = process.execPath;
              rewritten.settings.codexHome = scans.find(
                (other) => other !== scan,
              )!.settings.codexOptions.env.CODEX_HOME;
              await writeFile(scan.snapshotPath, JSON.stringify(rewritten));
            }
            if (phase === "incomplete") {
              const saved = JSON.parse(scan.snapshot);
              for (const key of [
                "model",
                "reasoningEffort",
                "reasoningSummary",
              ])
                delete saved.settings[key];
              // Native history restores the first provider. The second snapshot
              // retains the provider binding for its saved AWS selectors.
              if (scan.name === "first") delete saved.settings.modelProvider;
              if (scan.name === "first") delete saved.settings.serviceTier;
              await writeFile(scan.snapshotPath, JSON.stringify(saved));
              // Emulate an older trusted record with missing optional selections.
              scan.run.executionSettings = saved;
            }
            const snapshotBeforeRead = await readFile(
              scan.snapshotPath,
              "utf8",
            );
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
              const resumeThreadId = [
                "fresh",
                "readopted-fresh",
                "reconstructed-fresh",
              ].includes(phase)
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
              assert.equal(child.configPath, scan.configPath);
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
                scan.accessProgram,
              );
              assertConfigOverrides(
                child.argv,
                Object.fromEntries(
                  Object.entries(scan.apiFeatures).map(([key, value]) => [
                    `features.${key}`,
                    value,
                  ]),
                ),
              );
              assertConfigOverrides(preflight.argv, {
                model: scan.settings.model,
              });
              for (const launch of [child, preflight]) {
                assertConfigOverrides(launch.argv, {
                  model_provider: scan.config["model_provider"],
                  model_reasoning_summary:
                    scan.config["model_reasoning_summary"],
                  service_tier: scan.config["service_tier"],
                  model_reasoning_effort: "ultra",
                  openai_base_url: scan.settings.codexOptions.baseUrl,
                });
                const provider = launch.argv.filter((argument: string) =>
                  /^model_providers[.=]/u.test(argument),
                );
                assert.ok(
                  provider.length > 0,
                  "both preflight and worker launch receive provider configuration",
                );
                const providers = parseToml(provider.join("\n"))
                  .model_providers as Record<string, Record<string, unknown>>;
                if (scan.expectedProvider)
                  assert.deepEqual(
                    JSON.parse(JSON.stringify(providers)),
                    scan.expectedProvider,
                  );
                else
                  assert.deepEqual(Object.keys(providers.openrouter).sort(), [
                    "base_url",
                    "env_key",
                    "name",
                    "wire_api",
                  ]);
                assert.equal(
                  workerPermissionProfileOverride(launch.argv).includes(
                    "glob_scan_max_depth",
                  ),
                  false,
                  "a resumed bounded cap must not truncate an original uncapped deny glob, in either order",
                );
              }
              const filesystem = (
                parseToml(workerPermissionProfileOverride(child.argv))
                  .permissions as Record<
                  string,
                  { filesystem: Record<string, unknown> }
                >
              )["codex_security_deep_scan_worker"].filesystem;
              assert.deepEqual(
                JSON.parse(JSON.stringify(filesystem)),
                scan.expectedFilesystem,
              );
              assertReadOnlyWorkerPolicy(child.argv);
              assertWorkerSubagentPolicy(
                child.argv,
                scan.name === "first" ? 0 : 2,
              );
              assert.equal(filesystem["/repo/.env"], "deny");
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
            await writeFile(
              scan.configPath,
              'model_provider = "changed-provider"\nmodel_reasoning_summary = "detailed"\n[codex_security]\ncyber_access_program = "daybreak_red"\n[features]\napi_key_cyber_access_programs = false\napi_key_model_discovery = false\n',
            );
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

  async function testReducerCoveragePersistenceBinding() {
    const fixture = await fakeCodexFixture();
    const previousPath = process.env.CODEX_CLI_PATH;
    const previousMarker = process.env.FAKE_CODEX_MARKER;
    process.env.CODEX_CLI_PATH = fixture.executablePath;
    try {
      const promptPath = path.join(fixture.root, "prompt.md");
      const workingDirectory = path.join(fixture.root, "artifacts");
      await mkdir(workingDirectory);
      await writeFile(promptPath, "fixture reducer prompt\n");
      const launches: Promise<void>[] = [];
      for (const resume of [false, true]) {
        for (const persistSourceCoverage of [false, true]) {
          const markerPath = path.join(
            fixture.root,
            `coverage-${resume}-${persistSourceCoverage}.json`,
          );
          process.env.FAKE_CODEX_MARKER = markerPath;
          const scanRoot = path.join(
            fixture.root,
            `scan-${resume}-${persistSourceCoverage}`,
          );
          const deepReducer = {
            scanRoot,
            claimedWorkers: [
              {
                id: "worker-1",
                attempt: 2,
                resultPath: path.join(
                  scanRoot,
                  "worker",
                  "checkpoints",
                  "accepted.json",
                ),
                artifactDir: path.join(scanRoot, "worker"),
              },
            ],
            persistSourceCoverage,
          };
          const launch = new CodexSdkWorkerExecutor({
            parentSandbox: trustedParentSandbox,
            artifactContext: {
              pluginRoot: fixture.root,
              scanRoot: deepReducer.scanRoot,
              repoRoot: fixture.root,
              scanId: "fixture-scan-id",
            },
          }).run({
            kind: "dedup",
            promptPath,
            workingDirectory,
            subagents: 0,
            signal: new AbortController().signal,
            ...(resume
              ? {
                  resumeThreadId: "fixture-existing-thread",
                  continuationPrompt: "continue the reducer\n",
                }
              : {}),
            artifactContext: {
              root: workingDirectory,
              layout: "reducer",
              deepReducer,
            },
          });
          launches.push(
            launch.then(async () => {
              const invocation = JSON.parse(await readFile(markerPath, "utf8"));
              assertConfigOverrides(invocation.argv, {
                "mcp_servers.cs_artifacts.env.CODEX_SECURITY_REDUCER_CONTEXT_JSON":
                  JSON.stringify(deepReducer),
              });
            }),
          );
        }
      }
      await Promise.all(launches);
    } finally {
      restoreEnv("CODEX_CLI_PATH", previousPath);
      restoreEnv("FAKE_CODEX_MARKER", previousMarker);
    }
  }
}
