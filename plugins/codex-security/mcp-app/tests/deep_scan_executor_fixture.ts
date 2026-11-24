import assert from "node:assert/strict";
import childProcess, { type SpawnOptions } from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import path from "node:path";
import { parse as parseToml } from "smol-toml";
import type { CodexSdkWorkerExecutor as Executor } from "../src/deep-scan/executor.js";
import type { CodexWorkerRequest } from "../src/deep-scan/types.js";
import { assertConfigOverrides } from "./assertions.ts";
import { executor } from "./support/deep-scan-executor-module.ts";
import { createFakeCodexFixture } from "./support/fake-codex-fixture.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";

export const {
  resolveCodexPath,
  snapshotWorkerEnvironment,
  appendItemDiagnostic,
  parseDeepScan,
} = executor;

export const CodexSdkWorkerExecutor: typeof Executor =
  executor.CodexSdkWorkerExecutor;

export const temporaryDirectories = createTemporaryDirectories(true);
export const fakeCodexFixture = createFakeCodexFixture.bind(
  null,
  temporaryDirectories,
);

export type FakeCodexFixture = Awaited<ReturnType<typeof fakeCodexFixture>>;

interface WorkerLaunch {
  command: string;
  args: readonly string[];
  environment: NodeJS.ProcessEnv;
  markerPath: string;
}

// The caller restores spawn after all configurations. Never wrap a previous recorder.
export function captureWorkerLaunches(
  originalSpawn: typeof childProcess.spawn,
  fixture: FakeCodexFixture,
  permissionProfile?: (configPath: string | undefined) => object,
) {
  const launches: WorkerLaunch[] = [];
  childProcess.spawn = ((
    command: string,
    args: readonly string[],
    options: SpawnOptions,
  ) => {
    const markerPath = path.join(
      fixture.root,
      `invocation-${launches.length}.json`,
    );
    const environment: NodeJS.ProcessEnv = {
      ...options.env,
      FAKE_CODEX_MARKER: markerPath,
      FAKE_CODEX_PREFLIGHT_MARKER: markerPath,
    };
    if (permissionProfile)
      environment.FAKE_CODEX_PREFLIGHT_PROFILE = JSON.stringify(
        permissionProfile(options.env?.CODEX_SECURITY_CONFIG_PATH),
      );
    launches.push({ command, args, environment, markerPath });
    return originalSpawn(
      command,
      command === process.execPath ||
        command === path.toNamespacedPath(process.execPath)
        ? [fixture.executablePath, ...args]
        : args,
      { ...options, env: environment },
    );
  }) as typeof childProcess.spawn;
  syncBuiltinESMExports();
  return launches;
}

export function workerLaunchForModel(
  launches: WorkerLaunch[],
  model: string | undefined,
) {
  const launch = launches.find(({ args }) =>
    model === undefined
      ? !args.includes("--model")
      : args[args.indexOf("--model") + 1] === model,
  );
  assert.ok(launch, `missing worker launch for ${model}`);
  assert.equal(
    launch.command,
    process.platform === "win32"
      ? path.toNamespacedPath(process.execPath)
      : process.execPath,
  );
  assert.equal(launch.environment.CODEX_CLI_PATH, process.execPath);
  return launch;
}

export function assertWorkerPermissionProfile(
  args: readonly string[],
  expected: object,
) {
  const { permissions } = parseToml(workerPermissionProfileOverride(args));
  assert.deepEqual(JSON.parse(JSON.stringify(permissions)), {
    codex_security_deep_scan_worker: expected,
  });
}

export function workerRequest(
  promptPath: string,
  workingDirectory: string,
  options: Partial<CodexWorkerRequest> = {},
): CodexWorkerRequest {
  return {
    kind: "discovery",
    promptPath,
    workingDirectory,
    subagents: 0,
    signal: new AbortController().signal,
    ...options,
  };
}

export function assertReadOnlyWorkerPolicy(args: readonly string[]) {
  assert.equal(args.includes("--sandbox"), false);
  assert.equal(args.includes("--add-dir"), false);
  assert.deepEqual(
    args.filter((arg: string) => arg.startsWith("approval_policy=")),
    ['approval_policy="never"'],
  );
  assert.equal(
    args.some((arg: string) => arg.includes("network_access")),
    false,
  );
  const override = workerPermissionProfileOverride(args);
  assertConfigOverrides(args, {
    "permissions.codex_security_deep_scan_worker.extends": ":read-only",
    "permissions.codex_security_deep_scan_worker.filesystem.:root": "read",
    "permissions.codex_security_deep_scan_worker.network.enabled": false,
  });
  assert.equal(override.includes('"write"'), false);
}

export function workerPermissionProfileOverride(args: readonly string[]) {
  assert.deepEqual(
    args.filter((arg: string) => arg.startsWith("default_permissions=")),
    ['default_permissions="codex_security_deep_scan_worker"'],
  );
  const overrides = args.filter((arg: string) =>
    arg.startsWith("permissions.codex_security_deep_scan_worker="),
  );
  assert.equal(overrides.length, 1);
  return overrides[0];
}

export function assertWorkerSubagentPolicy(
  args: readonly string[],
  subagents: number,
  codeMode?: { enabled: boolean; excluded_tool_namespaces: string[] },
) {
  assertConfigOverrides(args, {
    "features.multi_agent_v2.enabled": false,
    "features.multi_agent_v2.max_concurrent_threads_per_session": subagents + 1,
    "features.multi_agent": undefined,
    "features.code_mode.excluded_tool_namespaces":
      codeMode?.excluded_tool_namespaces,
    ...(subagents === 0
      ? {
          "agents.max_threads": undefined,
          "features.enable_fanout": false,
          "features.code_mode.enabled": codeMode?.enabled,
        }
      : {
          "agents.max_threads": subagents,
          "features.enable_fanout": undefined,
        }),
  });
  assert.equal(args.includes("features.multi_agent_v2.enabled=true"), false);
}
