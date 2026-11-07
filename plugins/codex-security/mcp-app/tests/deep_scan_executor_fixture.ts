import assert from "node:assert/strict";
import path from "node:path";
import type { CodexSdkWorkerExecutor as Executor } from "../src/deep-scan/executor.js";
import type { CodexWorkerRequest } from "../src/deep-scan/types.js";
import { assertConfigOverrides } from "./assertions.ts";
import { importSource } from "./import-module.ts";
import { executor } from "./support/deep-scan-executor-module.ts";
import { createFakeCodexFixture } from "./support/fake-codex-fixture.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";

export const {
  bundledCodexSdkEnvironment,
}: {
  bundledCodexSdkEnvironment(
    command: string,
    environment: Record<string, string>,
  ): Record<string, string>;
} =
  process.platform === "win32"
    ? {}
    : await importSource(
        path.join(
          import.meta.dirname,
          "../../../../sdk/typescript/src/codex-sdk-environment.ts",
        ),
      );

export const {
  WorkbenchDeepScanStore,
  captureDeepScanExecutionSettings,
  loadDeepScanExecutionSettings,
  restoredDeepScanWorkerSettings,
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
