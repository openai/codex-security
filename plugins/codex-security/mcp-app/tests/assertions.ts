import assert from "node:assert/strict";
import { parse as parseToml } from "smol-toml";

interface ToolResponse {
  error?: { message?: string };
  result?: { isError?: boolean; content?: { text?: string }[] };
}

export function assertNoError(response: ToolResponse) {
  assert.equal(response.error, undefined, response.error?.message!);
  assert.ok(response.result, "Expected a JSON-RPC result");
  assert.notEqual(
    response.result.isError,
    true,
    response.result?.content?.map((item) => item.text).join(" ")!,
  );
}

export function assertFlagPair(
  args: readonly string[],
  flag: string,
  value: string,
) {
  const index = args.indexOf(flag);
  assert.notEqual(index, -1, `missing ${flag}`);
  assert.equal(args[index + 1], value);
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
) {
  assertConfigOverrides(args, {
    "features.multi_agent_v2.enabled": false,
    "features.multi_agent_v2.max_concurrent_threads_per_session": subagents + 1,
    "features.multi_agent": undefined,
    "features.code_mode.excluded_tool_namespaces": undefined,
    ...(subagents === 0
      ? {
          "agents.max_threads": undefined,
          "features.enable_fanout": false,
          "features.code_mode.enabled": undefined,
        }
      : {
          "agents.max_threads": subagents,
          "features.enable_fanout": undefined,
        }),
  });
  assert.equal(args.includes("features.multi_agent_v2.enabled=true"), false);
}

export function nativeConfigOverrides(args: readonly string[]) {
  return args.flatMap((arg, index) =>
    arg === "--config" || arg === "-c" ? [args[index + 1]] : [],
  );
}

export function assertConfigOverrides(
  args: readonly string[],
  values: Record<string, string | number | boolean | undefined>,
) {
  const overrides = nativeConfigOverrides(args).map((value) =>
    parseToml(value),
  );
  for (const [key, value] of Object.entries(values)) {
    const supplied = overrides.map((config) =>
      key
        .split(".")
        .reduce<unknown>(
          (current, part) =>
            (current as Record<string, unknown> | undefined)?.[part],
          config,
        ),
    );
    assert.deepEqual(
      supplied.findLast((item) => item !== undefined),
      value,
      key,
    );
  }
}
