import assert from "node:assert/strict";
import { parse as parseToml } from "smol-toml";

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
