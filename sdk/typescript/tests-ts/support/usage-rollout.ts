import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect } from "bun:test";

export const scanThreadId = "scan-thread";
export const lowerUuid7Turn = "019f9e4d-b3ba-7000-8000-000000000001";
export const childUuid7Thread = "019f9e4d-b3ba-7000-8000-000000000002";
export const higherUuid7Turn = "019f9e4d-b3ba-7000-8000-000000000003";
const uuid7EventTimestamp = "2026-07-26T12:02:00.250Z";
export const ownedSdkUsage = {
  input_tokens: 100,
  cached_input_tokens: 0,
  cache_write_input_tokens: 0,
  output_tokens: 10,
  reasoning_output_tokens: 0,
  total_tokens: 110,
};
export const ownedPythonUsage = {
  inputTokens: 100,
  cachedInputTokens: 0,
  cacheWriteInputTokens: 0,
  outputTokens: 10,
  reasoningOutputTokens: 0,
  totalTokens: 110,
};

function uuid7TaskStarted(turnId: string): Record<string, unknown> {
  return {
    type: "event_msg",
    timestamp: uuid7EventTimestamp,
    payload: {
      type: "task_started",
      turn_id: turnId,
      started_at: 1_785_067_320,
    },
  };
}

function uuid7TokenSnapshot(
  inputTokens: number,
  outputTokens: number,
): Record<string, unknown> {
  return {
    type: "event_msg",
    timestamp: uuid7EventTimestamp,
    payload: {
      type: "token_count",
      info: {
        total_token_usage: {
          ...ownedSdkUsage,
          input_tokens: inputTokens,
          output_tokens: outputTokens,
          total_tokens: inputTokens + outputTokens,
        },
      },
    },
  };
}

export function ownershipRollout(
  replayedTurnIds: readonly string[],
): Record<string, unknown>[] {
  return [
    {
      type: "session_meta",
      payload: {
        id: childUuid7Thread,
        timestamp: uuid7EventTimestamp,
        source: {
          subagent: { thread_spawn: { parent_thread_id: scanThreadId } },
        },
      },
    },
    {
      type: "session_meta",
      payload: {
        id: scanThreadId,
        timestamp: "2026-07-26T12:00:00.000Z",
        source: "exec",
      },
    },
    ...replayedTurnIds.map(uuid7TaskStarted),
    uuid7TokenSnapshot(1_000, 100),
    uuid7TaskStarted(higherUuid7Turn),
    uuid7TokenSnapshot(1_100, 110),
  ];
}

export function readPythonRolloutUsage(
  pluginRoot: string,
  rolloutPath: string,
): unknown {
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();
  const probe = [
    "import json, sys",
    "from datetime import datetime, timezone",
    "from pathlib import Path",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_scan_usage",
    "session = workbench_scan_usage.RolloutSession(sys.argv[3], sys.argv[4], Path(sys.argv[2]))",
    "usage, warnings = workbench_scan_usage._read_rollout_usage(",
    "    session,",
    "    started_at=datetime(2026, 7, 26, 12, tzinfo=timezone.utc),",
    "    completed_at=None,",
    ")",
    "print(json.dumps({'usage': usage, 'warnings': sorted(warnings)}, sort_keys=True))",
  ].join("\n");
  const result = spawnSync(
    python!,
    [
      "-I",
      "-B",
      "-c",
      probe,
      join(pluginRoot, "scripts"),
      rolloutPath,
      childUuid7Thread,
      scanThreadId,
    ],
    { encoding: "utf8" },
  );

  expect(result.error).toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout) as unknown;
}
