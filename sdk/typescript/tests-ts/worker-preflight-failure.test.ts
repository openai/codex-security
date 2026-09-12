import { expect, test } from "bun:test";
import { workerStatusFromEvent } from "../src/worker-progress.js";

function output(status: "ready" | "blocked" | "incomplete" = "ready") {
  return JSON.stringify({
    profile: "security_scan",
    status,
    results: [
      { capability: "delegated_workers", status: "pass", actual: true },
      { capability: "usable_worker_slots_6", status: "pass", actual: 8 },
    ],
  });
}

function event(overrides: Record<string, unknown> = {}) {
  return {
    type: "item.completed",
    item: {
      id: "preflight-1",
      type: "command_execution",
      command: "python3 /plugin/scripts/config_preflight.py --profile security_scan",
      aggregated_output: output(),
      status: "completed",
      exit_code: 0,
      ...overrides,
    },
  };
}

const capability = {
  kind: "preflight",
  delegation: "available",
  configuredSlots: 8,
} as const;

test("ignores capability output from failed or contradictory preflight commands", () => {
  expect(workerStatusFromEvent(event({ status: "failed" }))).toBeNull();
  expect(workerStatusFromEvent(event({ exit_code: 2 }))).toBeNull();
  expect(
    workerStatusFromEvent(
      event({ aggregated_output: output("blocked"), exit_code: 2 }),
    ),
  ).toBeNull();
});

test("keeps capability output from valid ready, blocked, and incomplete preflights", () => {
  expect(workerStatusFromEvent(event())).toEqual(capability);
  expect(
    workerStatusFromEvent(
      event({ aggregated_output: output("blocked"), exit_code: 1 }),
    ),
  ).toEqual(capability);
  expect(
    workerStatusFromEvent(
      event({ aggregated_output: output("incomplete"), exit_code: 2 }),
    ),
  ).toEqual(capability);
});
