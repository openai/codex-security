import { expect, test } from "bun:test";
import { workerStatusFromEvent } from "../src/worker-progress.js";

const output = JSON.stringify({
  profile: "security_scan",
  status: "ready",
  results: [
    { capability: "delegated_workers", status: "pass", actual: true },
    { capability: "usable_worker_slots_6", status: "pass", actual: 8 },
  ],
});

function event(overrides: Record<string, unknown>) {
  return {
    type: "item.completed",
    item: {
      id: "preflight-1",
      type: "command_execution",
      command: "python3 /plugin/scripts/config_preflight.py --profile security_scan",
      aggregated_output: output,
      status: "completed",
      exit_code: 0,
      ...overrides,
    },
  };
}

test("ignores capability output from explicitly failed preflight commands", () => {
  expect(workerStatusFromEvent(event({ status: "failed" }))).toBeNull();
  expect(workerStatusFromEvent(event({ exit_code: 2 }))).toBeNull();
});

test("keeps successful preflight capability output", () => {
  expect(workerStatusFromEvent(event({}))).toEqual({
    kind: "preflight",
    delegation: "available",
    configuredSlots: 8,
  });
});
