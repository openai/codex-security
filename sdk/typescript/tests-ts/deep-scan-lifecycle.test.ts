import { expect, test } from "bun:test";
import { newDeepScanCheckpoint } from "../src/deep-scan-checkpoint.js";
import { discoveryStopReason } from "../src/deep-scan-lifecycle.js";

test("saturation waits for reserved work while the deadline still stops it", () => {
  const state = newDeepScanCheckpoint("2026-01-01T00:00:00Z");
  state.noNewStreak = 3;
  state.passes = [{ directory: "artifacts/deep-scan/passes/pass-1" }];
  const input = {
    deadlineReached: false,
    hasUnfinishedPasses: true,
    maxDiscoveryRuns: 1,
    stopAfterNoNew: 3,
  };
  expect(discoveryStopReason(state, input)).toBeUndefined();
  expect(
    discoveryStopReason(state, { ...input, hasUnfinishedPasses: false }),
  ).toBe("saturated");
  expect(discoveryStopReason(state, { ...input, deadlineReached: true })).toBe(
    "capped",
  );
});
