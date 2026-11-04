import { expect, test } from "bun:test";
import { compareTimestamps } from "../src/timestamps.js";

test.each([
  ["offsets", "2026-08-01T03:00:00+02:00", "2026-08-01T01:30:00Z"],
  ["fractional seconds", "2026-08-01T01:00:00Z", "2026-08-01T01:00:00.100000Z"],
  [
    "microseconds",
    "2026-08-01T01:00:00.000001Z",
    "2026-08-01T01:00:00.000002Z",
  ],
  [
    "millisecond boundaries",
    "2026-08-01T01:00:00.481998Z",
    "2026-08-01T01:00:00.482012Z",
  ],
  [
    "offset microseconds",
    "2026-08-01T03:00:00.000001+02:00",
    "2026-08-01T01:00:00.000002Z",
  ],
])("compares %s chronologically in both directions", (_, older, newer) => {
  expect(compareTimestamps(older, newer)).toBeLessThan(0);
  expect(compareTimestamps(newer, older)).toBeGreaterThan(0);
});
