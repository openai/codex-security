import { expect, test } from "bun:test";
import { updateTestTimings } from "../scripts/update-test-timings.mts";

function report(cases: string) {
  return `<testsuites failures="0"><testsuite>${cases}</testsuite></testsuites>`;
}

test("refreshes per-file medians while retaining other platforms and undiscovered files", () => {
  const previous = {
    "slow.test.ts": { linux: 100, darwin: 20, win32: 50 },
    "stale.test.ts": { linux: 2, darwin: 3 },
  };
  const updated = updateTestTimings(previous, "linux", [
    report(`
      <testcase file="tests-ts/slow.test.ts" time="2" />
      <testcase file="tests-ts/slow.test.ts" time="4" />
      <testcase file="tests-ts/new.test.ts" time="0.24" />
    `),
    report('<testcase file="tests-ts/slow.test.ts" time="100" />'),
    report('<testcase file="tests-ts/slow.test.ts" time="10" />'),
  ]);
  expect(updated).toEqual({
    "new.test.ts": { linux: 0.2 },
    "slow.test.ts": { linux: 10, darwin: 20, win32: 50 },
    "stale.test.ts": { linux: 2, darwin: 3 },
  });
  expect(previous["slow.test.ts"].linux).toBe(100);
  expect(Object.keys(updated)).toEqual([
    "new.test.ts",
    "slow.test.ts",
    "stale.test.ts",
  ]);
});

test("updates executed Windows cases and retains estimates for skipped files", () => {
  const previous = { "skipped.test.ts": { win32: 34.5 } };
  const updated = updateTestTimings(previous, "win32", [
    report(String.raw`
      <testcase file="C:\checkout\tests-ts\names&amp;paths.test.ts" time="1.2" />
      <testcase file="tests-ts/names&amp;paths.test.ts" time="0.5" />
      <testcase file="tests-ts/names&amp;paths.test.ts" time="8"><skipped /></testcase>
      <testcase file="tests-ts/skipped.test.ts" time="0"><skipped /></testcase>
      <testcase file="tests-ts/new-skipped.test.ts"><skipped /></testcase>
      <testcase file="tests-ts/quick.test.ts" time="0" />
    `),
    report('<testcase file="tests-ts/names&amp;paths.test.ts" time="3.1" />'),
    report(
      '<testcase file="tests-ts/names&amp;paths.test.ts"><skipped /></testcase>',
    ),
  ]);
  expect(updated).toEqual({
    "names&paths.test.ts": { win32: 2.4 },
    "quick.test.ts": { win32: 0.1 },
    "skipped.test.ts": { win32: 34.5 },
  });
});

test.each([
  '<testsuites failures="1"><testcase file="tests-ts/example.test.ts" time="3" /></testsuites>',
  report(
    '<testcase file="tests-ts/example.test.ts" time="3"><failure /></testcase>',
  ),
  report('<testcase file="tests-ts/example.test.ts" time="NaN" />'),
  report('<testcase file="tests-ts/example.test.ts" time="-1" />'),
  report('<testcase time="1" />'),
  report(""),
  "<testsuites>",
])(
  "rejects unusable reports without altering the timing snapshot: %s",
  (invalid) => {
    const previous = { "example.test.ts": { darwin: 5 } };
    expect(() =>
      updateTestTimings(previous, "darwin", [
        report('<testcase file="tests-ts/example.test.ts" time="10" />'),
        invalid,
      ]),
    ).toThrow();
    expect(previous).toEqual({ "example.test.ts": { darwin: 5 } });
  },
);
