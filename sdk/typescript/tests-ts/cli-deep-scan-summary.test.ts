import { describe, expect, test, mock } from "bun:test";
import { main } from "../src/cli.js";
import type { JsonObject } from "../src/config.js";
import { dependencies, fakeResult } from "./cli-fixtures.js";
import { throwing } from "./support/errors.js";

import { createCliTest } from "./support/cli-run.js";

const cappedState: JsonObject = {
  terminalReason: "capped",
  dispatchedCount: 40,
  completionSequence: 40,
  noNewStreak: 0,
  config: { maxDiscoveryRuns: 40, maxTimeHours: 96 },
  createdAt: "2026-01-01T00:00:00Z",
  completedAt: "2026-01-01T01:00:00Z",
};

async function summary(
  options: Parameters<typeof dependencies>[0],
  args = ["--mode", "deep"],
) {
  const { stdout, stderr, runCli } = createCliTest(main);

  const result = options?.result ?? fakeResult(["high"], "partial");
  expect(
    await runCli(
      ["scan", ...args, "--json"],
      dependencies({ ...options, result }),
    ),
  ).toBe(result.coverage.completeness === "complete" ? 0 : 2);
  expect(JSON.parse(stdout.text())).toEqual(result.toJSON());
  return stderr.text();
}

describe("deep scan completion summary", () => {
  test.each([
    [
      "review limit while finding issues",
      {},
      "40 review rounds. The latest review still found new issues",
      "--max-discovery-runs greater than 40",
    ],
    [
      "quiet round",
      { noNewStreak: 1 },
      "More issues may remain",
      "--max-discovery-runs",
    ],
    [
      "no recent new issues",
      { terminalReason: "saturated", noNewStreak: 4 },
      "last 4 review rounds found no new issues",
      null,
    ],
    [
      "time limit",
      {
        dispatchedCount: 3,
        config: { maxDiscoveryRuns: 40, maxTimeHours: 0.5 },
      },
      "0.5-hour time limit",
      "higher --max-time-hours",
    ],
    [
      "maximum time limit",
      { dispatchedCount: 3, completedAt: "2026-01-05T00:00:00Z" },
      "96-hour time limit",
      "rerun with --path",
    ],
    [
      "another early stop",
      { dispatchedCount: 3 },
      "Stopped before the review finished",
      null,
    ],
  ] as const)("explains %s", async (_name, overrides, reason, next) => {
    const text = await summary({
      onWorkbench: (args) => {
        expect(args).toEqual([
          "get-deep-scan",
          "--scan-id",
          "scan",
          "--thread-id",
          "thread-1",
        ]);
        return { deepScan: { ...cappedState, ...overrides } };
      },
    });
    expect(text).toContain("STOPPED");
    expect(text).toContain(reason);
    if (next !== null) expect(text).toContain(next);
    expect(text).not.toMatch(/saturat|merged|reducer/i);
  });

  test("uses the overall cost limit even if discovery stopped earlier", async () => {
    const text = await summary(
      {
        result: fakeResult([], "partial", {
          input_tokens: 1_250,
          cached_input_tokens: 200,
          output_tokens: 30,
        }),
        onWorkbench: throwing("The exceeded cost limit is already known"),
      },
      ["--mode", "deep", "--max-cost", "0.004"],
    );
    expect(text).toContain("Reached the $0.004 cost limit");
    expect(text).toContain("higher --max-cost");
    expect(text).not.toContain("--max-discovery-runs");
  });

  test.each([false, true])(
    "keeps the result when stop details are unavailable (read fails: %p)",
    async (fails) => {
      const text = await summary({
        result: fakeResult(),
        onWorkbench: () => {
          if (fails) throw new Error("read failed");
          return {};
        },
      });
      expect(text).toContain("STOPPED   Stop reason unavailable");
    },
  );

  test("leaves standard scan summaries unchanged", async () => {
    const onWorkbench = mock<() => {}>().mockReturnValue({});
    const text = await summary(
      {
        result: fakeResult(),
        onWorkbench,
      },
      [],
    );
    expect(onWorkbench).toHaveBeenCalledTimes(0);
    expect(text).not.toContain("STOPPED");
  });
});
