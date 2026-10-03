import { expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { capture, dependencies, fakeResult } from "./cli-fixtures.js";

const result = fakeResult([], "complete", {
  input_tokens: 1250,
  cached_input_tokens: 200,
  output_tokens: 30,
});

test.each([false, true])("scan cost visibility with TTY %p", async (tty) => {
  for (const costFlags of [
    [],
    ["--show-cost"],
    ["--show-cost=false", "--max-cost", "20"],
  ]) {
    const stdout = capture();
    const stderr = capture(tty);
    expect(
      await main(
        ["scan", ".", ...costFlags, ...(tty ? [] : ["--json"])],
        stdout.stream,
        stderr.stream,
        dependencies({
          result,
          costUpdates: [result.cost!],
        }),
      ),
    ).toBe(0);
    const text = stderr.text();
    const showCost = costFlags.length > 0;
    expect(text.includes("COST")).toBe(showCost);
    expect(text).toContain("1,280 total");
    const progress = text.split("REPORT")[0]!;
    expect(progress.includes("$0.00488")).toBe(showCost);
    if (!tty) expect(JSON.parse(stdout.text())).toEqual(result.toJSON());
  }
});

test.each(["resume", "rerun"])(
  "scans %s uses the display flag and saved cost limit",
  async (command) => {
    for (const [flags, maxCostUsd, showCost] of [
      [[], undefined, false],
      [["--show-cost"], undefined, true],
      [[], 20, true],
    ] as const) {
      const stderr = capture();
      expect(
        await main(
          ["scans", command, "scan-original", ...flags],
          capture().stream,
          stderr.stream,
          dependencies({
            result,
            costUpdates: [result.cost!],
            onWorkbench: () => ({
              scanId: "scan-original",
              scanDir: "/tmp/scan",
              recipe: {
                repository: "/synthetic/repository",
                target: { kind: "repository", paths: [] },
                mode: "deep",
                config: {},
                ...(maxCostUsd === undefined ? {} : { maxCostUsd }),
              },
            }),
          }),
        ),
      ).toBe(0);
      expect(stderr.text().includes("$0.00488")).toBe(showCost);
    }
  },
);

test.each([false, true])(
  "missing pricing follows cost visibility: %j",
  async (showCost) => {
    const stderr = capture();
    expect(
      await main(
        ["scan", ...(showCost ? ["--show-cost"] : [])],
        capture().stream,
        stderr.stream,
        dependencies(),
      ),
    ).toBe(0);
    expect(
      stderr.text().includes("unavailable (model pricing or usage missing)"),
    ).toBe(showCost);
  },
);
