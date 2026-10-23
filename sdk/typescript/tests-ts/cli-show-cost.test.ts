import { expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { ScanResult, type ScanTokenUsage } from "../src/index.js";
import { dependencies, fakeResult, fakeSecurity } from "./cli-fixtures.js";
import { createCliTest, captureCli } from "./support/cli-run.js";

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
    const { stdout, stderr, runCli } = createCliTest(main, { stderr: tty });

    expect(
      await runCli(
        ["scan", ".", ...costFlags, ...(tty ? [] : ["--json"])],
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
      const stderr = captureCli(main, "stderr");
      expect(
        await stderr.run(
          ["scans", command, "scan-original", ...flags],
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
    const stderr = captureCli(main, "stderr");
    expect(
      await stderr.run(
        ["scan", ...(showCost ? ["--show-cost"] : [])],
        dependencies(),
      ),
    ).toBe(0);
    expect(
      stderr.text().includes("unavailable (model pricing or usage missing)"),
    ).toBe(showCost);
  },
);

const observedUsage: ScanTokenUsage = {
  input_tokens: 1250,
  cached_input_tokens: 200,
  cache_write_input_tokens: 0,
  cache_write_input_tokens_reported: false,
  output_tokens: 30,
  reasoning_output_tokens: 0,
  total_tokens: 1280,
};

test.each([
  { name: "headless", args: ["--headless"], tty: true, environment: {} },
  { name: "CI", args: [], tty: true, environment: { CI: "true" } },
  { name: "non-TTY", args: [], tty: false, environment: {} },
])("shows live unpriced usage in $name scans", async (mode) => {
  const { stderr, runCli } = createCliTest(main, { stderr: mode.tty });
  const unpriced = new ScanResult({
    ...result,
    turnResult: {
      ...result.turnResult,
      model: "synthetic-unpriced-model",
      usage: observedUsage,
    },
  });
  expect(unpriced.cost).toBeNull();
  const deps = dependencies({ environment: mode.environment });
  deps.createSecurity = () =>
    fakeSecurity(async (_repository, options = {}) => {
      options.onScanStarted?.();
      await Promise.resolve().then(() => options.onUsage?.(observedUsage));
      expect(stderr.text()).toContain("1,280 total");
      expect(stderr.text()).not.toContain("REPORT");
      options.onScanStarted?.();
      expect(stderr.text().trim().split("\n").at(-1)).toContain("1,280 total");
      return unpriced;
    });
  expect(await runCli(["scan", ".", ...mode.args], deps)).toBe(0);
  expect(stderr.text().split("REPORT")[1]).toContain("1,280 total");
});

test.each(
  [[], ["--show-cost"], ["--max-cost", "20"], ["--max-cost", "0.001"]].map(
    (flags) => ({ flags }),
  ),
)("paired usage and cost preserve progress with $flags", async ({ flags }) => {
  const outputs: string[] = [];
  for (const delivery of ["none", "direct", "deferred"]) {
    const { stderr, runCli } = createCliTest(main);
    const deps = dependencies();
    deps.createSecurity = () =>
      fakeSecurity(async (_repository, options = {}) => {
        options.onScanStarted?.();
        if (delivery === "direct") {
          const observed = options.onUsage?.(observedUsage);
          options.onCost?.(result.cost!);
          await observed;
        } else {
          await Promise.all([
            Promise.resolve().then(
              () => delivery === "deferred" && options.onUsage?.(observedUsage),
            ),
            Promise.resolve().then(() => options.onCost?.(result.cost!)),
          ]);
        }
        return result;
      });
    expect(await runCli(["scan", ".", ...flags], deps)).toBe(0);
    outputs.push(stderr.text());
  }
  expect(outputs[1]).toBe(outputs[0]);
  expect(outputs[2]).toBe(outputs[0]);
});
