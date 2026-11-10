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

test("headless scan reports account limits independently of token receipts", async () => {
  const { stdout, stderr, runCli } = createCliTest(main);
  const deps = dependencies();
  deps.createSecurity = () =>
    fakeSecurity(async (_repository, options = {}) => {
      options.onAuthentication?.({
        method: "stored_credentials",
        credentialType: "chatgpt",
        verified: false,
      });
      options.onScanStarted?.();
      expect(stderr.text()).toContain("ChatGPT allowance not reported");
      const accountRateLimits = [
        {
          limitId: "codex",
          observedAt: "2026-01-01T14:02:00.000Z",
          primary: null,
          secondary: { usedPercent: 87, windowMinutes: 10080, resetsAt: null },
        },
      ];
      await options.onUsageObservation?.({
        tokensUpdatedAt: null,
        accountRateLimits,
      });
      expect(stderr.text()).toContain("7d 87% used");
      expect(stderr.text()).not.toContain("Last usage report");
      options.onUsageObservation?.({
        tokensUpdatedAt: "2026-01-01T14:03:00.000Z",
        accountRateLimits,
      });
      await options.onUsage?.(observedUsage);
      options.onScanStarted?.();
      const progress = stderr.text().trim().split("\n").at(-1)!;
      expect(progress).toContain("1,280 total");
      expect(progress).toContain("14:03:00 UTC");
      expect(progress).toContain("in-flight");
      expect(progress).toContain("14:02:00 UTC");
      expect(progress).not.toContain("$");
      return result;
    });
  expect(await runCli(["scan", ".", "--headless", "--json"], deps)).toBe(0);
  expect(JSON.parse(stdout.text())).toEqual(result.toJSON());
});

const plainProgressModes = [
  { name: "headless", args: ["--headless"], tty: true, environment: {} },
  { name: "CI", args: [], tty: true, environment: { CI: "true" } },
  { name: "non-TTY", args: [], tty: false, environment: {} },
];

test.each(plainProgressModes)(
  "shows live unpriced usage in $name scans",
  async (mode) => {
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
        const progress = stderr.text().trim().split("\n").at(-1);
        expect(progress).toContain("1,280 total");
        expect(progress).toContain("Usage report time unavailable");
        return unpriced;
      });
    expect(await runCli(["scan", ".", ...mode.args], deps)).toBe(0);
    expect(stderr.text().split("REPORT")[1]).toContain("1,280 total");
  },
);

test.each(
  plainProgressModes.flatMap((mode) =>
    [false, true].map((priced) => ({ ...mode, priced })),
  ),
)(
  "refreshes successive partial subtotals in $name scans (priced: $priced)",
  async (mode) => {
    const { stderr, runCli } = createCliTest(main, { stderr: mode.tty });
    const deps = dependencies({ environment: mode.environment });
    const updates: Array<{ total: number; output: string }> = [];
    deps.createSecurity = () =>
      fakeSecurity(async (_repository, options = {}) => {
        options.onScanStarted?.();
        for (const total of [100, 200, 300]) {
          const usage: ScanTokenUsage = {
            input_tokens: total - 20,
            cached_input_tokens: 0,
            cache_write_input_tokens: 0,
            cache_write_input_tokens_reported: true,
            output_tokens: 20,
            reasoning_output_tokens: 0,
            total_tokens: total,
          };
          const offset = stderr.text().length;
          options.onMeasurement?.({
            usage,
            cost: mode.priced ? fakeResult([], "complete", usage).cost : null,
            coverage: "partial",
            observedAt: "2026-01-01T00:00:00Z",
            threadCount: 1,
            missingThreadCount: 1,
          });
          updates.push({ total, output: stderr.text().slice(offset) });
        }
        return result;
      });
    expect(await runCli(["scan", ".", "--show-cost", ...mode.args], deps)).toBe(
      0,
    );
    const displayedCosts = new Set<string>();
    for (const { total, output } of updates) {
      expect(output).toContain(`${total} total (partial)`);
      const cost = output.split(" | Cost: ")[1];
      if (mode.priced) {
        expect(cost).toContain("(partial)");
        displayedCosts.add(cost!);
      } else {
        expect(cost).toBeUndefined();
      }
    }
    expect(stderr.text().match(/Usage is partial/g)).toHaveLength(1);
    expect(displayedCosts.size).toBe(mode.priced ? 3 : 0);
  },
);

test.each(
  plainProgressModes.flatMap((mode) =>
    [false, true].flatMap((priced) =>
      [false, true].map((changed) => ({ ...mode, priced, changed })),
    ),
  ),
)(
  "clears recovered usage coverage in $name scans (priced: $priced, changed: $changed)",
  async (mode) => {
    const { stderr, runCli } = createCliTest(main, { stderr: mode.tty });
    const deps = dependencies({ environment: mode.environment });
    let recovery = "";
    const recoveredUsage = {
      ...observedUsage,
      input_tokens: observedUsage.input_tokens + (mode.changed ? 100 : 0),
      total_tokens: observedUsage.total_tokens + (mode.changed ? 100 : 0),
    };
    deps.createSecurity = () =>
      fakeSecurity(async (_repository, options = {}) => {
        options.onScanStarted?.();
        const measurement = {
          usage: observedUsage,
          cost: mode.priced ? result.cost : null,
          coverage: "complete" as const,
          observedAt: "2026-01-01T00:00:00Z",
          threadCount: 1,
          missingThreadCount: 0,
        };
        const initial = options.onMeasurement?.(measurement);
        const usage = options.onUsage?.(observedUsage);
        if (mode.priced) options.onCost?.(result.cost!);
        await Promise.all([initial, usage]);
        await options.onMeasurement?.({
          ...measurement,
          coverage: "partial",
          missingThreadCount: 1,
        });
        const offset = stderr.text().length;
        const cost = mode.priced
          ? fakeResult([], "complete", recoveredUsage).cost
          : null;
        const observed = options.onMeasurement?.({
          ...measurement,
          usage: recoveredUsage,
          cost,
          threadCount: 2,
        });
        const updatedUsage = mode.changed
          ? options.onUsage?.(recoveredUsage)
          : undefined;
        if (cost !== null) options.onCost?.(cost);
        await Promise.all([observed, updatedUsage]);
        recovery = stderr.text().slice(offset);
        return result;
      });
    expect(await runCli(["scan", ".", "--show-cost", ...mode.args], deps)).toBe(
      0,
    );
    expect(recovery).toContain(
      `${recoveredUsage.total_tokens.toLocaleString("en-US")} total`,
    );
    expect(recovery).not.toContain("(partial)");
    expect(recovery.match(/Running scan/g)).toHaveLength(1);
  },
);

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
        const beforeMeasurement = stderr.text();
        options.onMeasurement?.({
          usage: observedUsage,
          cost: result.cost!,
          coverage: "complete",
          observedAt: new Date().toISOString(),
          threadCount: 1,
          missingThreadCount: 0,
        });
        expect(stderr.text()).toBe(beforeMeasurement);
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
