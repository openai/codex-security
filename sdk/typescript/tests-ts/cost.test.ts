import { jsonLines } from "./support/json.js";
import { runNodePython } from "./support/python-probe.js";
import * as filesystem from "node:fs/promises";
import { appendFile, writeFile } from "node:fs/promises";
import * as fs from "node:fs/promises";
import { dirname, join, parse, sep } from "node:path";
import zlib from "node:zlib";
import { Codex } from "@openai/codex-sdk";
import { afterEach, describe, expect, spyOn, test } from "bun:test";
import {
  estimateScanCost,
  ScanCostTracker,
  type ScanSessionEvent,
  type ScanUsageObservation,
  type ScanWorkerEvent,
  type ScanUsageMeasurement,
} from "../src/cost.js";
import type { ScanActivity } from "../src/scan-activity.js";
import { formatTokenUsage, tokenUsage } from "../src/cost-model.js";
import { readScanLogs } from "../src/scan-logs.js";
import { sessionParentThreadId } from "../src/scan-sessions.js";
import type { ScanProgress } from "../src/worker-progress.js";
import { PLUGIN_ROOT as BUNDLED_PLUGIN_ROOT } from "./plugin-root.js";
import {
  childUuid7Thread,
  higherUuid7Turn,
  lowerUuid7Turn,
  ownedPythonUsage,
  ownedSdkUsage,
  parentFields,
  parentMetadata,
  writeSession,
  ownershipRollout,
  readPythonRolloutUsage,
  scanThreadId,
} from "./support/usage-rollout.js";

import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory: codexHome, cleanup } = createApiTestFixtures(
  "codex-security-cost-",
);
async function waitFor(check: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (check()) return;
    await new Promise<void>((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("Timed out waiting for the cost tracker.");
}

afterEach(cleanup);

async function workerSessionFixture() {
  const home = await codexHome();
  const usage = { input_tokens: 100, output_tokens: 10 };
  const parent = await writeSession(home, "scan-thread", usage);
  const worker = await writeSession(home, "worker-thread", usage, {
    parent: "scan-thread",
  });
  return { home, usage, parent, worker };
}

function costTracker(
  home: string,
  options: Omit<
    ConstructorParameters<typeof ScanCostTracker>[0],
    "codexHome" | "model"
  > = {},
) {
  return new ScanCostTracker({
    codexHome: home,
    model: "gpt-5.6-sol",
    ...options,
  });
}

function activityTracker(home: string) {
  const activities: ScanActivity[] = [];
  const tracker = costTracker(home, {
    repository: "/code/juice-shop",
    onActivity: (activity) => activities.push(activity),
  });
  return { activities, tracker };
}

async function appendSessionItem(
  path: string,
  payload: Readonly<Record<string, unknown>>,
): Promise<void> {
  await appendFile(
    path,
    `${JSON.stringify({ type: "response_item", payload })}\n`,
  );
}

function progressMessage(
  filesCompleted: number,
  filesTotal = 8,
  phase: ScanProgress["phase"] = "discovery",
): Record<string, unknown> {
  return {
    type: "message",
    role: "assistant",
    content: [
      {
        type: "output_text",
        text: `CODEX_SECURITY_SCAN_PROGRESS ${JSON.stringify({
          phase,
          filesCompleted,
          filesTotal,
        })}`,
      },
    ],
  };
}

function nativeUsageRecord(
  threadId: string,
  responseId: string,
  usage: Record<string, number>,
  total: Record<string, number> = usage,
): Record<string, unknown> {
  return {
    type: "token_usage_record",
    payload: {
      thread_id: threadId,
      response_id: responseId,
      usage: tokenUsage(usage),
      thread_token_usage: tokenUsage(total),
    },
  };
}

function legacyUsageRecord(usage: Record<string, number>) {
  return {
    type: "event_msg",
    payload: { type: "token_count", info: { total_token_usage: usage } },
  };
}

test.each([
  [
    "prefers the spawned parent over legacy parent fields",
    {
      source: {
        subagent: { thread_spawn: { parent_thread_id: "spawn-parent" } },
      },
      parent_thread_id: "direct-parent",
      forked_from_id: "fork-parent",
    },
    "spawn-parent",
  ],
  [
    "prefers the direct parent over fork ancestry",
    { parent_thread_id: "direct-parent", forked_from_id: "fork-parent" },
    "direct-parent",
  ],
  [
    "falls back from an empty spawned parent to the direct parent",
    {
      source: { subagent: { thread_spawn: { parent_thread_id: "" } } },
      parent_thread_id: "direct-parent",
    },
    "direct-parent",
  ],
  [
    "falls back from an empty direct parent to fork ancestry",
    { parent_thread_id: "", forked_from_id: "fork-parent" },
    "fork-parent",
  ],
  [
    "ignores a non-string direct parent when fork ancestry is present",
    { parent_thread_id: null, forked_from_id: "fork-parent" },
    "fork-parent",
  ],
  ["recognizes independent CLI sessions", { source: "cli" }, null],
  ["treats an empty parent as missing", { forked_from_id: "" }, null],
] as const)("session parent metadata %s", (_name, metadata, expected) => {
  expect(sessionParentThreadId(metadata)).toBe(expected);
});

describe("scan cost", () => {
  test("ignores token-count events without a usage snapshot in both readers", async () => {
    const home = await codexHome();
    const path = await writeSession(
      home,
      childUuid7Thread,
      {},
      { parent: scanThreadId },
    );
    const rollout = ownershipRollout([]);
    rollout.splice(2, 0, {
      type: "event_msg",
      timestamp: "2026-07-26T12:04:00Z",
      payload: {
        type: "token_count",
        info: null,
        rate_limits: { limit_id: "replayed" },
      },
    });
    await writeFile(
      path,
      jsonLines([
        ...rollout,
        {
          type: "event_msg",
          timestamp: "2026-07-26T12:03:00Z",
          payload: {
            type: "token_count",
            info: null,
            rate_limits: { primary: { used_percent: 5 } },
          },
        },
      ]) + "\n",
    );
    const observations: ScanUsageObservation[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-6-astra",
      onUsageObservation: (observation) => observations.push(observation),
    });
    tracker.start(scanThreadId);
    expect((await tracker.stop()).measurement).toMatchObject({
      coverage: "partial",
      usage: ownedSdkUsage,
      missingThreadCount: 1,
    });
    expect(observations).toEqual([
      {
        tokensUpdatedAt: "2026-07-26T12:02:00.250Z",
        accountRateLimits: [
          {
            limitId: "codex",
            observedAt: "2026-07-26T12:03:00.000Z",
            primary: { usedPercent: 5, windowMinutes: null, resetsAt: null },
            secondary: null,
          },
        ],
      },
    ]);
    expect(readPythonRolloutUsage(BUNDLED_PLUGIN_ROOT, path)).toEqual({
      usage: ownedPythonUsage,
      warnings: [],
    });
  });

  test("does not reopen unchanged rollouts and reads appended worker usage", async () => {
    const { home, parent, worker } = await workerSessionFixture();
    await writeSession(home, "unrelated-thread", {
      input_tokens: 900,
      output_tokens: 90,
    });
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-6-astra",
    });
    tracker.start("scan-thread");
    await tracker.refresh();
    const opened = spyOn(fs, "open");
    try {
      await tracker.refresh();
      expect(opened).not.toHaveBeenCalled();
      await appendFile(
        worker,
        jsonLines([
          {
            type: "event_msg",
            payload: {
              type: "token_count",
              info: {
                total_token_usage: { input_tokens: 200, output_tokens: 20 },
              },
            },
          },
        ]) + "\n",
      );
      const snapshot = await tracker.refresh();
      expect(opened.mock.calls.map(([path]) => path)).toEqual([worker]);
      expect(snapshot.usage).toMatchObject({
        input_tokens: 300,
        output_tokens: 30,
      });
      expect(opened.mock.calls.map(([path]) => path)).not.toContain(parent);
    } finally {
      opened.mockRestore();
      await tracker.stop();
    }
  });

  test("reports known usage even when model pricing is unavailable", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const usages: unknown[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "synthetic-unpriced-model",
      onUsage: (usage) => usages.push(usage),
    });
    tracker.start("scan-thread");
    const snapshot = await tracker.stop();
    expect(snapshot.cost).toBeNull();
    expect(snapshot.usage).toMatchObject({
      input_tokens: 100,
      output_tokens: 10,
    });
    expect(usages).toHaveLength(1);
    expect(usages[0]).toEqual(snapshot.usage);
  });

  test("shows distinct token categories without adding cached input twice", () => {
    expect(
      formatTokenUsage({
        input_tokens: 120,
        cached_input_tokens: 30,
        cache_write_tokens: 12,
        output_tokens: 15,
      }),
    ).toBe(
      "78 uncached input, 30 cache reads, 12 cache writes, 15 output, 135 total",
    );
  });

  test("distinguishes missing cache writes from a reported zero", () => {
    const usage = {
      input_tokens: 120,
      cached_input_tokens: 30,
      output_tokens: 15,
    };
    expect(formatTokenUsage(tokenUsage(usage))).toBe(
      "unavailable uncached input, 30 cache reads, unavailable cache writes, 15 output, 135 total",
    );
    expect(formatTokenUsage({ ...usage, cache_write_input_tokens: 0 })).toBe(
      "90 uncached input, 30 cache reads, 0 cache writes, 15 output, 135 total",
    );
    expect(estimateScanCost("gpt-6-astra", usage)).toMatchObject({
      cacheWriteInputTokens: 0,
      cacheWriteInputTokensReported: false,
    });
  });

  test("includes the price source and rates with each estimate", () => {
    const cost = estimateScanCost("gpt-6-astra", {
      input_tokens: 1_000_000,
      cached_input_tokens: 200_000,
      cache_write_input_tokens: 300_000,
      output_tokens: 100_000,
    });
    expect(cost).toEqual({
      model: "gpt-6-astra",
      inputTokens: 1_000_000,
      cachedInputTokens: 200_000,
      cacheWriteInputTokens: 300_000,
      outputTokens: 100_000,
      estimatedUsd: 13.95,
      estimatedUsdRange: { min: 13.95, max: 25.4, context: "unknown" },
      pricing: {
        source: "https://developers.openai.com/api/docs/pricing",
        asOf: "2026-09-14",
        serviceTier: "standard",
        context: "short",
        usdPerMillionTokens: {
          input: 10,
          cacheRead: 1,
          cacheWrite: 12.5,
          output: 50,
        },
        longContextUsdPerMillionTokens: {
          input: 20,
          cacheRead: 2,
          cacheWrite: 25,
          output: 75,
        },
      },
    });
  });
  test.each(["gpt-6-sol", "openai.gpt-6-sol"])(
    "prices every token category and both context ranges for %s",
    (model) => {
      expect(
        estimateScanCost(model, {
          input_tokens: 1_000_000,
          cached_input_tokens: 200_000,
          cache_write_input_tokens: 300_000,
          output_tokens: 100_000,
        }),
      ).toEqual({
        model,
        inputTokens: 1_000_000,
        cachedInputTokens: 200_000,
        cacheWriteInputTokens: 300_000,
        outputTokens: 100_000,
        estimatedUsd: 2.79,
        estimatedUsdRange: { min: 2.79, max: 5.08, context: "unknown" },
        pricing: {
          source: "https://developers.openai.com/api/docs/models/gpt-6-sol",
          asOf: "2026-10-10",
          serviceTier: "standard",
          context: "short",
          usdPerMillionTokens: {
            input: 2,
            cacheRead: 0.2,
            cacheWrite: 2.5,
            output: 10,
          },
          longContextUsdPerMillionTokens: {
            input: 4,
            cacheRead: 0.4,
            cacheWrite: 5,
            output: 15,
          },
        },
      });
    },
  );
  test.each([
    [{ cache_write_tokens: 15 }, 15],
    [{ cache_write_input_tokens: 0, cache_write_tokens: 15 }, 15],
    [{ cache_write_input_tokens: 0, cache_write_tokens: 80 }, 0],
  ] as const)(
    "keeps workbench cache-write normalization aligned with SDK usage for %j as %p tokens",
    async (cacheWrites, expectedCacheWrites) => {
      const { PLUGIN_ROOT } = await import("./plugin-root.js");
      const python = Bun.which("python3") ?? Bun.which("python");
      expect(python).not.toBeNull();
      const usage = {
        input_tokens: 100,
        cached_input_tokens: 40,
        ...cacheWrites,
        output_tokens: 20,
        reasoning_output_tokens: 5,
        total_tokens: 120,
      };
      const probe = [
        "import json, sys",
        "sys.path.insert(0, sys.argv[1])",
        "import workbench_scan_usage",
        "payload = {'info': {'total_token_usage': json.loads(sys.argv[2])}}",
        "print(json.dumps(workbench_scan_usage._token_snapshot(payload)))",
      ].join("\n");
      const result = runNodePython(python!, [
        "-c",
        probe,
        join(PLUGIN_ROOT, "scripts"),
        JSON.stringify(usage),
      ]);

      expect(result.status, result.stderr).toBe(0);
      expect(JSON.parse(result.stdout)).toMatchObject({
        inputTokens: 100,
        cachedInputTokens: 40,
        cacheWriteInputTokens: expectedCacheWrites,
        outputTokens: 20,
        totalTokens: 120,
      });
    },
  );

  test("charges cached input at its discounted rate", () => {
    expect(
      estimateScanCost("gpt-5.6-sol", {
        input_tokens: 1_250,
        cached_input_tokens: 200,
        output_tokens: 30,
      }),
    ).toMatchObject({
      model: "gpt-5.6-sol",
      inputTokens: 1_250,
      cachedInputTokens: 200,
      cacheWriteInputTokens: 0,
      outputTokens: 30,
      estimatedUsd: 0.00488,
    });
  });

  test("charges GPT-5.6 cache writes at their published rate", () => {
    expect(
      estimateScanCost("gpt-5.6-sol", {
        input_tokens: 1_000,
        cached_input_tokens: 100,
        cache_write_input_tokens: 200,
        output_tokens: 10,
      })?.estimatedUsd,
    ).toBe(0.00404);
  });

  test("preserves legacy cache writes after SDK normalization adds zero", () => {
    expect(
      estimateScanCost("gpt-5.6-sol", {
        input_tokens: 1_000,
        cached_input_tokens: 100,
        cache_write_input_tokens: 0,
        cache_write_tokens: 200,
        output_tokens: 10,
      }),
    ).toMatchObject({ cacheWriteInputTokens: 200, estimatedUsd: 0.00404 });
  });

  test("ignores impossible legacy cache writes while retaining canonical usage", () => {
    expect(
      estimateScanCost("gpt-5.6-sol", {
        input_tokens: 1_000,
        cached_input_tokens: 100,
        cache_write_input_tokens: 0,
        cache_write_tokens: 1_001,
        output_tokens: 10,
      }),
    ).toMatchObject({ cacheWriteInputTokens: 0, estimatedUsd: 0.00384 });
  });

  test("does not double-charge reasoning tokens included in output", () => {
    expect(
      estimateScanCost("gpt-5.6-sol", {
        input_tokens: 1_000,
        output_tokens: 10,
        reasoning_output_tokens: 9,
      })?.estimatedUsd,
    ).toBe(0.0042);
  });

  test.each(Object.getOwnPropertyNames(Object.prototype))(
    "does not inherit prices for unknown model %s",
    (model) => {
      for (const selected of [model, `openai.${model}`]) {
        expect(
          estimateScanCost(selected, { input_tokens: 1, output_tokens: 1 }),
        ).toBeNull();
      }
    },
  );

  test("does not invent prices for unknown models or incomplete usage", () => {
    for (const [model, usage] of [
      ["unknown-model", { input_tokens: 1, output_tokens: 1 }],
      ["openai.unknown-model", { input_tokens: 1, output_tokens: 1 }],
      ["gpt-5.6-sol", null],
      ["gpt-5.6-sol", {}],
      ["gpt-5.6-sol", { input_tokens: -1, output_tokens: 1 }],
      ["gpt-5.6-sol", { input_tokens: 1.5, output_tokens: 1 }],
      [
        "gpt-5.6-sol",
        { input_tokens: 1, cached_input_tokens: 2, output_tokens: 1 },
      ],
      [
        "gpt-5.6-sol",
        {
          input_tokens: Number.MAX_SAFE_INTEGER,
          output_tokens: Number.MAX_SAFE_INTEGER,
        },
      ],
    ] as const) {
      expect(estimateScanCost(model, usage)).toBeNull();
    }
  });
});

describe("live scan cost tracking", () => {
  test("observes account limits and actual token measurement times from this scan", async () => {
    const home = await codexHome();
    const path = await writeSession(home, scanThreadId, {});
    const unrelated = await writeSession(home, "unrelated", {});
    const older = "2026-07-26T12:00:00.000Z";
    const limitAt = "2026-07-26T12:01:00.000Z";
    const tokensAt = "2026-07-26T12:02:00.000Z";
    const later = "2026-07-26T12:03:00.000Z";
    const limit = (timestamp: string, usedPercent: number) => ({
      type: "event_msg",
      timestamp,
      payload: {
        type: "token_count",
        info: null,
        rate_limits: {
          limit_id: "codex",
          secondary: { used_percent: usedPercent, window_minutes: 10_080 },
        },
      },
    });
    await appendFile(path, jsonLines([limit(limitAt, 12)]) + "\n");
    await appendFile(unrelated, jsonLines([limit(later, 99)]) + "\n");
    const observations: ScanUsageObservation[] = [];
    const tracker = costTracker(home, {
      onUsageObservation: (observation) => observations.push(observation),
    });
    tracker.start(scanThreadId);
    const accountRateLimits = [
      {
        limitId: "codex",
        observedAt: limitAt,
        primary: null,
        secondary: { usedPercent: 12, windowMinutes: 10_080, resetsAt: null },
      },
    ];
    try {
      expect((await tracker.refresh()).usage).toBeNull();
      expect(observations).toEqual([
        { tokensUpdatedAt: null, accountRateLimits },
      ]);
      const receipt = nativeUsageRecord(
        scanThreadId,
        "response",
        ownedSdkUsage,
      );
      await appendFile(
        path,
        jsonLines([
          { ...receipt, timestamp: tokensAt },
          { ...receipt, timestamp: later },
          limit(older, 3),
        ]) + "\n",
      );
      expect((await tracker.refresh()).usage).toEqual(ownedSdkUsage);
      await tracker.refresh();
      expect(observations.slice(1)).toEqual([
        { tokensUpdatedAt: tokensAt, accountRateLimits },
      ]);
    } finally {
      await tracker.stop();
    }
  });

  test("keeps receipt cache-write detail when an equal legacy counter omits it", async () => {
    const home = await codexHome();
    const usage = {
      ...ownedSdkUsage,
      cached_input_tokens: 20,
      cache_write_input_tokens: 12,
    };
    const path = await writeSession(home, scanThreadId, ownedSdkUsage);
    await appendFile(
      path,
      jsonLines([
        nativeUsageRecord(scanThreadId, "response-1", usage),
        legacyUsageRecord(ownedSdkUsage),
      ]) + "\n",
    );
    const tracker = costTracker(home);
    tracker.start(scanThreadId);
    expect((await tracker.stop(ownedSdkUsage)).cost).toMatchObject({
      inputTokens: 100,
      cachedInputTokens: 20,
      cacheWriteInputTokens: 12,
      outputTokens: 10,
    });
  });

  test("keeps freshness with the last reportable token total", async () => {
    const home = await codexHome();
    const parent = await writeSession(home, scanThreadId, {});
    const first = "2026-07-26T10:01:00.000Z";
    const second = "2026-07-26T10:02:00.000Z";
    const third = "2026-07-26T10:03:00.000Z";
    const measure = (
      path: string,
      timestamp: string | undefined,
      input: number,
    ) =>
      appendFile(
        path,
        jsonLines([
          {
            ...legacyUsageRecord({ input_tokens: input, output_tokens: 0 }),
            timestamp,
          },
        ]) + "\n",
      );
    await measure(parent, first, 10);
    const times: Array<string | null> = [];
    const tracker = costTracker(home, {
      onUsageObservation: ({ tokensUpdatedAt }) => times.push(tokensUpdatedAt),
    });
    tracker.start(scanThreadId);
    try {
      expect((await tracker.refresh()).usage).toMatchObject({
        total_tokens: 10,
      });
      const worker = await writeSession(
        home,
        "worker",
        {},
        { parent: scanThreadId },
      );
      await measure(parent, second, 20);
      expect((await tracker.refresh()).usage).toBeNull();
      expect(times).toEqual([first]);
      await measure(worker, third, 7);
      expect((await tracker.refresh()).usage).toMatchObject({
        total_tokens: 27,
      });
      expect(times).toEqual([first, third]);
      tracker.recordUsage({ input_tokens: 30, output_tokens: 0 });
      expect((await tracker.refresh()).usage).toMatchObject({
        total_tokens: 37,
      });
      expect(times).toEqual([first, third, null]);
      await measure(parent, third, 30);
      await tracker.refresh();
      expect(times.at(-1)).toBe(third);
      await measure(parent, undefined, 30);
      await tracker.refresh();
      expect(times.at(-1)).toBe(third);
      await measure(parent, undefined, 31);
      expect((await tracker.refresh()).usage).toMatchObject({
        total_tokens: 38,
      });
      expect(times.at(-1)).toBeNull();
    } finally {
      await tracker.stop();
    }
  });

  test("counts compaction receipts before stale counters and deduplicates responses", async () => {
    const home = await codexHome();
    const original = { ...ownedSdkUsage };
    const compact = { ...ownedSdkUsage, input_tokens: 40, output_tokens: 3 };
    const compactTotal = {
      ...ownedSdkUsage,
      input_tokens: 140,
      output_tokens: 13,
    };
    const path = await writeSession(home, scanThreadId, original);
    await appendFile(
      path,
      jsonLines([nativeUsageRecord(scanThreadId, "response-1", original)]) +
        "\n",
    );
    const budget = new AbortController();
    const maxCostUsd = 0.000355;
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-6.1-sol",
      maxCostUsd,
      onCost: ({ estimatedUsd }) => {
        if (estimatedUsd > maxCostUsd) budget.abort();
      },
    });
    tracker.start(scanThreadId);
    expect((await tracker.refresh()).cost?.estimatedUsd).toBe(0.0003);
    expect(budget.signal.aborted).toBe(false);

    const compaction = nativeUsageRecord(
      scanThreadId,
      "response-compaction",
      compact,
      compactTotal,
    );
    await appendFile(
      path,
      jsonLines([
        compaction,
        { type: "compacted", payload: { message: "Compacted context." } },
        legacyUsageRecord(original),
      ]) + "\n",
    );
    expect((await tracker.refresh()).cost?.estimatedUsd).toBe(0.00041);
    expect(budget.signal.aborted).toBe(true);

    const final = { ...ownedSdkUsage, input_tokens: 170, output_tokens: 15 };
    const stale = { ...ownedSdkUsage, input_tokens: 130, output_tokens: 12 };
    await appendFile(
      path,
      jsonLines([
        compaction,
        nativeUsageRecord(
          scanThreadId,
          "response-2",
          { ...ownedSdkUsage, input_tokens: 30, output_tokens: 2 },
          final,
        ),
        legacyUsageRecord(stale),
      ]) + "\n",
    );
    expect((await tracker.stop(stale)).usage).toMatchObject({
      input_tokens: 170,
      output_tokens: 15,
      total_tokens: 185,
    });
  });

  test("keeps native receipts scoped to the owned fork across resumed turns", async () => {
    const home = await codexHome();
    const inherited = {
      ...ownedSdkUsage,
      input_tokens: 1_000,
      output_tokens: 100,
    };
    const parent = await writeSession(home, scanThreadId, inherited);
    await appendFile(
      parent,
      jsonLines([
        nativeUsageRecord(scanThreadId, "parent-response", inherited),
      ]) + "\n",
    );
    const child = await writeSession(home, childUuid7Thread, ownedSdkUsage, {
      parent: scanThreadId,
    });
    const rollout = ownershipRollout([lowerUuid7Turn]);
    rollout.splice(
      3,
      0,
      nativeUsageRecord(scanThreadId, "parent-response", inherited),
    );
    rollout.push(
      nativeUsageRecord(childUuid7Thread, "child-response", ownedSdkUsage),
      nativeUsageRecord(scanThreadId, "foreign-response", inherited),
    );
    await writeFile(child, jsonLines(rollout) + "\n");
    const tracker = costTracker(home, { onSessionEvent: () => {} });
    tracker.start(scanThreadId);
    expect((await tracker.refresh()).usage).toMatchObject({
      input_tokens: 1_100,
      output_tokens: 110,
    });
    const compact = { ...ownedSdkUsage, input_tokens: 40, output_tokens: 3 };
    const compactTotal = {
      ...ownedSdkUsage,
      input_tokens: 140,
      output_tokens: 13,
    };
    const compaction = nativeUsageRecord(
      childUuid7Thread,
      "child-compact",
      compact,
      compactTotal,
    );
    await appendFile(child, jsonLines([compaction, compaction]) + "\n");
    expect((await tracker.stop(inherited)).usage).toMatchObject({
      input_tokens: 1_140,
      output_tokens: 113,
    });

    await appendFile(
      child,
      jsonLines([
        {
          type: "event_msg",
          payload: {
            type: "task_started",
            turn_id: "019f9e4d-b3bb-7000-8000-000000000004",
          },
        },
        nativeUsageRecord(
          childUuid7Thread,
          "resumed-response",
          { ...ownedSdkUsage, input_tokens: 60, output_tokens: 6 },
          { ...ownedSdkUsage, input_tokens: 200, output_tokens: 19 },
        ),
      ]) + "\n",
    );
    const resumed = costTracker(home);
    resumed.start(scanThreadId);
    expect((await resumed.stop(inherited)).usage).toMatchObject({
      input_tokens: 1_200,
      output_tokens: 119,
    });
  });

  test.each([1_000, 1_100])(
    "reconciles a native resumed total with a final SDK receipt of %p input tokens",
    async (finalInput) => {
      const home = await codexHome();
      const path = await writeSession(home, scanThreadId, {
        ...ownedSdkUsage,
        input_tokens: 1_000,
      });
      await appendFile(
        path,
        jsonLines([
          nativeUsageRecord(
            scanThreadId,
            "resumed-response",
            { ...ownedSdkUsage, input_tokens: 20, output_tokens: 2 },
            { ...ownedSdkUsage, input_tokens: 1_020, output_tokens: 12 },
          ),
        ]) + "\n",
      );
      const tracker = costTracker(home);
      tracker.start(scanThreadId);
      expect(
        (await tracker.stop({ ...ownedSdkUsage, input_tokens: finalInput }))
          .cost?.inputTokens,
      ).toBe(Math.max(1_020, finalInput));
    },
  );

  test.each([
    [undefined, undefined],
    [0, 0],
    [12, undefined],
    [undefined, 12],
  ] as const)(
    "preserves cache-write usage through SDK normalization: log %p, receipt %p",
    async (writes, receiptWrites) => {
      const home = await codexHome();
      const usage = {
        input_tokens: 120,
        cached_input_tokens: 30,
        output_tokens: 15,
        ...(writes === undefined ? {} : { cache_write_input_tokens: writes }),
      };
      await writeSession(home, "scan-thread", usage);
      const thread = new Codex({
        codexPathOverride: process.execPath,
      }).startThread();
      const executable = thread as unknown as {
        _exec: { run(): AsyncGenerator<string> };
      };
      executable._exec.run = async function* () {
        yield JSON.stringify({
          type: "thread.started",
          thread_id: "scan-thread",
        });
        yield JSON.stringify({
          type: "turn.completed",
          usage: { ...usage, cache_write_input_tokens: receiptWrites },
        });
      };
      const receipt = (await thread.run("Scan the repository.")).usage;
      expect(receipt?.cache_write_input_tokens).toBe(receiptWrites ?? 0);
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-6-astra",
      });
      tracker.start("scan-thread");
      const running = await tracker.refresh();
      const completed = await tracker.stop(receipt);

      expect(formatTokenUsage(running.usage)).toContain(
        `${writes ?? "unavailable"} cache writes`,
      );
      const expectedWrites = receiptWrites ?? writes;
      expect(completed.cost).toMatchObject({
        inputTokens: 120,
        cachedInputTokens: 30,
        cacheWriteInputTokens: expectedWrites ?? 0,
        outputTokens: 15,
      });
      expect(completed.cost?.cacheWriteInputTokensReported).toBe(
        expectedWrites === undefined ? false : undefined,
      );
      expect(formatTokenUsage(completed.usage)).toContain(
        `${expectedWrites ?? "unavailable"} cache writes`,
      );
    },
  );

  test("retains reported write charges when another worker omits cache writes", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 100,
      cached_input_tokens: 20,
      output_tokens: 10,
    });
    await writeSession(
      home,
      "worker-thread",
      {
        input_tokens: 200,
        cached_input_tokens: 40,
        cache_write_input_tokens: 50,
        output_tokens: 20,
      },
      { parent: "scan-thread" },
    );
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-6-astra",
    });
    tracker.start("scan-thread");
    const snapshot = await tracker.stop();
    expect(snapshot.usage).toMatchObject({
      input_tokens: 300,
      cache_write_input_tokens: 50,
      cache_write_input_tokens_reported: false,
      total_tokens: 330,
    });
    expect(snapshot.cost).toMatchObject({
      cacheWriteInputTokens: 50,
      cacheWriteInputTokensReported: false,
      estimatedUsd: 0.004085,
    });
    expect(formatTokenUsage(snapshot.usage)).toContain(
      "unavailable cache writes",
    );
  });

  test("reports newly available cache writes even when the dollar amount is unchanged", async () => {
    const home = await codexHome();
    const updates: unknown[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.5",
      onCost: (cost) => updates.push(cost),
    });
    tracker.start("scan-thread");
    tracker.recordUsage(
      { input_tokens: 100, output_tokens: 10 },
      "scan-thread",
    );
    await tracker.refresh();
    tracker.recordUsage(
      { input_tokens: 100, cache_write_input_tokens: 0, output_tokens: 10 },
      "scan-thread",
    );
    await tracker.stop();
    expect(updates).toHaveLength(2);
    expect(updates[0]).toHaveProperty("cacheWriteInputTokensReported", false);
    expect(updates[1]).not.toHaveProperty("cacheWriteInputTokensReported");
  });
  test("coalesces overlapping polling ticks and bounds final work", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const releases: Array<() => void> = [];
    const tracker = costTracker(home, {
      maxCostUsd: 1,
    });
    const refresh = tracker.refresh.bind(tracker);
    tracker.refresh = async () => {
      await new Promise<void>((resolve) => releases.push(resolve));
      return refresh();
    };
    tracker.start("scan-thread");

    await new Promise<void>((resolve) => setTimeout(resolve, 350));
    expect(releases).toHaveLength(1);

    const stopped = tracker.stop();
    expect(releases).toHaveLength(2);
    releases[0]!();
    releases[1]!();

    expect((await stopped).cost?.inputTokens).toBe(100);
    expect(releases).toHaveLength(2);
  });

  test("retries one coalesced poll after a failed refresh", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const errors: string[] = [];
    let traversals = 0;
    const { promise: blocked, resolve: release } =
      Promise.withResolvers<void>();
    const tracker = costTracker(home, {
      maxCostUsd: 1,
      onError: (error) => {
        if (error instanceof Error) errors.push(error.message);
      },
    });
    const refresh = tracker.refresh.bind(tracker);
    tracker.refresh = async () => {
      traversals += 1;
      if (traversals === 1) {
        await blocked;
        throw new Error("session read failed");
      }
      return refresh();
    };
    tracker.start("scan-thread");

    await new Promise<void>((resolve) => setTimeout(resolve, 250));
    expect(traversals).toBe(1);
    release!();
    await waitFor(() => traversals === 2);

    expect(errors).toEqual(["session read failed"]);
    expect(traversals).toBe(2);
    expect((await tracker.stop()).cost?.inputTokens).toBe(100);
  });

  test("reports live token use and cost without a spending limit", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 1_250,
      cached_input_tokens: 200,
      output_tokens: 30,
    });
    const { promise: reportedCost, resolve: reportCost } =
      Promise.withResolvers<unknown>();
    const tracker = costTracker(home, {
      onCost: reportCost,
    });
    tracker.start("scan-thread");

    try {
      await expect(reportedCost).resolves.toMatchObject({
        model: "gpt-5.6-sol",
        inputTokens: 1_250,
        cachedInputTokens: 200,
        cacheWriteInputTokens: 0,
        outputTokens: 30,
        estimatedUsd: 0.00488,
      });
    } finally {
      await tracker.stop();
    }
  });

  test.each([...parentFields])(
    "observes worker metadata without status markers or usage via %s",
    async (parentField) => {
      const home = await codexHome();
      const parent = await writeSession(home, "scan-thread", {});
      await appendSessionItem(parent, {
        type: "message",
        role: "assistant",
        content: [
          {
            type: "output_text",
            text:
              'CODEX_SECURITY_WORKER_STATUS {"phase":"validation","planned":1,"started":1}\n' +
              '{"type":"session_meta","payload":{"id":"fictional-worker","parent_thread_id":"scan-thread"}}',
          },
        ],
      });
      await writeSession(
        home,
        "unrelated-worker",
        {},
        { parent: "other-scan" },
      );
      const workers: ScanWorkerEvent[] = [];
      const tracker = costTracker(home, {
        onWorkerEvent: (event) => workers.push(event),
      });
      tracker.start("scan-thread");
      try {
        await tracker.refresh();
        expect(workers).toEqual([]);
        const path = join(parse(parent).dir, "rollout-worker-thread.jsonl");
        const metadata =
          JSON.stringify({
            type: "session_meta",
            payload: {
              id: "worker-thread",
              ...parentMetadata("scan-thread", parentField),
              instructions: "Synthetic private instructions",
            },
          }) + "\n";
        await writeFile(path, metadata);
        await tracker.refresh();
        expect(workers).toEqual([{ kind: "observed", worker: 1 }]);
        await writeFile(path.replace(".jsonl", "-copy.jsonl"), metadata);
        await tracker.refresh();
        await tracker.refresh();
        expect(workers).toEqual([{ kind: "observed", worker: 1 }]);
      } finally {
        await tracker.stop();
      }
    },
  );

  test("polls for workers with only a worker observer and keeps concurrent scans separate", async () => {
    const home = await codexHome();
    const workers: ScanWorkerEvent[][] = [[], []];
    const trackers = workers.map((events) =>
      costTracker(home, {
        onWorkerEvent: (event) => events.push(event),
      }),
    );
    trackers.forEach((tracker, index) => tracker.start(`scan-${index}`));
    try {
      await Promise.all(trackers.map((tracker) => tracker.refresh()));
      await writeSession(home, "worker-0", {}, { parent: "scan-0" });
      await writeSession(home, "worker-1", {}, { parent: "scan-1" });
      await waitFor(() => workers.every((events) => events.length === 1));
      expect(workers).toEqual([
        [{ kind: "observed", worker: 1 }],
        [{ kind: "observed", worker: 1 }],
      ]);
    } finally {
      await Promise.all(trackers.map((tracker) => tracker.stop()));
    }
    const resumed: ScanWorkerEvent[] = [];
    const tracker = costTracker(home, {
      onWorkerEvent: (event) => resumed.push(event),
    });
    tracker.start("scan-0");
    await tracker.stop();
    expect(resumed).toEqual([{ kind: "observed", worker: 1 }]);
  });

  test("counts the scan and delegated workers without including other scans", async () => {
    const home = await codexHome();
    const parent = await writeSession(home, "scan-thread", {
      input_tokens: 1_000,
      cached_input_tokens: 100,
      cache_write_input_tokens: 200,
      output_tokens: 10,
      reasoning_output_tokens: 2,
    });
    const worker = await writeSession(
      home,
      "worker-thread",
      {
        input_tokens: 250,
        cached_input_tokens: 50,
        output_tokens: 5,
        reasoning_output_tokens: 1,
      },
      { parent: "scan-thread" },
    );
    await writeSession(home, "unrelated-thread", {
      input_tokens: 1_000_000,
      output_tokens: 1_000_000,
    });
    const events: ScanSessionEvent[] = [];
    const tracker = costTracker(home, {
      onSessionEvent: (event) => events.push(event),
    });
    tracker.start("scan-thread");
    await waitFor(() => events.length === 4);
    await appendFile(
      parent,
      `${JSON.stringify({ type: "turn_context", payload: { instructions: "Check authorization" } })}\n`,
    );
    await appendSessionItem(worker, {
      type: "function_call",
      name: "spawn_agent",
    });
    await tracker.refresh();
    await tracker.refresh();

    expect(await tracker.stop()).toMatchObject({
      usage: {
        input_tokens: 1_250,
        cached_input_tokens: 150,
        cache_write_input_tokens: 200,
        output_tokens: 15,
        reasoning_output_tokens: 3,
        total_tokens: 1_265,
      },
      cost: {
        model: "gpt-5.6-sol",
        inputTokens: 1_250,
        cachedInputTokens: 150,
        cacheWriteInputTokens: 200,
        outputTokens: 15,
        estimatedUsd: 0.00496,
      },
    });
    expect(
      events.map(({ threadId, parentThreadId, event }) => [
        threadId,
        parentThreadId,
        event["type"],
      ]),
    ).toEqual(
      expect.arrayContaining([
        ["scan-thread", null, "session_meta"],
        ["scan-thread", null, "event_msg"],
        ["worker-thread", "scan-thread", "session_meta"],
        ["worker-thread", "scan-thread", "event_msg"],
        ["scan-thread", null, "turn_context"],
        ["worker-thread", "scan-thread", "response_item"],
      ]),
    );
    expect(events).toHaveLength(6);
  });

  for (const compressed of [false, true]) {
    test
      .skipIf(compressed && typeof zlib.zstdCompressSync !== "function")
      .each(["initial copies", "copy", "move"] as const)(
      `forwards archived session events once after %s (compressed=${compressed})`,
      async (mode) => {
        const { home, worker } = await workerSessionFixture();
        const message = {
          type: "response_item",
          payload: {
            type: "message",
            role: "assistant",
            content: [{ type: "output_text", text: "Checking the next file." }],
          },
        };
        const call = {
          type: "response_item",
          payload: {
            type: "function_call",
            name: "exec_command",
            call_id: "call-one",
            arguments: '{"cmd":"pwd"}',
          },
        };
        // Identical messages at different positions are separate real events.
        await appendFile(worker, jsonLines([message, call, message]) + "\n");
        const contents = await fs.readFile(worker);
        const expected = contents
          .toString()
          .trimEnd()
          .split("\n")
          .map((line) => JSON.parse(line) as Record<string, unknown>);
        const archive = join(home, "archived_sessions");
        await fs.mkdir(archive);
        const archived = join(archive, "rollout-worker.jsonl");
        const copy = () =>
          writeFile(
            `${archived}${compressed ? ".zst" : ""}`,
            compressed ? zlib.zstdCompressSync(contents) : contents,
          );
        if (mode === "initial copies") await copy();
        const events: ScanSessionEvent[] = [];
        const tracker = costTracker(home, {
          onSessionEvent: (event) => events.push(event),
        });
        const workerEvents = () =>
          events
            .filter((event) => event.threadId === "worker-thread")
            .map((event) => event.event);
        tracker.start("scan-thread");
        try {
          await tracker.refresh();
          expect(workerEvents()).toEqual(expected);
          if (mode !== "initial copies") await copy();
          if (mode === "move") await fs.unlink(worker);
          await tracker.refresh();
          expect(workerEvents()).toEqual(expected);

          // Resuming cold history materializes the same bytes before appending.
          if (compressed) await writeFile(archived, contents);
          const continuation = [
            message,
            {
              type: "response_item",
              payload: {
                type: "function_call_output",
                call_id: "call-one",
                output: "/synthetic/repository",
              },
            },
          ];
          await appendFile(archived, jsonLines(continuation) + "\n");
          expected.push(...continuation);
          await tracker.refresh();
          expect(workerEvents()).toEqual(expected);

          // A lagging copy catching up must not replay the new suffix.
          if (mode !== "move") {
            await appendFile(worker, jsonLines(continuation) + "\n");
            await tracker.refresh();
            expect(workerEvents()).toEqual(expected);
          }
          const latest = [
            message,
            legacyUsageRecord({ input_tokens: 400, output_tokens: 40 }),
          ];
          await appendFile(
            mode === "move" ? archived : worker,
            jsonLines(latest) + "\n",
          );
          expected.push(...latest);
          const snapshot = await tracker.refresh();
          expect(workerEvents()).toEqual(expected);
          expect(snapshot.measurement).toMatchObject({
            coverage: "complete",
            threadCount: 2,
            usage: { input_tokens: 500, output_tokens: 50 },
          });
          await tracker.refresh();
          expect(workerEvents()).toEqual(expected);
        } finally {
          await tracker.stop();
        }
      },
    );
  }

  test("forwards a new rollout generation for an existing thread", async () => {
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    await writeSession(home, "scan-thread", usage);
    const worker = await writeSession(home, "worker-thread", usage, {
      parent: "scan-thread",
      timestamp: "2026-07-26T12:00:00.000Z",
    });
    const events: ScanSessionEvent[] = [];
    const tracker = costTracker(home, {
      onSessionEvent: (event) => events.push(event),
    });
    tracker.start("scan-thread");
    try {
      await tracker.refresh();
      const oldEvents = events
        .filter((event) => event.threadId === "worker-thread")
        .map((event) => event.event);
      expect(oldEvents).toHaveLength(2);
      // Revert keeps the thread ID but creates a new rollout and timestamp.
      const metadata = oldEvents[0]!;
      const newEvents = [
        {
          ...metadata,
          payload: {
            ...(metadata["payload"] as Record<string, unknown>),
            timestamp: "2026-07-26T12:01:00.000Z",
          },
        },
        oldEvents[1]!,
      ];
      await writeFile(
        `${worker.slice(0, -6)}_reverted.jsonl`,
        jsonLines(newEvents) + "\n",
      );
      await tracker.refresh();
      await tracker.refresh();
      expect(
        events
          .filter((event) => event.threadId === "worker-thread")
          .map((event) => event.event),
      ).toEqual([...oldEvents, ...newEvents]);
    } finally {
      await tracker.stop();
    }
  });

  test("does not replay stale worker activity or progress from archived copies", async () => {
    const { home, worker } = await workerSessionFixture();
    const otherWorker = await writeSession(
      home,
      "second-worker",
      { input_tokens: 100, output_tokens: 10 },
      { parent: "scan-thread" },
    );
    await appendSessionItem(worker, {
      type: "function_call",
      name: "exec_command",
      call_id: "call-one",
      arguments: '{"cmd":"pwd"}',
    });
    await appendSessionItem(worker, progressMessage(1, 8));
    const stale = await fs.readFile(worker);
    const activities: ScanActivity[] = [];
    const progress: ScanProgress[] = [];
    const tracker = costTracker(home, {
      repository: "/synthetic/repository",
      expectedFilesTotal: 16,
      onActivity: (activity) => activities.push(activity),
      onProgress: (update) => progress.push(update),
    });
    tracker.start("scan-thread");
    try {
      await tracker.refresh();
      await appendSessionItem(worker, {
        type: "function_call_output",
        call_id: "call-one",
        output: "/synthetic/repository",
      });
      await appendSessionItem(worker, progressMessage(3, 8));
      await tracker.refresh();
      const archive = join(home, "archived_sessions");
      await fs.mkdir(archive);
      await writeFile(join(archive, "rollout-worker.jsonl"), stale);
      await tracker.refresh();
      await appendSessionItem(otherWorker, progressMessage(1, 8));
      await tracker.refresh();
      expect({
        toolStatuses: activities
          .filter((activity) => activity.id === "worker-thread:call-one")
          .map((activity) => activity.status),
        completedFiles: progress.map((update) => update.filesCompleted),
      }).toEqual({
        toolStatuses: ["running", "completed"],
        completedFiles: [1, 3, 4],
      });
    } finally {
      await tracker.stop();
    }
  });

  test("recovers raw session events after their replay read fails", async () => {
    const { home, worker } = await workerSessionFixture();
    await appendSessionItem(worker, {
      type: "function_call",
      name: "exec_command",
      call_id: "call-one",
      arguments: '{"cmd":"pwd"}',
    });
    await appendSessionItem(worker, progressMessage(1));
    const expected = (await fs.readFile(worker, "utf8"))
      .trimEnd()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    let denied = true;
    let reads = 0;
    const opened = filesystem.open;
    const opening = spyOn(filesystem, "open").mockImplementation(
      async (...args: Parameters<typeof filesystem.open>) => {
        if (String(args[0]) === worker && ++reads > 1 && denied) {
          throw Object.assign(new Error("Synthetic replay read failure"), {
            code: "EACCES",
            syscall: "open",
            path: worker,
          });
        }
        return await opened(...args);
      },
    );
    const events: ScanSessionEvent[] = [];
    const activities: ScanActivity[] = [];
    const progress: ScanProgress[] = [];
    const tracker = costTracker(home, {
      repository: "/synthetic/repository",
      onSessionEvent: (event) => events.push(event),
      onActivity: (activity) => activities.push(activity),
      onProgress: (update) => progress.push(update),
    });
    const workerEvents = () =>
      events
        .filter((event) => event.threadId === "worker-thread")
        .map((event) => event.event);
    const toolStatuses = () =>
      activities
        .filter((activity) => activity.id === "worker-thread:call-one")
        .map((activity) => activity.status);
    tracker.start("scan-thread");
    try {
      await expect(tracker.refresh()).rejects.toMatchObject({ code: "EACCES" });
      expect(workerEvents()).toEqual([]);
      expect(toolStatuses()).toEqual(["running"]);
      expect(progress.map((update) => update.filesCompleted)).toEqual([1]);

      denied = false;
      const snapshot = await tracker.refresh();
      expect(workerEvents()).toEqual(expected);
      expect(toolStatuses()).toEqual(["running"]);
      expect(progress.map((update) => update.filesCompleted)).toEqual([1]);
      expect(snapshot.measurement).toMatchObject({
        coverage: "complete",
        usage: { input_tokens: 200, output_tokens: 20 },
      });
      const continuation = [
        {
          type: "response_item",
          payload: {
            type: "function_call_output",
            call_id: "call-one",
            output: "/synthetic/repository",
          },
        },
        { type: "response_item", payload: progressMessage(0) },
        { type: "response_item", payload: progressMessage(2) },
      ];
      await appendFile(worker, jsonLines(continuation) + "\n");
      await tracker.refresh();
      await tracker.refresh();
      expect(workerEvents()).toEqual([...expected, ...continuation]);
      expect(toolStatuses()).toEqual(["running", "completed"]);
      expect(progress.map((update) => update.filesCompleted)).toEqual([1, 2]);
    } finally {
      denied = false;
      opening.mockRestore();
      await tracker.stop();
    }
  });

  test.each(["parent", "main"] as const)(
    "replays early worker events when the %s session arrives later",
    async (missing) => {
      const home = await codexHome();
      const scanDirectory = join(home, "scan");
      const usage = { input_tokens: 10, output_tokens: 1 };
      const writeMain = () =>
        writeSession(home, "scan-thread", usage, {
          cwd: scanDirectory,
          timestamp: "2026-07-26T12:00:00Z",
        });
      if (missing === "parent") await writeMain();
      const worker = await writeSession(home, "worker-thread", usage, {
        parent: missing === "parent" ? "parent-worker" : undefined,
        cwd: join(
          scanDirectory,
          "artifacts",
          "deep_discovery",
          "workers",
          "one",
          "output",
        ),
        timestamp: "2026-07-26T12:01:00Z",
      });
      const message = (text: string) => ({
        type: "message",
        role: "assistant",
        content: [{ type: "output_text", text }],
      });
      await appendSessionItem(worker, message("Early worker output."));
      const unrelated = await writeSession(home, "unrelated-thread", usage);
      await appendSessionItem(unrelated, message("Unrelated output."));
      const events: ScanSessionEvent[] = [];
      const workers: ScanWorkerEvent[] = [];
      const tracker = costTracker(home, {
        scanDirectory,
        onSessionEvent: (event) => events.push(event),
        onWorkerEvent: (event) => workers.push(event),
      });
      tracker.start("scan-thread");
      await tracker.refresh();
      expect(events.some((event) => event.threadId === "worker-thread")).toBe(
        false,
      );

      expect(workers).toEqual([]);
      if (missing === "parent") {
        await writeSession(home, "parent-worker", usage, {
          parent: "scan-thread",
        });
      } else {
        await writeMain();
      }
      await appendSessionItem(worker, message("Late worker output."));
      await tracker.refresh();
      await tracker.refresh();
      await tracker.stop();

      expect(workers).toEqual(
        missing === "parent"
          ? [
              { kind: "observed", worker: 1 },
              { kind: "observed", worker: 2 },
            ]
          : [{ kind: "observed", worker: 1 }],
      );
      const workerEvents = events.filter(
        (event) => event.threadId === "worker-thread",
      );
      expect(workerEvents.map((event) => event.event)).toEqual([
        expect.objectContaining({ type: "session_meta" }),
        expect.objectContaining({ type: "event_msg" }),
        { type: "response_item", payload: message("Early worker output.") },
        { type: "response_item", payload: message("Late worker output.") },
      ]);
      expect(new Set(workerEvents.map((event) => event.worker))).toEqual(
        new Set([1]),
      );
      expect(
        events.some((event) => event.threadId === "unrelated-thread"),
      ).toBe(false);
    },
  );

  test.each([
    ["EACCES", true],
    ["EACCES", false],
    ["EPERM", true],
    ["EPERM", false],
  ] as const)(
    "retains and retries a %s worker when its parent appears later (already identified: %j)",
    async (code, identified) => {
      const home = await codexHome();
      const usage = (input_tokens: number) => ({
        input_tokens,
        output_tokens: 0,
      });
      await writeSession(home, "scan-thread", usage(10));
      const worker = await writeSession(home, "worker", usage(1), {
        parent: "middle",
      });
      let denied = !identified;
      let attempts = 0;
      const opened = filesystem.open;
      const opening = spyOn(filesystem, "open").mockImplementation(
        async (...args: Parameters<typeof filesystem.open>) => {
          if (String(args[0]) === worker && denied) {
            attempts += 1;
            throw Object.assign(new Error(`Synthetic ${code}`), {
              code,
              syscall: "open",
              path: worker,
            });
          }
          return await opened(...args);
        },
      );
      const reported: number[] = [];
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-sol",
        maxCostUsd: 1,
        onCost: (cost) => reported.push(cost.inputTokens),
      });
      tracker.start("scan-thread");
      try {
        if (identified) {
          expect((await tracker.refresh()).cost?.inputTokens).toBe(10);
          denied = true;
          expect((await tracker.refresh()).cost?.inputTokens).toBe(10);
        } else {
          await expect(tracker.refresh()).rejects.toMatchObject({ code });
        }
        await appendFile(
          worker,
          `${JSON.stringify({ type: "event_msg", payload: { type: "token_count", info: { total_token_usage: usage(1_000_000) } } })}\n`,
        );
        await writeSession(home, "middle", usage(20), {
          parent: "scan-thread",
        });
        await expect(tracker.refresh()).rejects.toMatchObject({ code });
        await expect(tracker.refresh()).rejects.toMatchObject({ code });
        denied = false;
        const snapshot = await tracker.stop();
        expect(snapshot.cost?.inputTokens).toBe(1_000_030);
        expect(snapshot.cost!.estimatedUsd).toBeGreaterThan(1);
        expect(reported).toContain(1_000_030);
        expect(attempts).toBeGreaterThanOrEqual(2);
      } finally {
        denied = false;
        await tracker.stop().catch(() => {});
        opening.mockRestore();
      }
    },
  );

  test.each([...parentFields])(
    "counts independent Deep workers and %s descendants",
    async (parentField) => {
      const home = await codexHome();
      const scanDirectory = join(home, "scans", "current");
      const artifacts = join(scanDirectory, "artifacts");
      const workerDirectory = join(
        artifacts,
        "deep_discovery",
        "workers",
        "worker",
        "output",
      );
      await writeSession(
        home,
        "scan-thread",
        { input_tokens: 1_000, output_tokens: 10 },
        { cwd: scanDirectory, timestamp: "2026-07-26T12:00:00.900Z" },
      );
      await writeSession(
        home,
        "deep-worker",
        { input_tokens: 250, output_tokens: 2 },
        {
          cwd:
            process.platform === "win32"
              ? workerDirectory.toUpperCase()
              : workerDirectory,
          timestamp: "2026-07-26T12:00:00.900Z",
        },
      );
      await writeSession(
        home,
        "deep-reducer",
        { input_tokens: 125, output_tokens: 1 },
        {
          cwd:
            (process.platform === "win32"
              ? artifacts.toUpperCase()
              : artifacts) + sep,
          timestamp: "2026-07-26T12:02:00Z",
        },
      );
      await writeSession(
        home,
        "deep-worker-child",
        { input_tokens: 50, output_tokens: 1 },
        { parent: "deep-worker", parentField },
      );
      await writeSession(
        home,
        "unrelated-thread",
        { input_tokens: 1_000_000, output_tokens: 1_000_000 },
        { cwd: `${scanDirectory}-other` },
      );
      await writeSession(
        home,
        "previous-scan",
        { input_tokens: 1_000_000, output_tokens: 1_000_000 },
        {
          cwd: join(
            scanDirectory,
            "artifacts",
            "deep_discovery",
            "previous-worker",
          ),
          timestamp: "2026-07-26T11:59:00Z",
        },
      );
      await writeSession(
        home,
        "unknown-start",
        { input_tokens: 1_000_000, output_tokens: 1_000_000 },
        {
          cwd: join(
            scanDirectory,
            "artifacts",
            "deep_discovery",
            "workers",
            "stale",
            "output",
          ),
        },
      );
      await writeSession(
        home,
        "nested-scan",
        { input_tokens: 1_000_000, output_tokens: 1_000_000 },
        {
          cwd: join(scanDirectory, "nested", "artifacts"),
          timestamp: "2026-07-26T12:03:00Z",
        },
      );
      const events: ScanSessionEvent[] = [];
      const workers: ScanWorkerEvent[] = [];
      const tracker = costTracker(home, {
        scanDirectory,
        onSessionEvent: (event) => events.push(event),
        onWorkerEvent: (event) => workers.push(event),
      });
      tracker.start("scan-thread");

      expect((await tracker.stop()).usage).toMatchObject({
        input_tokens: 1_425,
        output_tokens: 14,
      });
      expect(workers).toEqual(
        [1, 2, 3].map((worker) => ({ kind: "observed", worker })),
      );
      const labels = new Map(
        events.map(({ threadId, worker }) => [threadId, worker]),
      );
      expect(new Set(labels.keys())).toEqual(
        new Set([
          "scan-thread",
          "deep-worker",
          "deep-reducer",
          "deep-worker-child",
        ]),
      );
      expect(labels.get("scan-thread")).toBeUndefined();
      expect(
        [...labels.values()].filter((worker) => worker !== undefined).sort(),
      ).toEqual([1, 2, 3]);
      const logs = await readScanLogs({
        scanId: "scan-example",
        threadId: "scan-thread",
        codexHome: home,
        scanDirectory,
      });
      expect(new Set(logs.sessions.map(({ threadId }) => threadId))).toEqual(
        new Set(labels.keys()),
      );
    },
  );

  test.each([
    [
      "sessions beside the deep worker output directories",
      (scan: string) => join(scan, "artifacts", "deep_discovery", "output"),
      "2026-07-26T12:02:00Z",
      undefined,
      "source",
    ],
    [
      "sessions on another Windows drive",
      (scan: string) =>
        parse(scan).root.toLowerCase().startsWith("c:")
          ? "D:\\output"
          : "C:\\output",
      "2026-07-26T12:02:00Z",
      undefined,
      "source",
    ],
    [
      "sessions earlier in the same second",
      (scan: string) => join(scan, "artifacts"),
      "2026-07-26T12:00:00.100Z",
      undefined,
      "source",
    ],
    [
      "sessions with an invalid timestamp",
      (scan: string) => join(scan, "artifacts"),
      "not-a-timestamp",
      undefined,
      "source",
    ],
    [
      "sessions with an unrelated parent",
      (scan: string) => join(scan, "artifacts"),
      "2026-07-26T12:02:00Z",
      "unrelated-parent",
      "source",
    ],
    [
      "sessions with an unrelated direct parent",
      (scan: string) => join(scan, "artifacts"),
      "2026-07-26T12:02:00Z",
      "unrelated-parent",
      "parent_thread_id",
    ],
    [
      "sessions forked from an unrelated parent",
      (scan: string) => join(scan, "artifacts"),
      "2026-07-26T12:02:00Z",
      "unrelated-parent",
      "forked_from_id",
    ],
  ] as const)(
    "excludes %s from scan cost and logs",
    async (_name, workingDirectory, timestamp, parentThreadId, parentField) => {
      const home = await codexHome();
      const scanDirectory = join(home, "scans", "current");
      await writeSession(
        home,
        "scan-thread",
        { input_tokens: 1_000, output_tokens: 10 },
        { cwd: scanDirectory, timestamp: "2026-07-26T12:00:00.900Z" },
      );
      await writeSession(
        home,
        "deep-worker",
        { input_tokens: 250, output_tokens: 2 },
        {
          cwd: join(
            scanDirectory,
            "artifacts",
            "deep_discovery",
            "workers",
            "worker",
            "output",
          ),
          timestamp: "2026-07-26T12:00:00.950Z",
        },
      );
      await writeSession(
        home,
        "bystander",
        { input_tokens: 1_000_000, output_tokens: 1_000_000 },
        {
          parent: parentThreadId,
          cwd: workingDirectory(scanDirectory),
          timestamp,
          parentField,
        },
      );
      await writeSession(
        home,
        "bystander-child",
        { input_tokens: 1_000_000, output_tokens: 1_000_000 },
        { parent: "bystander" },
      );
      const events: ScanSessionEvent[] = [];
      const tracker = costTracker(home, {
        scanDirectory,
        maxCostUsd: 0.01,
        onSessionEvent: (event) => events.push(event),
      });
      tracker.start("scan-thread");

      const snapshot = await tracker.stop();
      expect(snapshot.usage).toMatchObject({
        input_tokens: 1_250,
        output_tokens: 12,
      });
      expect(snapshot.cost?.estimatedUsd).toBe(0.00524);
      const included = [
        ...new Set(events.map(({ threadId }) => threadId)),
      ].sort();
      expect(included).toEqual(["deep-worker", "scan-thread"]);
      const logs = await readScanLogs({
        scanId: "scan-example",
        threadId: "scan-thread",
        codexHome: home,
        scanDirectory,
      });
      expect(logs.sessions.map(({ threadId }) => threadId).sort()).toEqual(
        included,
      );
    },
  );

  test.each([undefined, "not-a-timestamp"])(
    "does not infer independent workers when the scan timestamp is %s",
    async (timestamp) => {
      const home = await codexHome();
      const scanDirectory = join(home, "scan");
      await writeSession(
        home,
        "scan-thread",
        { input_tokens: 1_000, output_tokens: 10 },
        { cwd: scanDirectory, timestamp },
      );
      await writeSession(
        home,
        "independent-worker",
        { input_tokens: 1_000_000, output_tokens: 1_000_000 },
        {
          cwd: join(scanDirectory, "artifacts"),
          timestamp: "2026-07-26T12:01:00Z",
        },
      );
      await writeSession(
        home,
        "child-worker",
        { input_tokens: 250, output_tokens: 2 },
        { parent: "scan-thread" },
      );
      const tracker = costTracker(home, {
        scanDirectory,
      });
      tracker.start("scan-thread");
      expect((await tracker.stop()).usage).toMatchObject({
        input_tokens: 1_250,
        output_tokens: 12,
      });
    },
  );

  test.each([...parentFields])(
    "ignores replayed parent history in %s worker sessions",
    async (parentField) => {
      const home = await codexHome();
      const inherited = {
        input_tokens: 1_000,
        cached_input_tokens: 500,
        cache_write_input_tokens: 100,
        output_tokens: 100,
        reasoning_output_tokens: 20,
      };
      await writeSession(home, "scan-thread", inherited);
      const worker = await writeSession(home, "worker-thread", inherited);
      const command =
        'rg "password" "$CODEX_SECURITY_REPOSITORY/routes/login.ts"';

      await writeFile(
        worker,
        jsonLines([
          {
            type: "session_meta",
            payload: {
              id: "worker-thread",
              timestamp: "2026-07-26T12:02:00.250Z",
              ...parentMetadata("scan-thread", parentField),
            },
          },
          {
            type: "session_meta",
            payload: {
              id: "scan-thread",
              timestamp: "2026-07-26T12:00:00.000Z",
              source: "exec",
            },
          },
          {
            type: "event_msg",
            payload: { type: "task_started", started_at: 1_785_067_200 },
          },
          {
            type: "event_msg",
            payload: {
              type: "agent_message",
              message: "Inherited parent commentary.",
            },
          },
          {
            type: "response_item",
            payload: {
              type: "function_call",
              name: "exec_command",
              call_id: "inherited-search",
              arguments: JSON.stringify({ cmd: command }),
            },
          },
          { type: "response_item", payload: progressMessage(7) },
          {
            type: "event_msg",
            payload: {
              type: "token_count",
              info: { total_token_usage: inherited },
            },
          },
          {
            type: "event_msg",
            payload: { type: "task_started", started_at: 1_785_067_320 },
          },
          {
            type: "event_msg",
            timestamp: "2026-07-26T12:02:01.000Z",
            payload: {
              type: "agent_message",
              message: "Reviewing the login query.",
            },
          },
          {
            type: "response_item",
            payload: {
              type: "function_call",
              name: "exec_command",
              call_id: "worker-search",
              arguments: JSON.stringify({ cmd: command }),
            },
          },
          {
            type: "response_item",
            payload: {
              type: "function_call_output",
              call_id: "worker-search",
              output:
                "Batch reviewed.\n" +
                'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":3,"filesTotal":8}',
            },
          },
          {
            type: "event_msg",
            payload: {
              type: "token_count",
              info: {
                total_token_usage: {
                  input_tokens: 1_300,
                  cached_input_tokens: 650,
                  cache_write_input_tokens: 150,
                  output_tokens: 130,
                  reasoning_output_tokens: 30,
                },
              },
            },
          },
        ]) + "\n",
      );

      const activities: ScanActivity[] = [];
      const progress: ScanProgress[] = [];
      const events: ScanSessionEvent[] = [];
      const workers: ScanWorkerEvent[] = [];
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-terra",
        repository: "/code/juice-shop",
        expectedFilesTotal: 8,
        onActivity: (activity) => activities.push(activity),
        onProgress: (update) => progress.push(update),
        onSessionEvent: (event) => events.push(event),
        onWorkerEvent: (event) => workers.push(event),
      });
      tracker.start("scan-thread");

      expect(await tracker.stop()).toMatchObject({
        usage: {
          input_tokens: 1_300,
          cached_input_tokens: 650,
          cache_write_input_tokens: 150,
          output_tokens: 130,
          reasoning_output_tokens: 30,
          total_tokens: 1_430,
        },
        cost: {
          model: "gpt-5.6-terra",
          inputTokens: 1_300,
          cachedInputTokens: 650,
          cacheWriteInputTokens: 150,
          outputTokens: 130,
          estimatedUsd: 0.003065,
        },
      });
      expect(workers).toEqual([{ kind: "observed", worker: 1 }]);
      expect(activities).toEqual([
        expect.objectContaining({
          kind: "message",
          description: "Reviewing the login query.",
          worker: 1,
        }),
        expect.objectContaining({
          id: "worker-thread:worker-search",
          kind: "command",
          status: "running",
          worker: 1,
        }),
        expect.objectContaining({
          id: "worker-thread:worker-search",
          kind: "command",
          status: "completed",
          worker: 1,
        }),
      ]);
      expect(progress).toEqual([
        { phase: "discovery", filesCompleted: 3, filesTotal: 8 },
      ]);
      const workerEvents = events.filter(
        ({ threadId }) => threadId === "worker-thread",
      );
      expect(workerEvents).toHaveLength(6);
      expect(JSON.stringify(workerEvents)).not.toContain(
        "Inherited parent commentary.",
      );
    },
  );

  test.each([
    [
      "keeps an earlier-millisecond UUIDv7 turn in inherited history",
      ["019f9e4d-b3b9-7000-8000-000000000001"],
    ],
    [
      "keeps a same-millisecond lower UUIDv7 turn in inherited history",
      [lowerUuid7Turn],
    ],
    ["accepts a same-millisecond higher UUIDv7 turn as child-owned", []],
  ] as const)("%s", async (_name, replayedTurnIds) => {
    const home = await codexHome();
    const rolloutPath = await writeSession(
      home,
      childUuid7Thread,
      { input_tokens: 1_100, output_tokens: 110 },
      { parent: scanThreadId },
    );
    const rollout = ownershipRollout(replayedTurnIds);
    await writeFile(rolloutPath, jsonLines(rollout) + "\n");

    const maxCostUsd = 0.001;
    const observedCosts: number[] = [];
    const forwardedEvents: ScanSessionEvent[] = [];
    const tracker = costTracker(home, {
      maxCostUsd,
      onCost: ({ estimatedUsd }) => observedCosts.push(estimatedUsd),
      onSessionEvent: (event) => forwardedEvents.push(event),
    });
    tracker.start(scanThreadId);
    const tracked = await tracker.stop();
    const python = readPythonRolloutUsage(BUNDLED_PLUGIN_ROOT, rolloutPath);

    expect({
      trackedUsage: tracked.measurement.usage,
      estimatedUsd: tracked.measurement.cost?.estimatedUsd,
      python,
    }).toMatchObject({
      trackedUsage: ownedSdkUsage,
      estimatedUsd: 0.0006,
      python: {
        usage: ownedPythonUsage,
        warnings: [],
      },
    });
    expect(tracked.measurement.coverage).toBe("partial");
    expect(tracked.measurement.missingThreadCount).toBe(1);
    expect(observedCosts.length).toBeGreaterThan(0);
    expect(observedCosts.every((cost) => cost < maxCostUsd)).toBe(true);
    const forwardedTurnIds = forwardedEvents.flatMap(({ event }) => {
      const payload = event["payload"];
      return typeof payload === "object" &&
        payload !== null &&
        (payload as Record<string, unknown>)["type"] === "task_started"
        ? [(payload as Record<string, unknown>)["turn_id"]]
        : [];
    });
    expect(forwardedTurnIds).toEqual([higherUuid7Turn]);
    const saved = await readScanLogs({
      scanId: "scan-example",
      threadId: childUuid7Thread,
      codexHome: home,
    });
    const ownedEvents = [rollout[0]!, ...rollout.slice(-3)];
    expect(forwardedEvents.map(({ event }) => event)).toEqual(ownedEvents);
    expect(saved.events.map(({ event }) => event)).toEqual(ownedEvents);
  });

  test("forwards actions from this scan's delegated workers only", async () => {
    const {
      home,
      usage,
      parent: parentPath,
      worker: workerPath,
    } = await workerSessionFixture();
    const unrelatedPath = await writeSession(home, "unrelated-thread", usage);
    const command =
      'rg -n "password" "$CODEX_SECURITY_REPOSITORY/routes/login.ts"';

    for (const [path, callId] of [
      [parentPath, "parent-command"],
      [workerPath, "worker-command"],
      [unrelatedPath, "unrelated-command"],
    ] as const) {
      await appendSessionItem(path, {
        type: "function_call",
        name: "exec_command",
        call_id: callId,
        arguments: JSON.stringify({ cmd: command }),
      });
      await appendSessionItem(path, {
        type: "function_call_output",
        call_id: callId,
      });
    }

    const activities: ScanActivity[] = [];
    const events: ScanSessionEvent[] = [];
    const tracker = costTracker(home, {
      repository: "/code/juice-shop",
      onActivity: (activity) => activities.push(activity),
      onSessionEvent: (event) => events.push(event),
    });
    tracker.start("scan-thread");
    await tracker.stop();

    expect(activities).toEqual([
      {
        id: "worker-thread:worker-command",
        kind: "command",
        status: "running",
        description: command,
        paths: ["routes/login.ts"],
        worker: 1,
      },
      {
        id: "worker-thread:worker-command",
        kind: "command",
        status: "completed",
        description: command,
        paths: ["routes/login.ts"],
        worker: 1,
      },
    ]);
    expect(
      new Map(events.map(({ threadId, worker }) => [threadId, worker])),
    ).toEqual(
      new Map([
        ["scan-thread", undefined],
        ["worker-thread", 1],
      ]),
    );
  });

  test("forwards genuine worker reasoning and transcript text", async () => {
    const { home, worker: path } = await workerSessionFixture();
    await appendSessionItem(path, {
      id: "thinking-1",
      type: "reasoning",
      summary: [{ type: "summary_text", text: "Following the login query." }],
      encrypted_content: "do-not-display",
    });
    await appendSessionItem(path, {
      id: "message-1",
      type: "message",
      role: "assistant",
      content: [{ type: "output_text", text: "The query uses request input." }],
    });

    const { activities, tracker } = activityTracker(home);
    tracker.start("scan-thread");
    await tracker.stop();

    expect(activities).toEqual([
      {
        id: "worker-thread:thinking-1",
        kind: "reasoning",
        status: "completed",
        description: "Following the login query.",
        paths: [],
        worker: 1,
      },
      {
        id: "worker-thread:message-1",
        kind: "message",
        status: "completed",
        description: "The query uses request input.",
        paths: [],
        worker: 1,
      },
    ]);
  });

  test("streams worker reasoning and commentary from live session events once", async () => {
    const { home, worker } = await workerSessionFixture();
    await appendFile(
      worker,
      [
        JSON.stringify({
          type: "event_msg",
          timestamp: "2026-07-26T12:00:00.000Z",
          payload: {
            type: "agent_reasoning",
            text: "Tracing the login query.",
          },
        }),
        JSON.stringify({
          type: "response_item",
          payload: {
            id: "reasoning-1",
            type: "reasoning",
            summary: [
              { type: "summary_text", text: "Tracing the login query." },
            ],
            encrypted_content: "must-never-be-displayed",
          },
        }),
        JSON.stringify({
          type: "event_msg",
          timestamp: "2026-07-26T12:00:01.000Z",
          payload: {
            type: "agent_message",
            message:
              "Reviewed the login query.\n" +
              'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":3,"filesTotal":8}',
          },
        }),
        JSON.stringify({
          type: "response_item",
          payload: {
            id: "message-1",
            type: "message",
            role: "assistant",
            content: [
              { type: "output_text", text: "Reviewed the login query." },
            ],
          },
        }),
        "",
      ].join("\n"),
    );

    const activities: ScanActivity[] = [];
    const updates: ScanProgress[] = [];
    const tracker = costTracker(home, {
      repository: "/code/juice-shop",
      expectedFilesTotal: 8,
      onActivity: (activity) => activities.push(activity),
      onProgress: (progress) => updates.push(progress),
    });
    tracker.start("scan-thread");
    await tracker.stop();

    expect(activities).toEqual([
      expect.objectContaining({
        kind: "reasoning",
        description: "Tracing the login query.",
        worker: 1,
      }),
      expect.objectContaining({
        kind: "message",
        description: "Reviewed the login query.",
        worker: 1,
      }),
    ]);
    expect(updates).toEqual([
      { phase: "discovery", filesCompleted: 3, filesTotal: 8 },
    ]);
  });

  test("expands streamed worker reasoning without duplicating summaries or exposing encrypted content", async () => {
    const { home, worker } = await workerSessionFixture();
    const details = `${"The query reaches a privileged tenant boundary. ".repeat(30)}Final authorization check.`;
    const raw = `**The route builds SQL from request parameters.** ${details}`;
    await appendFile(
      worker,
      [
        {
          type: "event_msg",
          payload: {
            type: "agent_reasoning_delta",
            delta: "Checking whether ",
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "agent_reasoning_delta",
            delta: "the login query escapes user input.",
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "agent_reasoning",
            text: "Checking whether the login query escapes user input.",
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "agent_reasoning_raw_content_delta",
            delta: "The route builds SQL ",
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "agent_reasoning_raw_content_delta",
            delta: "from request parameters.",
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "agent_reasoning_raw_content",
            text: raw,
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "agent_reasoning",
            text: "This summary must not replace public raw reasoning.",
          },
        },
        {
          type: "response_item",
          payload: {
            id: "reasoning-1",
            type: "reasoning",
            summary: [
              {
                type: "summary_text",
                text: "Checking whether the login query escapes user input.",
              },
              { type: "summary_text", text: "Preparing SQL validation." },
            ],
            encrypted_content: "never-display-encrypted-reasoning",
          },
        },
        "",
      ]
        .map((event) =>
          typeof event === "string" ? event : JSON.stringify(event),
        )
        .join("\n"),
    );

    const { activities, tracker } = activityTracker(home);
    tracker.start("scan-thread");
    await tracker.stop();

    expect(new Set(activities.map((activity) => activity.id))).toEqual(
      new Set(["worker-thread:reasoning-1"]),
    );
    expect(activities).toContainEqual(
      expect.objectContaining({
        kind: "reasoning",
        status: "running",
        description: "Checking whether the login query escapes user input.",
        worker: 1,
      }),
    );
    expect(activities.at(-1)).toEqual({
      id: "worker-thread:reasoning-1",
      kind: "reasoning",
      status: "completed",
      description: `The route builds SQL from request parameters. ${details}`,
      paths: [],
      worker: 1,
    });
    expect(activities.at(-1)!.description.length).toBeGreaterThan(1_000);
    expect(JSON.stringify(activities)).not.toContain("encrypted-reasoning");
  });

  test("keeps distinct streamed worker reasoning summaries separate", async () => {
    const { home, worker } = await workerSessionFixture();
    const summaries = [
      "**Planning discovery worker tasks**",
      "**Preparing thorough file batch reading**",
      "**Verifying repository read access and tools**",
    ];
    await appendFile(
      worker,
      [
        ...summaries.map((text) => ({
          type: "event_msg",
          payload: { type: "agent_reasoning", text },
        })),
        {
          type: "response_item",
          payload: {
            id: "reasoning-1",
            type: "reasoning",
            summary: summaries.map((text) => ({ type: "summary_text", text })),
            encrypted_content: "must-never-be-displayed",
          },
        },
        "",
      ]
        .map((event) =>
          typeof event === "string" ? event : JSON.stringify(event),
        )
        .join("\n"),
    );

    const { activities, tracker } = activityTracker(home);
    tracker.start("scan-thread");
    await tracker.stop();

    expect(activities).toEqual(
      summaries.map((text, index) => ({
        id: `worker-thread:reasoning-${index + 1}`,
        kind: "reasoning",
        status: "completed",
        description: text.replaceAll("**", ""),
        paths: [],
        worker: 1,
      })),
    );
  });

  test("splits worker reasoning summaries without streamed events", async () => {
    const { home, worker } = await workerSessionFixture();
    await appendSessionItem(worker, {
      id: "reasoning-1",
      type: "reasoning",
      summary: [
        { type: "summary_text", text: "**Planning discovery worker tasks**" },
        {
          type: "summary_text",
          text: "**Preparing thorough file batch reading**",
        },
      ],
      encrypted_content: "must-never-be-displayed",
    });

    const { activities, tracker } = activityTracker(home);
    tracker.start("scan-thread");
    await tracker.stop();

    expect(activities).toEqual([
      {
        id: "worker-thread:reasoning-1:0",
        kind: "reasoning",
        status: "completed",
        description: "Planning discovery worker tasks",
        paths: [],
        worker: 1,
      },
      {
        id: "worker-thread:reasoning-1:1",
        kind: "reasoning",
        status: "completed",
        description: "Preparing thorough file batch reading",
        paths: [],
        worker: 1,
      },
    ]);
    expect(JSON.stringify(activities)).not.toContain("must-never-be-displayed");
  });

  test("forwards reviewed-file progress from descendant workers only", async () => {
    const { home, usage, parent, worker } = await workerSessionFixture();
    const descendant = await writeSession(home, "nested-worker-thread", usage, {
      parent: "worker-thread",
    });
    const unrelated = await writeSession(home, "unrelated-thread", usage);

    await appendSessionItem(parent, progressMessage(1));
    await appendSessionItem(worker, progressMessage(3));
    await appendSessionItem(worker, progressMessage(4, 9));
    await appendSessionItem(descendant, progressMessage(5));
    await appendSessionItem(unrelated, progressMessage(7));

    const updates: ScanProgress[] = [];
    const tracker = costTracker(home, {
      expectedFilesTotal: 8,
      onProgress: (progress) => updates.push(progress),
    });
    tracker.start("scan-thread");
    await tracker.stop();

    expect(updates).toEqual([
      { phase: "discovery", filesCompleted: expect.any(Number), filesTotal: 8 },
      { phase: "discovery", filesCompleted: 8, filesTotal: 8 },
    ]);
    expect([3, 5]).toContain(updates[0]!.filesCompleted);
  });

  test("aggregates worker progress without regressing or changing assigned shards", async () => {
    const { home, usage, parent, worker } = await workerSessionFixture();
    const otherWorker = await writeSession(home, "other-worker-thread", usage, {
      parent: "scan-thread",
    });
    const unrelated = await writeSession(home, "unrelated-thread", usage);
    const updates: ScanProgress[] = [];
    const tracker = costTracker(home, {
      expectedFilesTotal: 1_258,
      onProgress: (progress) => updates.push(progress),
    });
    tracker.start("scan-thread");
    await tracker.refresh();

    await appendSessionItem(worker, progressMessage(3, 1_249));
    await tracker.refresh();

    await appendSessionItem(otherWorker, progressMessage(2, 2));
    await appendSessionItem(otherWorker, progressMessage(3, 3));
    await appendSessionItem(otherWorker, progressMessage(1, 1_259));
    await appendSessionItem(parent, progressMessage(1_200, 1_258));
    await appendSessionItem(unrelated, progressMessage(1_200, 1_258));

    const marker = `CODEX_SECURITY_SCAN_PROGRESS ${JSON.stringify({
      phase: "discovery",
      filesCompleted: 1_200,
      filesTotal: 1_249,
    })}`;
    await appendSessionItem(otherWorker, {
      type: "custom_tool_call_output",
      call_id: "failed-shard-review",
      status: "failed",
      output: [{ type: "input_text", text: marker }],
    });
    await appendSessionItem(otherWorker, {
      type: "custom_tool_call_output",
      call_id: "documented-shard-example",
      status: "completed",
      output: [{ type: "input_text", text: `\`\`\`text\n${marker}\n\`\`\`` }],
    });
    await tracker.refresh();

    await appendSessionItem(worker, progressMessage(1_249, 1_249));
    await tracker.refresh();
    await appendSessionItem(
      worker,
      progressMessage(1_249, 1_249, "validation"),
    );
    await tracker.refresh();
    await tracker.stop();

    expect(updates).toEqual([
      { phase: "discovery", filesCompleted: 3, filesTotal: 1_258 },
      { phase: "discovery", filesCompleted: 5, filesTotal: 1_258 },
      { phase: "discovery", filesCompleted: 1_251, filesTotal: 1_258 },
      { phase: "validation", filesCompleted: 1_251, filesTotal: 1_258 },
    ]);
  });

  test("adds reviewed files from independent delegated-worker shards", async () => {
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    await writeSession(home, "scan-thread", usage);
    const first = await writeSession(home, "worker-a", usage, {
      parent: "scan-thread",
    });
    const second = await writeSession(home, "worker-b", usage, {
      parent: "scan-thread",
    });
    const unrelated = await writeSession(home, "unrelated-worker", usage);
    const updates: ScanProgress[] = [];
    const tracker = costTracker(home, {
      expectedFilesTotal: 4_198,
      onProgress: (progress) => updates.push(progress),
    });
    tracker.start("scan-thread");
    await tracker.refresh();

    await appendSessionItem(first, progressMessage(250, 840));
    await tracker.refresh();
    await appendSessionItem(second, progressMessage(100, 839));
    await tracker.refresh();
    await appendSessionItem(unrelated, progressMessage(839, 839));
    await appendSessionItem(first, progressMessage(840, 840));
    await tracker.refresh();
    await appendSessionItem(second, progressMessage(839, 839));
    await tracker.refresh();
    await tracker.stop();

    expect(updates).toEqual([
      { phase: "discovery", filesCompleted: 250, filesTotal: 4_198 },
      { phase: "discovery", filesCompleted: 350, filesTotal: 4_198 },
      { phase: "discovery", filesCompleted: 940, filesTotal: 4_198 },
      { phase: "discovery", filesCompleted: 1_679, filesTotal: 4_198 },
    ]);
  });

  test("counts only explicit successful worker review receipts", async () => {
    const { home, worker } = await workerSessionFixture();
    const marker = (filesCompleted: number) =>
      `CODEX_SECURITY_SCAN_PROGRESS ${JSON.stringify({
        phase: "discovery",
        filesCompleted,
        filesTotal: 8,
      })}`;

    for (const payload of [
      {
        type: "function_call",
        name: "exec_command",
        call_id: "search",
        arguments: JSON.stringify({
          cmd: 'rg -n "password" "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
        }),
      },
      {
        type: "function_call_output",
        call_id: "search",
        output: "routes/login.ts:12: const password = request.body.password;",
      },
      {
        type: "function_call_output",
        call_id: "failed-review",
        status: "failed",
        output: marker(2),
      },
      {
        type: "function_call_output",
        call_id: "malformed-review",
        output:
          'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":}',
      },
      {
        type: "function_call_output",
        call_id: "completed-review",
        output: `Batch reviewed.\n${marker(3)}`,
      },
      {
        type: "custom_tool_call_output",
        call_id: "documented-example",
        output: [
          { type: "input_text", text: "Example:" },
          { type: "input_text", text: `\`\`\`text\n${marker(4)}\n\`\`\`` },
        ],
      },
      {
        type: "custom_tool_call_output",
        call_id: "completed-structured-review",
        status: "completed",
        output: [
          { type: "input_text", text: "Batch reviewed." },
          { type: "input_text", text: marker(4) },
        ],
      },
      {
        type: "custom_tool_call_output",
        call_id: "completed-custom-review",
        output: marker(5),
      },
      progressMessage(9),
    ]) {
      await appendSessionItem(worker, payload);
    }

    const updates: ScanProgress[] = [];
    const tracker = costTracker(home, {
      expectedFilesTotal: 8,
      onProgress: (progress) => updates.push(progress),
    });
    tracker.start("scan-thread");
    await tracker.stop();

    expect(updates).toEqual([
      { phase: "discovery", filesCompleted: 3, filesTotal: 8 },
      { phase: "discovery", filesCompleted: 4, filesTotal: 8 },
      { phase: "discovery", filesCompleted: 5, filesTotal: 8 },
    ]);
  });

  test("polls worker file progress without another observer", async () => {
    const { home, worker } = await workerSessionFixture();
    await appendSessionItem(worker, progressMessage(3));

    const { promise: reportedProgress, resolve: reportProgress } =
      Promise.withResolvers<ScanProgress>();
    const tracker = costTracker(home, {
      expectedFilesTotal: 8,
      onProgress: reportProgress,
    });
    tracker.start("scan-thread");

    try {
      await expect(reportedProgress).resolves.toEqual({
        phase: "discovery",
        filesCompleted: 3,
        filesTotal: 8,
      });
    } finally {
      await tracker.stop();
    }
  });

  test("reports newly completed worker batches once per progress update", async () => {
    const { home, worker } = await workerSessionFixture();
    const updates: ScanProgress[] = [];
    const tracker = costTracker(home, {
      expectedFilesTotal: 8,
      onProgress: (progress) => updates.push(progress),
    });
    tracker.start("scan-thread");
    await tracker.refresh();

    await appendSessionItem(worker, progressMessage(3));
    await tracker.refresh();
    await appendSessionItem(worker, progressMessage(3));
    await tracker.refresh();
    await appendSessionItem(worker, progressMessage(5));
    await tracker.refresh();
    await tracker.stop();

    expect(updates).toEqual([
      { phase: "discovery", filesCompleted: 3, filesTotal: 8 },
      { phase: "discovery", filesCompleted: 5, filesTotal: 8 },
    ]);
  });

  test("uses each session's final cumulative usage without double counting", async () => {
    const home = await codexHome();
    const path = await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
    });
    tracker.start("scan-thread");
    expect((await tracker.refresh()).cost?.estimatedUsd).toBe(0.00032);

    const latest = JSON.stringify({
      type: "event_msg",
      payload: {
        type: "token_count",
        info: {
          total_token_usage: { input_tokens: 250, output_tokens: 20 },
        },
      },
    });
    await appendFile(path, `${latest}\n${latest}\n`);

    expect((await tracker.stop()).cost).toMatchObject({
      model: "gpt-5.6-terra",
      inputTokens: 250,
      cachedInputTokens: 0,
      cacheWriteInputTokens: 0,
      outputTokens: 20,
      estimatedUsd: 0.00074,
    });
  });

  test("retains a partial event across incremental reads", async () => {
    const home = await codexHome();
    const path = await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const events: ScanSessionEvent[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
      onSessionEvent: (event) => events.push(event),
    });
    tracker.start("scan-thread");
    await tracker.refresh();

    const event = JSON.stringify({
      type: "event_msg",
      payload: {
        type: "token_count",
        details: "😀",
        info: {
          total_token_usage: { input_tokens: 250, output_tokens: 20 },
        },
      },
    });
    const encoded = Buffer.from(event);
    const split = encoded.indexOf(Buffer.from("😀")) + 2;
    const padding = " ".repeat(128 * 1_024);
    await appendFile(
      path,
      Buffer.concat([Buffer.from(padding), encoded.subarray(0, split)]),
    );
    expect((await tracker.refresh()).cost?.inputTokens).toBe(100);
    expect(events).toHaveLength(2);

    await appendFile(
      path,
      Buffer.concat([encoded.subarray(split), Buffer.from("\n")]),
    );
    expect((await tracker.stop()).cost?.inputTokens).toBe(250);
    expect(events).toHaveLength(3);
    expect(events.at(-1)?.event).toEqual(JSON.parse(event));
  });

  test("reads session events larger than 16 MiB", async () => {
    const home = await codexHome();
    const path = await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
    });
    tracker.start("scan-thread");

    const event = JSON.stringify({
      type: "event_msg",
      payload: {
        type: "token_count",
        info: {
          total_token_usage: { input_tokens: 250, output_tokens: 20 },
        },
        details: "x".repeat(16 * 1_024 * 1_024 + 1),
      },
    });
    await appendFile(path, event.slice(0, -10));
    expect((await tracker.refresh()).cost?.inputTokens).toBe(100);

    await appendFile(path, `${event.slice(-10)}\n`);
    expect((await tracker.stop()).cost?.inputTokens).toBe(250);
  });

  test("reports a changed running cost only once", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 1_250,
      cached_input_tokens: 200,
      output_tokens: 30,
    });
    const updates: number[] = [];
    const tracker = costTracker(home, {
      maxCostUsd: 0.005,
      onCost: (cost) => updates.push(cost.estimatedUsd),
    });
    tracker.start("scan-thread");

    await tracker.stop();

    expect(updates).toEqual([0.00488]);
  });

  test.each([undefined, 100, 1_000, 1_500])(
    "reconciles the parent receipt with worker usage when logged parent tokens are %p",
    async (parentTokens) => {
      const home = await codexHome();
      if (parentTokens !== undefined) {
        await writeSession(home, "scan-thread", {
          input_tokens: parentTokens,
          output_tokens: 0,
        });
      }
      await writeSession(
        home,
        "worker-thread",
        { input_tokens: 100, output_tokens: 0 },
        { parent: "scan-thread" },
      );
      const tracker = costTracker(home);
      tracker.start("scan-thread");

      const snapshot = await tracker.stop({
        input_tokens: 1_000,
        output_tokens: 0,
      });

      expect(snapshot.cost?.inputTokens).toBe(
        Math.max(parentTokens ?? 0, 1_000) + 100,
      );
    },
  );

  test("falls back to the completed turn when session logs are unavailable", async () => {
    const tracker = new ScanCostTracker({
      codexHome: await codexHome(),
      model: "gpt-5.6-luna",
    });
    const usage = { input_tokens: 1_000, output_tokens: 20 };
    tracker.start("scan-thread");

    expect(await tracker.stop(usage)).toMatchObject({
      usage: {
        ...usage,
        cached_input_tokens: 0,
        cache_write_input_tokens: 0,
        reasoning_output_tokens: 0,
        total_tokens: 1_020,
      },
      cost: {
        model: "gpt-5.6-luna",
        inputTokens: 1_000,
        cachedInputTokens: 0,
        cacheWriteInputTokens: 0,
        outputTokens: 20,
        estimatedUsd: 0.000224,
      },
    });
  });

  test("reports budget subtotals until missing worker usage becomes measured", async () => {
    const home = await codexHome();
    const parentUsage = { input_tokens: 1_000_000, output_tokens: 100_000 };
    await writeSession(home, "scan-thread", parentUsage);
    const costs: Array<[number, boolean]> = [];
    const usages: unknown[] = [];
    const measurements: Readonly<ScanUsageMeasurement>[] = [];
    const tracker = costTracker(home, {
      onCost: (cost, complete) => costs.push([cost.estimatedUsd, complete]),
      onUsage: (usage) => usages.push(usage),
      onMeasurement: (measurement) => measurements.push(measurement),
    });
    tracker.start("scan-thread");
    expect((await tracker.refresh()).cost?.estimatedUsd).toBe(6);

    const worker = await writeSession(
      home,
      "worker-thread",
      {},
      {
        parent: "scan-thread",
      },
    );
    expect(await tracker.refresh()).toMatchObject({ usage: null, cost: null });
    expect(costs.at(-1)).toEqual([6, false]);
    expect(usages).toHaveLength(1);
    expect(measurements.at(-1)).toMatchObject({
      coverage: "partial",
      threadCount: 1,
      missingThreadCount: 1,
      usage: { input_tokens: 1_000_000 },
      coverageScope: ["thread:scan-thread", "thread:worker-thread"],
    });

    await appendFile(
      worker,
      jsonLines([legacyUsageRecord({ input_tokens: 0, output_tokens: 0 })]) +
        "\n",
    );
    expect((await tracker.refresh()).usage).toMatchObject({
      ...parentUsage,
      total_tokens: 1_100_000,
    });
    expect(costs.at(-1)).toEqual([6, true]);
    expect(measurements.at(-1)).toMatchObject({
      coverage: "complete",
      threadCount: 2,
      missingThreadCount: 0,
      coverageScope: ["thread:scan-thread", "thread:worker-thread"],
    });
    expect(usages).toHaveLength(1);

    await appendFile(
      worker,
      jsonLines([
        legacyUsageRecord({ input_tokens: 500_000, output_tokens: 50_000 }),
      ]) + "\n",
    );
    expect((await tracker.stop(parentUsage)).usage).toMatchObject({
      input_tokens: 1_500_000,
      output_tokens: 150_000,
      total_tokens: 1_650_000,
    });
    expect(costs).toEqual([
      [6, true],
      [6, false],
      [6, true],
      [9, true],
    ]);
    expect(usages).toHaveLength(2);
  });

  test.skipIf(typeof zlib.zstdCompressSync !== "function").each([true, false])(
    "counts compressed independent workers in active and archived sessions once (native=%p)",
    async (native) => {
      const home = await codexHome();
      const scanDirectory = join(home, "scans", "compressed");
      const parentUsage = { input_tokens: 100, output_tokens: 10 };
      await writeSession(home, "scan-thread", parentUsage, {
        timestamp: "2026-07-26T12:00:00Z",
      });
      const worker = await writeSession(
        home,
        "compressed-worker",
        {
          input_tokens: 900,
          output_tokens: 90,
        },
        {
          cwd: join(
            scanDirectory,
            "artifacts",
            "deep_discovery",
            "workers",
            "one",
            "output",
          ),
          timestamp: "2026-07-26T12:01:00Z",
        },
      );
      await appendFile(
        worker,
        jsonLines([
          {
            type: "event_msg",
            timestamp: "2026-07-26T12:03:00Z",
            payload: {
              type: "token_count",
              info: null,
              rate_limits: { primary: { used_percent: 5 } },
            },
          },
        ]) + "\n",
      );
      const compressed = zlib.zstdCompressSync(await fs.readFile(worker));
      await writeFile(`${worker}.zst`, compressed);
      const archive = join(home, "archived_sessions");
      await fs.mkdir(archive);
      await writeFile(join(archive, "rollout-copy.jsonl.zst"), compressed);
      await writeFile(
        join(archive, "rollout-unrelated.jsonl.zst"),
        zlib.zstdCompressSync(
          Buffer.from(
            JSON.stringify({
              type: "session_meta",
              payload: { id: "unrelated-history" },
            }) +
              "\nnot a valid event; unrelated historical bodies must not be parsed\n",
          ),
        ),
      );
      await fs.unlink(worker);
      const observations: ScanUsageObservation[] = [];
      const tracker = costTracker(home, {
        scanDirectory,
        onUsageObservation: (value) => observations.push(value),
      });
      tracker.start("scan-thread");
      const original = Object.getOwnPropertyDescriptor(
        zlib,
        "createZstdDecompress",
      );
      if (!native)
        Object.defineProperty(zlib, "createZstdDecompress", {
          value: undefined,
        });
      let snapshot;
      try {
        snapshot = await tracker.stop(parentUsage);
      } finally {
        if (original)
          Object.defineProperty(zlib, "createZstdDecompress", original);
      }
      expect(snapshot.measurement).toMatchObject({
        coverage: "complete",
        threadCount: 2,
        missingThreadCount: 0,
        usage: { input_tokens: 1_000, output_tokens: 100 },
      });
      expect(snapshot.cost?.inputTokens).toBe(1_000);
      expect(observations).toEqual([
        {
          tokensUpdatedAt: null,
          accountRateLimits: [
            {
              limitId: "codex",
              observedAt: "2026-07-26T12:03:00.000Z",
              primary: { usedPercent: 5, windowMinutes: null, resetsAt: null },
              secondary: null,
            },
          ],
        },
      ]);
    },
  );

  for (const compressed of [false, true]) {
    test
      .skipIf(compressed && typeof zlib.zstdCompressSync !== "function")
      .each([false, true])(
      `retains SDK budget receipts when a rollout changes after enumeration (compressed=${compressed}, missing=%p)`,
      async (missing) => {
        const home = await codexHome();
        const costs: number[] = [];
        const tracker = costTracker(home, {
          maxCostUsd: 0.003,
          onCost: (cost) => costs.push(cost.estimatedUsd),
        });
        tracker.start("scan-thread");
        await tracker.stop();
        const plain = await writeSession(home, "scan-thread", {
          input_tokens: 1_000,
          output_tokens: 0,
        });
        const contents = await fs.readFile(plain);
        const path = `${plain}${compressed ? ".zst" : ""}`;
        const encoded = compressed ? zlib.zstdCompressSync(contents) : contents;
        if (compressed) {
          await writeFile(path, encoded);
          await fs.rm(plain);
        }
        let changed = false;
        const originalRead = filesystem.readdir;
        const reading = spyOn(filesystem, "readdir").mockImplementation(
          async (...args) => {
            const entries = await Reflect.apply(originalRead, filesystem, args);
            if (!changed && args[0] === dirname(path)) {
              changed = true;
              await fs.rm(path);
              if (!missing) await fs.mkdir(path);
            }
            return entries;
          },
        );
        const originalStat = filesystem.stat;
        const stating = spyOn(filesystem, "stat").mockImplementation(
          async (...args: unknown[]) => {
            const result = await Reflect.apply(originalStat, filesystem, args);
            // Windows directories can report zero bytes, like an unread empty file.
            if (args[0] === path && result.isDirectory()) result.size = 0;
            return result;
          },
        );
        try {
          const stopped = tracker.stop({ input_tokens: 500, output_tokens: 0 });
          if (missing) {
            expect(await stopped).toMatchObject({
              usage: { input_tokens: 500 },
              cost: { estimatedUsd: 0.002 },
              measurement: { coverage: "complete" },
            });
            await writeFile(path, encoded);
            expect(await tracker.stop()).toMatchObject({
              usage: { input_tokens: 1_000 },
              cost: { estimatedUsd: 0.004 },
              measurement: { coverage: "complete" },
            });
            expect(costs).toEqual([0.002, 0.004]);
          } else {
            await expect(stopped).rejects.toMatchObject({ code: "EISDIR" });
            expect(costs).toEqual([0.002]);
          }
          expect(changed).toBe(true);
        } finally {
          reading.mockRestore();
          stating.mockRestore();
          await tracker.stop().catch(() => {});
        }
      },
    );
  }

  test.each([false, true])(
    "retains SDK usage after a collection error with prior native usage=%p",
    async (previouslyMeasured) => {
      const home = await codexHome();
      if (previouslyMeasured) {
        await writeSession(home, "scan-thread", {
          input_tokens: 100,
          output_tokens: 10,
        });
        await writeSession(
          home,
          "worker-thread",
          { input_tokens: 200, output_tokens: 20 },
          { parent: "scan-thread" },
        );
      }
      const measurements: Readonly<ScanUsageMeasurement>[] = [];
      const tracker = costTracker(home, {
        onMeasurement: (measurement) => measurements.push(measurement),
      });
      tracker.start("scan-thread");
      await tracker.refresh();
      const originalRead = filesystem.readdir;
      const failure = Object.assign(new Error("Session directory unreadable"), {
        code: "EACCES",
      });
      const read = spyOn(filesystem, "readdir").mockImplementation(
        async (...args) => {
          if (args[0] === join(home, "sessions")) throw failure;
          return Reflect.apply(originalRead, filesystem, args);
        },
      );
      const usage = {
        input_tokens: previouslyMeasured ? 1_200 : 1_000,
        output_tokens: previouslyMeasured ? 120 : 100,
      };
      try {
        await expect(
          tracker.stop({ input_tokens: 1_000, output_tokens: 100 }),
        ).rejects.toBe(failure);
        expect(measurements.at(-1)).toMatchObject({
          coverage: "partial",
          threadCount: previouslyMeasured ? 2 : 1,
          missingThreadCount: 1,
          usage,
          cost: estimateScanCost("gpt-5.6-sol", usage),
        });
      } finally {
        read.mockRestore();
        await tracker.stop().catch(() => {});
      }
    },
  );

  test.each([
    ["reported zero", { cache_write_input_tokens: 0 }, {}, 0],
    ["missing writes", {}, { cache_write_input_tokens: 12 }, 12],
    [
      "defaulted zero",
      {
        cache_write_input_tokens: 0,
        cache_write_input_tokens_reported: false,
      },
      { cache_write_input_tokens: 12 },
      12,
    ],
  ] as const)(
    "preserves worker receipt provenance for %s during native reconciliation",
    async (_name, receiptWrites, nativeWrites, expectedWrites) => {
      const home = await codexHome();
      const scanId = "receipt-provenance";
      const directory = join(home, "worker-usage", scanId);
      await fs.mkdir(directory, { recursive: true });
      await writeSession(home, "scan-thread", {
        input_tokens: 100,
        cache_write_input_tokens: 0,
        output_tokens: 10,
      });
      const workerUsage = { input_tokens: 200, output_tokens: 20 };
      await writeFile(
        join(directory, "worker-attempt.json"),
        JSON.stringify({
          schemaVersion: 1,
          source: "codex_sdk",
          usageScope: "thread_cumulative",
          scanId,
          attemptId: "worker-attempt",
          threadId: "worker-thread",
          usage: { ...workerUsage, ...receiptWrites },
        }),
      );
      await writeSession(
        home,
        "worker-thread",
        { ...workerUsage, ...nativeWrites },
        { parent: "scan-thread" },
      );
      const tracker = costTracker(home, {
        workerReceipts: { directory, scanId },
      });
      tracker.start("scan-thread");
      const snapshot = await tracker.stop();
      expect(snapshot.measurement).toMatchObject({
        coverage: "complete",
        threadCount: 2,
        missingThreadCount: 0,
      });
      expect(snapshot.usage).toMatchObject({
        input_tokens: 300,
        cache_write_input_tokens: expectedWrites,
        output_tokens: 30,
      });
      expect(snapshot.usage).not.toHaveProperty(
        "cache_write_input_tokens_reported",
      );
      expect(snapshot.cost).not.toHaveProperty("cacheWriteInputTokensReported");
    },
  );

  test("retains cumulative resumed worker receipts without counting earlier turns twice", async () => {
    const home = await codexHome();
    const scanDirectory = join(home, "scans", "receipts");
    const scanId = "receipts";
    const receipts = join(home, "worker-usage", scanId);
    await fs.mkdir(receipts, { recursive: true });
    const parentUsage = { input_tokens: 100, output_tokens: 10 };
    await writeSession(home, "scan-thread", parentUsage);
    for (const [attemptId, input] of [
      ["first", 100],
      ["second", 150],
    ] as const) {
      await writeFile(
        join(receipts, `${attemptId}.json`),
        JSON.stringify({
          schemaVersion: 1,
          source: "codex_sdk",
          usageScope: "thread_cumulative",
          scanId,
          attemptId,
          threadId: "resumed-worker",
          usage: { input_tokens: input, output_tokens: 10 },
        }),
      );
    }
    const measurements: Readonly<ScanUsageMeasurement>[] = [];
    const tracker = costTracker(home, {
      scanDirectory,
      workerReceipts: { directory: receipts, scanId },
      onMeasurement: (measurement) => measurements.push(measurement),
    });
    tracker.start("scan-thread");
    const partial = await tracker.refresh();
    expect(partial).toMatchObject({
      usage: null,
      cost: null,
      measurement: {
        coverage: "partial",
        threadCount: 2,
        missingThreadCount: 1,
        usage: { input_tokens: 250, output_tokens: 20 },
        coverageScope: [
          "thread:resumed-worker",
          "thread:scan-thread",
          "worker-attempt:first",
          "worker-attempt:second",
        ],
      },
    });
    // Re-reading the same durable attempts does not increment their usage.
    expect((await tracker.refresh()).measurement.usage).toEqual(
      partial.measurement.usage,
    );
    const resumed = costTracker(home, {
      scanDirectory,
      workerReceipts: { directory: receipts, scanId },
    });
    resumed.start("scan-thread");
    expect((await resumed.stop(parentUsage)).measurement).toEqual(
      expect.objectContaining({
        coverage: "partial",
        usage: partial.measurement.usage,
        coverageScope: partial.measurement.coverageScope,
      }),
    );
    await writeSession(home, "resumed-worker", {
      input_tokens: 150,
      output_tokens: 10,
    });
    expect((await tracker.stop(parentUsage)).measurement).toMatchObject({
      coverage: "complete",
      threadCount: 2,
      missingThreadCount: 0,
      usage: { input_tokens: 250, output_tokens: 20 },
      coverageScope: partial.measurement.coverageScope,
    });
    expect(measurements.map((measurement) => measurement.coverage)).toEqual([
      "partial",
      "complete",
    ]);
  });

  test.each([
    "EIO",
    "ENOENT",
    "invalid",
    "missing-file",
    "missing-directory",
  ] as const)(
    "retains measured worker receipts through %s collection failures",
    async (failure) => {
      const home = await codexHome();
      const scanId = "receipt-recovery";
      const directory = join(home, "worker-usage", scanId);
      await fs.mkdir(directory, { recursive: true });
      const save = async (
        attemptId: string,
        threadId: string | null,
        usage: { input_tokens: number; output_tokens: number } | null,
      ) =>
        writeFile(
          join(directory, `${attemptId}.json`),
          JSON.stringify({
            schemaVersion: 1,
            source: "codex_sdk",
            usageScope: "thread_cumulative",
            scanId,
            attemptId,
            threadId,
            usage,
          }),
        );
      await save("earlier", "worker", { input_tokens: 500, output_tokens: 5 });
      await save("latest", "worker", {
        input_tokens: 1_000,
        output_tokens: 10,
      });
      await save("unknown", null, null);
      const measurements: Readonly<ScanUsageMeasurement>[] = [];
      const tracker = costTracker(home, {
        workerReceipts: { directory, scanId },
        maxCostUsd: 1,
        onMeasurement: (measurement) => measurements.push(measurement),
      });
      tracker.start("scan-thread");
      const before = (
        await tracker.stop({ input_tokens: 100, output_tokens: 1 })
      ).measurement;
      expect(before).toMatchObject({
        coverage: "partial",
        threadCount: 2,
        missingThreadCount: 2,
        usage: { total_tokens: 1_111 },
        cost: { inputTokens: 1_100, outputTokens: 11, estimatedUsd: 0.00462 },
      });
      const latest = join(directory, "latest.json");
      const originalRead = filesystem.readFile;
      const reading =
        failure === "EIO" || failure === "ENOENT"
          ? spyOn(filesystem, "readFile").mockImplementation((async (
              ...args: Parameters<typeof filesystem.readFile>
            ) => {
              if (args[0] === latest)
                throw Object.assign(new Error(`Synthetic receipt ${failure}`), {
                  code: failure,
                });
              return Reflect.apply(originalRead, filesystem, args);
            }) as typeof filesystem.readFile)
          : null;
      let moved = false;
      try {
        if (failure === "invalid") await writeFile(latest, "{invalid");
        if (failure === "missing-file") await fs.rm(latest);
        if (failure === "missing-directory") {
          await fs.rename(directory, `${directory}-unavailable`);
          moved = true;
        }
        const update = tracker.refresh();
        if (failure === "EIO")
          await expect(update).rejects.toMatchObject({ code: "EIO" });
        else if (failure === "invalid")
          await expect(update).rejects.toBeInstanceOf(SyntaxError);
        else await update;
        expect(measurements.at(-1)).toMatchObject({
          coverage: "partial",
          threadCount: 2,
          missingThreadCount: 2,
          usage: before.usage,
          cost: before.cost,
        });
        expect(measurements.at(-1)?.coverageScope).toEqual(
          failure === "EIO" || failure === "invalid"
            ? undefined
            : before.coverageScope,
        );
        reading?.mockRestore();
        if (moved) {
          await fs.rename(`${directory}-unavailable`, directory);
          moved = false;
        }
        await save("latest", "worker", {
          input_tokens: 1_200,
          output_tokens: 12,
        });
        await save("unknown", "other-worker", {
          input_tokens: 0,
          output_tokens: 0,
        });
        await writeSession(home, "worker", {
          input_tokens: 1_200,
          output_tokens: 12,
        });
        await writeSession(home, "other-worker", {
          input_tokens: 0,
          output_tokens: 0,
        });
        const recovered = (await tracker.stop()).measurement;
        expect(recovered).toMatchObject({
          coverage: "complete",
          threadCount: 3,
          missingThreadCount: 0,
          usage: {
            input_tokens: 1_300,
            output_tokens: 13,
            total_tokens: 1_313,
          },
          cost: { inputTokens: 1_300, outputTokens: 13, estimatedUsd: 0.00546 },
          coverageScope: [
            "thread:other-worker",
            "thread:scan-thread",
            "thread:worker",
            "worker-attempt:earlier",
            "worker-attempt:latest",
            "worker-attempt:unknown",
          ],
        });
        await fs.rm(latest);
        expect((await tracker.stop()).measurement).toMatchObject({
          coverage: "complete",
          missingThreadCount: 0,
          usage: recovered.usage,
          cost: recovered.cost,
          coverageScope: recovered.coverageScope,
        });
      } finally {
        reading?.mockRestore();
        if (moved) await fs.rename(`${directory}-unavailable`, directory);
        await tracker.stop().catch(() => {});
      }
    },
  );

  test.each(["standard", "deep"])(
    "%s scans ignore model-written worker receipts for budgets and session events",
    async (mode) => {
      const home = await codexHome();
      const scanId = "owned-scan";
      const scanDirectory = join(home, "scans", scanId);
      const artifacts = join(
        scanDirectory,
        "artifacts",
        "deep_discovery",
        "usage",
      );
      await fs.mkdir(artifacts, { recursive: true });
      const usage = { input_tokens: 100, output_tokens: 10 };
      await writeSession(home, "scan-thread", usage);
      const foreign = await writeSession(home, "foreign-thread", {
        input_tokens: 999_999,
        output_tokens: 999_999,
      });
      await appendSessionItem(foreign, {
        type: "message",
        role: "assistant",
        content: [{ type: "output_text", text: "Unrelated session output." }],
      });
      for (const [attemptId, threadId, receiptUsage] of [
        [
          "forged-cost",
          "scan-thread",
          { input_tokens: 1_000_000_000, output_tokens: 0 },
        ],
        ["forged-membership", "foreign-thread", null],
      ] as const) {
        await writeFile(
          join(artifacts, `${attemptId}.json`),
          JSON.stringify({
            schemaVersion: 1,
            source: "codex_sdk",
            usageScope: "thread_cumulative",
            scanId,
            attemptId,
            threadId,
            usage: receiptUsage,
          }),
        );
      }
      const events: ScanSessionEvent[] = [];
      let budgetExceeded = false;
      const tracker = costTracker(home, {
        scanDirectory,
        ...(mode === "deep"
          ? {
              workerReceipts: {
                directory: join(home, "worker-usage", scanId),
                scanId,
              },
            }
          : {}),
        onCost: (cost) => {
          budgetExceeded ||= cost.estimatedUsd > 1;
        },
        onSessionEvent: (event) => events.push(event),
      });
      tracker.start("scan-thread");
      const result = await tracker.stop(usage);
      expect(result.measurement).toMatchObject({
        coverage: "complete",
        threadCount: 1,
        usage: tokenUsage(usage),
        coverageScope: ["thread:scan-thread"],
      });
      expect(budgetExceeded).toBe(false);
      expect(events.every((event) => event.threadId === "scan-thread")).toBe(
        true,
      );
    },
  );

  test("binds protected worker receipts to the scan and durable attempt", async () => {
    const home = await codexHome();
    const scanId = "owned-scan";
    const directory = join(home, "worker-usage", scanId);
    const unrelated = join(home, "worker-usage", "other-scan");
    await fs.mkdir(directory, { recursive: true });
    await fs.mkdir(unrelated, { recursive: true });
    const usage = { input_tokens: 100, output_tokens: 10 };
    await writeSession(home, "scan-thread", usage);
    const receipt = {
      schemaVersion: 1,
      source: "codex_sdk",
      usageScope: "thread_cumulative",
      scanId: "other-scan",
      attemptId: "other-attempt",
      threadId: "unrelated-worker",
      usage: { input_tokens: 1_000_000, output_tokens: 0 },
    };
    await writeFile(
      join(unrelated, "other-attempt.json"),
      JSON.stringify(receipt),
    );
    await writeFile(
      join(directory, "other-attempt.json"),
      JSON.stringify(receipt),
    );
    await writeFile(
      join(directory, "wrong-attempt.json"),
      JSON.stringify({ ...receipt, scanId }),
    );
    const tracker = costTracker(home, {
      workerReceipts: { directory, scanId },
    });
    tracker.start("scan-thread");
    expect((await tracker.stop(usage)).measurement).toMatchObject({
      coverage: "complete",
      threadCount: 1,
      usage: tokenUsage(usage),
      coverageScope: ["thread:scan-thread"],
    });
  });

  test("keeps independent Deep worker usage unknown until a receipt supplies it", async () => {
    const home = await codexHome();
    const scanDirectory = join(home, "scans", "current");
    const parentUsage = { input_tokens: 100, output_tokens: 10 };
    await writeSession(home, "scan-thread", parentUsage, {
      cwd: scanDirectory,
      timestamp: "2026-07-26T12:00:00Z",
    });
    await writeSession(
      home,
      "deep-worker",
      {},
      {
        cwd: join(
          scanDirectory,
          "artifacts",
          "deep_discovery",
          "workers",
          "one",
          "output",
        ),
        timestamp: "2026-07-26T12:01:00Z",
      },
    );
    const tracker = costTracker(home, { scanDirectory });
    tracker.start("scan-thread");
    expect(await tracker.refresh()).toMatchObject({ usage: null, cost: null });

    tracker.recordUsage({ input_tokens: 50, output_tokens: 5 }, "deep-worker");
    expect((await tracker.stop(parentUsage)).usage).toMatchObject({
      input_tokens: 150,
      output_tokens: 15,
      total_tokens: 165,
    });
  });

  test.each(["receipt", "receipt-and-log", "unknown"] as const)(
    "accounts for a separate validation turn with %s usage",
    async (source) => {
      const home = await codexHome();
      const tracker = costTracker(home);
      tracker.start("scan-thread");
      const usage = { input_tokens: 500, output_tokens: 0 };
      tracker.recordUsage(
        source === "unknown" ? null : usage,
        "validation-thread",
      );
      if (source === "receipt-and-log")
        await writeSession(home, "validation-thread", usage);
      const snapshot = await tracker.stop({
        input_tokens: 1_000,
        output_tokens: 0,
      });
      if (source === "unknown")
        expect(snapshot).toMatchObject({ usage: null, cost: null });
      else expect(snapshot.cost?.inputTokens).toBe(1_500);
      expect(snapshot.measurement.coverageScope).toEqual([
        "thread:scan-thread",
        "thread:validation-thread",
      ]);
    },
  );

  test("includes a separate validation root and its missing child in coverage scope", async () => {
    const home = await codexHome();
    await writeSession(home, "validation-thread", {
      input_tokens: 500,
      output_tokens: 0,
    });
    await writeSession(
      home,
      "validation-child",
      {},
      {
        parent: "validation-thread",
      },
    );
    const tracker = costTracker(home);
    tracker.start("scan-thread");
    tracker.recordUsage(
      { input_tokens: 500, output_tokens: 0 },
      "validation-thread",
    );
    const snapshot = await tracker.stop({
      input_tokens: 1_000,
      output_tokens: 0,
    });
    expect(snapshot.measurement).toMatchObject({
      coverage: "partial",
      missingThreadCount: 1,
      usage: { input_tokens: 1_500 },
      coverageScope: [
        "thread:scan-thread",
        "thread:validation-child",
        "thread:validation-thread",
      ],
    });
  });
});
