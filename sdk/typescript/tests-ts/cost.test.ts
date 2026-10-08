import { jsonLines } from "./support/json.js";
import { spawnSync } from "node:child_process";
import {
  appendFile,
  cp,
  mkdir,
  readFile,
  rename,
  unlink,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join, parse, sep } from "node:path";
import { Codex } from "@openai/codex-sdk";
import { afterEach, describe, expect, test } from "bun:test";
import {
  estimateScanCost,
  ScanCostTracker,
  type ScanSessionEvent,
  type ScanCost,
  type ScanWorkerEvent,
} from "../src/cost.js";
import type { ScanActivity } from "../src/scan-activity.js";
import {
  estimateScanCostLowerBound,
  formatTokenUsage,
  tokenUsage,
} from "../src/cost-model.js";
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
      const result = spawnSync(
        python!,
        [
          "-I",
          "-B",
          "-c",
          probe,
          join(PLUGIN_ROOT, "scripts"),
          JSON.stringify(usage),
        ],
        { encoding: "utf8" },
      );

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
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
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
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
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
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
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
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-sol",
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
    const trackers = workers.map(
      (events) =>
        new ScanCostTracker({
          codexHome: home,
          model: "gpt-5.6-sol",
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
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      onWorkerEvent: (event) => resumed.push(event),
    });
    tracker.start("scan-0");
    await tracker.stop();
    expect(resumed).toEqual([{ kind: "observed", worker: 1 }]);
  });

  test("retains unknown Standard usage while reporting known cost and later child usage", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 1_250,
      cached_input_tokens: 200,
      output_tokens: 30,
    });
    const worker = await writeSession(
      home,
      "worker-thread",
      {},
      {
        parent: "scan-thread",
      },
    );
    await writeFile(
      worker,
      (await readFile(worker, "utf8")).split("\n")[0]! + "\n",
    );
    const publicCosts: Readonly<ScanCost>[] = [];
    const lowerBounds: Readonly<ScanCost>[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      onCost: (cost) => publicCosts.push(cost),
      onCostLowerBound: (cost) => lowerBounds.push(cost),
    });
    tracker.start("scan-thread");
    try {
      expect(await tracker.refresh()).toEqual({ usage: null, cost: null });
      expect(publicCosts).toEqual([]);
      expect(lowerBounds.at(-1)).toMatchObject({
        inputTokens: 1_250,
        estimatedUsd: 0.00488,
        coverage: "partial",
      });
      await writeSession(
        home,
        "worker-thread",
        {
          input_tokens: 100,
          output_tokens: 0,
        },
        { parent: "scan-thread" },
      );
      expect(await tracker.refresh()).toMatchObject({
        usage: { input_tokens: 1_350 },
        cost: { inputTokens: 1_350, estimatedUsd: 0.00528 },
      });
      expect(publicCosts.at(-1)?.estimatedUsd).toBe(0.00528);
    } finally {
      await tracker.stop();
    }
  });

  test("prices known Standard receipts by their recorded model while child usage is missing", async () => {
    const home = await codexHome();
    const parent = await writeSession(home, "scan-thread", {});
    await appendFile(
      parent,
      jsonLines([
        {
          type: "token_usage_record",
          payload: {
            thread_id: "scan-thread",
            response_id: "known-response",
            model: "gpt-5.6-luna",
            usage: { input_tokens: 1_000, output_tokens: 0 },
          },
        },
      ]) + "\n",
    );
    const child = await writeSession(
      home,
      "worker-thread",
      {},
      { parent: "scan-thread" },
    );
    await writeFile(
      child,
      (await readFile(child, "utf8")).split("\n")[0]! + "\n",
    );
    const lowerBounds: Readonly<ScanCost>[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      onCostLowerBound: (cost) => lowerBounds.push(cost),
    });
    tracker.start("scan-thread");
    try {
      expect(await tracker.refresh()).toEqual({ usage: null, cost: null });
      expect(lowerBounds).toHaveLength(1);
      expect(lowerBounds[0]).toMatchObject({
        estimatedUsd: estimateScanCost("gpt-5.6-luna", {
          input_tokens: 1_000,
          output_tokens: 0,
        })!.estimatedUsd,
        coverage: "partial",
        modelCosts: [{ model: "gpt-5.6-luna", inputTokens: 1_000 }],
      });
      await tracker.refresh();
      expect(lowerBounds).toHaveLength(1);
    } finally {
      await tracker.stop();
    }
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
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
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
      const tracker = new ScanCostTracker({
        codexHome: home,
        scanDirectory,
        model: "gpt-5.6-sol",
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
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-sol",
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
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-sol",
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
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-sol",
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
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      maxCostUsd,
      onCost: ({ estimatedUsd }) => observedCosts.push(estimatedUsd),
      onSessionEvent: (event) => forwardedEvents.push(event),
    });
    tracker.start(scanThreadId);
    const tracked = await tracker.stop();
    const python = readPythonRolloutUsage(BUNDLED_PLUGIN_ROOT, rolloutPath);

    expect({
      trackedUsage: tracked.usage,
      estimatedUsd: tracked.cost?.estimatedUsd,
      python,
    }).toMatchObject({
      trackedUsage: ownedSdkUsage,
      estimatedUsd: 0.0006,
      python: {
        usage: ownedPythonUsage,
        warnings: [],
      },
    });
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
    const ownedEvents = [rollout[0]!, ...rollout.slice(-2)];
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
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
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

    const activities: ScanActivity[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      repository: "/code/juice-shop",
      onActivity: (activity) => activities.push(activity),
    });
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
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
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

    const activities: ScanActivity[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      repository: "/code/juice-shop",
      onActivity: (activity) => activities.push(activity),
    });
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

    const activities: ScanActivity[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      repository: "/code/juice-shop",
      onActivity: (activity) => activities.push(activity),
    });
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

    const activities: ScanActivity[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      repository: "/code/juice-shop",
      onActivity: (activity) => activities.push(activity),
    });
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
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
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
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
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
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
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
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
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
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
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
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
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
        info: {
          total_token_usage: { input_tokens: 250, output_tokens: 20 },
        },
      },
    });
    const padding = " ".repeat(128 * 1_024);
    await appendFile(path, `${padding}${event.slice(0, 40)}`);
    expect((await tracker.refresh()).cost?.inputTokens).toBe(100);
    expect(events).toHaveLength(2);

    await appendFile(path, `${event.slice(40)}\n`);
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
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
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
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-sol",
      });
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

  test.each(["receipt", "receipt-and-log", "unknown"] as const)(
    "accounts for a separate validation turn with %s usage",
    async (source) => {
      const home = await codexHome();
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-sol",
      });
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
        expect(snapshot).toEqual({ usage: null, cost: null });
      else expect(snapshot.cost?.inputTokens).toBe(1_500);
    },
  );
});

describe("recorded Deep worker homes", () => {
  test.each([
    ["recorded=false archived=false", false, false],
    ["recorded=false archived=true", false, true],
    ["recorded=true archived=false", true, false],
    ["recorded=true archived=true", true, true],
  ] as const)(
    "retains archived worker usage: %s",
    async (_label, recorded, archived) => {
      const home = await codexHome();
      const workerHome = recorded ? await codexHome() : home;
      const at = "2026-09-01T00:00:02Z";
      await writeSession(home, "owner", {});
      const worker = await writeSession(workerHome, "worker", {});
      await appendFile(
        worker,
        jsonLines([
          {
            type: "turn_context",
            timestamp: at,
            payload: { turn_id: "worker-turn", model: "gpt-5.6-sol" },
          },
          {
            type: "token_usage_record",
            timestamp: at,
            payload: {
              thread_id: "worker",
              turn_id: "worker-turn",
              response_id: "worker-response",
              model: "gpt-5.6-sol",
              usage: { input_tokens: 1_000, output_tokens: 0 },
            },
          },
        ]) + "\n",
      );
      if (archived) {
        const directory = join(workerHome, "archived_sessions");
        await mkdir(directory, { recursive: true });
        await rename(worker, join(directory, "worker.jsonl"));
      }
      const costs: Readonly<ScanCost>[] = [];
      const tracker = new ScanCostTracker({
        codexHome: home,
        scanDirectory: join(home, "scan"),
        model: "gpt-5.6-sol",
        maxCostUsd: 0.003,
        onCost: (cost) => costs.push(cost),
        onCostLowerBound: (cost) => costs.push(cost),
      });
      tracker.setAttributionReader(async () => ({
        formatVersion: 1,
        workerCodexHome: workerHome,
        executionThreadIds: ["worker"],
        owner: { threadId: "owner", turnId: "owner-turn", startedAt: at },
        startedAt: at,
        completedAt: null,
      }));
      tracker.start("owner");
      try {
        await tracker.refresh();
        expect(costs.at(-1)?.inputTokens).toBe(1_000);
        expect(costs.at(-1)?.estimatedUsd).toBeCloseTo(0.004, 10);
        expect(costs.at(-1)!.estimatedUsd).toBeGreaterThan(0.003);
      } finally {
        await tracker.stop();
      }
    },
  );

  test("only enforces a priced subtotal from a valid attributed usage partition", () => {
    const known = {
      model: "gpt-5.6-sol",
      input_tokens: 1_000,
      output_tokens: 0,
    };
    const unknown = { model: null, input_tokens: 100, output_tokens: 0 };
    const usage = {
      input_tokens: 1_100,
      output_tokens: 0,
      modelUsage: [known, unknown],
    };
    expect(estimateScanCostLowerBound("gpt-5.6-sol", usage)?.estimatedUsd).toBe(
      0.004,
    );
    expect(estimateScanCost("gpt-5.6-sol", usage)).toBeNull();
    for (const invalid of [
      { ...usage, input_tokens: 999 },
      { ...usage, modelUsage: [known, known, unknown] },
      { ...usage, modelUsage: [known, { ...unknown, input_tokens: -1 }] },
      { ...usage, modelUsage: [{ ...known, model: null }, unknown] },
    ])
      expect(estimateScanCostLowerBound("gpt-5.6-sol", invalid)).toBeNull();
  });

  test.each(["gpt-5.6-sol", "synthetic-unpriced-model"])(
    "prices live worker counters after an earlier response receipt with model %s",
    async (currentModel) => {
      const home = await codexHome();
      const at = "2026-09-01T00:00:02Z";
      await writeSession(home, "owner", {});
      const worker = await writeSession(home, "worker", {});
      const receipt = (id: string, model: string, input: number) => ({
        type: "token_usage_record",
        timestamp: at,
        payload: {
          thread_id: "worker",
          turn_id: "worker-turn",
          response_id: id,
          model,
          usage: { input_tokens: input, output_tokens: 0 },
        },
      });
      await appendFile(
        worker,
        jsonLines([
          {
            type: "turn_context",
            timestamp: at,
            payload: { turn_id: "worker-turn", model: "gpt-5.6-sol" },
          },
          {
            type: "event_msg",
            timestamp: at,
            payload: {
              type: "token_count",
              info: {
                total_token_usage: {
                  input_tokens: 100,
                  output_tokens: 0,
                },
              },
            },
          },
          receipt("earlier", "gpt-5.6-sol", 100),
        ]) + "\n",
      );
      const costUpdates: Readonly<ScanCost>[] = [];
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-sol",
        maxCostUsd: 0.002,
        onCost: (cost) => costUpdates.push(cost),
        onCostLowerBound: (cost) => costUpdates.push(cost),
      });
      tracker.setAttributionReader(async () => ({
        formatVersion: 1,
        executionThreadIds: ["worker"],
        owner: { threadId: "owner", turnId: "turn", startedAt: at },
        startedAt: at,
        completedAt: null,
      }));
      tracker.start("owner");
      try {
        await tracker.refresh();
        expect(costUpdates.at(-1)?.estimatedUsd).toBeCloseTo(0.0004, 10);
        await appendFile(
          worker,
          jsonLines([
            {
              type: "turn_context",
              timestamp: at,
              payload: { turn_id: "worker-turn", model: currentModel },
            },
            {
              type: "event_msg",
              timestamp: at,
              payload: {
                type: "token_count",
                info: {
                  total_token_usage: {
                    input_tokens: 1_100,
                    output_tokens: 0,
                  },
                },
              },
            },
          ]) + "\n",
        );
        const running = await tracker.refresh();
        expect(tokenUsage(running.usage)?.input_tokens).toBe(1_100);
        expect(running.cost).toBeNull();
        expect(costUpdates.at(-1)?.estimatedUsd).toBeCloseTo(
          currentModel === "gpt-5.6-sol" ? 0.0044 : 0.0004,
          10,
        );
        if (currentModel === "gpt-5.6-sol")
          expect(costUpdates.at(-1)!.estimatedUsd).toBeGreaterThan(0.002);
        const completedReceipt = receipt("current", currentModel, 1_000);
        await appendFile(
          worker,
          jsonLines([completedReceipt, completedReceipt]) + "\n",
        );
        const completed = await tracker.refresh();
        expect(tokenUsage(completed.usage)?.input_tokens).toBe(1_100);
        expect(costUpdates.at(-1)?.estimatedUsd).toBeCloseTo(
          currentModel === "gpt-5.6-sol" ? 0.0044 : 0.0004,
          10,
        );
      } finally {
        await tracker.stop();
      }
    },
  );

  test.each([null, "synthetic-unpriced-model"])(
    "reports an internal priced lower bound with model %p without inventing a total",
    async (unknownModel) => {
      const home = await codexHome();
      const at = "2026-09-01T00:00:02Z";
      const known = await writeSession(home, "owner", {});
      await appendFile(
        known,
        JSON.stringify({
          type: "token_usage_record",
          timestamp: at,
          payload: {
            thread_id: "owner",
            turn_id: "turn",
            response_id: "known-response",
            model: "gpt-5.6-sol",
            usage: { input_tokens: 1_000, output_tokens: 0 },
          },
        }) + "\n",
      );
      const unknown = await writeSession(home, "worker", {});
      await appendFile(
        unknown,
        JSON.stringify({
          type: "turn_context",
          timestamp: at,
          payload: {
            turn_id: "worker-turn",
            ...(unknownModel === null ? {} : { model: unknownModel }),
          },
        }) +
          "\n" +
          JSON.stringify({
            type: "event_msg",
            timestamp: at,
            payload: {
              type: "token_count",
              info: {
                total_token_usage: { input_tokens: 100, output_tokens: 0 },
              },
            },
          }) +
          "\n",
      );
      const lowerBounds: Readonly<ScanCost>[] = [];
      const publicCosts: Readonly<ScanCost>[] = [];
      const options = {
        codexHome: home,
        model: "gpt-5.6-sol",
        maxCostUsd: 0.003,
        onCost: (cost: Readonly<ScanCost>) => publicCosts.push(cost),
        onCostLowerBound: (cost: Readonly<ScanCost>) => lowerBounds.push(cost),
      };
      const tracker = new ScanCostTracker(options);
      tracker.setAttributionReader(async () => ({
        formatVersion: 1,
        executionThreadIds: ["worker"],
        owner: { threadId: "owner", turnId: "turn", startedAt: at },
        startedAt: at,
        completedAt: null,
      }));
      tracker.start("owner");
      try {
        const snapshot = await tracker.refresh();
        expect(tokenUsage(snapshot.usage)?.input_tokens).toBe(1_100);
        expect(snapshot.cost).toBeNull();
        expect(publicCosts).toEqual([]);
        expect(lowerBounds).toHaveLength(1);
        expect(lowerBounds[0]).toMatchObject({
          inputTokens: 1_000,
          estimatedUsd: 0.004,
          coverage: "partial",
        });
        expect(lowerBounds[0]!.estimatedUsd).toBeGreaterThan(
          options.maxCostUsd,
        );
        await tracker.refresh();
        expect(lowerBounds).toHaveLength(1);
      } finally {
        await tracker.stop();
      }
    },
  );

  test.each(["identical", "prefix-first", "prefix-last"] as const)(
    "forwards each event occurrence once from copied logs: %s",
    async (copy) => {
      const home = await codexHome();
      const recordedHome = await codexHome();
      const scanDirectory = join(home, "scan");
      const settings = join(scanDirectory, "artifacts", "deep_discovery");
      await mkdir(settings, { recursive: true });
      await writeFile(
        join(settings, "execution-settings.json"),
        JSON.stringify({
          version: 1,
          settings: { codexHome: recordedHome },
        }),
      );
      await mkdir(join(home, "sessions"));
      await mkdir(join(recordedHome, "sessions"));
      const first = join(home, "sessions", "worker.jsonl");
      const second = join(recordedHome, "sessions", "worker-copy.jsonl");
      const repeated = {
        timestamp: "2026-09-01T00:00:02Z",
        type: "event_msg",
        payload: { type: "agent_message", message: "Reviewing source." },
      };
      const expected = [
        {
          timestamp: "2026-09-01T00:00:00Z",
          type: "session_meta",
          payload: { id: "worker", model: "gpt-5.6-sol" },
        },
        repeated,
        repeated,
        {
          timestamp: "2026-09-01T00:00:03Z",
          type: "token_usage_record",
          payload: {
            thread_id: "worker",
            turn_id: "turn",
            response_id: "response",
            model: "gpt-5.6-sol",
            usage: { input_tokens: 100, output_tokens: 0 },
          },
        },
      ];
      const contents = expected.map((event) => JSON.stringify(event) + "\n");
      await writeFile(
        first,
        contents.slice(0, copy === "prefix-first" ? 2 : 4).join(""),
      );
      await writeFile(
        second,
        contents.slice(0, copy === "prefix-last" ? 2 : 4).join(""),
      );
      const events: ScanSessionEvent[] = [];
      const options = {
        codexHome: home,
        scanDirectory,
        model: "gpt-5.6-sol",
        onSessionEvent: (event: ScanSessionEvent) => events.push(event),
      };
      const recordedOwner = async () => ({
        formatVersion: 1 as const,
        legacy: true as const,
        workerCodexHome: recordedHome,
        executionThreadIds: [],
        owner: {
          threadId: "worker",
          turnId: null,
          startedAt: "2026-09-01T00:00:00Z",
        },
        startedAt: "2026-09-01T00:00:00Z",
        completedAt: null,
      });
      const tracker = new ScanCostTracker(options);
      tracker.setAttributionReader(recordedOwner);
      tracker.start("worker");
      try {
        expect((await tracker.refresh()).cost?.inputTokens).toBe(100);
        expect(events.map((event) => event.event)).toEqual(expected);
        await tracker.refresh();
        expect(events).toHaveLength(expected.length);
        // Both logs catch up, then a genuine repeated occurrence is copied later.
        await writeFile(first, contents.join(""));
        await writeFile(second, contents.join(""));
        await appendFile(first, JSON.stringify(repeated) + "\n");
        await tracker.refresh();
        expect(events.map((event) => event.event)).toEqual([
          ...expected,
          repeated,
        ]);
        await appendFile(second, JSON.stringify(repeated) + "\n");
        await tracker.stop();
        expect(events.map((event) => event.event)).toEqual([
          ...expected,
          repeated,
        ]);
        // Re-reading after the owner interval becomes available filters early
        // events, but must not renumber the surviving source occurrences.
        tracker.setAttributionReader(async () => ({
          formatVersion: 1,
          workerCodexHome: recordedHome,
          executionThreadIds: ["worker"],
          owner: {
            threadId: "worker",
            turnId: "turn",
            startedAt: "2026-09-01T00:00:03Z",
          },
          startedAt: "2026-09-01T00:00:03Z",
          completedAt: "2026-09-01T00:00:04Z",
        }));
        await tracker.refresh();
        expect(events.map((event) => event.event)).toEqual([
          ...expected,
          repeated,
        ]);
        events.length = 0;
        const reconstructed = new ScanCostTracker(options);
        reconstructed.setAttributionReader(recordedOwner);
        reconstructed.start("worker");
        await reconstructed.stop();
        expect(events.map((event) => event.event)).toEqual([
          ...expected,
          repeated,
        ]);
      } finally {
        await tracker.stop();
      }
    },
  );

  test("keeps resumed worker usage and current parent usage isolated per scan", async () => {
    const currentHome = await codexHome();
    const firstHome = await codexHome();
    const secondHome = await codexHome();
    const at = "2026-09-01T00:00:02Z";
    const trackers: ScanCostTracker[] = [];
    const fixture = async (home: string, id: string, count: number) => {
      const path = await writeSession(home, id, {});
      await appendFile(
        path,
        [
          {
            type: "turn_context",
            timestamp: at,
            payload: { turn_id: "scan-turn", model: "gpt-5.6-sol" },
          },
          {
            type: "token_usage_record",
            timestamp: at,
            payload: {
              thread_id: id,
              turn_id: "scan-turn",
              response_id: `${id}-response`,
              model: "gpt-5.6-sol",
              usage: { input_tokens: count, output_tokens: 0 },
            },
          },
        ]
          .map((event) => JSON.stringify(event))
          .join("\n") + "\n",
      );
      return path;
    };
    try {
      const cases = [
        { id: "one", home: firstHome, parent: 10, discovery: 20, reducer: 30 },
        { id: "two", home: secondHome, parent: 11, discovery: 21, reducer: 31 },
      ];
      for (const row of cases) {
        const scanDirectory = join(currentHome, "scans", row.id);
        const settingsDirectory = join(
          scanDirectory,
          "artifacts",
          "deep_discovery",
        );
        await mkdir(settingsDirectory, { recursive: true });
        await writeFile(
          join(settingsDirectory, "execution-settings.json"),
          JSON.stringify({
            version: 1,
            settings: { codexHome: row.home },
          }),
        );
        await fixture(currentHome, `${row.id}-parent`, row.parent);
        const discovery = await fixture(
          row.home,
          `${row.id}-discovery`,
          row.discovery,
        );
        await fixture(row.home, `${row.id}-reducer`, row.reducer);
        await fixture(row.home, `${row.id}-unrelated`, 10_000);
        // Repeated receipt identity after reconnect must remain one charge.
        const duplicate = (await readFile(discovery, "utf8"))
          .trim()
          .split("\n")
          .at(-1)!;
        await appendFile(discovery, duplicate + "\n");
        const attribution = {
          formatVersion: 1 as const,
          workerCodexHome: row.home,
          executionThreadIds: [`${row.id}-discovery`, `${row.id}-reducer`],
          owner: {
            threadId: `${row.id}-parent`,
            turnId: "scan-turn",
            startedAt: at,
          },
          startedAt: at,
          completedAt: null,
        };
        const tracker = new ScanCostTracker({
          codexHome: currentHome,
          scanDirectory,
          model: "gpt-5.6-sol",
          maxCostUsd: 0.0002,
        });
        tracker.setAttributionReader(async () => attribution);
        tracker.start(`${row.id}-parent`);
        trackers.push(tracker);
      }
      const initial = await Promise.all(
        trackers.map((tracker) => tracker.refresh()),
      );
      expect(
        initial.map((snapshot) => tokenUsage(snapshot.usage)?.input_tokens),
      ).toEqual([60, 63]);
      expect(initial.map((snapshot) => snapshot.cost?.inputTokens)).toEqual([
        60, 63,
      ]);
      expect(initial[0]!.cost!.estimatedUsd).toBeGreaterThan(0.0002);
      const firstDirectory = join(currentHome, "scans", "one");
      await writeFile(
        join(
          firstDirectory,
          "artifacts",
          "deep_discovery",
          "execution-settings.json",
        ),
        JSON.stringify({ version: 1, settings: { codexHome: secondHome } }),
      );
      await unlink(
        join(
          currentHome,
          "scans",
          "two",
          "artifacts",
          "deep_discovery",
          "execution-settings.json",
        ),
      );
      expect(
        (await Promise.all(trackers.map((tracker) => tracker.refresh()))).map(
          (snapshot) => snapshot.cost?.inputTokens,
        ),
      ).toEqual([60, 63]);
      const rebuilt = new ScanCostTracker({
        codexHome: currentHome,
        scanDirectory: firstDirectory,
        model: "gpt-5.6-sol",
        maxCostUsd: 0.0002,
      });
      rebuilt.setAttributionReader(async () => ({
        formatVersion: 1,
        workerCodexHome: firstHome,
        executionThreadIds: [
          "one-discovery",
          "one-reducer",
          "one-missing-attempt",
        ],
        owner: { threadId: "one-parent", turnId: "scan-turn", startedAt: at },
        startedAt: at,
        completedAt: null,
      }));
      rebuilt.start("one-parent");
      trackers.push(rebuilt);
      expect((await rebuilt.refresh()).usage).toMatchObject({
        input_tokens: 60,
        coverage: "partial",
      });
      expect((await rebuilt.refresh()).cost!.estimatedUsd).toBeGreaterThan(
        0.0002,
      );
      await fixture(firstHome, "one-missing-attempt", 7);
      expect((await rebuilt.refresh()).cost?.inputTokens).toBe(67);
      expect((await trackers[1]!.refresh()).cost?.inputTokens).toBe(63);
    } finally {
      await Promise.all(trackers.map((tracker) => tracker.stop()));
    }
  });

  test("reads a recorded directory alias only once", async () => {
    const home = await codexHome();
    const alias = join(await codexHome(), "recorded-home");
    await symlink(
      home,
      alias,
      process.platform === "win32" ? "junction" : "dir",
    );
    const scanDirectory = join(home, "scan");
    const directory = join(scanDirectory, "artifacts", "deep_discovery");
    await mkdir(directory, { recursive: true });
    await writeFile(
      join(directory, "execution-settings.json"),
      JSON.stringify({ version: 1, settings: { codexHome: alias } }),
    );
    await writeSession(home, "worker", { input_tokens: 100, output_tokens: 0 });
    const events: ScanSessionEvent[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      scanDirectory,
      model: "gpt-5.6-sol",
      onSessionEvent: (event) => events.push(event),
    });
    tracker.start("worker");
    try {
      expect((await tracker.stop()).cost?.inputTokens).toBe(100);
      expect(events).toHaveLength(2);
    } finally {
      await tracker.stop();
    }
  });

  test.each([
    ["identical, attribution: false", "identical", false],
    ["identical, attribution: true", "identical", true],
    ["prefix-first, attribution: false", "prefix-first", false],
    ["prefix-first, attribution: true", "prefix-first", true],
    ["prefix-last, attribution: false", "prefix-last", false],
    ["prefix-last, attribution: true", "prefix-last", true],
    ["truncated-first, attribution: false", "truncated-first", false],
    ["truncated-first, attribution: true", "truncated-first", true],
    ["truncated-last, attribution: false", "truncated-last", false],
    ["truncated-last, attribution: true", "truncated-last", true],
    ["tail-first, attribution: false", "tail-first", false],
    ["tail-first, attribution: true", "tail-first", true],
    ["tail-last, attribution: false", "tail-last", false],
    ["tail-last, attribution: true", "tail-last", true],
  ] as const)(
    "prices copied response records (%s)",
    async (_label, copy, attributed) => {
      const home = await codexHome();
      const recordedHome = await codexHome();
      const scanDirectory = join(home, "scan");
      const directory = join(scanDirectory, "artifacts", "deep_discovery");
      await mkdir(directory, { recursive: true });
      await writeFile(
        join(directory, "execution-settings.json"),
        JSON.stringify({ version: 1, settings: { codexHome: recordedHome } }),
      );
      const path = await writeSession(home, "worker", {});
      for (const [id, model, input, output] of [
        ["response-one", "gpt-5.6-sol", 100, 10],
        ["response-two", "gpt-6-astra", 50, 5],
      ] as const) {
        await appendFile(
          path,
          JSON.stringify({
            type: "token_usage_record",
            timestamp: "2026-09-01T00:00:02Z",
            payload: {
              thread_id: "worker",
              turn_id: "turn",
              response_id: id,
              model,
              usage: { input_tokens: input, output_tokens: output },
            },
          }) + "\n",
        );
      }
      await mkdir(join(recordedHome, "sessions"));
      const copiedPath = join(recordedHome, "sessions", "copied-worker.jsonl");
      await cp(path, copiedPath);
      const prefix =
        (await readFile(path, "utf8"))
          .trimEnd()
          .split("\n")
          .slice(0, -1)
          .join("\n") + "\n";
      if (copy === "prefix-first") await writeFile(path, prefix);
      if (copy === "prefix-last") await writeFile(copiedPath, prefix);
      const truncated = prefix + '{"type":"token_usage_record"';
      if (copy === "truncated-first") await writeFile(path, truncated);
      if (copy === "truncated-last") await writeFile(copiedPath, truncated);
      if (copy === "tail-first") await appendFile(path, '{"type":"event_msg"');
      if (copy === "tail-last")
        await appendFile(copiedPath, '{"type":"event_msg"');
      const tracker = new ScanCostTracker({
        codexHome: home,
        scanDirectory,
        model: "gpt-5.6-sol",
      });
      tracker.setAttributionReader(async () => ({
        formatVersion: 1,
        ...(attributed ? {} : { legacy: true as const }),
        workerCodexHome: recordedHome,
        executionThreadIds: ["worker"],
        owner: {
          threadId: null,
          turnId: null,
          startedAt: "2026-09-01T00:00:00Z",
        },
        startedAt: "2026-09-01T00:00:00Z",
        completedAt: null,
      }));
      tracker.start("worker");
      try {
        const snapshot = await tracker.stop();
        expect(snapshot.usage).toMatchObject({
          input_tokens: 150,
          output_tokens: 15,
          total_tokens: 165,
        });
        expect(snapshot.usage).not.toMatchObject({ coverage: "partial" });
        expect(
          Object.fromEntries(
            snapshot.cost!.modelCosts!.map((part) => [
              part.model,
              [part.inputTokens, part.outputTokens],
            ]),
          ),
        ).toEqual({
          "gpt-5.6-sol": [100, 10],
          "gpt-6-astra": [50, 5],
        });
      } finally {
        await tracker.stop();
      }
    },
  );
});

test.each([
  ["150000/15000 vs 100000/200000", 150_000, 15_000, 100_000, 200_000],
  ["150000/15000 vs 100000/20000", 150_000, 15_000, 100_000, 20_000],
  ["100000/50000 vs 110000/10000", 100_000, 50_000, 110_000, 10_000],
  ["100000/50000 vs 200000/10000", 100_000, 50_000, 200_000, 10_000],
  ["100000/10000 vs 100000/10000", 100_000, 10_000, 100_000, 10_000],
] as const)(
  "preserves receipt pricing across divergent counters %s",
  async (_label, input, output, counterInput, counterOutput) => {
    const home = await codexHome();
    const path = await writeSession(home, "worker", {});
    const counts = (input: number, output: number) => ({
      input_tokens: input,
      output_tokens: output,
      cached_input_tokens: 0,
      cache_write_input_tokens: 0,
      reasoning_output_tokens: 0,
      total_tokens: input + output,
    });
    await appendFile(
      path,
      JSON.stringify({
        type: "token_usage_record",
        timestamp: "2026-09-01T00:00:02Z",
        payload: {
          thread_id: "worker",
          turn_id: "turn",
          response_id: "receipt",
          model: "gpt-5.6-sol",
          usage: counts(input, output),
          thread_token_usage: counts(counterInput, counterOutput),
        },
      }) +
        "\n" +
        JSON.stringify({
          type: "event_msg",
          timestamp: "2026-09-01T00:00:02Z",
          payload: {
            type: "token_count",
            info: { total_token_usage: counts(counterInput, counterOutput) },
          },
        }) +
        "\n",
    );
    const lowerBounds: Readonly<ScanCost>[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      maxCostUsd: 0.8,
      onCost: (cost) => lowerBounds.push(cost),
      onCostLowerBound: (cost) => lowerBounds.push(cost),
    });
    tracker.start("worker");
    try {
      const snapshot = await tracker.stop();
      expect(snapshot.usage).toMatchObject({
        input_tokens: Math.max(input, counterInput),
        output_tokens: Math.max(output, counterOutput),
      });
      if (counterInput > input || counterOutput > output)
        expect(snapshot.usage).toMatchObject({ coverage: "partial" });
      else expect(snapshot.usage).not.toMatchObject({ coverage: "partial" });
      const measured = tokenUsage(snapshot.usage);
      expect(measured).not.toBeNull();
      expect(lowerBounds.length).toBeGreaterThan(0);
      expect(lowerBounds.at(-1)!.estimatedUsd).toBeGreaterThanOrEqual(
        estimateScanCost("gpt-5.6-sol", counts(input, output))!.estimatedUsd,
      );
    } finally {
      await tracker.stop();
    }
  },
);

test.each(["standard", "pending-deep", "legacy-deep", "bound-deep"] as const)(
  "uses bound log homes rather than draft settings: %s",
  async (kind) => {
    const home = await codexHome();
    const foreign = await codexHome();
    const scanDirectory = join(home, "scan");
    const settings = join(scanDirectory, "artifacts", "deep_discovery");
    await mkdir(settings, { recursive: true });
    await writeFile(
      join(settings, "execution-settings.json"),
      JSON.stringify({ version: 1, settings: { codexHome: foreign } }),
    );
    for (const [directory, input] of [
      [home, 100],
      [foreign, 900_000],
    ] as const) {
      const path = await writeSession(
        directory,
        "scan-thread",
        {
          input_tokens: input,
          output_tokens: 0,
          cached_input_tokens: 0,
          cache_write_input_tokens: 0,
        },
        { timestamp: "2026-09-01T00:00:02Z" },
      );
      const lines = (await readFile(path, "utf8"))
        .trimEnd()
        .split("\n")
        .map((line) => ({
          ...JSON.parse(line),
          timestamp: "2026-09-01T00:00:02Z",
        }));
      await writeFile(path, jsonLines(lines) + "\n");
    }
    const tracker = new ScanCostTracker({
      codexHome: home,
      scanDirectory,
      model: "gpt-5.6-sol",
    });
    if (kind !== "standard")
      tracker.setAttributionReader(async () =>
        kind === "pending-deep"
          ? null
          : {
              formatVersion: 1,
              ...(kind === "legacy-deep"
                ? { legacy: true as const }
                : { workerCodexHome: foreign }),
              executionThreadIds: ["scan-thread"],
              owner: {
                threadId: null,
                turnId: null,
                startedAt: "2026-09-01T00:00:00Z",
              },
              startedAt: "2026-09-01T00:00:00Z",
              completedAt: null,
            },
      );
    tracker.start("scan-thread");
    try {
      expect((await tracker.stop()).usage).toMatchObject({
        input_tokens: kind === "bound-deep" ? 900_000 : 100,
      });
    } finally {
      await tracker.stop();
    }
  },
);

test.each(["no-reader", "pending-reader"] as const)(
  "enforces dedicated parent cost before orchestration: %s",
  async (kind) => {
    const home = await codexHome();
    await writeSession(home, "new-parent", {
      input_tokens: 100_000,
      output_tokens: 0,
      cached_input_tokens: 0,
      cache_write_input_tokens: 0,
    });
    const costs: Readonly<ScanCost>[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      maxCostUsd: 0.003,
      onCost: (cost) => costs.push(cost),
      onCostLowerBound: (cost) => costs.push(cost),
    });
    if (kind === "pending-reader")
      tracker.setAttributionReader(async () => null);
    tracker.start("new-parent");
    try {
      const snapshot = await tracker.stop();
      expect(snapshot.cost?.estimatedUsd).toBeGreaterThan(0.003);
      expect(costs.length).toBeGreaterThan(0);
    } finally {
      await tracker.stop();
    }
  },
);

test.each(["single", "identical", "prefix-first", "prefix-last"] as const)(
  "forwards copied worker activities without replaying completed calls: %s",
  async (copy) => {
    const { home, worker } = await workerSessionFixture();
    const recordedHome = await codexHome();
    await mkdir(join(recordedHome, "sessions"));
    const second = join(recordedHome, "sessions", "worker-copy.jsonl");
    const call = (id: string) => ({
      type: "response_item",
      payload: {
        type: "function_call",
        name: "exec_command",
        call_id: id,
        arguments: JSON.stringify({ cmd: "rg -n source routes/login.ts" }),
      },
    });
    const done = (id: string) => ({
      type: "response_item",
      payload: { type: "function_call_output", call_id: id },
    });
    const prefix =
      (await readFile(worker, "utf8")) + jsonLines([call("first")]) + "\n";
    const complete = prefix + jsonLines([done("first")]) + "\n";
    await writeFile(worker, copy === "prefix-first" ? prefix : complete);
    if (copy !== "single")
      await writeFile(second, copy === "prefix-last" ? prefix : complete);
    const activities: ScanActivity[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      scanDirectory: join(home, "scan"),
      model: "gpt-5.6-sol",
      repository: "/code/juice-shop",
      onActivity: (activity) => activities.push(activity),
    });
    tracker.setAttributionReader(async () => ({
      formatVersion: 1,
      legacy: true,
      workerCodexHome: recordedHome,
      executionThreadIds: [],
      owner: {
        threadId: "scan-thread",
        turnId: null,
        startedAt: "2026-09-01T00:00:00Z",
      },
      startedAt: "2026-09-01T00:00:00Z",
      completedAt: null,
    }));
    tracker.start("scan-thread");
    try {
      await tracker.refresh();
      expect(activities.map(({ id, status }) => [id, status])).toEqual([
        ["worker-thread:first", "running"],
        ["worker-thread:first", "completed"],
      ]);
      await writeFile(worker, complete);
      if (copy !== "single") await writeFile(second, complete);
      await tracker.refresh();
      expect(activities).toHaveLength(2);
      const later = jsonLines([call("second"), done("second")]) + "\n";
      await appendFile(worker, later);
      await tracker.refresh();
      if (copy !== "single") await appendFile(second, later);
      await tracker.stop();
      expect(activities.map(({ id, status }) => [id, status])).toEqual([
        ["worker-thread:first", "running"],
        ["worker-thread:first", "completed"],
        ["worker-thread:second", "running"],
        ["worker-thread:second", "completed"],
      ]);
    } finally {
      await tracker.stop();
    }
  },
);

test.each([0, 100])(
  "ignores only zero unpriced counter buckets: %i",
  async (unpricedTokens) => {
    const home = await codexHome();
    const path = await writeSession(home, "owner", {
      input_tokens: unpricedTokens,
      output_tokens: 0,
    });
    await appendFile(
      path,
      jsonLines([
        {
          type: "turn_context",
          timestamp: "2026-09-01T00:00:02Z",
          payload: { turn_id: "turn", model: "gpt-5.6-sol" },
        },
        {
          type: "event_msg",
          timestamp: "2026-09-01T00:00:02Z",
          payload: {
            type: "token_count",
            info: {
              total_token_usage: {
                input_tokens: unpricedTokens + 1000,
                output_tokens: 0,
              },
            },
          },
        },
      ]) + "\n",
    );
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
    });
    tracker.start("owner");
    try {
      const snapshot = await tracker.refresh();
      expect(tokenUsage(snapshot.usage)?.input_tokens).toBe(
        unpricedTokens + 1000,
      );
      if (unpricedTokens === 0)
        expect(snapshot.cost?.estimatedUsd).toBeCloseTo(0.004, 10);
      else expect(snapshot.cost).toBeNull();
    } finally {
      await tracker.stop();
    }
  },
);

test.each(["other turn", "outside window"])(
  "keeps owned legacy model before an unrelated first receipt: %s",
  async (kind) => {
    const home = await codexHome();
    const path = await writeSession(home, "owner", {});
    const at = "2026-09-01T00:00:02Z";
    await appendFile(
      path,
      jsonLines([
        {
          type: "turn_context",
          timestamp: at,
          payload: { turn_id: "turn", model: "gpt-5.6-sol" },
        },
        {
          type: "event_msg",
          timestamp: at,
          payload: {
            type: "token_count",
            info: {
              total_token_usage: { input_tokens: 1000, output_tokens: 0 },
            },
          },
        },
        {
          type: "token_usage_record",
          timestamp: kind === "outside window" ? "2026-09-01T00:00:04Z" : at,
          payload: {
            thread_id: "owner",
            turn_id: kind === "other turn" ? "other" : "turn",
            response_id: "unrelated-response",
            model: "gpt-6-astra",
            usage: { input_tokens: 50, output_tokens: 0 },
          },
        },
      ]) + "\n",
    );
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
    });
    tracker.setAttributionReader(async () => ({
      formatVersion: 1,
      executionThreadIds: [],
      owner: { threadId: "owner", turnId: "turn", startedAt: at },
      startedAt: at,
      completedAt: "2026-09-01T00:00:03Z",
    }));
    tracker.start("owner");
    try {
      const snapshot = await tracker.refresh();
      expect(tokenUsage(snapshot.usage)?.input_tokens).toBe(1000);
      expect(snapshot.cost?.estimatedUsd).toBeCloseTo(0.004, 10);
      expect(snapshot.usage).not.toMatchObject({ coverage: "partial" });
    } finally {
      await tracker.stop();
    }
  },
);

test.each(["sdk-owner", "unbound-owner", "unknown-worker"] as const)(
  "prices known completion receipts without a rollout: %s",
  async (kind) => {
    const home = await codexHome();
    const observed: Readonly<ScanCost>[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      maxCostUsd: 0.003,
      onCost: (cost) => observed.push(cost),
      onCostLowerBound: (cost) => observed.push(cost),
    });
    if (kind !== "unbound-owner")
      tracker.setAttributionReader(async () => ({
        formatVersion: 1,
        executionThreadIds: [kind === "unknown-worker" ? "worker" : "owner"],
        owner: {
          threadId: "owner",
          turnId: "turn",
          startedAt: "2026-09-01T00:00:00Z",
          dedicated: true,
        },
        startedAt: "2026-09-01T00:00:00Z",
        completedAt: null,
      }));
    tracker.start("owner");
    try {
      const receipt = { input_tokens: 1000, output_tokens: 0 };
      if (kind === "unknown-worker") tracker.recordUsage(receipt, "worker");
      const snapshot = await tracker.stop(
        kind === "unknown-worker" ? undefined : receipt,
      );
      expect(tokenUsage(snapshot.usage)?.input_tokens).toBe(1000);
      if (kind === "unknown-worker") {
        expect(snapshot.cost).toBeNull();
        expect(observed).toHaveLength(0);
      } else {
        expect(snapshot.cost?.estimatedUsd).toBeCloseTo(0.004, 10);
        expect(observed.at(-1)?.estimatedUsd).toBeGreaterThan(0.003);
      }
    } finally {
      await tracker.stop();
    }
  },
);
