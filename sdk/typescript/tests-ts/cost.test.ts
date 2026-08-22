import { spawnSync } from "node:child_process";
import {
  appendFile,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, parse, sep } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  estimateScanCost,
  ScanCostTracker,
  type ScanSessionEvent,
} from "../src/cost.js";
import type { ScanActivity } from "../src/scan-activity.js";
import { readScanLogs } from "../src/scan-logs.js";
import { sessionParentThreadId } from "../src/scan-sessions.js";
import type { ScanProgress } from "../src/worker-progress.js";

const temporaryDirectories: string[] = [];
const parentFields = ["source", "parent_thread_id", "forked_from_id"] as const;
type SessionParentField = (typeof parentFields)[number];

function parentMetadata(parentThreadId: string, field: SessionParentField) {
  return field === "source"
    ? {
        source: {
          subagent: { thread_spawn: { parent_thread_id: parentThreadId } },
        },
      }
    : { [field]: parentThreadId };
}

async function waitFor(check: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (check()) return;
    await new Promise<void>((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("Timed out waiting for the cost tracker.");
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function codexHome(): Promise<string> {
  const directory = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-cost-")),
  );
  temporaryDirectories.push(directory);
  return directory;
}

async function writeSession(
  home: string,
  threadId: string,
  usage: Record<string, number>,
  parentThreadId?: string,
  workingDirectory?: string,
  timestamp?: string,
  parentField: SessionParentField = "source",
): Promise<string> {
  const directory = join(home, "sessions", "2026", "07", "26");
  await mkdir(directory, { recursive: true });
  const path = join(directory, `rollout-${threadId}.jsonl`);
  await writeFile(
    path,
    [
      JSON.stringify({
        type: "session_meta",
        payload: {
          id: threadId,
          ...(workingDirectory === undefined ? {} : { cwd: workingDirectory }),
          ...(timestamp === undefined ? {} : { timestamp }),
          ...(parentThreadId === undefined
            ? {}
            : parentMetadata(parentThreadId, parentField)),
        },
      }),
      JSON.stringify({
        type: "event_msg",
        payload: {
          type: "token_count",
          info: { total_token_usage: usage },
        },
      }),
      "",
    ].join("\n"),
  );
  return path;
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

  test("uses published GPT-5.6 model rates", () => {
    const usage = { input_tokens: 1_000_000, output_tokens: 1_000_000 };

    expect(estimateScanCost("gpt-5.6", usage)?.estimatedUsd).toBe(35);
    expect(estimateScanCost("gpt-5.6-sol", usage)?.estimatedUsd).toBe(35);
    expect(estimateScanCost("gpt-5.6-terra", usage)?.estimatedUsd).toBe(14);
    expect(estimateScanCost("gpt-5.6-luna", usage)?.estimatedUsd).toBe(1.4);
  });

  test("uses canonical OpenAI pricing for Amazon Bedrock model identifiers", () => {
    const usage = { input_tokens: 1_000_000, output_tokens: 1_000_000 };

    for (const [model, expectedUsd] of [
      ["openai.gpt-5.6", 35],
      ["openai.gpt-5.6-sol", 35],
      ["openai.gpt-daybreak-blue-latest", 35],
      ["openai.gpt-daybreak-red-latest", 87.5],
      ["openai.gpt-5.6-terra", 14],
      ["openai.gpt-5.6-luna", 1.4],
    ] as const) {
      expect(estimateScanCost(model, usage)).toMatchObject({
        model,
        estimatedUsd: expectedUsd,
      });
    }

    expect(estimateScanCost("openai.unknown-model", usage)).toBeNull();
  });

  test("uses current input, cache, and output rates", () => {
    for (const [model, input, cached, write, output] of [
      ["gpt-daybreak-blue-latest", 5, 0.5, 6.25, 30],
      ["gpt-daybreak-red-latest", 12.5, 1.25, 15.625, 75],
      ["gpt-5.6-terra", 2, 0.2, 2.5, 12],
      ["gpt-5.6-luna", 0.2, 0.02, 0.25, 1.2],
    ] as const) {
      expect(
        estimateScanCost(model, {
          input_tokens: 1_000_000,
          output_tokens: 0,
        })?.estimatedUsd,
      ).toBe(input);
      expect(
        estimateScanCost(model, {
          input_tokens: 1_000_000,
          cached_input_tokens: 1_000_000,
          output_tokens: 0,
        })?.estimatedUsd,
      ).toBe(cached);
      expect(
        estimateScanCost(model, {
          input_tokens: 1_000_000,
          cache_write_input_tokens: 1_000_000,
          output_tokens: 0,
        })?.estimatedUsd,
      ).toBe(write);
      expect(
        estimateScanCost(model, {
          input_tokens: 0,
          output_tokens: 1_000_000,
        })?.estimatedUsd,
      ).toBe(output);
    }
  });

  test("charges cached input at its discounted rate", () => {
    expect(
      estimateScanCost("gpt-5.6-sol", {
        input_tokens: 1_250,
        cached_input_tokens: 200,
        output_tokens: 30,
      }),
    ).toEqual({
      model: "gpt-5.6-sol",
      inputTokens: 1_250,
      cachedInputTokens: 200,
      cacheWriteInputTokens: 0,
      outputTokens: 30,
      estimatedUsd: 0.00625,
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
    ).toBe(0.0051);
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
    ).toMatchObject({ cacheWriteInputTokens: 200, estimatedUsd: 0.0051 });
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
    ).toMatchObject({ cacheWriteInputTokens: 0, estimatedUsd: 0.00485 });
  });

  test("does not double-charge reasoning tokens included in output", () => {
    expect(
      estimateScanCost("gpt-5.6-sol", {
        input_tokens: 1_000,
        output_tokens: 10,
        reasoning_output_tokens: 9,
      })?.estimatedUsd,
    ).toBe(0.0053);
  });

  test("does not invent prices for unknown models or incomplete usage", () => {
    for (const [model, usage] of [
      ["unknown-model", { input_tokens: 1, output_tokens: 1 }],
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
    let release: (() => void) | undefined;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
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
    let reportCost!: (cost: unknown) => void;
    const reportedCost = new Promise<unknown>((resolve) => {
      reportCost = resolve;
    });
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      onCost: reportCost,
    });
    tracker.start("scan-thread");

    try {
      await expect(reportedCost).resolves.toEqual({
        model: "gpt-5.6-sol",
        inputTokens: 1_250,
        cachedInputTokens: 200,
        cacheWriteInputTokens: 0,
        outputTokens: 30,
        estimatedUsd: 0.00625,
      });
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
      "scan-thread",
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

    expect(await tracker.stop()).toEqual({
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
        estimatedUsd: 0.006275,
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
        writeSession(
          home,
          "scan-thread",
          usage,
          undefined,
          scanDirectory,
          "2026-07-26T12:00:00Z",
        );
      if (missing === "parent") await writeMain();
      const worker = await writeSession(
        home,
        "worker-thread",
        usage,
        missing === "parent" ? "parent-worker" : undefined,
        join(
          scanDirectory,
          "artifacts",
          "deep_discovery",
          "workers",
          "one",
          "output",
        ),
        "2026-07-26T12:01:00Z",
      );
      const message = (text: string) => ({
        type: "message",
        role: "assistant",
        content: [{ type: "output_text", text }],
      });
      await appendSessionItem(worker, message("Early worker output."));
      const unrelated = await writeSession(home, "unrelated-thread", usage);
      await appendSessionItem(unrelated, message("Unrelated output."));
      const events: ScanSessionEvent[] = [];
      const tracker = new ScanCostTracker({
        codexHome: home,
        scanDirectory,
        model: "gpt-5.6-sol",
        onSessionEvent: (event) => events.push(event),
      });
      tracker.start("scan-thread");
      await tracker.refresh();
      expect(events.some((event) => event.threadId === "worker-thread")).toBe(
        false,
      );

      if (missing === "parent") {
        await writeSession(home, "parent-worker", usage, "scan-thread");
      } else {
        await writeMain();
      }
      await appendSessionItem(worker, message("Late worker output."));
      await tracker.refresh();
      await tracker.refresh();
      await tracker.stop();

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
        undefined,
        scanDirectory,
        "2026-07-26T12:00:00.900Z",
      );
      await writeSession(
        home,
        "deep-worker",
        { input_tokens: 250, output_tokens: 2 },
        undefined,
        process.platform === "win32"
          ? workerDirectory.toUpperCase()
          : workerDirectory,
        "2026-07-26T12:00:00.900Z",
      );
      await writeSession(
        home,
        "deep-reducer",
        { input_tokens: 125, output_tokens: 1 },
        undefined,
        (process.platform === "win32" ? artifacts.toUpperCase() : artifacts) +
          sep,
        "2026-07-26T12:02:00Z",
      );
      await writeSession(
        home,
        "deep-worker-child",
        { input_tokens: 50, output_tokens: 1 },
        "deep-worker",
        undefined,
        undefined,
        parentField,
      );
      await writeSession(
        home,
        "unrelated-thread",
        { input_tokens: 1_000_000, output_tokens: 1_000_000 },
        undefined,
        `${scanDirectory}-other`,
      );
      await writeSession(
        home,
        "previous-scan",
        { input_tokens: 1_000_000, output_tokens: 1_000_000 },
        undefined,
        join(scanDirectory, "artifacts", "deep_discovery", "previous-worker"),
        "2026-07-26T11:59:00Z",
      );
      await writeSession(
        home,
        "unknown-start",
        { input_tokens: 1_000_000, output_tokens: 1_000_000 },
        undefined,
        join(
          scanDirectory,
          "artifacts",
          "deep_discovery",
          "workers",
          "stale",
          "output",
        ),
      );
      await writeSession(
        home,
        "nested-scan",
        { input_tokens: 1_000_000, output_tokens: 1_000_000 },
        undefined,
        join(scanDirectory, "nested", "artifacts"),
        "2026-07-26T12:03:00Z",
      );
      const events: ScanSessionEvent[] = [];
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-sol",
        scanDirectory,
        onSessionEvent: (event) => events.push(event),
      });
      tracker.start("scan-thread");

      expect((await tracker.stop()).usage).toMatchObject({
        input_tokens: 1_425,
        output_tokens: 14,
      });
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
        undefined,
        scanDirectory,
        "2026-07-26T12:00:00.900Z",
      );
      await writeSession(
        home,
        "deep-worker",
        { input_tokens: 250, output_tokens: 2 },
        undefined,
        join(
          scanDirectory,
          "artifacts",
          "deep_discovery",
          "workers",
          "worker",
          "output",
        ),
        "2026-07-26T12:00:00.950Z",
      );
      await writeSession(
        home,
        "bystander",
        { input_tokens: 1_000_000, output_tokens: 1_000_000 },
        parentThreadId,
        workingDirectory(scanDirectory),
        timestamp,
        parentField,
      );
      await writeSession(
        home,
        "bystander-child",
        { input_tokens: 1_000_000, output_tokens: 1_000_000 },
        "bystander",
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
      expect(snapshot.cost?.estimatedUsd).toBe(0.00661);
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
        undefined,
        scanDirectory,
        timestamp,
      );
      await writeSession(
        home,
        "independent-worker",
        { input_tokens: 1_000_000, output_tokens: 1_000_000 },
        undefined,
        join(scanDirectory, "artifacts"),
        "2026-07-26T12:01:00Z",
      );
      await writeSession(
        home,
        "child-worker",
        { input_tokens: 250, output_tokens: 2 },
        "scan-thread",
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
        [
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
        ]
          .map((event) => JSON.stringify(event))
          .join("\n") + "\n",
      );

      const activities: ScanActivity[] = [];
      const progress: ScanProgress[] = [];
      const events: ScanSessionEvent[] = [];
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-terra",
        repository: "/code/juice-shop",
        expectedFilesTotal: 8,
        onActivity: (activity) => activities.push(activity),
        onProgress: (update) => progress.push(update),
        onSessionEvent: (event) => events.push(event),
      });
      tracker.start("scan-thread");

      expect(await tracker.stop()).toEqual({
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

  test("forwards actions from this scan's delegated workers only", async () => {
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    const parentPath = await writeSession(home, "scan-thread", usage);
    const workerPath = await writeSession(
      home,
      "worker-thread",
      usage,
      "scan-thread",
    );
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
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    await writeSession(home, "scan-thread", usage);
    const path = await writeSession(
      home,
      "worker-thread",
      usage,
      "scan-thread",
    );
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
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    await writeSession(home, "scan-thread", usage);
    const worker = await writeSession(
      home,
      "worker-thread",
      usage,
      "scan-thread",
    );
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
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    await writeSession(home, "scan-thread", usage);
    const worker = await writeSession(
      home,
      "worker-thread",
      usage,
      "scan-thread",
    );
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
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    await writeSession(home, "scan-thread", usage);
    const worker = await writeSession(
      home,
      "worker-thread",
      usage,
      "scan-thread",
    );
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
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    await writeSession(home, "scan-thread", usage);
    const worker = await writeSession(
      home,
      "worker-thread",
      usage,
      "scan-thread",
    );
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
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    const parent = await writeSession(home, "scan-thread", usage);
    const worker = await writeSession(
      home,
      "worker-thread",
      usage,
      "scan-thread",
    );
    const descendant = await writeSession(
      home,
      "nested-worker-thread",
      usage,
      "worker-thread",
    );
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
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    const parent = await writeSession(home, "scan-thread", usage);
    const worker = await writeSession(
      home,
      "worker-thread",
      usage,
      "scan-thread",
    );
    const otherWorker = await writeSession(
      home,
      "other-worker-thread",
      usage,
      "scan-thread",
    );
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
    const first = await writeSession(home, "worker-a", usage, "scan-thread");
    const second = await writeSession(home, "worker-b", usage, "scan-thread");
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
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    await writeSession(home, "scan-thread", usage);
    const worker = await writeSession(
      home,
      "worker-thread",
      usage,
      "scan-thread",
    );
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
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    await writeSession(home, "scan-thread", usage);
    const worker = await writeSession(
      home,
      "worker-thread",
      usage,
      "scan-thread",
    );
    await appendSessionItem(worker, progressMessage(3));

    let reportProgress!: (progress: ScanProgress) => void;
    const reportedProgress = new Promise<ScanProgress>((resolve) => {
      reportProgress = resolve;
    });
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
    const home = await codexHome();
    const usage = { input_tokens: 100, output_tokens: 10 };
    await writeSession(home, "scan-thread", usage);
    const worker = await writeSession(
      home,
      "worker-thread",
      usage,
      "scan-thread",
    );
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

    expect((await tracker.stop()).cost).toEqual({
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

    expect(updates).toEqual([0.00625]);
  });

  test("falls back to the completed turn when session logs are unavailable", async () => {
    const tracker = new ScanCostTracker({
      codexHome: await codexHome(),
      model: "gpt-5.6-luna",
    });
    const usage = { input_tokens: 1_000, output_tokens: 20 };
    tracker.start("scan-thread");

    expect(await tracker.stop(usage)).toEqual({
      usage,
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
});
