import { spawnSync } from "node:child_process";
import * as fsPromises from "node:fs/promises";
import {
  appendFile,
  chmod,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, mock, spyOn, test } from "bun:test";
import {
  estimateScanCost,
  ScanCostTracker,
  type ScanSessionEvent,
} from "../src/cost.js";
import type { ScanActivity } from "../src/scan-activity.js";
import type { ScanProgress } from "../src/worker-progress.js";
import { runMockInSubprocess } from "./support/isolated-mock.js";

const temporaryDirectories: string[] = [];
const testPosix =
  process.platform === "win32" || process.geteuid?.() === 0 ? test.skip : test;

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
  usage: Record<string, number> | null,
  parentThreadId?: string,
  workingDirectory?: string,
  timestamp?: string,
  completed = false,
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
            : {
                source: {
                  subagent: {
                    thread_spawn: { parent_thread_id: parentThreadId },
                  },
                },
              }),
        },
      }),
      ...(completed ? [taskEvent("task_started")] : []),
      ...(usage === null
        ? []
        : [
            JSON.stringify({
              type: "event_msg",
              payload: {
                type: "token_count",
                info: { total_token_usage: usage },
              },
            }),
          ]),
      ...(completed ? [taskEvent("task_complete")] : []),
      "",
    ].join("\n"),
  );
  return path;
}

function taskEvent(
  type: "task_started" | "task_complete" | "turn_complete" | "turn_aborted",
): string {
  return JSON.stringify({
    type: "event_msg",
    payload: {
      type,
      turn_id: "fixture-turn",
      started_at: 1_785_067_320,
      ...(type === "task_started" ? {} : { completed_at: 1_785_067_321 }),
      ...(type === "turn_aborted" ? { reason: "interrupted" } : {}),
    },
  });
}

type MockAccountingEvent = Readonly<Record<string, unknown>> | Error;

function accountingEvent(
  usage: Readonly<Record<string, number>> | null,
): MockAccountingEvent {
  return {
    type: "event_msg",
    payload: { type: "token_count", info: { total_token_usage: usage } },
  };
}

const accountingFork = {
  // The inherited turn, child, and owned turn start within the same second.
  inheritedTurnId: "019f9e4d-b324-7000-8000-000000000001",
  threadId: "019f9e4d-b3ba-7000-8000-000000000002",
  ownedTurnId: "019f9e4d-b3ec-7000-8000-000000000003",
  pendingTurnId: "019f9e4d-b450-4000-8000-000000000004",
  timestamp: "2026-07-26T12:02:00.250Z",
  startedAt: 1_785_067_320,
};

function accountingTaskStart(
  turnId: string,
  startedAt: number,
): MockAccountingEvent {
  return {
    type: "event_msg",
    payload: {
      type: "task_started",
      turn_id: turnId,
      started_at: startedAt,
    },
  };
}

function accountingSession(
  threadId: string,
  events: readonly MockAccountingEvent[],
  parentThreadId?: string,
  metadata: Readonly<Record<string, unknown>> = {},
): MockAccountingEvent[] {
  return [
    {
      type: "session_meta",
      payload: { ...metadata, id: threadId, parent_thread_id: parentThreadId },
    },
    ...events,
    { type: "event_msg", payload: { type: "task_complete" } },
  ];
}

async function withMockAccountingSessions(
  sessions: Readonly<Record<string, readonly MockAccountingEvent[]>>,
  options: Omit<ConstructorParameters<typeof ScanCostTracker>[0], "codexHome">,
  check: (
    tracker: ScanCostTracker,
    append: (threadId: string, events: readonly MockAccountingEvent[]) => void,
    omit: (threadId: string) => void,
  ) => Promise<void>,
  beforeOpen?: (
    path: string,
    attempt: number,
    append: (threadId: string, events: readonly MockAccountingEvent[]) => void,
  ) => void,
): Promise<void> {
  const home = join(tmpdir(), "codex-security-mock-cost");
  const directory = join(home, "sessions");
  const files = new Map<string, Buffer>();
  const omittedFiles = new Set<string>();
  const opens = new Map<string, number>();
  const events = new Map<string, MockAccountingEvent>();
  const append = (
    threadId: string,
    next: readonly MockAccountingEvent[],
  ): void => {
    const path = join(directory, `rollout-${threadId}.jsonl`);
    const lines = next.map((event) => {
      // The reader sees valid markers; decoded events and errors stay in memory.
      const marker = JSON.stringify({ mockSessionEvent: events.size });
      events.set(marker, event);
      return `${marker}\n`;
    });
    files.set(
      path,
      Buffer.concat([
        files.get(path) ?? Buffer.alloc(0),
        Buffer.from(lines.join("")),
      ]),
    );
  };
  for (const [threadId, initial] of Object.entries(sessions)) {
    append(threadId, initial);
  }
  const originalOpen = fsPromises.open;
  const originalReaddir = fsPromises.readdir;
  const originalParse = JSON.parse;
  mock.module("node:fs/promises", () => ({
    ...fsPromises,
    readdir: async (path: unknown) => {
      if (String(path) !== directory)
        throw new Error("Unexpected session directory");
      return [...files.keys()]
        .filter((path) => !omittedFiles.has(path))
        .map((path) => ({
          name: path.slice(directory.length + 1),
          isDirectory: () => false,
          isFile: () => true,
        }));
    },
    open: async (path: unknown) => {
      const name = String(path);
      const attempt = (opens.get(name) ?? 0) + 1;
      opens.set(name, attempt);
      beforeOpen?.(name, attempt, append);
      const contents = files.get(name);
      if (contents === undefined) throw new Error("Unexpected session file");
      return {
        read: async (
          buffer: Buffer,
          offset: number,
          length: number,
          position: number,
        ) => ({
          bytesRead:
            position >= contents.length
              ? 0
              : contents.copy(buffer, offset, position, position + length),
          buffer,
        }),
        close: async () => {},
      };
    },
  }));
  const parse = spyOn(JSON, "parse").mockImplementation((text, reviver) => {
    const event = events.get(text);
    if (event instanceof Error) throw event;
    return event ?? originalParse(text, reviver);
  });
  const tracker = new ScanCostTracker({ ...options, codexHome: home });
  tracker.start("scan-thread");
  try {
    await check(tracker, append, (threadId) => {
      omittedFiles.add(join(directory, `rollout-${threadId}.jsonl`));
    });
  } finally {
    await tracker.stop().catch(() => {});
    parse.mockRestore();
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      open: originalOpen,
      readdir: originalReaddir,
    }));
  }
}

async function workerScan({
  rootUsage = { input_tokens: 100, output_tokens: 10 },
  workerUsage = { input_tokens: 100, output_tokens: 10 },
  workerCompleted = true,
  maxCostUsd,
  onCost,
}: {
  rootUsage?: Record<string, number> | null;
  workerUsage?: Record<string, number> | null;
  workerCompleted?: boolean;
  maxCostUsd?: number;
  onCost?: (cost: { estimatedUsd: number }) => void;
} = {}): Promise<{
  home: string;
  root: string;
  worker: string;
  tracker: ScanCostTracker;
}> {
  const home = await codexHome();
  const root = await writeSession(home, "scan-thread", rootUsage);
  const worker = await writeSession(
    home,
    "worker-thread",
    workerUsage,
    "scan-thread",
    undefined,
    undefined,
    workerCompleted,
  );
  const tracker = new ScanCostTracker({
    codexHome: home,
    model: "gpt-5.6-terra",
    maxCostUsd,
    onCost,
  });
  tracker.start("scan-thread");
  return { home, root, worker, tracker };
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

async function appendIncompleteTokenUsage(path: string): Promise<void> {
  const event = JSON.stringify({
    type: "event_msg",
    payload: {
      type: "token_count",
      info: {
        total_token_usage: { input_tokens: 10_000, output_tokens: 1_000 },
      },
    },
  });
  await appendFile(path, event.slice(0, -1));
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

describe("scan cost", () => {
  test.each([
    [{ cache_write_tokens: 15 }, 15],
    [{ cache_write_input_tokens: 0, cache_write_tokens: 15 }, 15],
    [{ cache_write_input_tokens: 0, cache_write_tokens: 80 }, 0],
  ] as const)(
    "keeps workbench cache-write normalization aligned with SDK usage",
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

  test("uses current Terra and Luna input, cache, and output rates", () => {
    for (const [model, input, cached, write, output] of [
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
        scanDirectory: missing === "main" ? scanDirectory : undefined,
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

  test("counts independent Deep workers inside the scan directory only", async () => {
    const home = await codexHome();
    const scanDirectory = join(home, "scans", "current");
    await writeSession(
      home,
      "scan-thread",
      { input_tokens: 1_000, output_tokens: 10 },
      undefined,
      scanDirectory,
      "2026-07-26T12:00:00Z",
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
      "2026-07-26T12:01:00Z",
    );
    await writeSession(
      home,
      "deep-reducer",
      { input_tokens: 125, output_tokens: 1 },
      undefined,
      join(scanDirectory, "artifacts"),
      "2026-07-26T12:02:00Z",
    );
    await writeSession(
      home,
      "deep-worker-child",
      { input_tokens: 50, output_tokens: 1 },
      "deep-worker",
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
  });

  test.each([
    ["root metadata is missing", "missing", "independent", 1, true],
    ["root timing is missing", "untimed", "independent", 1, true],
    ["root timing is invalid", "invalid", "independent", 1, true],
    ["worker timing is missing", "timed", "untimed", 1, true],
    ["worker timing is invalid", "timed", "invalid", 1, true],
    ["the worker parent is unobserved", "missing", "orphaned", 1, true],
    ["the worker has a parent", "missing", "parented", 1, false],
    ["the worker is unrelated", "missing", "unrelated", 1, false],
    ["tracking is optional", "missing", "independent", undefined, false],
    ["no worker needs attribution", "missing", "none", 1, false],
  ] as const)(
    "verifies independent Deep worker ownership when %s",
    async (_scenario, rootState, workerState, maxCostUsd, shouldReject) => {
      const home = await codexHome();
      const scanDirectory = join(home, "scans", "current");
      if (rootState !== "missing") {
        await writeSession(
          home,
          "scan-thread",
          { input_tokens: 100, output_tokens: 10 },
          undefined,
          scanDirectory,
          rootState === "timed"
            ? "2026-07-26T12:00:00Z"
            : rootState === "invalid"
              ? "not a timestamp"
              : undefined,
        );
      }
      if (workerState !== "none") {
        await writeSession(
          home,
          "deep-worker",
          { input_tokens: 1_000, output_tokens: 100 },
          workerState === "parented"
            ? "scan-thread"
            : workerState === "orphaned"
              ? "unobserved-coordinator"
              : undefined,
          workerState === "unrelated"
            ? join(home, "another-scan", "artifacts")
            : join(
                scanDirectory,
                "artifacts",
                "deep_discovery",
                "workers",
                "worker",
                "output",
              ),
          workerState === "untimed"
            ? undefined
            : workerState === "invalid"
              ? "not a timestamp"
              : "2026-07-26T12:01:00Z",
          true,
        );
      }
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-terra",
        scanDirectory,
        maxCostUsd,
      });
      tracker.start("scan-thread");
      await tracker.refresh();

      const completed = tracker.stop({ input_tokens: 100, output_tokens: 10 });
      if (shouldReject) {
        await expect(completed).rejects.toThrow(
          "The scan cost limit could not be verified",
        );
      } else {
        await expect(completed).resolves.toMatchObject({
          cost: {
            inputTokens: workerState === "parented" ? 1_100 : 100,
          },
        });
      }
    },
  );

  test("resolves mocked worker ancestry before directory attribution", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "resolves mocked worker ancestry before directory attribution",
      )
    ) {
      return;
    }
    const scanDirectory = join(tmpdir(), "codex-security-mock-scan");
    const artifacts = join(scanDirectory, "artifacts");
    const workerDirectory = join(
      artifacts,
      "deep_discovery",
      "workers",
      "worker",
      "output",
    );
    const rootUsage = { input_tokens: 100, output_tokens: 10 };
    const session = (
      id: string,
      parent?: string,
      cwd?: string,
      timestamp?: string,
      input = 1_000,
    ) =>
      accountingSession(
        id,
        [accountingEvent({ input_tokens: input, output_tokens: input / 10 })],
        parent,
        { cwd, timestamp },
      );
    const roots = {
      "scan-thread": session(
        "scan-thread",
        undefined,
        scanDirectory,
        "2026-07-26T12:00:00Z",
        100,
      ),
      "previous-root": session(
        "previous-root",
        undefined,
        scanDirectory,
        "2026-07-26T11:00:00Z",
      ),
    };
    const previousWorkers = {
      "previous-coordinator": session(
        "previous-coordinator",
        "previous-root",
        artifacts,
      ),
      "previous-worker": session(
        "previous-worker",
        "previous-coordinator",
        workerDirectory,
        "invalid timestamp",
      ),
      "resumed-previous-worker": session(
        "resumed-previous-worker",
        "previous-root",
        workerDirectory,
        "2026-07-26T12:02:00Z",
      ),
      "older-independent": session(
        "older-independent",
        undefined,
        workerDirectory,
        "2026-07-26T11:59:00Z",
      ),
      "older-orphan": session(
        "older-orphan",
        "missing-parent",
        workerDirectory,
        "2026-07-26T11:59:00Z",
      ),
      "older-cycle-a": session(
        "older-cycle-a",
        "older-cycle-b",
        workerDirectory,
        "2026-07-26T11:59:00Z",
      ),
      "older-cycle-b": session("older-cycle-b", "older-cycle-a"),
    };
    await withMockAccountingSessions(
      {
        ...roots,
        ...previousWorkers,
        "current-child": session(
          "current-child",
          "current-independent",
          workerDirectory,
          "2026-07-26T11:59:00Z",
          300,
        ),
        "current-independent": session(
          "current-independent",
          undefined,
          artifacts,
          "2026-07-26T12:01:00Z",
          200,
        ),
        "unrelated-conflict-a": session("unrelated-conflict", "previous-root"),
        "unrelated-conflict-b": session("unrelated-conflict", "missing-parent"),
      },
      { model: "gpt-5.6-terra", maxCostUsd: 1, scanDirectory },
      async (tracker) => {
        expect((await tracker.stop(rootUsage)).cost).toMatchObject({
          inputTokens: 600,
          outputTokens: 60,
        });
      },
    );
    await withMockAccountingSessions(
      {
        ...roots,
        ...previousWorkers,
        "scan-thread": [
          new SyntaxError("mock parser diagnostic"),
          ...roots["scan-thread"],
        ],
      },
      { model: "gpt-5.6-terra", maxCostUsd: 1, scanDirectory },
      async (tracker) => {
        expect((await tracker.stop(rootUsage)).cost?.inputTokens).toBe(100);
      },
    );
    const unresolvedWorkers: Array<Record<string, MockAccountingEvent[]>> = [
      {
        orphan: session(
          "orphan",
          "missing-parent",
          workerDirectory,
          "2026-07-26T12:01:00Z",
        ),
      },
      { orphan: session("orphan", "missing-parent", workerDirectory) },
      {
        "cycle-a": session("cycle-a", "cycle-b", workerDirectory),
        "cycle-b": session("cycle-b", "cycle-a"),
      },
      {
        "conflict-a": session(
          "conflict",
          "scan-thread",
          workerDirectory,
          "2026-07-26T11:59:00Z",
        ),
        "conflict-b": session("conflict", "previous-root"),
      },
      {
        "conflict-a": session("conflict", "scan-thread"),
        "conflict-b": session("conflict", "previous-root"),
      },
    ];
    for (const workers of unresolvedWorkers) {
      await withMockAccountingSessions(
        { ...roots, ...workers },
        { model: "gpt-5.6-terra", maxCostUsd: 1, scanDirectory },
        async (tracker) => {
          await expect(tracker.stop(rootUsage)).rejects.toThrow(
            "The scan cost limit could not be verified",
          );
        },
      );
    }
  });

  test("limits mocked worker-directory attribution to contained output paths", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "limits mocked worker-directory attribution to contained output paths",
      )
    ) {
      return;
    }
    const scanDirectory = join(tmpdir(), "codex-security-mock-scan");
    const artifacts = join(scanDirectory, "artifacts");
    const workers = join(artifacts, "deep_discovery", "workers");
    const timestamp = "2026-07-26T12:01:00Z";
    const rootUsage = { input_tokens: 100, output_tokens: 10 };
    for (const [cwd, startedAt, expectedInput] of [
      [artifacts, timestamp, 1_100],
      [join(workers, "worker", "output"), timestamp, 1_100],
      [join(workers, "worker", "output"), undefined, null],
      [join(artifacts, "deep_discovery", "output"), undefined, 100],
      [join(artifacts, "deep_discovery", "output"), timestamp, 100],
      [
        join(artifacts, "deep_discovery", "workers-other", "worker", "output"),
        undefined,
        100,
      ],
    ] as const) {
      await withMockAccountingSessions(
        {
          "scan-thread": accountingSession(
            "scan-thread",
            [accountingEvent(rootUsage)],
            undefined,
            {
              cwd: scanDirectory,
              timestamp: "2026-07-26T12:00:00Z",
            },
          ),
          worker: accountingSession(
            "worker",
            [accountingEvent({ input_tokens: 1_000, output_tokens: 100 })],
            undefined,
            {
              cwd,
              timestamp: startedAt,
            },
          ),
        },
        { model: "gpt-5.6-terra", maxCostUsd: 1, scanDirectory },
        async (tracker) => {
          const stopped = tracker.stop(rootUsage);
          if (expectedInput === null) {
            await expect(stopped).rejects.toThrow(
              "The scan cost limit could not be verified",
            );
          } else {
            expect((await stopped).cost?.inputTokens).toBe(expectedInput);
          }
        },
      );
    }
  });

  test("keeps mocked replay errors outside owned accounting", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "keeps mocked replay errors outside owned accounting",
      )
    ) {
      return;
    }
    const rootUsage = { input_tokens: 100, output_tokens: 10 };
    for (const location of ["replay", "owned-before", "owned-after"] as const) {
      const costs: number[] = [];
      await withMockAccountingSessions(
        {
          "scan-thread": accountingSession("scan-thread", [
            accountingEvent(rootUsage),
          ]),
          "worker-thread": [
            {
              type: "session_meta",
              payload: {
                id: "worker-thread",
                parent_thread_id: "scan-thread",
                timestamp: "2026-07-26T12:02:00Z",
              },
            },
            ...(location === "owned-before"
              ? [new SyntaxError("mock owned parser diagnostic")]
              : []),
            { type: "session_meta", payload: { id: "scan-thread" } },
            new SyntaxError("mock replay parser diagnostic"),
            accountingEvent({ input_tokens: 1_000, output_tokens: 100 }),
            {
              type: "event_msg",
              payload: { type: "task_started", started_at: 1_785_067_320 },
            },
            ...(location === "owned-after"
              ? [new SyntaxError("mock owned parser diagnostic")]
              : []),
            accountingEvent({ input_tokens: 1_200, output_tokens: 120 }),
            { type: "event_msg", payload: { type: "task_complete" } },
          ],
        },
        {
          model: "gpt-5.6-terra",
          maxCostUsd: 1,
          onCost: (cost) => costs.push(cost.estimatedUsd),
        },
        async (tracker) => {
          const stopped = tracker.stop(rootUsage);
          if (location === "replay") {
            await expect(stopped).resolves.toMatchObject({
              usage: { input_tokens: 300, output_tokens: 30 },
              cost: { estimatedUsd: 0.00096 },
            });
          } else {
            await expect(stopped).rejects.toThrow(
              "tracked session record could not be read",
            );
          }
          expect(costs).toEqual([0.00096]);
        },
      );
    }
  });

  test("ignores replayed parent history in forked worker sessions", async () => {
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
            source: {
              subagent: {
                thread_spawn: { parent_thread_id: "scan-thread" },
              },
            },
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
  });

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

  test("accumulates usage after a token-counter reset", async () => {
    const home = await codexHome();
    const root = await writeSession(home, "scan-thread", {
      input_tokens: 1_000,
      output_tokens: 100,
    });
    const costs: number[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
      maxCostUsd: 0.001,
      onCost: (cost) => costs.push(cost.estimatedUsd),
    });
    tracker.start("scan-thread");
    expect((await tracker.refresh()).cost?.estimatedUsd).toBe(0.0032);
    await appendFile(
      root,
      `${JSON.stringify({
        type: "event_msg",
        payload: {
          type: "token_count",
          info: {
            total_token_usage: { input_tokens: 500, output_tokens: 50 },
          },
        },
      })}\n`,
    );

    expect((await tracker.stop()).cost?.estimatedUsd).toBe(0.0048);
    expect(costs).toEqual([0.0032, 0.0048]);
  });

  test("keeps live and persisted usage aligned across counter resets", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "keeps live and persisted usage aligned across counter resets",
      )
    ) {
      return;
    }
    type Usage = Record<string, number> & {
      input_tokens: number;
      output_tokens: number;
    };
    const { PLUGIN_ROOT } = await import("./plugin-root.js");
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const probe = [
      "import io, json, sys",
      "from datetime import datetime, timezone",
      "from pathlib import Path",
      "from unittest.mock import patch",
      "sys.path.insert(0, sys.argv[1])",
      "import workbench_scan_usage as usage",
      "case = json.loads(sys.argv[2])",
      "inherited = case.get('inherited')",
      "fork = case['fork']",
      "thread = 'scan-thread' if inherited is None else fork['threadId']",
      "parent = None if inherited is None else 'scan-thread'",
      "stamp = '2026-07-26T12:02:00Z'",
      "def token_event(sample):",
      "    snapshot = {**sample, 'total_tokens': sample['input_tokens'] + sample['output_tokens']}",
      "    return {'type': 'event_msg', 'timestamp': stamp, 'payload': {'type': 'token_count', 'info': {'total_token_usage': snapshot}}}",
      "def task_event(turn_id):",
      "    return {'type': 'event_msg', 'timestamp': stamp, 'payload': {'type': 'task_started', 'turn_id': turn_id, 'started_at': fork['startedAt']}}",
      "metadata = {'id': thread, 'parent_thread_id': parent}",
      "if inherited is not None and not case.get('copiedHistory'):",
      "    metadata['forked_from_id'] = parent",
      "events = [{'type': 'session_meta', 'payload': metadata}]",
      "if inherited is not None:",
      "    if case.get('copiedHistory'):",
      "        events.append({'type': 'session_meta', 'payload': {'id': parent}})",
      "    events.extend([task_event(fork['inheritedTurnId']), token_event(inherited), task_event(fork['pendingTurnId']), token_event(inherited), task_event(fork['ownedTurnId'])])",
      "for index, sample in enumerate(case['samples']):",
      "    if inherited is not None and index == 1:",
      "        events.append(task_event(fork['pendingTurnId']))",
      "    events.append(token_event(sample))",
      "session = usage.RolloutSession(thread, parent, Path('fixture-rollout'))",
      "with patch.object(Path, 'open', return_value=io.BytesIO(b'{}\\n' * len(events))), patch.object(usage.json, 'loads', side_effect=events):",
      "    measured, warnings = usage._read_rollout_usage(session, started_at=datetime(2026, 7, 26, 12, tzinfo=timezone.utc), completed_at=None)",
      "print(json.dumps({'usage': measured, 'warnings': sorted(warnings)}))",
    ].join("\n");
    const inheritedReset = {
      inherited: { input_tokens: 1_000, output_tokens: 1_000 },
      samples: [
        { input_tokens: 1_500, output_tokens: 100 },
        { input_tokens: 1_600, output_tokens: 150 },
        { input_tokens: 1_600, output_tokens: 150 },
      ],
      expected: { input_tokens: 1_600, output_tokens: 150 },
    };
    const cases: Array<{
      samples: Usage[];
      expected: Usage;
      inherited?: Usage;
      copiedHistory?: boolean;
      limit?: number;
    }> = [
      {
        samples: [
          { input_tokens: 1_000, output_tokens: 1_000 },
          { input_tokens: 1_500, output_tokens: 100 },
          { input_tokens: 1_500, output_tokens: 100 },
        ],
        expected: { input_tokens: 2_500, output_tokens: 1_100 },
        limit: 0.017,
      },
      {
        samples: [
          {
            input_tokens: 1_000,
            cached_input_tokens: 400,
            cache_write_input_tokens: 100,
            output_tokens: 1_000,
            reasoning_output_tokens: 800,
          },
          {
            input_tokens: 1_500,
            cached_input_tokens: 600,
            cache_write_input_tokens: 200,
            output_tokens: 100,
            reasoning_output_tokens: 50,
          },
        ],
        expected: {
          input_tokens: 2_500,
          cached_input_tokens: 1_000,
          cache_write_input_tokens: 300,
          output_tokens: 1_100,
          reasoning_output_tokens: 850,
        },
      },
      {
        samples: [
          {
            input_tokens: 100,
            cached_input_tokens: 20,
            cache_write_input_tokens: 10,
            output_tokens: 50,
            reasoning_output_tokens: 10,
          },
          {
            input_tokens: 150,
            cached_input_tokens: 10,
            cache_write_input_tokens: 20,
            output_tokens: 30,
            reasoning_output_tokens: 5,
          },
        ],
        expected: {
          input_tokens: 150,
          cached_input_tokens: 30,
          cache_write_input_tokens: 20,
          output_tokens: 80,
          reasoning_output_tokens: 15,
        },
      },
      {
        samples: [
          { input_tokens: 1_000, output_tokens: 1_000 },
          { input_tokens: 0, output_tokens: 0 },
          { input_tokens: 1_500, output_tokens: 100 },
        ],
        expected: { input_tokens: 2_500, output_tokens: 1_100 },
      },
      inheritedReset,
      { ...inheritedReset, copiedHistory: true },
      {
        samples: [
          { input_tokens: 100, output_tokens: 100 },
          { input_tokens: 110, output_tokens: 90 },
          { input_tokens: 120, output_tokens: 100 },
        ],
        expected: { input_tokens: 110, output_tokens: 110 },
      },
    ];
    for (const {
      samples,
      inherited,
      copiedHistory,
      expected: counters,
      limit,
    } of cases) {
      const expected = {
        cached_input_tokens: 0,
        cache_write_input_tokens: 0,
        reasoning_output_tokens: 0,
        ...counters,
        total_tokens: counters.input_tokens + counters.output_tokens,
      };
      const persisted = spawnSync(
        python!,
        [
          "-I",
          "-B",
          "-c",
          probe,
          join(PLUGIN_ROOT, "scripts"),
          JSON.stringify({
            samples,
            inherited,
            copiedHistory,
            fork: accountingFork,
          }),
        ],
        { encoding: "utf8" },
      );
      expect(persisted.status, persisted.stderr).toBe(0);
      expect(JSON.parse(persisted.stdout)).toEqual({
        usage: {
          inputTokens: expected.input_tokens,
          cachedInputTokens: expected.cached_input_tokens,
          cacheWriteInputTokens: expected.cache_write_input_tokens,
          outputTokens: expected.output_tokens,
          reasoningOutputTokens: expected.reasoning_output_tokens,
          totalTokens: expected.total_tokens,
        },
        warnings: [],
      });
      const taskStart = (turnId: string) =>
        accountingTaskStart(turnId, accountingFork.startedAt);
      const events: MockAccountingEvent[] = [];
      if (inherited !== undefined) {
        if (copiedHistory) {
          events.push({
            type: "session_meta",
            payload: { id: "scan-thread" },
          });
        }
        events.push(
          taskStart(accountingFork.inheritedTurnId),
          accountingEvent(inherited),
          taskStart(accountingFork.pendingTurnId),
          accountingEvent(inherited),
          taskStart(accountingFork.ownedTurnId),
        );
      }
      for (const [index, sample] of samples.entries()) {
        if (inherited !== undefined && index === 1) {
          events.push(taskStart(accountingFork.pendingTurnId));
        }
        events.push(accountingEvent(sample));
      }
      const metadata = { timestamp: accountingFork.timestamp };
      const sessions: Record<string, MockAccountingEvent[]> =
        inherited === undefined
          ? {
              "scan-thread": accountingSession(
                "scan-thread",
                events,
                undefined,
                metadata,
              ),
            }
          : {
              "scan-thread": accountingSession("scan-thread", [
                accountingEvent({ input_tokens: 0, output_tokens: 0 }),
              ]),
              [accountingFork.threadId]: accountingSession(
                accountingFork.threadId,
                events,
                "scan-thread",
                {
                  ...metadata,
                  ...(copiedHistory ? {} : { forked_from_id: "scan-thread" }),
                },
              ),
            };
      const costs: number[] = [];
      await withMockAccountingSessions(
        sessions,
        {
          model: "gpt-5.6-terra",
          maxCostUsd: limit ?? 1,
          onCost: (cost) => costs.push(cost.estimatedUsd),
        },
        async (tracker) => {
          const final = await tracker.stop(undefined);
          expect(final.usage).toEqual(expected);
          expect(final.cost).toEqual(
            estimateScanCost("gpt-5.6-terra", expected),
          );
          expect(costs.at(-1)).toBe(final.cost!.estimatedUsd);
          if (limit !== undefined) {
            expect(final.cost!.estimatedUsd).toBeGreaterThan(limit);
          }
          expect(await tracker.stop()).toBe(final);
        },
      );
    }
  });

  test("keeps unstarted fork usage out of budget totals", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "keeps unstarted fork usage out of budget totals",
      )
    ) {
      return;
    }
    const rootUsage = { input_tokens: 100, output_tokens: 10 };
    const inherited = { input_tokens: 1_000, output_tokens: 1_000 };
    for (const maxCostUsd of [undefined, 0.01]) {
      const costs: number[] = [];
      await withMockAccountingSessions(
        {
          "scan-thread": accountingSession("scan-thread", [
            accountingEvent(rootUsage),
          ]),
          [accountingFork.threadId]: accountingSession(
            accountingFork.threadId,
            [
              accountingTaskStart(
                accountingFork.inheritedTurnId,
                accountingFork.startedAt,
              ),
              accountingEvent(inherited),
              accountingTaskStart(
                accountingFork.pendingTurnId,
                accountingFork.startedAt,
              ),
              accountingEvent(inherited),
            ],
            "scan-thread",
            {
              timestamp: accountingFork.timestamp,
              forked_from_id: "scan-thread",
            },
          ),
        },
        {
          model: "gpt-5.6-terra",
          maxCostUsd,
          onCost: (cost) => costs.push(cost.estimatedUsd),
        },
        async (tracker) => {
          expect((await tracker.refresh()).cost?.inputTokens).toBe(100);
          const final = tracker.stop(rootUsage);
          if (maxCostUsd === undefined) {
            await expect(final).resolves.toMatchObject({
              cost: { inputTokens: 100, outputTokens: 10 },
            });
          } else {
            await expect(final).rejects.toThrow(
              "The scan cost limit could not be verified",
            );
          }
          expect(costs.every((cost) => cost < 0.01)).toBe(true);
        },
      );
    }
  });

  test("counts ordinary UUID7 workers without a fork boundary", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "counts ordinary UUID7 workers without a fork boundary",
      )
    ) {
      return;
    }
    const rootUsage = { input_tokens: 100, output_tokens: 10 };
    await withMockAccountingSessions(
      {
        "scan-thread": accountingSession("scan-thread", [
          accountingEvent(rootUsage),
        ]),
        [accountingFork.threadId]: accountingSession(
          accountingFork.threadId,
          [accountingEvent({ input_tokens: 250, output_tokens: 25 })],
          "scan-thread",
          { timestamp: accountingFork.timestamp },
        ),
      },
      { model: "gpt-5.6-terra", maxCostUsd: 1 },
      async (tracker) => {
        await expect(tracker.stop(rootUsage)).resolves.toMatchObject({
          cost: { inputTokens: 350, outputTokens: 35 },
        });
      },
    );
  });

  test("keeps mocked session-detail replay separate from accounting", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "keeps mocked session-detail replay separate from accounting",
      )
    ) {
      return;
    }
    const initial = { input_tokens: 100, output_tokens: 10 };
    const later = { input_tokens: 150, output_tokens: 15 };
    const events: ScanSessionEvent[] = [];
    const costs: number[] = [];
    await withMockAccountingSessions(
      {
        "scan-thread": accountingSession("scan-thread", [
          accountingEvent(initial),
        ]),
      },
      {
        model: "gpt-5.6-terra",
        maxCostUsd: 1,
        onSessionEvent: (event) => events.push(event),
        onCost: (cost) => costs.push(cost.inputTokens),
      },
      async (tracker) => {
        expect((await tracker.stop(later)).cost?.inputTokens).toBe(150);
        expect(costs).toEqual([100, 150]);
        expect(events).toHaveLength(5);
        expect(
          events
            .map(({ event }) => event["payload"] as Record<string, unknown>)
            .filter((payload) => payload["type"] === "token_count")
            .map((payload) => payload["info"]),
        ).toEqual([
          { total_token_usage: initial },
          { total_token_usage: later },
        ]);
      },
      (_path, attempt, append) => {
        if (attempt === 2) {
          append("scan-thread", [
            accountingEvent(later),
            { type: "event_msg", payload: { type: "task_complete" } },
          ]);
        }
      },
    );

    for (const accountingFailed of [false, true]) {
      const costs: number[] = [];
      await withMockAccountingSessions(
        {
          "scan-thread": accountingSession("scan-thread", [
            ...(accountingFailed
              ? [new Error("Synthetic decoded record error")]
              : []),
            accountingEvent(initial),
          ]),
        },
        {
          model: "gpt-5.6-terra",
          maxCostUsd: 1,
          onSessionEvent: () => {},
          onCost: (cost) => costs.push(cost.inputTokens),
        },
        async (tracker) => {
          const refresh = tracker.refresh();
          if (accountingFailed) {
            await expect(refresh).rejects.toThrow(
              "tracked session record could not be read",
            );
            await expect(tracker.stop()).rejects.toThrow(
              "tracked session record could not be read",
            );
          } else {
            await expect(refresh).resolves.toMatchObject({
              cost: { inputTokens: 100 },
            });
            await expect(tracker.stop(initial)).resolves.toMatchObject({
              cost: { inputTokens: 100 },
            });
          }
          expect(costs).toEqual([100]);
        },
        (_path, attempt) => {
          if (attempt === 2) throw new Error("Synthetic detail replay failure");
        },
      );
    }
  });

  test("prefers completed root usage on mocked equal-price ties", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "prefers completed root usage on mocked equal-price ties",
      )
    ) {
      return;
    }
    const model = "gpt-5.6-terra";
    const observed = {
      input_tokens: 100,
      output_tokens: 1,
      reasoning_output_tokens: 1,
    };
    const completed = {
      input_tokens: 101,
      cached_input_tokens: 0,
      cache_write_input_tokens: 20,
      output_tokens: 0,
      reasoning_output_tokens: 0,
    };
    expect(estimateScanCost(model, observed)?.estimatedUsd).toBe(
      estimateScanCost(model, completed)?.estimatedUsd,
    );
    for (const withWorker of [false, true]) {
      const sessions: Record<string, MockAccountingEvent[]> = {
        "scan-thread": accountingSession("scan-thread", [
          accountingEvent(observed),
        ]),
      };
      if (withWorker) {
        sessions["worker-thread"] = accountingSession(
          "worker-thread",
          [
            accountingEvent({
              input_tokens: 20,
              output_tokens: 2,
              reasoning_output_tokens: 1,
            }),
          ],
          "scan-thread",
        );
      }
      const expected = {
        ...completed,
        input_tokens: withWorker ? 121 : 101,
        output_tokens: withWorker ? 2 : 0,
        reasoning_output_tokens: withWorker ? 1 : 0,
      };
      await withMockAccountingSessions(
        sessions,
        { model, maxCostUsd: 1 },
        async (tracker) => {
          const final = await tracker.stop(completed);
          expect(final.usage).toMatchObject(expected);
          expect(final.cost).toEqual(estimateScanCost(model, expected));
          expect(await tracker.stop()).toBe(final);
        },
      );
    }
  });

  test("recovers mocked root read failures only with verified workers", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "recovers mocked root read failures only with verified workers",
      )
    ) {
      return;
    }
    const rootUsage = { input_tokens: 100, output_tokens: 10 };
    const workerUsage = { input_tokens: 250, output_tokens: 20 };
    const completedRoot = { input_tokens: 1_000, output_tokens: 100 };
    for (const workerState of [
      "complete",
      "unreadable",
      "accounting-error",
      "missing",
      "unfinished",
      "missing-usage",
    ] as const) {
      let failReads = false;
      await withMockAccountingSessions(
        {
          "scan-thread": accountingSession("scan-thread", [
            accountingEvent(rootUsage),
          ]),
          "worker-thread": accountingSession(
            "worker-thread",
            workerState === "missing-usage"
              ? []
              : [accountingEvent(workerUsage)],
            "scan-thread",
          ),
        },
        { model: "gpt-5.6-terra", maxCostUsd: 1 },
        async (tracker, append, omit) => {
          await tracker.refresh();
          if (workerState === "accounting-error") {
            append("worker-thread", [
              new Error("Synthetic worker accounting error"),
              { type: "event_msg", payload: { type: "task_complete" } },
            ]);
          } else if (workerState === "missing") {
            omit("worker-thread");
          } else if (workerState === "unfinished") {
            append("worker-thread", [
              { type: "event_msg", payload: { type: "task_started" } },
            ]);
          }
          failReads = true;
          const final = tracker.stop(completedRoot);
          if (workerState === "complete") {
            await expect(final).resolves.toMatchObject({
              usage: { input_tokens: 1_250, output_tokens: 120 },
              cost: { inputTokens: 1_250, outputTokens: 120 },
            });
          } else {
            await expect(final).rejects.toThrow();
          }
        },
        (path) => {
          if (
            failReads &&
            (path.endsWith("rollout-scan-thread.jsonl") ||
              (workerState === "unreadable" &&
                path.endsWith("rollout-worker-thread.jsonl")))
          ) {
            throw new Error("Synthetic session read failure");
          }
        },
      );
    }
  });

  test("accumulates mocked owned reset epochs without double counting", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "accumulates mocked owned reset epochs without double counting",
      )
    ) {
      return;
    }
    const completed = { type: "event_msg", payload: { type: "task_complete" } };
    const initialRoot = { input_tokens: 100, output_tokens: 10 };
    const loggedRoot = { input_tokens: 280, output_tokens: 28 };
    const inherited = {
      input_tokens: 1_000,
      cached_input_tokens: 400,
      cache_write_input_tokens: 100,
      output_tokens: 100,
      reasoning_output_tokens: 20,
    };
    const latestWorker = {
      input_tokens: 140,
      cached_input_tokens: 30,
      cache_write_input_tokens: 15,
      output_tokens: 25,
      reasoning_output_tokens: 7,
    };
    const withWorkers = (root: typeof initialRoot) => ({
      input_tokens: root.input_tokens + 340,
      cached_input_tokens: 80,
      cache_write_input_tokens: 35,
      output_tokens: root.output_tokens + 65,
      reasoning_output_tokens: 17,
      total_tokens: root.input_tokens + root.output_tokens + 405,
    });
    for (const [authoritative, expectedRoot] of [
      [{ input_tokens: 200, output_tokens: 20 }, loggedRoot],
      [
        { input_tokens: 400, output_tokens: 40 },
        { input_tokens: 400, output_tokens: 40 },
      ],
    ] as const) {
      const costs: number[] = [];
      await withMockAccountingSessions(
        {
          "scan-thread": accountingSession("scan-thread", [
            accountingEvent(initialRoot),
          ]),
          "worker-thread": accountingSession(
            "worker-thread",
            [
              { type: "session_meta", payload: { id: "inherited-thread" } },
              accountingEvent(inherited),
              {
                type: "event_msg",
                payload: { type: "task_started", started_at: 1_785_067_320 },
              },
              accountingEvent({
                input_tokens: 1_200,
                cached_input_tokens: 450,
                cache_write_input_tokens: 120,
                output_tokens: 140,
                reasoning_output_tokens: 30,
              }),
            ],
            "scan-thread",
            { timestamp: "2026-07-26T12:02:00Z" },
          ),
        },
        {
          model: "gpt-5.6-terra",
          maxCostUsd: 1,
          onCost: (cost) => costs.push(cost.estimatedUsd),
        },
        async (tracker, append) => {
          const initial = await tracker.stop();
          expect(initial.usage).toMatchObject({
            input_tokens: 300,
            output_tokens: 50,
          });
          append("scan-thread", [
            accountingEvent({ input_tokens: 200, output_tokens: 20 }),
            accountingEvent({ input_tokens: 50, output_tokens: 5 }),
            accountingEvent({ input_tokens: 80, output_tokens: 8 }),
            accountingEvent({ input_tokens: 80, output_tokens: 8 }),
            completed,
          ]);
          append("worker-thread", [
            accountingEvent({
              input_tokens: 100,
              cached_input_tokens: 20,
              cache_write_input_tokens: 10,
              output_tokens: 20,
              reasoning_output_tokens: 5,
            }),
            accountingEvent(latestWorker),
            completed,
          ]);
          const current = await tracker.refresh();
          expect(current.usage).toEqual(withWorkers(loggedRoot));
          expect(await tracker.refresh()).toEqual(current);

          append("worker-thread", [accountingEvent(latestWorker)]);
          await expect(tracker.stop(authoritative)).rejects.toThrow(
            "The scan cost limit could not be verified",
          );
          append("worker-thread", [completed]);
          const final = await tracker.stop(authoritative);
          const expected = withWorkers(expectedRoot);
          expect(final.usage).toEqual(expected);
          expect(final.cost).toEqual(
            estimateScanCost("gpt-5.6-terra", expected),
          );
          expect(await tracker.stop()).toBe(final);
          expect(costs).toEqual([
            initial.cost!.estimatedUsd,
            current.cost!.estimatedUsd,
            ...(final.cost!.estimatedUsd === current.cost!.estimatedUsd
              ? []
              : [final.cost!.estimatedUsd]),
          ]);
        },
      );
    }
  });

  test("keeps mocked parse errors scoped to included budgeted sessions", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "keeps mocked parse errors scoped to included budgeted sessions",
      )
    ) {
      return;
    }
    const rootUsage = { input_tokens: 100, output_tokens: 10 };
    const workerUsage = { input_tokens: 200, output_tokens: 20 };
    for (const [
      failedSession,
      withWorker,
      maxCostUsd,
      authoritative,
      rejects,
    ] of [
      ["worker-thread", true, 1, true, true],
      ["scan-thread", true, 1, true, false],
      ["scan-thread", true, 1, false, true],
      ["unrelated-thread", true, 1, true, false],
      ["worker-thread", true, undefined, true, false],
      ["scan-thread", false, undefined, false, false],
      ["scan-thread", false, 1, true, false],
      ["scan-thread", false, 1, false, true],
    ] as const) {
      const sessions: Record<string, MockAccountingEvent[]> = {
        "scan-thread": accountingSession("scan-thread", [
          accountingEvent(rootUsage),
        ]),
        "unrelated-thread": accountingSession("unrelated-thread", [
          accountingEvent(workerUsage),
        ]),
      };
      if (withWorker) {
        sessions["worker-thread"] = accountingSession(
          "worker-thread",
          [accountingEvent(workerUsage)],
          "scan-thread",
        );
      }
      sessions[failedSession]!.unshift(
        new SyntaxError("mock parser diagnostic"),
      );
      const costs: number[] = [];
      await withMockAccountingSessions(
        sessions,
        {
          model: "gpt-5.6-terra",
          maxCostUsd,
          onCost: (cost) => costs.push(cost.estimatedUsd),
        },
        async (tracker) => {
          const refresh = tracker.refresh();
          if (
            maxCostUsd !== undefined &&
            failedSession !== "unrelated-thread"
          ) {
            await expect(refresh).rejects.toThrow(
              "tracked session record could not be read",
            );
          } else {
            await expect(refresh).resolves.toMatchObject({
              cost: { inputTokens: withWorker ? 300 : 100 },
            });
          }
          const completed = tracker.stop(authoritative ? rootUsage : undefined);
          if (rejects) {
            await expect(completed).rejects.toThrow(
              "tracked session record could not be read",
            );
          } else {
            await expect(completed).resolves.toMatchObject({
              cost: { inputTokens: withWorker ? 300 : 100 },
            });
          }
          expect(costs).toEqual([withWorker ? 0.00096 : 0.00032]);
        },
      );
    }
  });

  test("retains mocked per-session priced high-water snapshots", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "retains mocked per-session priced high-water snapshots",
      )
    ) {
      return;
    }
    type Usage = Record<string, number> & {
      input_tokens: number;
      output_tokens: number;
    };
    const reclassified: Usage[] = [
      { input_tokens: 100, cached_input_tokens: 100, output_tokens: 0 },
      { input_tokens: 100, cached_input_tokens: 0, output_tokens: 0 },
      { input_tokens: 90, cached_input_tokens: 0, output_tokens: 10 },
      { input_tokens: 100, cached_input_tokens: 0, output_tokens: 10 },
    ];
    const equalPrice: Usage[] = [
      { input_tokens: 100, output_tokens: 1 },
      {
        input_tokens: 101,
        cache_write_input_tokens: 20,
        output_tokens: 0,
      },
    ];
    const cases: Array<{
      model: string;
      samples: Usage[];
      expected: Usage;
      inherited?: Usage;
    }> = [
      {
        model: "gpt-5.6-terra",
        samples: [
          {
            input_tokens: 100,
            cached_input_tokens: 20,
            cache_write_input_tokens: 10,
            output_tokens: 50,
            reasoning_output_tokens: 10,
          },
          {
            input_tokens: 150,
            cached_input_tokens: 10,
            cache_write_input_tokens: 20,
            output_tokens: 30,
            reasoning_output_tokens: 5,
          },
        ],
        expected: {
          input_tokens: 150,
          cached_input_tokens: 30,
          cache_write_input_tokens: 20,
          output_tokens: 80,
          reasoning_output_tokens: 15,
        },
      },
      {
        model: "gpt-5.6-terra",
        samples: reclassified,
        expected: { input_tokens: 100, output_tokens: 10 },
      },
      {
        model: "unknown-model",
        samples: reclassified,
        expected: {
          input_tokens: 110,
          cached_input_tokens: 100,
          output_tokens: 0,
        },
      },
      {
        model: "gpt-5.6-terra",
        samples: equalPrice,
        expected: { input_tokens: 100, output_tokens: 1 },
      },
      {
        model: "unknown-model",
        samples: equalPrice,
        expected: { input_tokens: 100, output_tokens: 1 },
      },
      {
        model: "unknown-model",
        samples: [
          { input_tokens: Number.MAX_SAFE_INTEGER, output_tokens: 2 },
          { input_tokens: Number.MAX_SAFE_INTEGER, output_tokens: 1 },
        ],
        // The full reset would overflow input, so retain the last valid whole.
        expected: {
          input_tokens: Number.MAX_SAFE_INTEGER,
          output_tokens: 2,
        },
      },
      {
        model: "unknown-model",
        samples: [
          { input_tokens: Number.MAX_SAFE_INTEGER - 5, output_tokens: 0 },
          { input_tokens: 10, output_tokens: 0 },
          { input_tokens: 11, output_tokens: 0 },
        ],
        expected: {
          input_tokens: Number.MAX_SAFE_INTEGER - 4,
          output_tokens: 0,
        },
      },
      {
        model: "unknown-model",
        inherited: {
          input_tokens: Number.MAX_SAFE_INTEGER,
          cached_input_tokens: Number.MAX_SAFE_INTEGER,
          output_tokens: 0,
        },
        samples: [
          {
            input_tokens: Number.MAX_SAFE_INTEGER - 1,
            cached_input_tokens: Number.MAX_SAFE_INTEGER - 2,
            output_tokens: 0,
          },
          {
            input_tokens: Number.MAX_SAFE_INTEGER - 1,
            cached_input_tokens: 3,
            output_tokens: 1,
          },
          {
            input_tokens: Number.MAX_SAFE_INTEGER - 1,
            cached_input_tokens: 3,
            output_tokens: 2,
          },
        ],
        expected: {
          input_tokens: Number.MAX_SAFE_INTEGER - 1,
          cached_input_tokens: Number.MAX_SAFE_INTEGER - 2,
          output_tokens: 1,
        },
      },
    ];
    for (const { model, samples, expected, inherited } of cases) {
      const events: MockAccountingEvent[] = [
        ...(inherited === undefined
          ? []
          : [
              {
                type: "session_meta",
                payload: { id: "inherited-thread" },
              },
              accountingEvent(inherited),
              {
                type: "event_msg",
                payload: { type: "task_started", started_at: 1_785_067_320 },
              },
            ]),
        ...samples.map(accountingEvent),
      ];
      await withMockAccountingSessions(
        {
          "scan-thread": accountingSession("scan-thread", events, undefined, {
            timestamp: "2026-07-26T12:02:00Z",
          }),
        },
        {
          model,
          ...(model === "unknown-model" ? {} : { maxCostUsd: 1 }),
        },
        async (tracker) => {
          const final = await tracker.stop(undefined);
          expect(final.usage).toEqual({
            cached_input_tokens: 0,
            cache_write_input_tokens: 0,
            reasoning_output_tokens: 0,
            ...expected,
            total_tokens: expected.input_tokens + expected.output_tokens,
          });
          expect(final.cost).toEqual(estimateScanCost(model, expected));
          expect(await tracker.stop()).toBe(final);
        },
      );
    }
  });

  test("keeps mocked unverified evidence separate from known cost floors", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "keeps mocked unverified evidence separate from known cost floors",
      )
    ) {
      return;
    }
    const rootUsage = { input_tokens: 100, output_tokens: 10 };
    const unpriceable = accountingEvent({
      input_tokens: Number.MAX_SAFE_INTEGER,
      output_tokens: 0,
    });
    for (const [evidence, expectedInput, expectedCost] of [
      [new SyntaxError("mock parser diagnostic"), 1_200, 0.00384],
      [unpriceable, 1_100, 0.00352],
    ] as const) {
      const reports: Array<number | "error"> = [];
      await withMockAccountingSessions(
        {
          "scan-thread": accountingSession("scan-thread", [
            accountingEvent(rootUsage),
          ]),
          "worker-thread": accountingSession(
            "worker-thread",
            [
              accountingEvent({ input_tokens: 1_000, output_tokens: 100 }),
              evidence,
              accountingEvent(rootUsage),
            ],
            "scan-thread",
          ),
        },
        {
          model: "gpt-5.6-terra",
          maxCostUsd: 0.001,
          onCost: (cost) => reports.push(cost.estimatedUsd),
          onError: () => reports.push("error"),
        },
        async (tracker) => {
          await expect(tracker.stop(rootUsage)).rejects.toThrow(
            "The scan cost limit could not be verified",
          );
          expect((await tracker.stop()).cost).toMatchObject({
            inputTokens: expectedInput,
            outputTokens: expectedInput / 10,
            estimatedUsd: expectedCost,
          });
          expect(reports[0]).toBe(expectedCost);
          expect(reports).toContain("error");
        },
      );
    }
    await withMockAccountingSessions(
      {
        "scan-thread": accountingSession("scan-thread", [
          accountingEvent(rootUsage),
          unpriceable,
        ]),
      },
      { model: "gpt-5.6-terra", maxCostUsd: 1 },
      async (tracker) => {
        expect(
          (await tracker.stop({ input_tokens: 1_000, output_tokens: 100 })).cost
            ?.estimatedUsd,
        ).toBe(0.0032);
      },
    );
    await withMockAccountingSessions(
      {
        "scan-thread": accountingSession("scan-thread", [
          accountingEvent(rootUsage),
          accountingEvent({ input_tokens: 200, output_tokens: 20 }),
        ]),
      },
      { model: "unknown-model" },
      async (tracker) => {
        expect(await tracker.stop(undefined)).toMatchObject({
          usage: { input_tokens: 200, output_tokens: 20 },
          cost: null,
        });
      },
    );
  });

  test("keeps mocked unusable own usage scoped to accounting", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "keeps mocked unusable own usage scoped to accounting",
      )
    ) {
      return;
    }
    const rootUsage = { input_tokens: 100, output_tokens: 10 };
    const inherited = { input_tokens: 1_000, output_tokens: 100 };
    const high = accountingEvent({ input_tokens: 2_000, output_tokens: 200 });
    const low = accountingEvent({ input_tokens: 1_100, output_tokens: 110 });
    const metadata = { timestamp: "2026-07-26T12:02:00Z" };
    const history = [
      { type: "session_meta", payload: { id: "inherited-thread" } },
      accountingEvent(inherited),
    ];
    const started = {
      type: "event_msg",
      payload: { type: "task_started", started_at: 1_785_067_320 },
    };
    const infoOnly = {
      type: "event_msg",
      payload: { type: "token_count", info: null },
    };
    for (const [unavailable, invalid] of [
      [accountingEvent(null), true],
      [accountingEvent({ input_tokens: 900, output_tokens: 90 }), false],
    ] as const) {
      for (const [scope, maxCostUsd] of [
        ["worker", 0.001],
        ["first-error", 0.001],
        ["worker", undefined],
        ["unrelated", 1],
        ["root", 1],
        ["replay", 1],
      ] as const) {
        const rejects =
          scope === "first-error" ||
          (scope === "worker" && maxCostUsd !== undefined && invalid);
        const expectedInput =
          scope === "unrelated" ? 100 : scope === "root" ? 2_100 : 2_200;
        const events =
          scope === "replay"
            ? [
                ...history,
                unavailable,
                accountingEvent(inherited),
                started,
                high,
                infoOnly,
                low,
              ]
            : [
                ...history,
                started,
                high,
                ...(scope === "first-error"
                  ? [new SyntaxError("mock existing accounting diagnostic")]
                  : []),
                unavailable,
                low,
              ];
        const sessions: Readonly<
          Record<string, readonly MockAccountingEvent[]>
        > =
          scope === "root"
            ? {
                "scan-thread": accountingSession(
                  "scan-thread",
                  events,
                  undefined,
                  metadata,
                ),
              }
            : {
                "scan-thread": accountingSession("scan-thread", [
                  accountingEvent(rootUsage),
                ]),
                "worker-thread": accountingSession(
                  "worker-thread",
                  events,
                  scope === "unrelated" ? undefined : "scan-thread",
                  metadata,
                ),
              };
        const costs: number[] = [];
        await withMockAccountingSessions(
          sessions,
          {
            model: "gpt-5.6-terra",
            maxCostUsd,
            onCost: (cost) => costs.push(cost.estimatedUsd),
          },
          async (tracker) => {
            const completed = tracker.stop(
              scope === "root"
                ? { input_tokens: 1_200, output_tokens: 120 }
                : rootUsage,
            );
            if (rejects) {
              await expect(completed).rejects.toThrow(
                scope === "first-error"
                  ? "tracked session record could not be read"
                  : "model pricing or token usage is unavailable",
              );
              expect((await tracker.stop()).cost).toMatchObject({
                inputTokens: 2_200,
                outputTokens: 220,
                estimatedUsd: 0.00704,
              });
              expect(costs[0]).toBe(0.00704);
            } else {
              expect((await completed).cost).toMatchObject({
                inputTokens: expectedInput,
                outputTokens: expectedInput / 10,
              });
            }
          },
        );
      }
    }
  });

  test("keeps mocked invalid accumulated usage fail closed", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "keeps mocked invalid accumulated usage fail closed",
      )
    ) {
      return;
    }
    const rootUsage = { input_tokens: 100, output_tokens: 10 };
    const inherited = {
      input_tokens: 1_000,
      cached_input_tokens: 800,
      output_tokens: 0,
    };
    for (const [middle, latest, expectedInput] of [
      [
        accountingEvent(null),
        { input_tokens: 120, cached_input_tokens: 80, output_tokens: 0 },
        120,
      ],
      [
        accountingEvent({
          input_tokens: 110,
          cached_input_tokens: 50,
          output_tokens: 0,
        }),
        { input_tokens: 160, cached_input_tokens: 50, output_tokens: 0 },
        150,
      ],
    ] as const) {
      for (const [scope, maxCostUsd] of [
        ["worker", 0.0001],
        ["worker", undefined],
        ["unrelated", 1],
        ["root", 1],
      ] as const) {
        const events: MockAccountingEvent[] = [
          { type: "session_meta", payload: { id: "inherited-thread" } },
          accountingEvent(inherited),
          {
            type: "event_msg",
            payload: { type: "task_started", started_at: 1_785_067_320 },
          },
          accountingEvent({
            input_tokens: 100,
            cached_input_tokens: 80,
            output_tokens: 0,
          }),
          middle,
          accountingEvent(latest),
        ];
        const metadata = { timestamp: "2026-07-26T12:02:00Z" };
        const sessions: Record<string, MockAccountingEvent[]> =
          scope === "root"
            ? {
                "scan-thread": accountingSession(
                  "scan-thread",
                  events,
                  undefined,
                  metadata,
                ),
              }
            : {
                "scan-thread": accountingSession("scan-thread", [
                  accountingEvent(rootUsage),
                ]),
                "worker-thread": accountingSession(
                  "worker-thread",
                  events,
                  scope === "unrelated" ? undefined : "scan-thread",
                  metadata,
                ),
              };
        const authoritative =
          scope === "root"
            ? { input_tokens: 200, output_tokens: 20 }
            : rootUsage;
        const expected =
          scope === "root" || scope === "unrelated"
            ? authoritative
            : {
                input_tokens: expectedInput + rootUsage.input_tokens,
                cached_input_tokens: 80,
                output_tokens: rootUsage.output_tokens,
              };
        const expectedCost = estimateScanCost("gpt-5.6-terra", expected);
        const reports: number[] = [];
        await withMockAccountingSessions(
          sessions,
          {
            model: "gpt-5.6-terra",
            maxCostUsd,
            onCost: (cost) => reports.push(cost.estimatedUsd),
          },
          async (tracker) => {
            const final = tracker.stop(authoritative);
            if (scope === "worker" && maxCostUsd !== undefined) {
              await expect(final).rejects.toThrow(
                "model pricing or token usage is unavailable",
              );
              expect((await tracker.stop()).cost).toEqual(expectedCost);
              expect(reports[0]).toBe(expectedCost!.estimatedUsd);
              await expect(tracker.stop(authoritative)).rejects.toThrow(
                "model pricing or token usage is unavailable",
              );
            } else {
              await expect(final).resolves.toMatchObject({
                usage: expected,
                cost: expectedCost,
              });
            }
          },
        );
      }
    }
  });

  test("reports mocked readable costs before rejecting missing sessions", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "reports mocked readable costs before rejecting missing sessions",
      )
    ) {
      return;
    }
    const rootUsage = { input_tokens: 100, output_tokens: 10 };
    const freshUsage = { input_tokens: 1_000, output_tokens: 100 };
    const finalCost = {
      inputTokens: 1_200,
      outputTokens: 120,
      estimatedUsd: 0.00384,
    };
    const missingMessage =
      "A tracked scan session disappeared before its cost could be verified.";
    for (const [missingSession, maxCostUsd, rejects] of [
      ["scan-thread", 0.001, true],
      ["retained-worker", 0.001, true],
      ["unrelated-thread", 1, false],
      ["retained-worker", undefined, false],
    ] as const) {
      const reports: Array<number | "rejected"> = [];
      await withMockAccountingSessions(
        {
          "scan-thread": accountingSession("scan-thread", [
            accountingEvent(rootUsage),
          ]),
          "retained-worker": accountingSession(
            "retained-worker",
            [accountingEvent(rootUsage)],
            "scan-thread",
          ),
          "growing-worker": accountingSession(
            "growing-worker",
            [accountingEvent(rootUsage)],
            "scan-thread",
          ),
          "unrelated-thread": accountingSession("unrelated-thread", [
            accountingEvent(freshUsage),
          ]),
        },
        {
          model: "gpt-5.6-terra",
          maxCostUsd,
          onCost: (cost) => reports.push(cost.estimatedUsd),
        },
        async (tracker, append, omit) => {
          expect((await tracker.stop()).cost?.estimatedUsd).toBe(0.00096);
          omit(missingSession);
          append("growing-worker", [
            accountingEvent(freshUsage),
            { type: "event_msg", payload: { type: "task_complete" } },
          ]);
          const refreshed = tracker.refresh();
          if (rejects) {
            await expect(
              refreshed.catch((error: unknown) => {
                reports.push("rejected");
                throw error;
              }),
            ).rejects.toThrow(missingMessage);
            expect(reports).toEqual([0.00096, 0.00384, "rejected"]);
            const cleanup = await tracker.stop();
            expect(cleanup.cost).toMatchObject(finalCost);
            await expect(tracker.stop(rootUsage)).rejects.toThrow(
              missingMessage,
            );
            expect(await tracker.stop()).toEqual(cleanup);
          } else {
            await expect(refreshed).resolves.toMatchObject({ cost: finalCost });
            await expect(tracker.stop(rootUsage)).resolves.toMatchObject({
              cost: finalCost,
            });
            expect(reports).toEqual([0.00096, 0.00384]);
          }
        },
      );
    }
    await withMockAccountingSessions(
      {
        "scan-thread": accountingSession("scan-thread", [
          accountingEvent(rootUsage),
        ]),
      },
      { model: "gpt-5.6-terra", maxCostUsd: 1 },
      async (tracker, _append, omit) => {
        expect((await tracker.stop()).cost?.estimatedUsd).toBe(0.00032);
        omit("scan-thread");
        await expect(tracker.stop(rootUsage)).rejects.toThrow(missingMessage);
      },
    );
  });

  test("prefers mocked completed usage when prices are unavailable", async () => {
    if (
      runMockInSubprocess(
        import.meta.path,
        "prefers mocked completed usage when prices are unavailable",
      )
    ) {
      return;
    }
    const observedRoot = { input_tokens: 100, output_tokens: 10 };
    const workerUsage = { input_tokens: 200, output_tokens: 20 };
    const completedRoot = { input_tokens: 1_000, output_tokens: 100 };
    const equalTotalRoot = { input_tokens: 900, output_tokens: 200 };
    const boundaryObserved = {
      input_tokens: Number.MAX_SAFE_INTEGER,
      output_tokens: 2,
    };
    const boundaryCompleted = { ...boundaryObserved, output_tokens: 1 };
    expect(boundaryObserved.input_tokens + boundaryObserved.output_tokens).toBe(
      boundaryCompleted.input_tokens + boundaryCompleted.output_tokens,
    );
    for (const [observed, completed, expected, withWorker, refreshFails] of [
      [observedRoot, completedRoot, completedRoot, false, true],
      [observedRoot, completedRoot, completedRoot, true, true],
      [observedRoot, completedRoot, completedRoot, true, false],
      [completedRoot, observedRoot, completedRoot, false, true],
      [completedRoot, observedRoot, completedRoot, true, true],
      [completedRoot, equalTotalRoot, equalTotalRoot, false, true],
      [completedRoot, equalTotalRoot, equalTotalRoot, true, true],
      [boundaryObserved, boundaryCompleted, boundaryObserved, false, true],
    ] as const) {
      const sessions: Record<string, MockAccountingEvent[]> = {
        "scan-thread": accountingSession("scan-thread", [
          accountingEvent(observed),
        ]),
      };
      if (withWorker) {
        sessions["worker-thread"] = accountingSession(
          "worker-thread",
          [accountingEvent(workerUsage)],
          "scan-thread",
        );
      }
      const reportedErrors: unknown[] = [];
      const reportedCosts: number[] = [];
      const refreshError = new Error("Mock final accounting refresh failed.");
      await withMockAccountingSessions(
        sessions,
        {
          model: "unknown-model",
          onCost: (cost) => reportedCosts.push(cost.estimatedUsd),
          onError: (error) => reportedErrors.push(error),
        },
        async (tracker) => {
          expect((await tracker.stop()).usage).toMatchObject({
            input_tokens:
              observed.input_tokens +
              (withWorker ? workerUsage.input_tokens : 0),
            output_tokens:
              observed.output_tokens +
              (withWorker ? workerUsage.output_tokens : 0),
          });
          const refresh = refreshFails
            ? spyOn(tracker, "refresh").mockRejectedValue(refreshError)
            : null;
          try {
            const final = await tracker.stop(completed);
            expect(final).toMatchObject({
              usage: {
                input_tokens:
                  expected.input_tokens +
                  (withWorker ? workerUsage.input_tokens : 0),
                output_tokens:
                  expected.output_tokens +
                  (withWorker ? workerUsage.output_tokens : 0),
              },
              cost: null,
            });
            if (!withWorker && expected === completed) {
              expect(final.usage).toBe(completed);
            }
            expect(await tracker.stop()).toBe(final);
            expect(reportedErrors).toEqual(refreshFails ? [refreshError] : []);
            expect(reportedCosts).toEqual([]);
          } finally {
            refresh?.mockRestore();
          }
        },
      );
    }
    const unpriceable = {
      input_tokens: Number.MAX_SAFE_INTEGER,
      output_tokens: 0,
    };
    for (const [replacement, maxCostUsd, rejects] of [
      [observedRoot, undefined, false],
      [unpriceable, undefined, false],
      [unpriceable, 1, true],
    ] as const) {
      const costs: number[] = [];
      await withMockAccountingSessions(
        {
          "scan-thread": accountingSession("scan-thread", [
            accountingEvent(completedRoot),
          ]),
        },
        {
          model: "gpt-5.6-terra",
          maxCostUsd,
          onCost: (cost) => costs.push(cost.estimatedUsd),
        },
        async (tracker) => {
          const prior = await tracker.stop();
          expect(prior.cost?.estimatedUsd).toBe(0.0032);
          const completed = tracker.stop(replacement);
          if (rejects) {
            await expect(completed).rejects.toThrow(
              "The scan cost limit could not be verified",
            );
          } else {
            await expect(completed).resolves.toEqual(prior);
          }
          expect(costs).toEqual([0.0032]);
        },
      );
    }
    await withMockAccountingSessions(
      {
        "scan-thread": accountingSession("scan-thread", []),
        "worker-thread": accountingSession(
          "worker-thread",
          [accountingEvent(workerUsage)],
          "scan-thread",
        ),
      },
      { model: "unknown-model" },
      async (tracker, append) => {
        const prior = await tracker.stop();
        expect(prior).toMatchObject({ usage: workerUsage, cost: null });
        append(
          "conflicting-worker",
          accountingSession("worker-thread", [], "another-thread"),
        );
        await tracker.refresh();
        expect(await tracker.stop({})).toBe(prior);
      },
    );
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

  testPosix(
    "quarantines unreadable unrelated sessions after one failure",
    async () => {
      const home = await codexHome();
      const unreadable = await writeSession(home, "unrelated-thread", {
        input_tokens: 99,
        output_tokens: 1,
      });
      await writeSession(home, "scan-thread", {
        input_tokens: 100,
        output_tokens: 10,
      });
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-terra",
      });
      tracker.start("scan-thread");
      await chmod(unreadable, 0o000);

      try {
        await expect(tracker.refresh()).rejects.toThrow();
        expect((await tracker.refresh()).cost?.inputTokens).toBe(100);
        expect((await tracker.stop()).cost?.inputTokens).toBe(100);
      } finally {
        await chmod(unreadable, 0o600);
      }
    },
  );

  testPosix(
    "keeps budgeted worker sessions fail-closed after they become unreadable",
    async () => {
      const { worker, tracker } = await workerScan({
        workerUsage: { input_tokens: 250, output_tokens: 20 },
        maxCostUsd: 1,
      });
      expect((await tracker.refresh()).cost?.inputTokens).toBe(350);
      await chmod(worker, 0o000);

      try {
        await expect(tracker.refresh()).rejects.toThrow();
        await expect(tracker.refresh()).rejects.toThrow();
        await expect(
          tracker.stop({ input_tokens: 100, output_tokens: 10 }),
        ).rejects.toThrow();
      } finally {
        await chmod(worker, 0o600);
      }
    },
  );

  testPosix(
    "combines verified workers with completed usage after a root read failure",
    async () => {
      const { root, tracker } = await workerScan({
        workerUsage: { input_tokens: 250, output_tokens: 20 },
        maxCostUsd: 1,
      });
      expect((await tracker.refresh()).cost?.inputTokens).toBe(350);
      await chmod(root, 0o000);

      try {
        await expect(
          tracker.stop({ input_tokens: 1_000, output_tokens: 100 }),
        ).resolves.toMatchObject({
          usage: { input_tokens: 1_250, output_tokens: 120 },
          cost: { inputTokens: 1_250, outputTokens: 120 },
        });
      } finally {
        await chmod(root, 0o600);
      }
    },
  );

  testPosix.each(["parented", "independent"] as const)(
    "rejects budget fallback for a newly discovered %s worker during a failed refresh",
    async (workerKind) => {
      const home = await codexHome();
      const scanDirectory = join(home, "scan");
      const active = await writeSession(home, "scan-thread", {
        input_tokens: 100,
        output_tokens: 10,
      });
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-terra",
        scanDirectory,
        maxCostUsd: 0.001,
      });
      tracker.start("scan-thread");
      await tracker.refresh();
      await writeSession(
        home,
        "worker-thread",
        { input_tokens: 10_000, output_tokens: 1_000 },
        workerKind === "parented" ? "scan-thread" : undefined,
        workerKind === "independent"
          ? join(scanDirectory, "artifacts")
          : undefined,
        "2026-07-26T12:01:00Z",
      );
      await chmod(active, 0o000);

      try {
        await expect(
          tracker.stop({ input_tokens: 100, output_tokens: 10 }),
        ).rejects.toThrow();
      } finally {
        await chmod(active, 0o600);
      }
    },
  );

  testPosix(
    "rejects budget fallback when an unreadable session cannot be attributed",
    async () => {
      const home = await codexHome();
      const unreadable = await writeSession(home, "unidentified-thread", {
        input_tokens: 100,
        output_tokens: 10,
      });
      await chmod(unreadable, 0o000);
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-terra",
        maxCostUsd: 1,
      });
      tracker.start("scan-thread");

      try {
        await expect(
          tracker.stop({ input_tokens: 1_000, output_tokens: 100 }),
        ).rejects.toThrow();
      } finally {
        await chmod(unreadable, 0o600);
      }
    },
  );

  test.each(["scan-thread", "worker-thread"] as const)(
    "rejects a budgeted scan when its tracked %s session disappears",
    async (missingThread) => {
      const { root, worker, tracker } = await workerScan({ maxCostUsd: 1 });
      await tracker.refresh();
      await rm(missingThread === "scan-thread" ? root : worker);

      await expect(
        tracker.stop({ input_tokens: 1_000, output_tokens: 100 }),
      ).rejects.toThrow(
        "A tracked scan session disappeared before its cost could be verified.",
      );
    },
  );

  test("ignores unrelated disappearing sessions when enforcing a budget", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const unrelated = await writeSession(home, "unrelated-thread", {
      input_tokens: 1_000,
      output_tokens: 100,
    });
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
      maxCostUsd: 1,
    });
    tracker.start("scan-thread");
    await tracker.refresh();
    await rm(unrelated);

    expect((await tracker.stop()).cost?.inputTokens).toBe(100);
  });

  test("preserves known usage when an optional worker session disappears", async () => {
    const { worker, tracker } = await workerScan();
    await tracker.refresh();
    await rm(worker);

    expect(
      (await tracker.stop({ input_tokens: 1_000, output_tokens: 100 })).cost,
    ).toMatchObject({ inputTokens: 1_100, outputTokens: 110 });
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

  test.each([
    ["missing", undefined],
    ["null", null],
    ["malformed", {}],
  ] as const)(
    "rejects a budgeted scan when completed-turn usage is %s",
    async (_description, usage) => {
      const tracker = new ScanCostTracker({
        codexHome: await codexHome(),
        model: "gpt-5.6-terra",
        maxCostUsd: 1,
      });
      tracker.start("scan-thread");

      await expect(tracker.stop(usage)).rejects.toThrow(
        "The scan cost limit could not be verified because model pricing or token usage is unavailable.",
      );
    },
  );

  test.each([
    ["missing", undefined],
    ["null", null],
    ["malformed", {}],
  ] as const)(
    "requires completed root-session evidence when final usage is %s",
    async (_description, usage) => {
      const home = await codexHome();
      const root = await writeSession(home, "scan-thread", {
        input_tokens: 100,
        output_tokens: 10,
      });
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-terra",
        maxCostUsd: 1,
      });
      tracker.start("scan-thread");
      expect((await tracker.refresh()).cost?.inputTokens).toBe(100);

      await expect(tracker.stop(usage)).rejects.toThrow(
        "The scan cost limit could not be verified",
      );
      await appendFile(root, `${taskEvent("task_complete")}\n`);
      expect((await tracker.stop(usage)).cost).toMatchObject({
        inputTokens: 100,
        outputTokens: 10,
      });
    },
  );

  test("rejects a budgeted scan when the completed model cannot be priced", async () => {
    const tracker = new ScanCostTracker({
      codexHome: await codexHome(),
      model: "unknown-model",
      maxCostUsd: 1,
    });
    tracker.start("scan-thread");

    await expect(
      tracker.stop({ input_tokens: 1_000, output_tokens: 100 }),
    ).rejects.toThrow(
      "The scan cost limit could not be verified because model pricing or token usage is unavailable.",
    );
  });

  test("allows unavailable completed-turn usage without an explicit budget", async () => {
    const tracker = new ScanCostTracker({
      codexHome: await codexHome(),
      model: "gpt-5.6-terra",
    });
    tracker.start("scan-thread");

    await expect(tracker.stop(null)).resolves.toEqual({
      usage: null,
      cost: null,
    });
  });

  test("preserves unfinished root usage when tracking is optional", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
    });
    tracker.start("scan-thread");

    expect((await tracker.stop(undefined)).cost).toMatchObject({
      inputTokens: 100,
      outputTokens: 10,
    });
  });

  test.each([
    ["missing", undefined],
    ["malformed", {}],
  ] as const)(
    "rejects worker-only usage when the budgeted root completion is %s",
    async (_description, completedRoot) => {
      const { tracker } = await workerScan({
        rootUsage: null,
        maxCostUsd: 1,
      });
      expect((await tracker.refresh()).cost?.inputTokens).toBe(100);

      await expect(tracker.stop(completedRoot)).rejects.toThrow(
        "The scan cost limit could not be verified because model pricing or token usage is unavailable.",
      );
    },
  );

  test.each([
    ["rejects", 1],
    ["allows", undefined],
  ] as const)(
    "%s incomplete delegated-worker usage according to the explicit budget",
    async (_result, maxCostUsd) => {
      const { tracker } = await workerScan({ workerUsage: null, maxCostUsd });
      expect((await tracker.refresh()).cost?.inputTokens).toBe(100);

      const completed = tracker.stop({
        input_tokens: 1_000,
        output_tokens: 100,
      });
      if (maxCostUsd === undefined) {
        await expect(completed).resolves.toMatchObject({
          cost: { inputTokens: 1_000, outputTokens: 100 },
        });
      } else {
        await expect(completed).rejects.toThrow(
          "The scan cost limit could not be verified because model pricing or token usage is unavailable.",
        );
      }
    },
  );

  test.each([
    ["still-running worker", "running", 1, true],
    ["completed worker", "task_complete", 1, false],
    ["compatible completed worker", "turn_complete", 1, false],
    ["canceled worker", "turn_aborted", 1, false],
    ["worker restarted after completion", "task_started", 1, true],
    ["optional still-running worker", "running", undefined, false],
  ] as const)(
    "verifies final delegated-worker completion for a %s",
    async (_scenario, state, maxCostUsd, shouldReject) => {
      const { worker, tracker } = await workerScan({
        workerCompleted: false,
        maxCostUsd,
      });
      expect((await tracker.refresh()).cost?.inputTokens).toBe(200);
      if (state !== "running") {
        if (state === "task_started") {
          await appendFile(worker, `${taskEvent("task_complete")}\n`);
        }
        await appendFile(worker, `${taskEvent(state)}\n`);
      }
      expect((await tracker.refresh()).cost?.inputTokens).toBe(200);

      const completed = tracker.stop({ input_tokens: 100, output_tokens: 10 });
      if (shouldReject) {
        await expect(completed).rejects.toThrow(
          "The scan cost limit could not be verified",
        );
      } else {
        await expect(completed).resolves.toMatchObject({
          cost: { inputTokens: 200, outputTokens: 20 },
        });
      }
    },
  );

  test("preserves observed active-worker costs during budget failure cleanup", async () => {
    const { tracker } = await workerScan({
      workerCompleted: false,
      maxCostUsd: 1,
    });
    expect((await tracker.refresh()).cost?.inputTokens).toBe(200);

    expect((await tracker.stop()).cost).toMatchObject({
      inputTokens: 200,
      outputTokens: 20,
    });
  });

  test.each([
    ["null", null],
    ["undefined", undefined],
  ] as const)(
    "rejects an active worker when completed-turn usage is %s",
    async (_description, usage) => {
      const { tracker } = await workerScan({
        workerCompleted: false,
        maxCostUsd: 1,
      });
      expect((await tracker.refresh()).cost?.inputTokens).toBe(200);

      await expect(tracker.stop(usage)).rejects.toThrow(
        "The scan cost limit could not be verified",
      );
    },
  );

  test.each([
    ["budgeted root", "root", 0.001, true],
    ["budgeted delegated worker", "worker", 0.001, true],
    ["budgeted unrelated session", "unrelated", 0.001, false],
    ["unbudgeted delegated worker", "worker", undefined, false],
  ] as const)(
    "handles an incomplete final event from a %s",
    async (_description, session, maxCostUsd, shouldReject) => {
      const { home, root, worker, tracker } = await workerScan({ maxCostUsd });
      expect((await tracker.refresh()).cost?.inputTokens).toBe(200);
      const path =
        session === "root"
          ? root
          : session === "worker"
            ? worker
            : await writeSession(home, "unrelated-thread", {
                input_tokens: 100,
                output_tokens: 10,
              });
      await appendIncompleteTokenUsage(path);
      expect((await tracker.refresh()).cost?.inputTokens).toBe(200);

      const completed = tracker.stop({ input_tokens: 100, output_tokens: 10 });
      if (shouldReject) {
        await expect(completed).rejects.toThrow(
          "The scan cost limit could not be verified because model pricing or token usage is unavailable.",
        );
      } else {
        await expect(completed).resolves.toMatchObject({
          cost: { inputTokens: 200, outputTokens: 20 },
        });
      }
    },
  );

  test("rejects an incomplete final root event without delegated workers", async () => {
    const home = await codexHome();
    const root = await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
      maxCostUsd: 0.001,
    });
    tracker.start("scan-thread");
    await appendIncompleteTokenUsage(root);
    expect((await tracker.refresh()).cost?.inputTokens).toBe(100);

    await expect(
      tracker.stop({ input_tokens: 100, output_tokens: 10 }),
    ).rejects.toThrow("The scan cost limit could not be verified");
  });

  test("keeps final budget enforcement stable when cleanup stops tracking twice", async () => {
    const budget = 0.001;
    const exceeded = new AbortController();
    const reportedCosts: number[] = [];
    const { tracker } = await workerScan({
      maxCostUsd: budget,
      onCost: (cost) => {
        reportedCosts.push(cost.estimatedUsd);
        if (cost.estimatedUsd > budget) exceeded.abort();
      },
    });
    expect((await tracker.refresh()).cost?.inputTokens).toBe(200);

    expect(
      (await tracker.stop({ input_tokens: 1_000, output_tokens: 100 })).cost,
    ).toMatchObject({ inputTokens: 1_100, outputTokens: 110 });
    expect((await tracker.stop()).cost).toMatchObject({
      inputTokens: 1_100,
      outputTokens: 110,
    });
    expect(reportedCosts).toEqual([0.00064, 0.00352]);
    expect(exceeded.signal.aborted).toBe(true);
  });

  test.each(["incomplete", "unfinished", "unreadable"] as const)(
    "preserves a definitive overage when final worker evidence is %s",
    async (evidence) => {
      const reportedCosts: number[] = [];
      const { worker, tracker } = await workerScan({
        workerCompleted: evidence !== "unfinished",
        maxCostUsd: 0.001,
        onCost: (cost) => reportedCosts.push(cost.estimatedUsd),
      });
      const refresh = tracker.refresh.bind(tracker);
      expect((await tracker.refresh()).cost?.inputTokens).toBe(200);
      if (evidence === "incomplete") {
        await appendIncompleteTokenUsage(worker);
      } else if (evidence === "unreadable") {
        tracker.refresh = async () => {
          throw new Error("session read failed");
        };
      }

      await expect(
        tracker.stop({ input_tokens: 1_000, output_tokens: 100 }),
      ).rejects.toThrow(
        evidence === "unreadable"
          ? "session read failed"
          : "The scan cost limit could not be verified",
      );
      expect(reportedCosts).toEqual([0.00064, 0.00352]);
      expect((await tracker.stop()).cost).toMatchObject({
        inputTokens: 1_100,
        outputTokens: 110,
        estimatedUsd: 0.00352,
      });
      tracker.refresh = refresh;
      if (evidence !== "incomplete") {
        await appendIncompleteTokenUsage(worker);
      }
      await appendFile(worker, `}\n${taskEvent("task_complete")}\n`);
      expect((await tracker.stop()).cost).toMatchObject({
        inputTokens: 11_000,
        outputTokens: 1_100,
        estimatedUsd: 0.0352,
      });
      expect(reportedCosts.at(-1)).toBe(0.0352);
    },
  );

  test("returns a definitive overage first discovered during failure cleanup", async () => {
    const { worker, tracker } = await workerScan({
      rootUsage: { input_tokens: 1_000, output_tokens: 100 },
      maxCostUsd: 0.001,
    });
    await appendIncompleteTokenUsage(worker);

    expect((await tracker.stop()).cost).toMatchObject({
      inputTokens: 1_100,
      outputTokens: 110,
      estimatedUsd: 0.00352,
    });
  });

  test("preserves higher observed root usage when completed-turn usage is stale", async () => {
    const { tracker } = await workerScan({
      rootUsage: { input_tokens: 1_000, output_tokens: 100 },
      maxCostUsd: 1,
    });

    expect(
      (await tracker.stop({ input_tokens: 100, output_tokens: 10 })).cost,
    ).toMatchObject({ inputTokens: 1_100, outputTokens: 110 });
  });

  test("combines worker-only observations with a valid completed root", async () => {
    const budget = 0.001;
    const exceeded = new AbortController();
    const { tracker } = await workerScan({
      rootUsage: null,
      maxCostUsd: budget,
      onCost: (cost) => {
        if (cost.estimatedUsd > budget) exceeded.abort();
      },
    });
    expect((await tracker.refresh()).cost?.inputTokens).toBe(100);

    expect(
      (await tracker.stop({ input_tokens: 1_000, output_tokens: 100 })).cost,
    ).toMatchObject({ inputTokens: 1_100, outputTokens: 110 });
    expect(exceeded.signal.aborted).toBe(true);
  });

  test("uses completed-turn usage when the final session refresh fails", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const reportedCosts: number[] = [];
    const reportedErrors: unknown[] = [];
    const refreshError = new Error("session read failed");
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
      onCost: (cost) => reportedCosts.push(cost.estimatedUsd),
      onError: (error) => reportedErrors.push(error),
    });
    tracker.start("scan-thread");
    expect((await tracker.refresh()).cost?.estimatedUsd).toBe(0.00032);
    tracker.refresh = async () => {
      throw refreshError;
    };
    const usage = { input_tokens: 1_000, output_tokens: 100 };

    expect(await tracker.stop(usage)).toMatchObject({
      usage,
      cost: { inputTokens: 1_000, estimatedUsd: 0.0032 },
    });
    expect(reportedCosts).toEqual([0.00032, 0.0032]);
    expect(reportedErrors).toEqual([refreshError]);
  });

  test("adds observed worker usage to the completed root after a failed refresh", async () => {
    const { tracker } = await workerScan();
    expect((await tracker.refresh()).cost?.inputTokens).toBe(200);
    tracker.refresh = async () => {
      throw new Error("session read failed");
    };

    expect(
      (await tracker.stop({ input_tokens: 1_000, output_tokens: 100 })).cost,
    ).toMatchObject({ inputTokens: 1_100, outputTokens: 110 });
  });

  testPosix(
    "enforces a budget with completed-turn usage when only its root session is unreadable",
    async () => {
      const home = await codexHome();
      const active = await writeSession(home, "scan-thread", {
        input_tokens: 100,
        output_tokens: 10,
      });
      const budget = 0.001;
      const exceeded = new AbortController();
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-terra",
        maxCostUsd: budget,
        onCost: (cost) => {
          if (cost.estimatedUsd > budget) exceeded.abort();
        },
      });
      tracker.start("scan-thread");
      await tracker.refresh();
      await chmod(active, 0o000);

      try {
        await expect(tracker.refresh()).rejects.toThrow();
        expect(
          (await tracker.stop({ input_tokens: 1_000, output_tokens: 100 }))
            .cost,
        ).toMatchObject({ estimatedUsd: 0.0032 });
        expect(exceeded.signal.aborted).toBe(true);
      } finally {
        await chmod(active, 0o600);
      }
    },
  );

  testPosix(
    "uses completed-turn usage when an unrelated session cannot be opened",
    async () => {
      const home = await codexHome();
      const unreadable = await writeSession(home, "unrelated-thread", {
        input_tokens: 99,
        output_tokens: 1,
      });
      await chmod(unreadable, 0o000);
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-luna",
      });
      tracker.start("scan-thread");
      const usage = { input_tokens: 1_000, output_tokens: 20 };

      try {
        expect(await tracker.stop(usage)).toMatchObject({
          usage,
          cost: { inputTokens: 1_000, estimatedUsd: 0.000224 },
        });
      } finally {
        await chmod(unreadable, 0o600);
      }
    },
  );
});
