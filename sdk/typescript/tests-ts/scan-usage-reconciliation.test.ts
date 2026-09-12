import { describe, expect, test } from "bun:test";
import { appendFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { estimateScanCost } from "../src/cost-model.js";
import { ScanCostTracker } from "../src/cost.js";
import { readScanLogs } from "../src/scan-logs.js";
import type { ScanExecutionAttribution } from "../src/scan-sessions.js";

describe("scan usage reconciliation", () => {
  test("SDK usage and logs share attempt membership and the original owner turn", async () => {
    const home = await mkdtemp(join(tmpdir(), "usage-attribution-"));
    const observed: unknown[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      onSessionEvent: (event) => observed.push(event),
    });
    const at = (second: number) =>
      `2026-09-01T00:00:${String(second).padStart(2, "0")}Z`;
    const attribution: ScanExecutionAttribution = {
      formatVersion: 1,
      executionThreadIds: ["old-worker", "replacement-worker"],
      owner: { threadId: "parent", turnId: "scan-turn", startedAt: at(1) },
      startedAt: at(1),
      completedAt: at(10),
    };
    const token = (second: number, count: number) => ({
      timestamp: at(second),
      type: "event_msg",
      payload: {
        type: "token_count",
        info: { total_token_usage: { input_tokens: count, output_tokens: 0 } },
      },
    });
    const context = (second: number, turn: string) => ({
      timestamp: at(second),
      type: "turn_context",
      payload: { turn_id: turn, model: "gpt-5.6-sol" },
    });
    try {
      await mkdir(join(home, "sessions"));
      for (const [id, parent, events] of [
        [
          "parent",
          null,
          [
            context(0, "prior-turn"),
            token(0, 100),
            context(1, "scan-turn"),
            token(2, 110),
            context(3, "unrelated-turn"),
            token(4, 1010),
          ],
        ],
        [
          "old-worker",
          null,
          [context(1, "worker-turn"), token(2, 20), token(11, 120)],
        ],
        ["replacement-worker", null, [context(3, "worker-turn"), token(4, 30)]],
        ["worker-child", "old-worker", [context(3, "child-turn"), token(4, 5)]],
        ["unrelated-child", "parent", [context(3, "side-turn"), token(4, 900)]],
      ] as const) {
        const records = [
          {
            type: "session_meta",
            payload: { id, ...(parent ? { parent_thread_id: parent } : {}) },
          },
          ...events,
        ];
        await writeFile(
          join(home, "sessions", `${id}.jsonl`),
          records.map((value) => JSON.stringify(value)).join("\n") + "\n",
        );
      }
      tracker.setAttributionReader(async () => attribution);
      tracker.start("parent");
      const snapshot = await tracker.stop();
      expect(snapshot.cost?.inputTokens).toBe(65);
      expect(JSON.stringify(observed)).not.toContain("unrelated-turn");
      expect(JSON.stringify(observed)).not.toContain(at(11));
      const logs = await readScanLogs({
        scanId: "scan",
        threadId: "parent",
        codexHome: home,
        executionAttribution: attribution,
      });
      expect(logs.sessions.map((session) => session.threadId).sort()).toEqual([
        "old-worker",
        "parent",
        "replacement-worker",
        "worker-child",
      ]);
      expect(
        logs.events.some(({ event }) =>
          JSON.stringify(event).includes("unrelated-turn"),
        ),
      ).toBe(false);
      expect(
        logs.events.some(({ event }) => JSON.stringify(event).includes(at(11))),
      ).toBe(false);
    } finally {
      await tracker.stop();
      await rm(home, { recursive: true, force: true });
    }
  });

  test("waits for attribution and retains uncertainty until missing attempt usage arrives", async () => {
    const home = await mkdtemp(join(tmpdir(), "usage-delayed-"));
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
    });
    let attribution: ScanExecutionAttribution | null = null;
    tracker.setAttributionReader(async () => attribution);
    const at = "2026-09-01T00:00:02Z";
    const records = (id: string, count: number) =>
      [
        { type: "session_meta", payload: { id } },
        {
          timestamp: at,
          type: "turn_context",
          payload: { model: "gpt-5.6-sol", turn_id: "own" },
        },
        {
          timestamp: at,
          type: "event_msg",
          payload: {
            type: "token_count",
            info: {
              total_token_usage: { input_tokens: count, output_tokens: 0 },
            },
          },
        },
      ]
        .map((event) => JSON.stringify(event))
        .join("\n") + "\n";
    try {
      await mkdir(join(home, "sessions"));
      await writeFile(
        join(home, "sessions", "worker.jsonl"),
        records("worker", 20),
      );
      tracker.start("worker");
      tracker.recordUsage({ input_tokens: 20, output_tokens: 0 });
      expect((await tracker.refresh()).cost).toBeNull();
      attribution = {
        formatVersion: 1,
        executionThreadIds: ["worker", "failed-attempt"],
        owner: { threadId: "worker", turnId: "own", startedAt: at },
        startedAt: "2026-09-01T00:00:01Z",
        completedAt: "2026-09-01T00:00:10Z",
      };
      expect((await tracker.refresh()).cost).toMatchObject({
        inputTokens: 20,
        coverage: "partial",
      });
      await writeFile(
        join(home, "sessions", "failed.jsonl"),
        records("failed-attempt", 5),
      );
      const final = await tracker.stop();
      expect(final.cost?.inputTokens).toBe(25);
      expect(final.cost?.coverage).toBeUndefined();
    } finally {
      await tracker.stop();
      await rm(home, { recursive: true, force: true });
    }
  });

  test("preserves receipt accounting for a resumed legacy Deep scan", async () => {
    const home = await mkdtemp(join(tmpdir(), "usage-legacy-"));
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
    });
    tracker.setAttributionReader(async () => ({
      formatVersion: 1,
      legacy: true,
      executionThreadIds: ["legacy-parent"],
      owner: {
        threadId: "legacy-parent",
        turnId: null,
        startedAt: "2026-09-01T00:00:00Z",
      },
      startedAt: "2026-09-01T00:00:00Z",
      completedAt: null,
    }));
    try {
      tracker.start("legacy-parent");
      const snapshot = await tracker.stop({
        input_tokens: 10000,
        output_tokens: 100,
      });
      expect(snapshot.cost?.inputTokens).toBe(10000);
    } finally {
      await tracker.stop();
      await rm(home, { recursive: true, force: true });
    }
  });

  test("prices each observed model instead of repricing the sum with the parent", () => {
    const usage = {
      input_tokens: 200,
      output_tokens: 20,
      modelUsage: [
        { model: "gpt-5.6-sol", input_tokens: 100, output_tokens: 10 },
        { model: "gpt-6-astra", input_tokens: 100, output_tokens: 10 },
      ],
    };
    const expected =
      estimateScanCost("gpt-5.6-sol", usage.modelUsage[0])!.estimatedUsd +
      estimateScanCost("gpt-6-astra", usage.modelUsage[1])!.estimatedUsd;
    expect(estimateScanCost("gpt-5.6-sol", usage)?.estimatedUsd).toBe(expected);
  });

  test("keeps incomplete model attribution unpriced", () => {
    expect(
      estimateScanCost("gpt-5.6-sol", {
        input_tokens: 200,
        output_tokens: 20,
        modelUsage: [
          { model: "gpt-5.6-sol", input_tokens: 100, output_tokens: 10 },
          { model: null, input_tokens: 100, output_tokens: 10 },
        ],
      }),
    ).toBeNull();
  });

  test("reconciles stale and missing cumulative receipts without reducing usage", async () => {
    const home = await mkdtemp(join(tmpdir(), "usage-receipts-"));
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
    });
    try {
      tracker.start("worker");
      tracker.recordUsage({ input_tokens: 160, output_tokens: 0 });
      tracker.recordUsage({ input_tokens: 100, output_tokens: 0 });
      tracker.recordUsage(null);
      expect((await tracker.stop()).cost?.inputTokens).toBe(160);
    } finally {
      await tracker.stop();
      await rm(home, { recursive: true, force: true });
    }
  });

  test("tracks per-model deltas within one resumed session", async () => {
    const home = await mkdtemp(join(tmpdir(), "usage-models-"));
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
    });
    try {
      await mkdir(join(home, "sessions"));
      const records = [
        { type: "session_meta", payload: { id: "worker" } },
        {
          type: "turn_context",
          payload: { model: "gpt-5.6-sol", turn_id: "turn-1" },
        },
        {
          type: "event_msg",
          payload: {
            type: "token_count",
            info: {
              total_token_usage: { input_tokens: 100, output_tokens: 10 },
            },
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "token_count",
            info: { total_token_usage: { input_tokens: 60, output_tokens: 6 } },
          },
        },
        {
          type: "turn_context",
          payload: { model: "gpt-6-astra", turn_id: "turn-2" },
        },
        {
          type: "event_msg",
          payload: {
            type: "token_count",
            info: {
              total_token_usage: { input_tokens: 200, output_tokens: 20 },
            },
          },
        },
      ];
      await writeFile(
        join(home, "sessions", "worker.jsonl"),
        records.map((record) => JSON.stringify(record)).join("\n") + "\n",
      );
      tracker.start("worker");
      tracker.recordUsage({ input_tokens: 200, output_tokens: 20 });
      const snapshot = await tracker.stop();
      expect(snapshot.cost?.inputTokens).toBe(200);
      expect(snapshot.cost?.estimatedUsd).toBeCloseTo(0.0021, 12);
      expect(snapshot.cost?.modelCosts?.map((cost) => cost.model)).toEqual([
        "gpt-5.6-sol",
        "gpt-6-astra",
      ]);
      tracker.recordUsage({ input_tokens: 250, output_tokens: 25 });
      expect((await tracker.refresh()).cost).toBeNull();
      await appendFile(
        join(home, "sessions", "worker.jsonl"),
        JSON.stringify({
          type: "event_msg",
          payload: {
            type: "token_count",
            info: {
              total_token_usage: { input_tokens: 250, output_tokens: 25 },
            },
          },
        }) + "\n",
      );
      expect((await tracker.refresh()).cost?.estimatedUsd).toBeCloseTo(
        0.00285,
        12,
      );
    } finally {
      await tracker.stop();
      await rm(home, { recursive: true, force: true });
    }
  });
});

describe("charged response receipts", () => {
  for (const exactOnly of [false, true]) {
    test(`counts compaction and deduplicates responses across counter resets (exact only: ${exactOnly})`, async () => {
      const home = await mkdtemp(join(tmpdir(), "usage-response-receipts-"));
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-sol",
      });
      const usage = (input: number, cached: number, output: number) => ({
        input_tokens: input,
        cached_input_tokens: cached,
        cache_write_input_tokens: 0,
        output_tokens: output,
        reasoning_output_tokens: 0,
        total_tokens: input + output,
      });
      const record = (
        id: string,
        count: unknown,
        cumulative: unknown,
        model = "gpt-5.6-sol",
      ) => ({
        type: "token_usage_record",
        payload: {
          thread_id: "worker",
          turn_id: "turn",
          response_id: id,
          model,
          usage: count,
          thread_token_usage: cumulative,
        },
      });
      const first = record("normal-1", usage(100, 80, 10), usage(100, 80, 10));
      const compact = record(
        "compaction",
        usage(50, 40, 5),
        usage(150, 120, 15),
        "gpt-6-astra",
      );
      const second = record("normal-2", usage(120, 90, 12), usage(120, 90, 12));
      const counter = (count: unknown) => ({
        type: "event_msg",
        payload: {
          type: "token_count",
          info: { total_token_usage: count },
        },
      });
      const events = [
        { type: "session_meta", payload: { id: "worker" } },
        first,
        ...(!exactOnly ? [counter(usage(100, 80, 10))] : []),
        compact,
        {
          type: "compacted",
          payload: { message: "Synthetic context summary" },
        },
        compact,
        second,
        ...(!exactOnly ? [counter(usage(220, 170, 22))] : []),
        first,
      ];
      try {
        await mkdir(join(home, "sessions"));
        await writeFile(
          join(home, "sessions", "worker.jsonl"),
          events.map((e) => JSON.stringify(e)).join("\n") + "\n",
        );
        tracker.start("worker");
        tracker.recordUsage(usage(220, 170, 22));
        const result = await tracker.stop();
        expect(result.usage).toMatchObject(usage(270, 210, 27));
        expect(
          result.cost?.modelCosts?.map((part) => [
            part.model,
            part.inputTokens + part.outputTokens,
          ]),
        ).toEqual([
          ["gpt-5.6-sol", 242],
          ["gpt-6-astra", 55],
        ]);
        expect((await tracker.refresh()).usage).toEqual(result.usage);
      } finally {
        await tracker.stop();
        await rm(home, { recursive: true, force: true });
      }
    });
  }

  test("uses receipt turn identity for shared-parent usage and logs", async () => {
    const home = await mkdtemp(join(tmpdir(), "usage-response-owner-"));
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
    });
    const attribution: ScanExecutionAttribution = {
      formatVersion: 1,
      executionThreadIds: [],
      owner: {
        threadId: "parent",
        turnId: "scan-turn",
        startedAt: "2026-09-01T00:00:01Z",
      },
      startedAt: "2026-09-01T00:00:01Z",
      completedAt: "2026-09-01T00:00:10Z",
    };
    const receipt = (
      id: string,
      turn: string,
      second: string,
      input: number,
    ) => ({
      type: "token_usage_record",
      timestamp: `2026-09-01T00:00:${second}Z`,
      payload: {
        response_id: id,
        thread_id: "parent",
        turn_id: turn,
        model: "gpt-5.6-sol",
        usage: { input_tokens: input, output_tokens: 0 },
      },
    });
    try {
      await mkdir(join(home, "sessions"));
      await writeFile(
        join(home, "sessions", "parent.jsonl"),
        [
          { type: "session_meta", payload: { id: "parent" } },
          receipt("prior", "prior-turn", "00", 900),
          receipt("owned", "scan-turn", "02", 20),
          receipt("side", "other-turn", "03", 800),
          receipt("post", "scan-turn", "11", 700),
        ]
          .map((e) => JSON.stringify(e))
          .join("\n") + "\n",
      );
      tracker.setAttributionReader(async () => attribution);
      tracker.start("parent");
      expect((await tracker.stop()).cost?.inputTokens).toBe(20);
      const logs = await readScanLogs({
        scanId: "scan",
        threadId: "parent",
        codexHome: home,
        executionAttribution: attribution,
      });
      const ids = logs.events
        .map(
          ({ event }) =>
            (event as { payload?: Record<string, unknown> })["payload"]?.[
              "response_id"
            ],
        )
        .filter(Boolean);
      expect(ids).toEqual(["owned"]);
    } finally {
      await tracker.stop();
      await rm(home, { recursive: true, force: true });
    }
  });
});

test("delayed response receipts resolve cumulative gaps without treating smaller counters as stale", async () => {
  const home = await mkdtemp(join(tmpdir(), "usage-delayed-response-"));
  const tracker = new ScanCostTracker({
    codexHome: home,
    model: "gpt-5.6-sol",
  });
  const record = (id: string, tokens: number, cumulative: number) =>
    JSON.stringify({
      type: "token_usage_record",
      payload: {
        response_id: id,
        thread_id: "worker",
        model: "gpt-5.6-sol",
        usage: { input_tokens: tokens, output_tokens: 0 },
        thread_token_usage: { input_tokens: cumulative, output_tokens: 0 },
      },
    }) + "\n";
  try {
    await mkdir(join(home, "sessions"));
    const file = join(home, "sessions", "worker.jsonl");
    await writeFile(
      file,
      JSON.stringify({ type: "session_meta", payload: { id: "worker" } }) +
        "\n" +
        record("first", 100, 100) +
        record("third", 50, 180),
    );
    tracker.start("worker");
    expect((await tracker.refresh()).cost).toMatchObject({
      inputTokens: 150,
      coverage: "partial",
    });
    await appendFile(file, record("second", 30, 130));
    const result = await tracker.stop();
    expect(result.cost?.inputTokens).toBe(180);
    expect(result.cost?.coverage).toBeUndefined();
  } finally {
    await tracker.stop();
    await rm(home, { recursive: true, force: true });
  }
});

test("a reader installed before the native attribution writer preserves legacy receipts", async () => {
  const home = await mkdtemp(join(tmpdir(), "usage-reader-first-"));
  const tracker = new ScanCostTracker({
    codexHome: home,
    model: "gpt-5.6-sol",
  });
  try {
    tracker.setAttributionReader(async () => undefined);
    tracker.start("parent");
    tracker.recordUsage({ input_tokens: 100, output_tokens: 0 });
    expect((await tracker.stop()).cost?.inputTokens).toBe(100);
  } finally {
    await tracker.stop();
    await rm(home, { recursive: true, force: true });
  }
});

test("late exact receipts replace an overlapping legacy counter without adding it twice", async () => {
  const home = await mkdtemp(join(tmpdir(), "usage-overlap-"));
  const tracker = new ScanCostTracker({
    codexHome: home,
    model: "gpt-5.6-sol",
  });
  const usage = (count: number) => ({ input_tokens: count, output_tokens: 0 });
  const receipt = (id: string, count: number, cumulative: number) => ({
    type: "token_usage_record",
    payload: {
      thread_id: "worker",
      response_id: id,
      model: "gpt-5.6-sol",
      usage: usage(count),
      thread_token_usage: usage(cumulative),
    },
  });
  try {
    await mkdir(join(home, "sessions"));
    await writeFile(
      join(home, "sessions", "worker.jsonl"),
      [
        { type: "session_meta", payload: { id: "worker" } },
        {
          type: "event_msg",
          payload: {
            type: "token_count",
            info: { total_token_usage: usage(100) },
          },
        },
        receipt("new", 10, 110),
        receipt("old", 100, 100),
        {
          type: "event_msg",
          payload: {
            type: "token_count",
            info: { total_token_usage: usage(10) },
          },
        },
      ]
        .map((e) => JSON.stringify(e))
        .join("\n") + "\n",
    );
    tracker.start("worker");
    const result = await tracker.stop();
    expect(result.cost?.inputTokens).toBe(110);
    expect(result.cost?.coverage).toBeUndefined();
  } finally {
    await tracker.stop();
    await rm(home, { recursive: true, force: true });
  }
});
