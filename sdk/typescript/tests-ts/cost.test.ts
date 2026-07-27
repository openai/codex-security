import {
  appendFile,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { estimateScanCost, ScanCostTracker } from "../src/cost.js";

const temporaryDirectories: string[] = [];

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

describe("scan cost", () => {
  test("uses published GPT-5.6 model rates", () => {
    const usage = { input_tokens: 1_000_000, output_tokens: 1_000_000 };

    expect(estimateScanCost("gpt-5.6", usage)?.estimatedUsd).toBe(35);
    expect(estimateScanCost("gpt-5.6-sol", usage)?.estimatedUsd).toBe(35);
    expect(estimateScanCost("gpt-5.6-terra", usage)?.estimatedUsd).toBe(17.5);
    expect(estimateScanCost("gpt-5.6-luna", usage)?.estimatedUsd).toBe(7);
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
  test("counts the scan and delegated workers without including other scans", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 1_000,
      cached_input_tokens: 100,
      cache_write_input_tokens: 200,
      output_tokens: 10,
      reasoning_output_tokens: 2,
    });
    await writeSession(
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
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
    });
    tracker.start("scan-thread");

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
    expect((await tracker.refresh()).cost?.estimatedUsd).toBe(0.0004);

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
      estimatedUsd: 0.000925,
    });
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
        estimatedUsd: 0.00112,
      },
    });
  });
});
