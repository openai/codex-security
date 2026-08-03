import {
  appendFile,
  chmod,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import * as fsPromises from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, mock, test } from "bun:test";
import { estimateScanCost, ScanCostTracker } from "../src/cost.js";

const temporaryDirectories: string[] = [];
const testPosix = process.platform === "win32" ? test.skip : test;

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

function failingOpen(
  path: string,
  code: string,
): { attempts: () => number; restore: () => void } {
  const originalOpen = fsPromises.open;
  let attempts = 0;
  mock.module("node:fs/promises", () => ({
    ...fsPromises,
    open: async (...parameters: Parameters<typeof originalOpen>) => {
      if (String(parameters[0]) !== path) return originalOpen(...parameters);
      attempts += 1;
      throw Object.assign(new Error(`${code}: simulated open failure`), {
        code,
      });
    },
  }));
  return {
    attempts: () => attempts,
    restore: () => {
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        open: originalOpen,
      }));
    },
  };
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

  test("retains a bounded partial event across incremental reads", async () => {
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

    await appendFile(path, `${event.slice(40)}\n`);
    expect((await tracker.stop()).cost?.inputTokens).toBe(250);
  });

  test("rejects and quarantines a session event larger than 1 MiB", async () => {
    const home = await codexHome();
    const path = await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    await appendFile(path, "x".repeat(1 * 1_024 * 1_024 + 1));
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
    });
    tracker.start("scan-thread");

    await expect(tracker.refresh()).rejects.toThrow(
      "Codex session event exceeds the 1 MiB safety limit.",
    );
    expect((await tracker.refresh()).cost).toEqual({
      model: "gpt-5.6-terra",
      inputTokens: 100,
      cachedInputTokens: 0,
      cacheWriteInputTokens: 0,
      outputTokens: 10,
      estimatedUsd: 0.0004,
    });
  });

  test("ignores oversized events from unrelated prior credential sessions", async () => {
    const home = await codexHome();
    const unrelated = await writeSession(home, "unrelated-thread", {
      input_tokens: 99,
      output_tokens: 1,
    });
    await appendFile(unrelated, "x".repeat(1 * 1_024 * 1_024 + 1));
    await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
    });
    tracker.start("scan-thread");

    expect((await tracker.stop()).cost).toMatchObject({
      inputTokens: 100,
      outputTokens: 10,
    });
  });

  test("ignores oversized delegated sessions belonging to an unrelated scan", async () => {
    const home = await codexHome();
    await writeSession(home, "unrelated-parent", {
      input_tokens: 1,
      output_tokens: 1,
    });
    const unrelated = await writeSession(
      home,
      "unrelated-child",
      { input_tokens: 1, output_tokens: 1 },
      "unrelated-parent",
    );
    await appendFile(unrelated, "x".repeat(1 * 1_024 * 1_024 + 1));
    await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
    });
    tracker.start("scan-thread");

    expect((await tracker.stop()).cost).toMatchObject({
      inputTokens: 100,
      outputTokens: 10,
    });
  });

  testPosix(
    "keeps tracking after an unreadable unrelated session is reported",
    async () => {
      const home = await codexHome();
      const unrelated = await writeSession(home, "unrelated-thread", {
        input_tokens: 99,
        output_tokens: 1,
      });
      await writeSession(home, "scan-thread", {
        input_tokens: 100,
        output_tokens: 10,
      });
      await chmod(unrelated, 0o000);
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-terra",
      });
      tracker.start("scan-thread");

      try {
        await expect(tracker.refresh()).rejects.toThrow();
        expect((await tracker.refresh()).cost).toMatchObject({
          inputTokens: 100,
          outputTokens: 10,
        });
        expect((await tracker.stop()).cost).toMatchObject({
          inputTokens: 100,
          outputTokens: 10,
        });
      } finally {
        await chmod(unrelated, 0o600);
      }
    },
  );

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

  test("prefers the completed turn when the final refresh fails", async () => {
    const home = await codexHome();
    const path = await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const updates: number[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
      onCost: (cost) => updates.push(cost.estimatedUsd),
    });
    tracker.start("scan-thread");
    expect((await tracker.refresh()).cost?.estimatedUsd).toBe(0.0004);

    await appendFile(path, "x".repeat(1 * 1_024 * 1_024 + 1));
    const usage = { input_tokens: 1_000, output_tokens: 100 };

    expect(await tracker.stop(usage)).toEqual({
      usage,
      cost: {
        model: "gpt-5.6-terra",
        inputTokens: 1_000,
        cachedInputTokens: 0,
        cacheWriteInputTokens: 0,
        outputTokens: 100,
        estimatedUsd: 0.004,
      },
    });
    expect(updates).toEqual([0.0004, 0.004]);
  });

  test("keeps the observed usage when the completed turn charges less", async () => {
    const home = await codexHome();
    const path = await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const updates: number[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
      onCost: (cost) => updates.push(cost.estimatedUsd),
    });
    tracker.start("scan-thread");
    await tracker.refresh();

    await appendFile(path, "x".repeat(1 * 1_024 * 1_024 + 1));

    expect(
      (await tracker.stop({ input_tokens: 10, output_tokens: 1 })).cost,
    ).toMatchObject({ inputTokens: 100, outputTokens: 10 });
    expect(updates).toEqual([0.0004]);
  });

  test("retries a session log after a transient open failure", async () => {
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
    const open = failingOpen(path, "EMFILE");

    try {
      await expect(tracker.refresh()).rejects.toThrow("EMFILE");
      await expect(tracker.refresh()).rejects.toThrow("EMFILE");
      expect(open.attempts()).toBe(2);
    } finally {
      open.restore();
    }

    expect((await tracker.refresh()).cost).toMatchObject({
      inputTokens: 100,
      outputTokens: 10,
    });
  });

  test("stops reopening a session log after a permanent open failure", async () => {
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
    const open = failingOpen(path, "EACCES");

    try {
      await expect(tracker.refresh()).rejects.toThrow("EACCES");
      expect((await tracker.refresh()).cost).toBeNull();
      expect(open.attempts()).toBe(1);
    } finally {
      open.restore();
    }
  });

  testPosix(
    "falls back to the completed turn when session logs cannot be read",
    async () => {
      const home = await codexHome();
      const unrelated = await writeSession(home, "unrelated-thread", {
        input_tokens: 99,
        output_tokens: 1,
      });
      await chmod(unrelated, 0o000);
      const tracker = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-luna",
      });
      const usage = { input_tokens: 1_000, output_tokens: 20 };
      tracker.start("scan-thread");

      try {
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
      } finally {
        await chmod(unrelated, 0o600);
      }
    },
  );
});
