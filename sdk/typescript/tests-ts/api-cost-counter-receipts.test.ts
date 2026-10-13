import { afterEach, expect, test } from "bun:test";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { once } from "node:events";
import { spawnSync } from "node:child_process";
import { ScanCostTracker } from "../src/cost.js";
import { ScanCostLimitExceededError } from "../src/errors.js";
import { TestClient, mockWorkbench } from "./support/api-client.js";
import { scanRuntimeDependencies } from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "scan-priced-counter-",
);
afterEach(cleanup);
function usage(input: number) {
  return {
    input_tokens: input,
    cached_input_tokens: 0,
    cache_write_input_tokens: 0,
    output_tokens: 0,
    reasoning_output_tokens: 0,
    total_tokens: input,
  };
}
async function rollout(home: string, receipt: boolean, model = "gpt-5.6-sol") {
  const at = "2026-09-01T00:00:01Z";
  const records = [
    {
      type: "session_meta",
      timestamp: at,
      payload: { id: "scan-thread", model, timestamp: at },
    },
    {
      type: "turn_context",
      timestamp: at,
      payload: { turn_id: "owned-turn", model },
    },
    {
      type: "event_msg",
      timestamp: at,
      payload: {
        type: "token_count",
        info: { total_token_usage: usage(1000) },
      },
    },
    ...(receipt
      ? [
          {
            type: "token_usage_record",
            timestamp: at,
            payload: {
              thread_id: "scan-thread",
              turn_id: "owned-turn",
              response_id: "last-response",
              model,
              usage: usage(20),
              thread_token_usage: usage(1000),
            },
          },
        ]
      : []),
  ];
  await mkdir(join(home, "sessions"), { recursive: true });
  const path = join(home, "sessions", "owner.jsonl");
  await writeFile(path, records.map((x) => JSON.stringify(x) + "\n").join(""));
  return path;
}
test.each([false, true])(
  "priced legacy floor survives first refresh with delayed receipts: %p",
  async (receipt) => {
    const home = await temporaryDirectory();
    await rollout(home, receipt);
    const floors: number[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      maxCostUsd: 0.003,
      onCost: (c) => floors.push(c.estimatedUsd),
      onCostLowerBound: (c) => floors.push(c.estimatedUsd),
    });
    tracker.start("scan-thread");
    try {
      const snapshot = await tracker.refresh();
      expect(Math.max(...floors)).toBe(0.004);
      if (receipt) expect(snapshot.usage).toHaveProperty("coverage", "partial");
    } finally {
      await tracker.stop();
    }
  },
);
test("an unpriced legacy counter is not assigned a priced default", async () => {
  const home = await temporaryDirectory();
  await rollout(home, true, "synthetic-unpriced-model");
  const floors: number[] = [];
  const tracker = new ScanCostTracker({
    codexHome: home,
    model: "gpt-5.6-sol",
    maxCostUsd: 0.003,
    onCost: (c) => floors.push(c.estimatedUsd),
    onCostLowerBound: (c) => floors.push(c.estimatedUsd),
  });
  tracker.start("scan-thread");
  try {
    const snapshot = await tracker.refresh();
    expect(snapshot.cost).toBeNull();
    expect(floors).toEqual([]);
  } finally {
    await tracker.stop();
  }
});
test.each([false, true])(
  "real API budget enforces independently priced legacy counter: %p",
  async (receipt) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository"),
      home = join(root, "home"),
      scanDir = join(root, "scan");
    await Promise.all([
      mkdir(repository),
      mkdir(home),
      mkdir(scanDir, { mode: 0o700 }),
    ]);
    const client = new TestClient(
      {},
      {
        ...scanRuntimeDependencies(home, scanDir),
        runWorkbench: async (_options, args, input) => {
          return mockWorkbench(args, input);
        },
        createCodex: () => ({
          startThread: () => ({
            id: null,
            async runStreamed(
              _input: string,
              options: { signal: AbortSignal },
            ) {
              async function* events() {
                await rollout(home, receipt);
                yield {
                  type: "thread.started" as const,
                  thread_id: "scan-thread",
                };
                await (options.signal.aborted
                  ? undefined
                  : once(options.signal, "abort"));
                throw new DOMException("aborted", "AbortError");
              }
              return { events: events() };
            },
          }),
        }),
      },
    );
    const keepAlive = setTimeout(() => {}, 10000);
    try {
      const failure = await client
        .run(repository, {
          maxCostUsd: 0.003,
          signal: AbortSignal.timeout(5000),
        })
        .catch((e) => e);
      expect(failure).toBeInstanceOf(ScanCostLimitExceededError);
      expect(failure).toMatchObject({
        maxCostUsd: 0.003,
        cost: { estimatedUsd: 0.004 },
      });
    } finally {
      clearTimeout(keepAlive);
      await client.close();
    }
  },
);
test("Python reader retains exact models and unmatched counter remainder", async () => {
  const home = await temporaryDirectory();
  const path = await rollout(home, true);
  const code = [
    "import json,sys",
    "from datetime import datetime, timezone",
    "from pathlib import Path",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_scan_usage as w",
    "models={}",
    "tokens,warnings=w._read_rollout_usage(w.RolloutSession('scan-thread',None,Path(sys.argv[2])),started_at=datetime(2026,9,1,tzinfo=timezone.utc),completed_at=None,model_usage=models)",
    "print(json.dumps({'tokens':tokens,'warnings':sorted(warnings),'modelUsage':[{'model':model,**usage} for model,usage in models.items()]}))",
  ].join("\n");
  const executable = Bun.which("python3") ?? Bun.which("python");
  expect(executable).not.toBeNull();
  const r = spawnSync(
    executable!,
    [
      "-I",
      "-B",
      "-c",
      code,
      join(import.meta.dir, "../../../plugins/codex-security/scripts"),
      path,
    ],
    { encoding: "utf8" },
  );
  expect(r.status, r.stderr).toBe(0);
  const result = JSON.parse(r.stdout);
  expect(result.tokens.inputTokens).toBe(1000);
  expect(result.modelUsage).toContainEqual(
    expect.objectContaining({ model: "gpt-5.6-sol", inputTokens: 20 }),
  );
  expect(result.modelUsage).toContainEqual(
    expect.objectContaining({ model: null, inputTokens: 980 }),
  );
});
