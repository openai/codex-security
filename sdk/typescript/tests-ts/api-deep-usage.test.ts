import { Database } from "bun:sqlite";

import { appendFile, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, expect, spyOn, test } from "bun:test";

import { type ScanOptions } from "../src/api.js";
import type { JsonObject } from "../src/config.js";
import { runWorkbench } from "../src/runtime.js";

import { ScanTransportClosedError } from "../src/scan-execution.js";

import {
  DeepScanPublicationError,
  DeepScanRecoveryError,
  ScanCostTrackingError,
} from "../src/deep-scan.js";

import { estimateScanCost, ScanCostTracker } from "../src/cost.js";
import { tokenUsage, type ScanTokenUsage } from "../src/cost-model.js";

import { tokenUsageEvent } from "./support/usage-rollout.js";

import { createDeepApiFixtures, usage } from "./support/deep-api.js";

const { fixture, cleanup } = createDeepApiFixtures();
afterEach(cleanup);

test.each(
  ["gpt-6-astra", "synthetic-unpriced-model"].flatMap((model) =>
    [false, true].flatMap((observe) =>
      [
        "fresh",
        "child",
        "publication",
        ...(model === "gpt-6-astra" ? ["budget"] : []),
      ].map((stage) => ({ model, observe, stage })),
    ),
  ),
)(
  "Deep results retain measured usage independently of cost: %j",
  async ({ model, observe, stage }) => {
    const h = await fixture();
    const measured = { ...usage, reasoning_output_tokens: 2 };
    h.setUsage(measured);
    const updates: unknown[] = [];
    const options: ScanOptions = {
      ...h.options,
      knowledgeBasePaths: undefined,
      ...(observe ? { onUsage: (snapshot) => updates.push(snapshot) } : {}),
      ...(stage === "child" ? { workers: 1 } : {}),
      ...(stage === "budget"
        ? {
            workers: 1,
            maxDiscoveryRuns: 3,
            maxCostUsd: estimateScanCost(model, measured)!.estimatedUsd * 1.5,
          }
        : {}),
    };
    let parentId: string | undefined;
    if (stage === "child" || stage === "publication") {
      if (stage === "child") h.stopBeforeSealing();
      else h.failPublication(true);
      await using first = h.makeClient({ model });
      await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
        stage === "child" ? ScanTransportClosedError : DeepScanPublicationError,
      );
      parentId = [...h.records].find(
        ([, record]) => record.mode === "deep",
      )![0];
      h.failPublication(false);
      updates.length = 0;
    }
    await using client = h.makeClient({ model });
    const result = await client.run(h.repository, {
      ...options,
      signal: undefined,
      ...(parentId === undefined ? {} : { resumeScanId: parentId }),
    });
    const runs = stage === "budget" ? 2 : stage === "child" ? 4 : 3;
    const expected = tokenUsage({
      ...measured,
      input_tokens: measured.input_tokens * runs,
      output_tokens: measured.output_tokens * runs,
      reasoning_output_tokens: measured.reasoning_output_tokens * runs,
    });
    expect(result.turnResult.usage).toEqual(expected);
    expect(result.cost).toEqual(estimateScanCost(model, expected));
    expect(h.launches).toHaveLength(runs);
    if (observe) expect(updates.at(-1)).toEqual(expected);
    if (stage === "budget")
      expect(result.coverage).not.toHaveProperty("completeness");
  },
);

test.each([
  { failure: "all", passes: 1, model: "gpt-6-astra", required: false },
  { failure: "all", passes: 2, model: "gpt-6-astra", required: false },
  { failure: "first", passes: 2, model: "gpt-6-astra", required: false },
  { failure: "none", passes: 2, model: "gpt-6-astra", required: false },
  { failure: "late", passes: 1, model: "gpt-6-astra", required: false },
  {
    failure: "all",
    passes: 1,
    model: "synthetic-unpriced-model",
    required: false,
  },
  { failure: "all", passes: 1, model: "gpt-6-astra", required: true },
] as const)(
  "Deep final receipts retain usage when child tracking fails: %j",
  async ({ failure, passes, model, required }) => {
    const h = await fixture(undefined, false, failure === "late");
    const measured = { ...usage, reasoning_output_tokens: 2 };
    const worker = {
      input_tokens: 5,
      output_tokens: 2,
      reasoning_output_tokens: 1,
    };
    h.setUsage(measured);
    const updates: Readonly<ScanTokenUsage>[] = [];
    const warnings: string[] = [];
    const threads = new WeakMap<ScanCostTracker, string>();
    const stopping = new WeakSet<ScanCostTracker>();
    const failed = new Set<string>();
    const writtenWorkers = new Set<string>();
    const start = ScanCostTracker.prototype.start;
    const refresh = ScanCostTracker.prototype.refresh;
    const stop = ScanCostTracker.prototype.stop;
    const childThread = (tracker: ScanCostTracker) => {
      const thread = threads.get(tracker);
      const scan = thread === undefined ? undefined : h.threadScans.get(thread);
      return scan !== undefined && h.records.get(scan)?.mode === "standard"
        ? thread
        : undefined;
    };
    const startSpy = spyOn(
      ScanCostTracker.prototype,
      "start",
    ).mockImplementation(function (this: ScanCostTracker, thread) {
      threads.set(this, thread);
      return start.call(this, thread);
    });
    const refreshSpy = spyOn(
      ScanCostTracker.prototype,
      "refresh",
    ).mockImplementation(async function (this: ScanCostTracker) {
      const thread = childThread(this);
      if (thread !== undefined) {
        const first = [...h.records].find(
          ([, record]) => record.mode === "standard",
        )![0];
        if (
          failure === "all" ||
          (failure === "first" && h.threadScans.get(thread) === first) ||
          (failure === "late" && stopping.has(this))
        ) {
          failed.add(thread);
          throw Object.assign(
            new Error("Synthetic child rollout read denied"),
            {
              code: "EACCES",
              syscall: "open",
              path: join(h.home, "sessions", `rollout-${thread}.jsonl`),
            },
          );
        }
        if (failure === "late") {
          for (const { id, mode, path } of h.observedSubagents) {
            if (mode !== "standard" || writtenWorkers.has(id)) continue;
            writtenWorkers.add(id);
            await appendFile(
              path,
              JSON.stringify(tokenUsageEvent(worker)) + "\n",
            );
          }
        }
      }
      return refresh.call(this);
    });
    const stopSpy = spyOn(ScanCostTracker.prototype, "stop").mockImplementation(
      async function (this: ScanCostTracker, fallback) {
        if (failure === "late" && childThread(this) !== undefined) {
          // Observe both root and worker counters before the final log read fails.
          await this.refresh();
          stopping.add(this);
        }
        return stop.call(this, fallback);
      },
    );
    try {
      await using client = h.makeClient({ model });
      const result = client.run(h.repository, {
        ...h.options,
        knowledgeBasePaths: undefined,
        workers: 1,
        maxDiscoveryRuns: passes,
        requireCost: required,
        onUsage: (snapshot) => updates.push(snapshot),
        onWarning: (warning) => warnings.push(warning),
      });
      if (required) {
        await expect(result).rejects.toBeInstanceOf(ScanCostTrackingError);
        await expect(result).rejects.toThrow(
          "Synthetic child rollout read denied",
        );
        expect(h.launches).toHaveLength(1);
        return;
      }
      const completed = await result;
      const turns = passes === 1 ? 1 : 3;
      const expected = tokenUsage({
        ...measured,
        input_tokens:
          measured.input_tokens * turns +
          (failure === "late" ? worker.input_tokens : 0),
        output_tokens:
          measured.output_tokens * turns +
          (failure === "late" ? worker.output_tokens : 0),
        reasoning_output_tokens:
          measured.reasoning_output_tokens * turns +
          (failure === "late" ? worker.reasoning_output_tokens : 0),
      });
      expect(completed.turnResult.usage).toEqual(expected);
      expect(updates.at(-1)).toEqual(expected!);
      expect(h.launches).toHaveLength(turns);
      if (failure !== "late")
        expect(completed.cost).toEqual(estimateScanCost(model, expected));
      expect(failed.size).toBe(
        failure === "none" ? 0 : failure === "first" ? 1 : passes,
      );
      if (failure !== "none") {
        expect(warnings).toContain(
          "Could not track scan activity: Synthetic child rollout read denied",
        );
      } else {
        expect(
          warnings.some((warning) =>
            warning.includes("Synthetic child rollout read denied"),
          ),
        ).toBe(false);
      }
    } finally {
      stopSpy.mockRestore();
      refreshSpy.mockRestore();
      startSpy.mockRestore();
    }
  },
);

test.each([
  { receipt: "legacy", rollout: false, moreWork: false },
  { receipt: "legacy", rollout: false, moreWork: true },
  { receipt: "legacy", rollout: true, moreWork: false },
  { receipt: "measured", rollout: false, moreWork: false },
  { receipt: "unavailable", rollout: false, moreWork: false },
  { receipt: "partial", rollout: false, moreWork: false },
  { receipt: "partial", rollout: false, moreWork: true },
  { receipt: "measured", rollout: "partial", moreWork: false },
  { receipt: "legacy", rollout: "partial", moreWork: true },
  { receipt: "legacy", rollout: "additional", moreWork: false },
  { receipt: "unpriced-partial", rollout: false, moreWork: false },
] as const)(
  "Deep resume retains each completed child's usage: %j",
  async ({ receipt, rollout, moreWork }) => {
    const h = await fixture();
    const measured = { ...usage, reasoning_output_tokens: 2 };
    h.setUsage(measured);
    h.failChildProjection(true);
    const options: ScanOptions = {
      ...h.options,
      knowledgeBasePaths: undefined,
      workers: 1,
      maxDiscoveryRuns: moreWork ? 2 : 1,
    };
    {
      await using first = h.makeClient();
      await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
        DeepScanRecoveryError,
      );
    }
    expect(h.launches).toHaveLength(1);
    const [parentId] = [...h.records].find(
      ([, record]) => record.mode === "deep",
    )!;
    const [childId, child] = [...h.records].find(
      ([, record]) => record.mode === "standard",
    )!;
    const childCost = estimateScanCost("gpt-6-astra", measured)!;
    const partial = {
      ...measured,
      input_tokens: 5,
      output_tokens: 1,
      reasoning_output_tokens: 1,
    };
    const additional = {
      ...measured,
      input_tokens: 15,
      output_tokens: 5,
      reasoning_output_tokens: 3,
    };
    const partialReceipt =
      receipt === "partial" || receipt === "unpriced-partial";
    const savedUsage = partialReceipt ? partial : measured;
    const priced = receipt !== "unavailable" && receipt !== "unpriced-partial";
    const database = new Database(join(h.root, "state", "workbench.sqlite3"));
    try {
      const saved =
        receipt === "unavailable"
          ? null
          : JSON.stringify(
              receipt === "legacy"
                ? childCost
                : {
                    cost: priced ? childCost : null,
                    usage: {
                      coverage: partialReceipt ? "partial" : "complete",
                      inputTokens: savedUsage.input_tokens,
                      cachedInputTokens: savedUsage.cached_input_tokens,
                      cacheWriteInputTokens: 0,
                      outputTokens: savedUsage.output_tokens,
                      reasoningOutputTokens: savedUsage.reasoning_output_tokens,
                      totalTokens:
                        savedUsage.input_tokens + savedUsage.output_tokens,
                    },
                  },
            );
      expect(
        database
          .query(
            "UPDATE scans SET cost_json = ? WHERE id = ? AND status = 'complete'",
          )
          .run(saved, childId).changes,
      ).toBe(1);
    } finally {
      database.close();
    }
    const saved = await runWorkbench({ ...child.options, signal: undefined }, [
      "get-scan",
      "--scan-id",
      childId,
    ]);
    const savedChild = saved["scan"] as JsonObject;
    expect(savedChild["progress"]).toMatchObject({ status: "complete" });
    if (receipt === "legacy") {
      expect<unknown>(savedChild["cost"]).toEqual(childCost);
      expect(savedChild["usage"]).toBeUndefined();
    }
    const rolloutPath = join(
      h.home,
      "sessions",
      `rollout-${savedChild["continuationThreadId"]}.jsonl`,
    );
    if (!rollout) await rm(rolloutPath);
    else if (rollout === "partial") {
      // A completed receipt can include pruned workers while only the root's
      // smaller cumulative usage survives in the session directory.
      const metadata = (await readFile(rolloutPath, "utf8")).split("\n")[0]!;
      await writeFile(
        rolloutPath,
        metadata + "\n" + JSON.stringify(tokenUsageEvent(partial)) + "\n",
      );
    } else if (rollout === "additional") {
      await appendFile(
        rolloutPath,
        JSON.stringify(tokenUsageEvent(additional)) + "\n",
      );
    }
    h.failChildProjection(false);
    const subsequent = {
      input_tokens: 5,
      cached_input_tokens: 0,
      output_tokens: 2,
      reasoning_output_tokens: 1,
    };
    h.setUsage(subsequent);
    const updates: Readonly<ScanTokenUsage>[] = [];
    await using resumed = h.makeClient();
    const result = await resumed.run(h.repository, {
      ...options,
      signal: undefined,
      resumeScanId: parentId,
      onUsage: (snapshot) => updates.push(snapshot),
    });
    const laterTurns = moreWork ? 2 : 0;
    const recovered =
      receipt === "unpriced-partial"
        ? partial
        : rollout === "additional"
          ? additional
          : measured;
    const expected =
      receipt === "unavailable"
        ? null
        : tokenUsage({
            ...recovered,
            input_tokens:
              recovered.input_tokens + subsequent.input_tokens * laterTurns,
            output_tokens:
              recovered.output_tokens + subsequent.output_tokens * laterTurns,
            reasoning_output_tokens:
              (receipt === "measured" ||
              receipt === "unpriced-partial" ||
              rollout === true ||
              rollout === "additional"
                ? recovered.reasoning_output_tokens
                : 0) +
              subsequent.reasoning_output_tokens * laterTurns,
          });
    expect(result.turnResult.usage).toEqual(expected);
    if (!priced) expect(result.cost).toBeNull();
    else {
      expect(result.cost).toMatchObject({
        inputTokens:
          measured.input_tokens + subsequent.input_tokens * laterTurns,
        cachedInputTokens: measured.cached_input_tokens,
        cacheWriteInputTokens: 0,
        cacheWriteInputTokensReported: false,
        outputTokens:
          measured.output_tokens + subsequent.output_tokens * laterTurns,
      });
      expect(result.cost!.estimatedUsd).toBeCloseTo(
        childCost.estimatedUsd +
          estimateScanCost("gpt-6-astra", subsequent)!.estimatedUsd *
            laterTurns,
        12,
      );
    }
    expect(h.launches).toHaveLength(1 + laterTurns);
    if (expected === null) expect(updates).toEqual([]);
    else expect(updates.at(-1)).toEqual(expected);
    expect(
      updates.every(
        (snapshot, index) =>
          index === 0 ||
          snapshot.total_tokens >= updates[index - 1]!.total_tokens,
      ),
    ).toBe(true);
  },
);
