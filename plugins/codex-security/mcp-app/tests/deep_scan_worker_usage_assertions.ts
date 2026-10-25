import assert from "node:assert/strict";
import { readdir } from "node:fs/promises";
import { join } from "node:path";
import type { DeepScanLogEvent } from "../src/deep-scan/types.js";
import type { WorkerUsageReceipt } from "../src/deep-scan/usage-receipt.js";
import { readJson } from "./support/json.ts";
import {
  coordinatorFixture,
  FakeExecutor,
  runCoordinator,
} from "./deep_scan_coordinator_fixture.ts";

export function workerUsage(completedTurns: number) {
  return {
    input_tokens: 10 * completedTurns,
    cached_input_tokens: 0,
    cache_write_input_tokens: 0,
    output_tokens: 2 * completedTurns,
    reasoning_output_tokens: completedTurns,
    total_tokens: 12 * completedTurns,
  };
}

export function withCumulativeUsage(
  executor: FakeExecutor,
  workerUsageDirectory: string | undefined,
) {
  const originalRun = executor.run.bind(executor);
  executor.run = async (request) => {
    assert.equal(request.workerUsageDirectory, workerUsageDirectory);
    const completedTurns = request.resumeThreadId ? 2 : 1;
    return {
      ...(await originalRun(request)),
      usage: workerUsage(completedTurns),
    };
  };
}

export async function testWorkerUsageWithoutHostDirectory() {
  const { fixture, store } = await coordinatorFixture();
  delete fixture.run.workerUsageDirectory;
  delete store.run.workerUsageDirectory;
  const executor = new FakeExecutor();
  const events: DeepScanLogEvent[] = [];
  const terminal = await runCoordinator(fixture, store, executor, {
    log: (event) => events.push(event),
  });
  assert.equal(terminal?.status, "succeeded");
  assert.ok(events.some((event) => event.event === "worker_usage_unavailable"));
  await assertNoArtifactUsage(fixture.run.scanDir);
}

export function assertNoArtifactUsage(scanDir: string) {
  return assert.rejects(
    readdir(join(scanDir, "artifacts", "deep_discovery", "usage")),
    {
      code: "ENOENT",
    },
  );
}

async function workerReceipts(
  directory: string,
): Promise<WorkerUsageReceipt[]> {
  return Promise.all(
    (await readdir(directory)).map((name) => readJson(join(directory, name))),
  );
}

function assertPairedAttempts(
  receipts: WorkerUsageReceipt[],
  events: DeepScanLogEvent[],
) {
  const starts = events.filter((event) => event.event === "worker_started");
  const finishes = events.filter((event) => event.event === "worker_finished");
  assert.equal(starts.length, receipts.length);
  assert.equal(finishes.length, starts.length);
  for (const receipt of receipts)
    assert.equal(receipt.usageScope, "thread_cumulative");
  for (const start of starts) {
    const finish = finishes.find(
      (event) => event.attemptId === start.attemptId,
    );
    assert.ok(finish);
    assert.equal(finish.kind, start.kind);
    assert.equal(finish.retry, start.retry);
    assert.equal(finish.resumed, start.resumed);
    assert.ok(Number.isFinite(Date.parse(start.timestamp!)));
    assert.ok(Number.isFinite(Date.parse(finish.timestamp!)));
    assert.ok(finish.durationMs! >= 0);
  }
}

export async function assertWorkerRetryReceipts(
  directory: string,
  events: DeepScanLogEvent[],
  kind: "discovery" | "dedup" = "discovery",
) {
  const receipts = await workerReceipts(directory);
  const workers = receipts
    .filter((receipt) => receipt.kind === kind)
    .sort((left, right) => left.attempt - right.attempt);
  assert.equal(workers.length, 2);
  assert.notEqual(workers[0].attemptId, workers[1].attemptId);
  assert.equal(workers[0].threadId, workers[1].threadId);
  assert.deepEqual(
    workers.map((receipt) => [
      receipt.outcome,
      receipt.resumed,
      receipt.usage?.total_tokens,
    ]),
    [
      ["failed", false, 12],
      ["succeeded", true, 24],
    ],
  );
  assertPairedAttempts(receipts, events);
}

export async function assertCanceledWorkerReceipts(
  directory: string,
  events: DeepScanLogEvent[],
  usageReported: boolean,
) {
  const receipts = await workerReceipts(directory);
  assert.equal(receipts.length, 1);
  assert.equal(receipts[0].outcome, "canceled");
  if (usageReported) {
    assert.equal(receipts[0].usage?.total_tokens, 12);
    assert.equal(receipts[0].turnId, "synthetic-turn");
  } else assert.equal(receipts[0].usage, null);
  assert.ok(receipts[0].threadId);
  assert.equal(
    events.find((event) => event.event === "worker_finished")?.outcome,
    "canceled",
  );
  assertPairedAttempts(receipts, events);
}
