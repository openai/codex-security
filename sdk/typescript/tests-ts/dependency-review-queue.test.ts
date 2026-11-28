import { expect, test } from "bun:test";
import { DependencyAttemptStore } from "../src/dependency/attempt-store.js";
import {
  approveDependencyClaims,
  type Claim,
} from "../src/dependency/analyzers/repository/claims.js";
import {
  createPremiseQueue,
  currentApproval,
  premiseKey,
} from "../src/dependency/analyzers/repository/review-queue.js";

function premise(store: DependencyAttemptStore, id: string, previous = 0) {
  return store.recordClaim<Claim["value"]>(
    "premise:" + id,
    {
      kind: "premise",
      scope: "checkout",
      statement: id + " at revision " + (previous + 1),
      receiptIds: [],
      sources: [],
      dependencies: [],
    },
    previous,
  );
}

test("a selected review completes while a sibling is blocked and a correction stays current", async () => {
  const store = new DependencyAttemptStore(":memory:");
  const calls: string[] = [];
  const blocked = Promise.withResolvers<void>();
  const started = Promise.withResolvers<void>();
  const a = premise(store, "first");
  const b = premise(store, "second");
  const queue = createPremiseQueue({
    store,
    directory: ".",
    revision: undefined,
    signal: new AbortController().signal,
    records: new Map(),
    async review(batch) {
      for (const c of batch) {
        calls.push(premiseKey(c));
        if (c.hash === a.hash) {
          started.resolve();
          await blocked.promise;
        }
        approveDependencyClaims(
          store,
          [c],
          [
            {
              id: c.id,
              revision: c.revision,
              hash: c.hash,
              approved: true,
              evidenceKeys: [],
              reason: "Checked.",
            },
          ],
        );
      }
    },
  });
  try {
    queue.enqueue([a]);
    await started.promise;
    queue.enqueue([a]);
    queue.enqueue([b]);
    queue.enqueue([b]);
    // Unrelated work remains blocked and the coordinator still obtains B.
    expect((await queue.query({ ids: [b.id], wait: true }))[0]?.state).toBe(
      "approved",
    );
    const a2 = premise(store, "first", a.revision);
    queue.enqueue([a2]);
    queue.enqueue([a2]);
    expect(currentApproval(store, a)).toBeUndefined();
    expect(calls).toEqual([premiseKey(a), premiseKey(b)]);
    blocked.resolve();
    expect((await queue.query({ ids: [a.id], wait: true }))[0]).toMatchObject({
      state: "approved",
      hash: a2.hash,
    });
    expect(currentApproval(store, a)).toBeUndefined();
    expect(calls).toEqual([premiseKey(a), premiseKey(b), premiseKey(a2)]);
  } finally {
    blocked.resolve();
    await queue.drain();
    store.close();
  }
});

test("independent review batches respect the original concurrency limit and release waiting work", async () => {
  const store = new DependencyAttemptStore(":memory:");
  const release = Promise.withResolvers<void>();
  const full = Promise.withResolvers<void>();
  let active = 0;
  let started = 0;
  let peak = 0;
  const queue = createPremiseQueue({
    store,
    directory: ".",
    revision: undefined,
    signal: new AbortController().signal,
    records: new Map(),
    async review(batch) {
      expect(batch).toHaveLength(2);
      active++;
      started++;
      peak = Math.max(peak, active);
      if (active === 16) full.resolve();
      await release.promise;
      active--;
    },
  });
  try {
    for (let i = 0; i < 17; i++) {
      queue.enqueue([premise(store, String(i))]);
      queue.enqueue([premise(store, "sibling-" + i)]);
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    await full.promise;
    expect(started).toBe(16);
    release.resolve();
    await queue.drain();
    expect(peak).toBe(16);
    expect(started).toBe(17);
  } finally {
    release.resolve();
    await queue.drain();
    store.close();
  }
});
