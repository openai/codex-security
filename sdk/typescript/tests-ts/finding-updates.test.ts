import { expect, mock, spyOn, test } from "bun:test";
import {
  FindingUpdateTracker,
  type FindingUpdate,
} from "../src/finding-updates.js";

const scanId = "standard-test";

function row(cursor: number, kind: FindingUpdate["kind"]) {
  return {
    cursor,
    kind,
    ...(kind === "updated" ? { changedFields: ["evidence"] } : {}),
    findingId: "csf_test",
    title: "Missing access check",
    severity: "high",
    summary: "Reviewed finding",
    validation: "static",
    locations: [{ file: "route.ts", line: 3 }],
  };
}

function page(updates: ReturnType<typeof row>[], hasMore: boolean) {
  return {
    scanId,
    updates,
    nextCursor: updates.at(-1)?.cursor ?? 0,
    hasMore,
  };
}

test("streams a committed update during the scan and drains later pages after sealing", async () => {
  const seen = Promise.withResolvers<void>();
  const read = mock(async (after: number) => {
    if (after === 0) return page([row(1, "reviewed")], false);
    if (after === 1) return page([row(3, "updated")], true);
    return page([row(6, "finalized")], false);
  });
  const updates: FindingUpdate[] = [];
  const onError = mock();
  const tracker = new FindingUpdateTracker({
    scanId,
    read,
    onUpdate(update) {
      updates.push(update);
      seen.resolve();
    },
    onError,
  });
  tracker.start();
  try {
    await seen.promise;
    expect(updates).toEqual([{ scanId, ...row(1, "reviewed") }]);
  } finally {
    await tracker.finish(new AbortController().signal);
  }
  expect(read.mock.calls.map(([after]) => after)).toEqual([0, 1, 3]);
  expect(updates.map((update) => update.kind)).toEqual([
    "reviewed",
    "updated",
    "finalized",
  ]);
  expect(updates[1]?.changedFields).toEqual(["evidence"]);
  expect(onError).not.toHaveBeenCalled();
});

test("resamples progress during a long finding backlog", async () => {
  let elapsed = 0;
  const clock = spyOn(performance, "now").mockImplementation(() => elapsed);
  const drained = Promise.withResolvers<void>();
  const reads: string[] = [];
  const read = (kind: "feed" | "combined", after: number) => {
    reads.push(`${kind} ${after}`);
    if (after === 1) elapsed += 5_001;
    return page([row(after + 1, "updated")], after < 3);
  };
  const tracker = new FindingUpdateTracker({
    scanId,
    read: async (after) => read("feed", after),
    onUpdate(update) {
      if (update.cursor === 4) drained.resolve();
    },
    onError: drained.reject,
  });
  try {
    tracker.start(async (after) => read("combined", after));
    await drained.promise;
  } finally {
    elapsed += 5_001;
    await tracker
      .finish(new AbortController().signal)
      .finally(() => clock.mockRestore());
  }
  expect(reads).toEqual([
    "combined 0",
    "feed 1",
    "combined 2",
    "feed 3",
    "feed 4",
  ]);
});

test.each(["separate", "combined"])(
  "final read discards a stale %s poll and delivers committed withdrawals",
  async (mode) => {
    const stale = async (_after: number, signal: AbortSignal) => {
      await new Promise<void>((resolve) =>
        signal.addEventListener("abort", () => resolve(), { once: true }),
      );
      return page([row(1, "updated")], false);
    };
    const read = mock(async (after: number, signal: AbortSignal) => {
      if (mode === "separate" && read.mock.calls.length === 1)
        return await stale(after, signal);
      return page([row(1, "reviewed"), row(2, "withdrawn")], false);
    });
    const onUpdate = mock();
    const onError = mock();
    const tracker = new FindingUpdateTracker({
      scanId,
      read,
      onUpdate,
      onError,
    });
    tracker.start(mode === "combined" ? stale : undefined);
    await tracker.finish(new AbortController().signal);
    expect(read.mock.calls).toHaveLength(mode === "combined" ? 1 : 2);
    expect(onUpdate.mock.calls.map(([update]) => update.kind)).toEqual([
      "reviewed",
      "withdrawn",
    ]);
    expect(onError).not.toHaveBeenCalled();
  },
);

test("a failed read keeps its cursor for the next read", async () => {
  const failed = Promise.withResolvers<void>();
  const read = mock(async (_cursor: number) => {
    if (read.mock.calls.length === 1) throw new Error("database unavailable");
    return page([row(1, "finalized")], false);
  });
  const onUpdate = mock();
  const tracker = new FindingUpdateTracker({
    scanId,
    read,
    onUpdate,
    onError() {
      failed.resolve();
    },
  });
  tracker.start();
  try {
    await failed.promise;
  } finally {
    await tracker.finish(new AbortController().signal);
  }
  expect(read.mock.calls.map(([after]) => after)).toEqual([0, 0]);
  expect(onUpdate).toHaveBeenCalledWith({ scanId, ...row(1, "finalized") });
});

test.each(["recovered", "persistent", "canceled"])(
  "handles a %s workbench read failure on the second page of the final drain",
  async (outcome) => {
    const controller = new AbortController();
    const error = new Error("unavailable");
    let failed = false;
    const read = mock(async (after: number) => {
      if (after === 0) return page([row(1, "reviewed")], true);
      if (outcome === "canceled") controller.abort();
      if (!failed || outcome !== "recovered") {
        failed = true;
        throw error;
      }
      return page([row(2, "finalized")], false);
    });
    const onUpdate = mock();
    const onError = mock();
    const tracker = new FindingUpdateTracker({
      scanId,
      read,
      onUpdate,
      onError,
    });

    await tracker.finish(controller.signal);
    expect(read.mock.calls.map(([cursor]) => cursor)).toEqual(
      outcome === "canceled" ? [0, 1] : [0, 1, 1],
    );
    expect(onUpdate.mock.calls.map(([update]) => update.kind)).toEqual(
      outcome === "recovered" ? ["reviewed", "finalized"] : ["reviewed"],
    );
    expect(onError.mock.calls).toEqual(
      outcome === "persistent" ? [[error]] : [],
    );
  },
);
