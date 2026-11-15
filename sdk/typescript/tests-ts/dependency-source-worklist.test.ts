import { expect, test } from "bun:test";
import { createDependencySourceWorklist } from "../src/dependency-source-worklist.js";

const source = { search: "find decoder imports", sourceRefs: ["search-1"] };
const clipped = {
  id: "clipped-workers",
  description: "Rescan the remaining workers.",
};

test("retains the exact path roster across partial pages and separately searched partitions", () => {
  const work = createDependencySourceWorklist();
  const first = work.appendRosterPage({
    id: "decode-imports",
    owner: "census-owner",
    paths: ["worker/copy.py", "service/entry.py"],
    ...source,
    declaredComplete: false,
    gaps: [clipped],
  });
  const claim = work.createPartition({
    id: "service",
    rosterId: first.id,
    owner: "investigator-1",
    paths: ["service/entry.py"],
  });
  expect(claim.remainingFileCount).toBe(1);

  expect(() =>
    work.appendRosterPage({
      id: first.id,
      owner: first.owner,
      expectedRevision: first.revision - 1,
      paths: ["worker/queued.py"],
      ...source,
      declaredComplete: true,
      gaps: [],
    }),
  ).toThrow("revision changed");
  expect(() =>
    work.appendRosterPage({
      id: first.id,
      owner: "other-worker",
      expectedRevision: first.revision,
      paths: ["worker/queued.py"],
      ...source,
      declaredComplete: true,
      gaps: [],
    }),
  ).toThrow("owner or revision changed");
  expect(() =>
    work.appendRosterPage({
      id: first.id,
      owner: first.owner,
      expectedRevision: first.revision,
      paths: [],
      search: "Empty completion attempt",
      sourceRefs: [],
      declaredComplete: true,
      gaps: [],
    }),
  ).toThrow("Resolve all recorded source roster gaps");
  expect(work.readRoster(first.id)).toMatchObject({
    declaredComplete: false,
    gaps: [clipped],
  });
  expect(work.generation()).toBe(2);
  expect(work.limitations()).toEqual([
    expect.stringContaining(
      'gap "clipped-workers" (Rescan the remaining workers.)',
    ),
  ]);
  expect(work.limitations()[0]).toContain('["search-1"]');

  const complete = work.appendRosterPage({
    id: first.id,
    owner: first.owner,
    expectedRevision: first.revision,
    paths: ["worker/queued.py", "worker/copy.py"],
    ...source,
    declaredComplete: true,
    gaps: [],
    resolutions: [{ id: clipped.id, sourceRef: "retained-worker-rescan" }],
  });
  const known = work.readRoster(first.id);
  expect(known.paths).toEqual([
    "service/entry.py",
    "worker/copy.py",
    "worker/queued.py",
  ]);
  expect(known.pages).toMatchObject([
    {
      declaredComplete: false,
      gaps: [clipped],
    },
    {
      declaredComplete: true,
      gaps: [],
      resolutions: [{ id: clipped.id, sourceRef: "retained-worker-rescan" }],
    },
  ]);
  expect(known.gaps).toEqual([]);
  expect(known.unassigned).toEqual(["worker/copy.py", "worker/queued.py"]);
  expect(complete.pathListSha256).not.toBe(first.pathListSha256);

  const another = work.appendRosterPage({
    id: "alternate-format-dispatch",
    owner: "alternate-census-owner",
    paths: [...known.paths].reverse(),
    ...source,
    declaredComplete: true,
    gaps: [],
  });
  expect(another.pathListSha256).toBe(complete.pathListSha256);
  expect(
    work.createPartition({
      id: "alternate-service",
      rosterId: another.id,
      owner: "investigator-2",
      paths: ["service/entry.py"],
    }).remainingFileCount,
  ).toBe(1);
  expect(() =>
    work.createPartition({
      id: "overlap",
      rosterId: first.id,
      owner: "investigator-2",
      paths: ["service/entry.py", "worker/queued.py"],
    }),
  ).toThrow("already has an owner");
  expect(work.readRoster(first.id).unassigned).toEqual([
    "worker/copy.py",
    "worker/queued.py",
  ]);
});

test("keeps exact examined and remaining paths through a checked handoff", () => {
  const work = createDependencySourceWorklist();
  work.appendRosterPage({
    id: "dispatch",
    owner: "census-owner",
    paths: ["api/a.ts", "api/b.ts", "worker/c.ts"],
    ...source,
    declaredComplete: true,
    gaps: [],
  });
  const group = work.createPartition({
    id: "all",
    rosterId: "dispatch",
    owner: "investigator-1",
    paths: ["api/a.ts", "api/b.ts", "worker/c.ts"],
  });
  const progress = work.recordExamined({
    partitionId: group.id,
    owner: group.owner,
    expectedRevision: group.revision,
    paths: ["api/a.ts"],
  });
  const offer = work.offerHandoff({
    partitionId: group.id,
    owner: group.owner,
    expectedRevision: progress.revision,
    recipient: "investigator-2",
    newPartitionId: "api",
    paths: ["api/a.ts", "api/b.ts"],
  });

  expect(work.readPartition(group.id)).toMatchObject({
    owner: group.owner,
    remaining: ["api/b.ts", "worker/c.ts"],
    handoffPaths: ["api/a.ts", "api/b.ts"],
  });
  expect(() => work.readPartition("api")).toThrow("Unknown source partition");
  expect(() =>
    work.acceptHandoff({
      partitionId: group.id,
      recipient: "other",
      expectedRevision: offer.revision,
    }),
  ).toThrow("recipient or revision changed");
  expect(() =>
    work.recordExamined({
      partitionId: group.id,
      owner: group.owner,
      expectedRevision: offer.revision,
      paths: ["api/b.ts"],
    }),
  ).toThrow("pending source handoff");

  const moved = work.acceptHandoff({
    partitionId: group.id,
    recipient: "investigator-2",
    expectedRevision: offer.revision,
  });
  expect(moved.from.remainingFileCount).toBe(1);
  expect(work.readPartition(group.id).remaining).toEqual(["worker/c.ts"]);
  expect(work.readPartition(moved.to.id)).toMatchObject({
    owner: "investigator-2",
    paths: ["api/a.ts", "api/b.ts"],
    remaining: ["api/b.ts"],
  });
  expect(() =>
    work.recordExamined({
      partitionId: moved.to.id,
      owner: group.owner,
      expectedRevision: moved.to.revision,
      paths: ["api/b.ts"],
    }),
  ).toThrow("owner or revision changed");
  expect(work.readRoster("dispatch").unassigned).toEqual([]);
  expect(work.summary()).toMatchObject({
    incompleteRosterCount: 0,
    unassignedFileCount: 0,
    remainingFileCount: 2,
    pendingHandoffCount: 0,
  });
});

test("cancels an unopened handoff without losing ownership or accepting a stale recipient", () => {
  const work = createDependencySourceWorklist();
  expect(() =>
    work.appendRosterPage({
      id: "bad-roster",
      owner: "census-owner",
      paths: ["../other-checkout/a.ts"],
      ...source,
      declaredComplete: false,
      gaps: [clipped],
    }),
  ).toThrow("checkout-relative");
  work.appendRosterPage({
    id: "scan",
    owner: "census-owner",
    paths: ["a.ts", "b.ts"],
    ...source,
    declaredComplete: true,
    gaps: [],
  });
  const assigned = work.createPartition({
    id: "group",
    rosterId: "scan",
    owner: "first",
    paths: ["a.ts"],
  });
  const pending = work.offerHandoff({
    partitionId: assigned.id,
    owner: assigned.owner,
    expectedRevision: assigned.revision,
    recipient: "unavailable",
    newPartitionId: "handoff",
    paths: ["a.ts"],
  });
  expect(() =>
    work.createPartition({
      id: "handoff",
      rosterId: "scan",
      owner: "other",
      paths: ["b.ts"],
    }),
  ).toThrow("ID is already in use");

  const resumed = work.cancelHandoff({
    partitionId: assigned.id,
    owner: assigned.owner,
    expectedRevision: pending.revision,
  });
  expect(() =>
    work.acceptHandoff({
      partitionId: assigned.id,
      recipient: "unavailable",
      expectedRevision: pending.revision,
    }),
  ).toThrow("recipient or revision changed");
  expect(
    work.recordExamined({
      partitionId: resumed.id,
      owner: resumed.owner,
      expectedRevision: resumed.revision,
      paths: ["a.ts"],
    }).remainingFileCount,
  ).toBe(0);
  expect(work.readRoster("scan").unassigned).toEqual(["b.ts"]);
});
