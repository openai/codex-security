import { expect, test } from "bun:test";
import {
  dependencyClaimQueueSchema,
  dependencyClaimQuerySchema,
} from "../src/dependency-claims.js";
import {
  createDependencyClaims,
  type PreparedDependencyClaim,
  type DependencyClaimReference,
} from "../src/dependency-claims.js";
import type { JsonValue } from "../src/config.js";

const context = {
  advisory: "fixture-cve",
  checkout: "fixture-checkout",
  caller: "fixture-production",
};
const approval = {
  accepted: true,
  reason: "Fixture reviewer found proof.",
  evidenceKeys: [],
};
const draft = (
  id: string,
  payload: JsonValue,
  dependencies: DependencyClaimReference[] = [],
): PreparedDependencyClaim => ({
  id,
  payload,
  scope: { group: "fixture-production" },
  dependencies,
  excerpts: [],
  receipts: [],
});
const ref = (row: DependencyClaimReference) => ({
  id: row.id,
  revision: row.revision,
  hash: row.hash,
});
function propose(
  store: ReturnType<typeof createDependencyClaims>,
  id: string,
  payload: JsonValue,
  deps: DependencyClaimReference[] = [],
  expectedRevision?: number,
) {
  return ref(store.propose(draft(id, payload, deps), expectedRevision).record);
}
function approve(
  store: ReturnType<typeof createDependencyClaims>,
  claim: DependencyClaimReference,
) {
  expect(store.lease(claim)).toBeDefined();
  expect(store.complete(claim, approval)).toBe(true);
}

test("pending is discoverable, detached and never inherits nested host-owned fields", () => {
  const store = createDependencyClaims(context);
  const original = {
    nested: { value: "stable", approved: true, state: "approved" },
    sample: [null, false],
  };
  const claim = propose(store, "wrapper", original);
  original.nested.value = "mutated-after-propose";
  const byId = store.query({ ids: ["wrapper", "absent"] });
  const [row] = byId.claims;
  if (!row || !("payload" in row))
    throw new Error("Expected an exact claim envelope.");
  expect(byId.missingIds).toEqual(["absent"]);
  expect(row!.state).toBe("pending");
  expect(row!.payload).toMatchObject({ nested: { value: "stable" } });
  (row!.payload as { nested: { value: string } }).nested.value =
    "mutated-in-query";
  const bySearch = store.query({ search: "stable" });
  expect(bySearch.claims).toHaveLength(1);
  expect(ref(bySearch.claims[0]!)).toEqual(claim);
  expect(store.isApproved(claim)).toBe(false);
});

test("same semantics are idempotent, different writes require compare-and-set", () => {
  const store = createDependencyClaims(context);
  const first = propose(store, "wrapper", { one: 1, two: 2 });
  approve(store, first);
  const same = propose(store, "wrapper", { two: 2, one: 1 });
  expect(same).toEqual(first);
  expect(store.isApproved(same)).toBe(true);
  expect(() => propose(store, "wrapper", "new")).toThrow();
  const second = propose(store, "wrapper", "new", [], first.revision);
  expect(second.hash).not.toBe(first.hash);
  expect(second.revision).toBe(2);
  expect(() =>
    propose(store, "wrapper", "racing-writer", [], first.revision),
  ).toThrow();
  expect(store.latest("wrapper")?.hash).toBe(second.hash);
  expect(store.get(first)?.state).toBe("stale");
});

test("pending premises and stable-ID ancestor cycles cannot authorize a dependent claim", () => {
  const store = createDependencyClaims(context);
  const first = propose(store, "p", { mode: "PNG" });
  expect(() =>
    propose(store, "a", { verdict: "ruled_out" }, [first]),
  ).toThrow();
  approve(store, first);
  expect(() =>
    propose(store, "p", { recursive: true }, [first], first.revision),
  ).toThrow();
  const application = propose(store, "a", { verdict: "ruled_out" }, [first]);
  approve(store, application);
  expect(() =>
    propose(store, "p", { recursive: true }, [application], first.revision),
  ).toThrow();
  expect(store.isApproved(first)).toBe(true);
});

test("revision changes invalidate transitive dependencies and prevent late application approval", () => {
  const store = createDependencyClaims(context);
  const p1 = propose(store, "premise", { mode: "PNG" });
  approve(store, p1);
  const wrapper = propose(store, "wrapper", ["observed"], [p1]);
  approve(store, wrapper);
  const use = propose(store, "use", { branch: "bound" }, [wrapper]);
  expect(store.lease(use)).toBeDefined();
  expect(store.lease(use)).toBeUndefined();
  const other = propose(store, "independent", null);
  approve(store, other);
  const p2 = propose(store, "premise", { mode: "TIFF" }, [], p1.revision);
  expect(store.complete(use, approval)).toBe(false);
  expect(store.get(use)?.state).toBe("stale");
  expect(store.isApproved(wrapper)).toBe(false);
  expect(store.isApproved(p1)).toBe(false);
  expect(store.isApproved(p2)).toBe(false);
  expect(store.isApproved(other)).toBe(true);
  expect(() => store.closure([wrapper])).toThrow();
});

test("an unreturned subject stays discoverable without automatic retry", () => {
  const store = createDependencyClaims(context);
  const claim = propose(store, "pending", { text: "fixture pending" });
  expect(store.lease(claim)).toBeDefined();
  store.reviewError(claim, "Reviewer omitted this exact subject.");
  expect(store.query({ search: "fixture" }).claims[0]).toMatchObject({
    state: "pending",
    reviewing: false,
  });
  expect(store.pending()).toHaveLength(0);
  store.retry(claim);
  expect(store.pending()).toHaveLength(1);
  approve(store, claim);
  expect(store.isApproved(claim)).toBe(true);
});

test("a nonexistent reference cannot borrow approval through a colon-delimited key", () => {
  const store = createDependencyClaims({ advisory: "identity probe" });
  const item = (id: string, dependencies: DependencyClaimReference[] = []) => ({
    id,
    payload: null,
    scope: null,
    dependencies,
    excerpts: [],
    receipts: [],
  });
  const existing = store.propose(item("fixture:1")).record;
  const exact = {
    id: existing.id,
    revision: existing.revision,
    hash: existing.hash,
  };
  expect(store.lease(exact)).toBeDefined();
  expect(
    store.complete(exact, {
      accepted: true,
      reason: "Synthetic",
      evidenceKeys: [],
    }),
  ).toBe(true);
  const forged = { id: "fixture", revision: 1, hash: `1:${exact.hash}` };
  expect(store.get(forged)).toBeUndefined();
  expect(() => store.propose(item("dependent", [exact, forged]))).toThrow();
});

test("search pages compact indexes without cutting off stored payloads or later matches", () => {
  const store = createDependencyClaims(context);
  const privatePayload = "large opaque fixture bytes ".repeat(1000);
  for (let index = 0; index < 121; index++)
    propose(store, `common-${String(index).padStart(3, "0")}`, {
      title: "common",
      nested: privatePayload,
    });
  const first = store.query({ search: "common" });
  expect(first.total).toBe(121);
  expect(first.claims).toHaveLength(50);
  expect(JSON.stringify(first)).not.toContain(privatePayload);
  expect(first.claims[0]).not.toHaveProperty("payload");
  const second = store.query({
    search: "common",
    page: { cursor: first.nextCursor },
  });
  const third = store.query({
    search: "common",
    page: { cursor: second.nextCursor },
  });
  expect(second.claims).toHaveLength(50);
  expect(third.claims).toHaveLength(21);
  expect(third.nextCursor).toBeNull();
  expect(
    new Set(
      [...first.claims, ...second.claims, ...third.claims].map((row) => row.id),
    ).size,
  ).toBe(121);
  const exact = store.query({ ids: [third.claims.at(-1)!.id] });
  expect(exact.claims[0]).toMatchObject({
    payload: { nested: privatePayload },
    state: "pending",
  });
  propose(store, "common-new", false);
  expect(() =>
    store.query({ search: "common", page: { cursor: first.nextCursor } }),
  ).toThrow(/revisions changed/i);
});

test("claim tools reject ambiguous lookups and reserved assessment IDs", () => {
  expect(() =>
    dependencyClaimQuerySchema.parse({ search: "wrapper", ids: ["wrapper"] }),
  ).toThrow();
  expect(() =>
    dependencyClaimQueueSchema.parse({
      claims: [{ id: "application:spoof", payload: null, scope: null }],
    }),
  ).toThrow(/reserved/i);
});
