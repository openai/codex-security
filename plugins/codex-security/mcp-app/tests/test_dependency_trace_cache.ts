import assert from "node:assert/strict";
import { test } from "node:test";
import { createTraceCache } from "../src/dependency-trace/cache.ts";
import type { ScopeResult } from "../src/dependency-trace/types.ts";

function result(name: string): ScopeResult {
  return {
    complete: true,
    next: [],
    evidence: [
      {
        source: "file.ts",
        line: 3,
        step: {
          from: { kind: "file", name: "file.ts" },
          relation: "candidate_call",
          calleeText: name,
        },
      },
    ],
  };
}

test("reads and replacement refresh the recency of a complete scope", () => {
  const cache = createTraceCache(6800);
  const large = result("x".repeat(1000));
  const changed = result("y".repeat(1000));
  cache.store("a", large);
  cache.store("b", large);
  assert.deepEqual(cache.read("a"), large);
  cache.store("c", large);
  assert.equal(cache.read("b"), undefined);

  cache.store("a", changed);
  cache.store("d", large);
  assert.equal(cache.read("c"), undefined);
  assert.deepEqual(cache.read("a"), changed);
  assert.deepEqual(cache.read("d"), large);
});

test("oversized and incomplete results do not displace other entries", () => {
  const cache = createTraceCache(4096);
  const small = result("observation");
  cache.store("a", small);
  const huge = "x".repeat(8192);
  cache.store("oversized-evidence", result(huge));
  cache.store("oversized-text", {
    ...small,
    textMatches: [{ source: "registry.ts", text: huge }],
  });
  cache.store("oversized-scope", {
    ...small,
    next: [{ kind: "file", package: "pkg", path: huge }],
  });
  cache.store(huge, small);
  cache.store("incomplete", { ...small, complete: false });
  for (const key of [
    "oversized-evidence",
    "oversized-text",
    "oversized-scope",
    huge,
    "incomplete",
  ])
    assert.equal(cache.read(key), undefined);
  assert.deepEqual(cache.read("a"), small);
});

test("each cache owns its entries and clears both data and size accounting", () => {
  const cache = createTraceCache(6800);
  const value = result("x".repeat(1000));
  cache.store("first", value);
  cache.store("second", value);
  assert.equal(createTraceCache().read("first"), undefined);
  cache.clear();
  assert.equal(cache.read("first"), undefined);
  assert.equal(cache.read("second"), undefined);
  cache.store("third", value);
  cache.store("fourth", value);
  assert.deepEqual(cache.read("third"), value);
  assert.deepEqual(cache.read("fourth"), value);
});

test("small entries also obey the entry-count limit", () => {
  const cache = createTraceCache();
  const value = result("observed");
  for (let i = 0; i < 1024; i++) cache.store(String(i), value);
  assert.deepEqual(cache.read("0"), value);
  cache.store("new", value);
  assert.equal(cache.read("1"), undefined);
  assert.deepEqual(cache.read("0"), value);
});
