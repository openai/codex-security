import assert from "node:assert/strict";
import { join } from "node:path";
import { test } from "node:test";
import type {
  ScopeResult,
  TraceRequest,
  TraceScope,
} from "../src/dependency-trace/types.ts";
import { importSource } from "./import-module.ts";

const { processTrace, createDependencyTracer, traceConcurrency } =
  (await importSource(
    join(import.meta.dirname, "../src/dependency-trace/trace.ts"),
  )) as typeof import("../src/dependency-trace/trace.ts");
const request: TraceRequest = {
  package: "sample",
  paths: ["a", "b"],
  time_budget_ms: 3000,
  max_hops: 3,
};
const file = (path: string): TraceScope => ({
  kind: "file",
  package: "sample",
  path,
});
const finished = (...next: TraceScope[]): ScopeResult => ({
  complete: true,
  evidence: [],
  next,
});

function declaration(source: string, name: string) {
  return {
    source,
    line: 1,
    step: {
      from: { kind: "file", name: source },
      relation: "depends_on",
      to: { kind: "package", name, scope: source },
    },
  };
}

test("a fast branch can finish its shared child before the other branch returns", async () => {
  const release = Promise.withResolvers<void>();
  const calls = new Map<string, number>();
  const result = await processTrace(
    request,
    async ({ path }) => {
      calls.set(path!, (calls.get(path!) ?? 0) + 1);
      if (path === "a") await release.promise;
      if (path === "shared") {
        release.resolve();
        return finished();
      }
      return finished(file("shared"));
    },
    2,
  );
  assert.equal(result.complete, true);
  assert.equal(calls.get("shared"), 1);
  const child = result.scopes.find((entry) => entry.scope.path === "shared");
  assert.deepEqual(
    result.expansions
      .filter((edge) => edge.to === child!.id)
      .map((e) => e.from)
      .sort(),
    [0, 1],
  );
});

test("a shorter path can reopen a hop-limited scope without rerunning the provider", async () => {
  const release = Promise.withResolvers<void>();
  const calls: string[] = [];
  const result = await processTrace(
    { ...request, max_hops: 2 },
    async ({ path }) => {
      calls.push(path!);
      if (path === "a") return finished(file("middle"));
      if (path === "middle") return finished(file("shared"));
      if (path === "shared") {
        // Deliver the shorter branch after the coordinator has processed this completion.
        setImmediate(() => release.resolve());
        return finished(file("leaf"));
      }
      if (path === "b") {
        await release.promise;
        return finished(file("shared"));
      }
      return finished();
    },
    2,
  );
  assert.equal(result.complete, true);
  assert.equal(calls.filter((p) => p === "shared").length, 1);
  assert.ok(calls.includes("leaf"));
});

test("zero hops returns unresolved candidate scopes and deadline retains completed work", async () => {
  const zero = await processTrace(
    { ...request, paths: ["."], max_hops: 0 },
    async () => finished(file("candidate")),
    1,
  );
  assert.deepEqual(zero.frontier, [file("candidate")]);
  assert.equal(zero.complete, false);
  let terminated = false;
  const result = await processTrace(
    { ...request, time_budget_ms: 80 },
    async ({ path }, stop) => {
      if (path === "a")
        return {
          ...finished(),
          evidence: [declaration("observed", "dependency")],
        };
      await new Promise<void>((resolve) =>
        stop.addEventListener(
          "abort",
          () => {
            terminated = true;
            resolve();
          },
          { once: true },
        ),
      );
      return finished();
    },
    1,
  );
  assert.equal(terminated, true);
  assert.deepEqual(result.limits, ["time budget"]);
  assert.equal(result.scopes[0].evidence.length, 1);
  assert.equal(result.scopes[1].complete, false);
});

test("a full text sample leaves room for structural evidence", async () => {
  const textMatches = Array.from({ length: 200 }, (_, index) => ({
    source: "registry.ts",
    text: "dependency",
    line: index + 1,
  }));
  const dependency = declaration("package.json", "dependency");
  const result = await processTrace(
    { ...request, paths: ["."] },
    async ({ kind }) =>
      kind === "search"
        ? { ...finished(file("package.json")), textMatches }
        : { ...finished(), evidence: [dependency] },
    1,
  );
  assert.deepEqual(result.limits, ["text match limit"]);
  assert.equal(result.scopes[0].textMatches?.length, 128);
  assert.equal(result.scopes[0].complete, false);
  assert.deepEqual(result.scopes[1].evidence, [dependency]);
  assert.equal(result.scopes[1].complete, true);
});

test("a cycle reaching the hop boundary does not hide completed coverage", async () => {
  const result = await processTrace(
    { ...request, paths: ["."], max_hops: 1 },
    async (scope) =>
      scope.kind === "search"
        ? finished(file("child"))
        : finished({ kind: "search", package: "sample", path: "." }),
    1,
  );
  assert.equal(result.complete, true);
  assert.deepEqual(result.frontier, []);
});

test("only unchanged file evidence is reused, and only within a single check", async () => {
  let revision = "original";
  let reads = 0;
  const provider = {
    fingerprint: async (scope: TraceScope) =>
      scope.kind === "file" ? revision : undefined,
    async run(scope: TraceScope) {
      if (scope.kind === "search") return finished(file("manifest"));
      reads++;
      return {
        ...finished(),
        fingerprint: revision,
        evidence: [declaration("manifest", revision)],
      };
    },
  };
  async function check(tracer: ReturnType<typeof createDependencyTracer>) {
    const result = await tracer.trace({ ...request, paths: ["."] });
    assert.deepEqual(result.scopes[1].evidence, [
      declaration("manifest", revision),
    ]);
    assert.ok(result.complete);
  }
  const first = createDependencyTracer(".", provider);
  try {
    await check(first);
    await check(first);
    assert.equal(reads, 1);
    revision = "edited";
    await check(first);
    assert.equal(reads, 2);
  } finally {
    await first.close();
  }
  const second = createDependencyTracer(".", provider);
  try {
    await check(second);
    assert.equal(reads, 3);
  } finally {
    await second.close();
  }
});

test("a check shares its CPU and memory slots across simultaneous traces", async () => {
  const GiB = 1024 ** 3;
  for (const [threads, bytes, expected] of [
    [1, 8 * GiB, 1],
    [8, 8 * GiB, 8],
    [8, GiB, 2],
    [8, 0, 1],
  ]) {
    let active = 0;
    let peak = 0;
    const tracer = createDependencyTracer(
      ".",
      {
        async run() {
          peak = Math.max(peak, ++active);
          await new Promise<void>((resolve) => setImmediate(resolve));
          active--;
          return finished();
        },
      },
      traceConcurrency(threads, bytes),
    );
    const paths = Array.from({ length: 12 }, (_, i) => String(i));
    try {
      for (const simultaneous of [1, 2]) {
        peak = 0;
        const reports = await Promise.all(
          Array.from({ length: simultaneous }, () =>
            tracer.trace({ ...request, paths }),
          ),
        );
        assert.equal(peak, expected);
        assert.ok(
          reports.every(
            (report) =>
              report.complete && report.scopes.length === paths.length,
          ),
        );
      }
    } finally {
      await tracer.close();
    }
  }
});
