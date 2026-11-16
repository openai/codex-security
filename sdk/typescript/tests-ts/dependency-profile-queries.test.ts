import { afterEach, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDependencyEndpoints } from "../src/dependency-endpoints.js";
import { evidenceHash } from "../src/dependency-evidence-store.js";
import {
  createDependencyProfileEvidence,
  dependencyProfileToolSchema,
  type DependencyProfileQuery,
} from "../src/dependency-profile-evidence.js";

const directories: string[] = [];
async function directory() {
  const path = await mkdtemp(join(tmpdir(), "profile-query-test-"));
  directories.push(path);
  return path;
}
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});
const window = {
  start: "2026-01-01T00:00:00.000Z",
  end: "2026-01-01T00:05:00.000Z",
};
const selector = { cluster: "cluster-a", service: "frontend" };
const pair = {
  kind: "pair",
  sources: [{ name: "handle" }],
  sinks: [{ name: "decode" }],
};
const request = { selector, window, limit: 20, query: pair };
const frame = (name: string, location = `${name}.py:10`) => ({
  kind: "function",
  name,
  attributes: {
    name,
    language: "python",
    location,
    binary: "/app/python",
    build_id: "build-1",
    build_hash: "hash-1",
    offset: "0",
  },
});
const observation = (index: number, names = ["handle", "decode"]) => ({
  id: `stack-${index}`,
  kind: "sampled_stack",
  scope: {
    ...selector,
    container: "worker",
    observed_image: { name: "registry/example", tag: "build-a" },
    window,
    stack_key: index.toString(16).padStart(64, "0"),
    profile_rows: 1,
  },
  frames: names.map((name) => frame(name)),
});
type Observation = ReturnType<typeof observation>;
type PageOptions = {
  next?: string;
  partial?: boolean | null;
  wrongScope?: boolean;
  wrongHash?: boolean;
  wrongChild?: boolean;
  missingAsyncContext?: boolean;
  measurement?: { status: string; counts: Record<string, number> };
};
function provider(
  respond: (query: DependencyProfileQuery) => {
    rows: Observation[];
    options?: PageOptions;
  },
) {
  const resources = new Map<string, string>();
  const calls: DependencyProfileQuery[] = [];
  const captured: {
    query: DependencyProfileQuery;
    collectionId: string;
    resource: string;
  }[] = [];
  return {
    calls,
    captured,
    options: {
      providerKey: "fixture/ordered-profiles/v1",
      authorize(_query: DependencyProfileQuery) {},
      async lookup(query: DependencyProfileQuery) {
        calls.push(query);
        const { rows, options = {} } = respond(query);
        const partial = options.partial === undefined ? false : options.partial;
        const truncated = Boolean(options.next);
        const complete = partial === false && !truncated && !query.cursor;
        const text = JSON.stringify({
          format: "codex-security-graph-evidence/v1",
          frame_order: "root_first",
          metadata: {
            scope: {
              ...query.selector,
              ...query.window,
              frame_match: query.query
                ? "ordered_exact_selectors"
                : "any_exact_name",
              ...(query.query
                ? {
                    query: options.wrongChild
                      ? {
                          ...query.query,
                          child: {
                            ...query.query.child,
                            stack_id: "foreign-child",
                          },
                        }
                      : query.query,
                  }
                : {}),
              ...(options.wrongScope ? { service: "foreign" } : {}),
            },
            coverage: {
              result_complete: complete,
              backend_partial: partial,
              returned_stack_count: rows.length,
              returned_profile_row_count: rows.reduce(
                (sum, row) => sum + row.scope.profile_rows,
                0,
              ),
              total_workload_profile_row_count: null,
              identity_mismatch_count: 0,
            },
            limits: { stack_limit: query.limit, truncated },
            ...(query.query
              ? {
                  pagination: {
                    order: "stack_key_ascending",
                    cursor: query.cursor ?? null,
                    next_cursor: options.next ?? null,
                    snapshot_pinned: false,
                    query_exhausted: partial === false && !truncated,
                  },
                }
              : {}),
            status: rows.length ? "found_stacks" : "telemetry_unknown",
            ...(options.measurement
              ? { measurement: options.measurement }
              : {}),
            ...(query.query?.kind === "async_parent"
              ? {
                  join_basis: "inferred_from_creator_code_and_observed_build",
                  instance_correlation_verified: false,
                }
              : {}),
          },
          observations: rows.map((row) => ({
            ...row,
            scope: {
              ...row.scope,
              window: query.window,
              ...(query.query?.kind === "async_parent" &&
              !options.missingAsyncContext
                ? {
                    async_context: {
                      join_basis:
                        "inferred_from_creator_code_and_observed_build",
                      instance_correlation_verified: false,
                      child: query.query.child,
                      creator_code_evidence: query.query.evidence,
                      taint_dependencies: query.query.taint_dependencies,
                    },
                  }
                : {}),
            },
          })),
        });
        const hash = evidenceHash(text);
        const uri = `profile-fixture://${hash}`;
        resources.set(uri, text);
        return {
          graph_evidence: {
            format: "codex-security-graph-evidence/v1",
            uri,
            sha256: options.wrongHash ? "f".repeat(64) : hash,
          },
        };
      },
      async readResource(uri: string) {
        return resources.get(uri)!;
      },
      recordCollection(value: {
        query: DependencyProfileQuery;
        collectionId: string;
        resource: string;
      }) {
        captured.push(value);
        return `receipt-${value.collectionId}`;
      },
    },
  };
}

test("structured profile schema stays an object and passes ordered selectors intact", async () => {
  expect(dependencyProfileToolSchema["type"]).toBe("object");
  const backend = provider(() => ({ rows: [observation(1)] }));
  const profiles = createDependencyProfileEvidence({
    directory: await directory(),
    ...backend.options,
  });
  const result = await profiles.collect(request);
  expect(result.uncovered).toEqual([]);
  expect(backend.calls[0]).toMatchObject({
    selector: { ...selector, frames: ["decode"] },
    query: pair,
  });
  expect(result.slices).toMatchObject([
    { stackCount: 1, pageChainComplete: true },
  ]);
});

test("follows a page chain outside model context, caches all pages and keeps original row receipts", async () => {
  const path = await directory();
  const backend = provider((query) =>
    query.cursor
      ? { rows: [observation(3)] }
      : { rows: [observation(1), observation(2)], options: { next: "tail" } },
  );
  const profiles = createDependencyProfileEvidence({
    directory: path,
    ...backend.options,
  });
  const result = await profiles.collect({ ...request, limit: 2 });
  expect(result.uncovered).toEqual([]);
  expect(backend.calls.map(({ cursor }) => cursor)).toEqual([
    undefined,
    "tail",
  ]);
  expect(backend.captured).toHaveLength(2);
  const collectionId = result.slices[1]!.collectionId!;
  expect(
    profiles.witnesses({
      collectionId,
      searchId: result.searchId,
      firstRow: 1,
      lastRow: 1,
    }),
  ).toMatchObject([
    {
      row: 1,
      receiptSelection: { record: ["observations", 0] },
      frames: [{ name: "handle" }, { name: "decode" }],
    },
  ]);
  const reopened = createDependencyProfileEvidence({
    directory: path,
    ...backend.options,
  });
  const again = await reopened.collect({ ...request, limit: 100 });
  expect(again.uncovered).toEqual([]);
  expect(again.slices).toHaveLength(2);
  expect(again.slices.every(({ cached }) => cached)).toBe(true);
  expect(backend.calls).toHaveLength(2);
});

test("a complete cached sink population answers a fresh pair without another backend query", async () => {
  const path = await directory();
  const backend = provider(() => ({
    rows: [
      observation(1, ["other", "decode"]),
      observation(2),
      observation(3, ["decode", "handle"]),
    ],
  }));
  await createDependencyProfileEvidence({
    directory: path,
    ...backend.options,
  }).collect({
    ...request,
    query: { kind: "sink", sinks: [{ name: "decode" }] },
  });
  const profiles = createDependencyProfileEvidence({
    directory: path,
    ...backend.options,
  });
  const result = await profiles.collect({ ...request, limit: 1 });
  expect(backend.calls).toHaveLength(1);
  expect(result.slices).toMatchObject([
    {
      sourcePopulationReuse: true,
      stackCount: 1,
      populationStackCount: 3,
      cached: true,
    },
  ]);
  expect(result.slices).toMatchObject([
    { profileSampleCount: 1, populationProfileSampleCount: 3 },
  ]);
  const collectionId = result.slices[0]!.collectionId!;
  expect(
    profiles.witnesses({
      collectionId,
      searchId: result.searchId,
      firstRow: 1,
      lastRow: 1,
    }),
  ).toMatchObject([
    {
      row: 2,
      matchOrdinal: 1,
      receiptSelection: { record: ["observations", 1] },
    },
  ]);
  expect(
    profiles.assess({
      findings: [
        {
          id: "matched",
          assessed: [{ collectionId, firstRow: 2, lastRow: 2 }],
        },
      ],
    }).unassessed,
  ).toEqual([]);
});

test("local pair reuse labels sink-population measurements separately from pair matches", async () => {
  const row = observation(1, ["other", "decode"]);
  row.scope.profile_rows = 3;
  const backend = provider(() => ({
    rows: [row],
    options: {
      measurement: {
        status: "complete",
        counts: { matching_profile_row_count: 3, matching_stack_count: 1 },
      },
    },
  }));
  const profiles = createDependencyProfileEvidence({
    directory: await directory(),
    ...backend.options,
  });
  await profiles.collect({
    ...request,
    measure: true,
    query: { kind: "sink", sinks: [{ name: "decode" }] },
  });
  const result = await profiles.collect({ ...request, measure: true });
  expect(backend.calls).toHaveLength(1);
  expect(result.slices).toMatchObject([
    {
      stackCount: 0,
      profileSampleCount: 0,
      populationProfileSampleCount: 3,
      localPairStatus: "no_matching_pair_in_complete_saved_population",
      populationMeasurement: {
        counts: { matching_profile_row_count: 3, matching_stack_count: 1 },
      },
    },
  ]);
  expect(result.slices[0]).not.toHaveProperty("measurement");
  expect(result.slices[0]).not.toHaveProperty("providerStatus");
});

test("an incomplete sink-only top20 cannot answer a pair negatively", async () => {
  const backend = provider((query) =>
    query.query?.kind === "pair"
      ? { rows: [observation(99)] }
      : {
          rows: Array.from({ length: 20 }, (_, i) =>
            observation(i + 1, ["other", "decode"]),
          ),
          options: { partial: true, next: "truncated" },
        },
  );
  const profiles = createDependencyProfileEvidence({
    directory: await directory(),
    ...backend.options,
  });
  const seed = await profiles.collect({
    ...request,
    query: { kind: "sink", sinks: [{ name: "decode" }] },
  });
  expect(seed.uncovered).toEqual([window]);
  const found = await profiles.collect(request);
  expect(backend.calls).toHaveLength(2);
  expect(backend.calls[1]?.query?.kind).toBe("pair");
  expect(found.slices).toMatchObject([{ stackCount: 1, cached: false }]);
});

test("exact receipt reuse preserves unknown coverage on an earlier page", async () => {
  const backend = provider((query) =>
    query.cursor
      ? { rows: [observation(2)] }
      : { rows: [observation(1)], options: { partial: null, next: "tail" } },
  );
  const profiles = createDependencyProfileEvidence({
    directory: await directory(),
    ...backend.options,
  });
  expect((await profiles.collect({ ...request, limit: 1 })).uncovered).toEqual([
    window,
  ]);
  expect((await profiles.collect({ ...request, limit: 1 })).uncovered).toEqual([
    window,
  ]);
  expect(backend.calls).toHaveLength(2);
  expect(backend.captured).toHaveLength(2);
  await profiles.collect({
    ...request,
    limit: 1,
    query: { ...pair, sources: [{ name: "other-source" }] },
  });
  expect(backend.calls).toHaveLength(3);
});

test("repeated cursors, rows and resource hash mismatches never complete a collection", async () => {
  for (const mode of ["cursor", "row", "hash"]) {
    const backend = provider((query) => ({
      rows: [observation(query.cursor && mode !== "row" ? 2 : 1)],
      options: mode === "hash" ? { wrongHash: true } : { next: "repeat" },
    }));
    const profiles = createDependencyProfileEvidence({
      directory: await directory(),
      ...backend.options,
    });
    const result = await profiles.collect({ ...request, limit: 1 });
    expect(result.uncovered).toEqual([window]);
    expect(result.slices.at(-1)).toMatchObject({ outcome: "failed" });
    expect(backend.calls.length).toBeLessThanOrEqual(2);
  }
});

test("rejects wrong ancestry and accidental cross-rule pairs from a provider", async () => {
  for (const query of [
    pair,
    {
      kind: "pair",
      rules: [
        { sources: [{ name: "source_a" }], sinks: [{ name: "sink_a" }] },
        { sources: [{ name: "source_b" }], sinks: [{ name: "sink_b" }] },
      ],
    },
  ]) {
    const backend = provider(() => ({
      rows: [
        observation(
          1,
          "rules" in query ? ["source_a", "sink_b"] : ["decode", "handle"],
        ),
      ],
    }));
    const profiles = createDependencyProfileEvidence({
      directory: await directory(),
      ...backend.options,
    });
    const result = await profiles.collect({ ...request, query });
    expect(result.slices).toMatchObject([{ outcome: "failed" }]);
    expect(backend.captured).toHaveLength(0);
  }
});

test("internal workload/window and supplied endpoint sides constrain host requests", async () => {
  const endpoints = await openDependencyEndpoints({
    configuration: {
      sources: [
        {
          id: "source",
          function: "app.handle",
          runtime_selectors: [{ name: "handle" }],
        },
      ],
      sinks: [
        {
          id: "sink",
          function: "codec.decode",
          runtime_selectors: [{ name: "decode" }],
        },
      ],
    },
    runtimeScope: { ...selector, window, image_tag: "build-a" },
  });
  await endpoints.record({
    endpoint: {
      id: "other-source",
      role: "source",
      function: "other",
      runtime_selectors: [{ name: "other" }],
    },
  });
  const backend = provider(() => ({ rows: [observation(1)] }));
  const profiles = createDependencyProfileEvidence({
    directory: await directory(),
    ...backend.options,
    endpointGraph: () => endpoints,
  });
  const input = {
    endpoints: { sources: ["source"], sinks: ["sink"] },
    limit: 20,
  };
  const result = await profiles.collect(input);
  expect(result.uncovered).toEqual([]);
  expect(backend.calls[0]?.selector).toMatchObject({
    ...selector,
    image_tag: "build-a",
    frames: ["decode"],
  });
  for (const value of [
    { ...input, selector: { service: "other" } },
    { ...input, window: { ...window, end: "2026-01-01T01:00:00.000Z" } },
    request,
  ])
    await expect(profiles.collect(value)).rejects.toThrow();
  const gap = await profiles.collect({
    ...input,
    endpoints: { sources: ["other-source"], sinks: ["sink"] },
  });
  expect(gap).toMatchObject({
    status: "unresolved_endpoints",
    endpointGaps: [{ endpoint_id: "other-source" }],
  });
  expect(backend.calls).toHaveLength(1);
});

test("unknown endpoint mappings remain visible while valid same-rule subsets proceed", async () => {
  const endpoints = await openDependencyEndpoints({
    configuration: {
      sources: [
        {
          id: "known",
          function: "handle",
          runtime_selectors: [{ name: "handle" }],
        },
        { id: "unresolved", function: "alias.handle" },
      ],
      sinks: [
        {
          id: "sink",
          function: "decode",
          runtime_selectors: [{ name: "decode" }],
        },
      ],
    },
    runtimeScope: { ...selector, window },
  });
  const backend = provider(() => ({ rows: [observation(1)] }));
  const profiles = createDependencyProfileEvidence({
    directory: await directory(),
    ...backend.options,
    endpointGraph: () => endpoints,
  });
  const result = await profiles.collect({
    endpoints: { sources: ["known", "unresolved"], sinks: ["sink"] },
    limit: 20,
  });
  expect(result).toMatchObject({
    endpointGaps: [{ endpoint_id: "unresolved" }],
  });
  expect(backend.calls[0]?.query?.sources).toEqual([{ name: "handle" }]);
});

test("registered cache-writer discovery stays queryable without widening supplied final endpoints", async () => {
  const endpoints = await openDependencyEndpoints({
    configuration: {
      sources: [
        {
          id: "source",
          function: "handle",
          runtime_selectors: [{ name: "handle" }],
        },
      ],
      sinks: [
        {
          id: "sink",
          function: "decode",
          runtime_selectors: [{ name: "decode" }],
        },
      ],
    },
    runtimeScope: { ...selector, window },
  });
  await endpoints.record({
    endpoint: {
      id: "writer",
      role: "intermediate",
      function: "cache.write",
      runtime_selectors: [{ name: "write" }],
      relationships: [{ kind: "writes_cache", endpoint_id: "sink" }],
    },
  });
  const backend = provider(() => ({
    rows: [observation(1, ["handle", "write"])],
  }));
  const profiles = createDependencyProfileEvidence({
    directory: await directory(),
    ...backend.options,
    endpointGraph: () => endpoints,
  });
  const result = await profiles.collect({
    endpoints: { kind: "discovery", sinks: ["writer"] },
    limit: 20,
  });
  expect(result.uncovered).toEqual([]);
  expect(result).toMatchObject({
    endpoints: { kind: "discovery", sinks: ["writer"] },
  });
  expect(backend.calls[0]?.query).toMatchObject({
    kind: "discovery",
    sinks: [{ name: "write" }],
    sources: [],
  });
  expect(endpoints.isBoundaryEndpoint("writer", "sink")).toBe(false);
  const refused = await profiles.collect({
    endpoints: { sources: ["source"], sinks: ["writer"] },
    limit: 20,
  });
  expect(refused).toMatchObject({
    status: "unresolved_endpoints",
    endpointGaps: [{ endpoint_id: "writer" }],
  });
  expect(backend.calls).toHaveLength(1);
});

test("qualified requested names are preserved while observed type/file/line/build are independently checked", async () => {
  const query = {
    kind: "sink",
    sinks: [
      {
        name: "library.decode",
        observed_name: "decode",
        frame_type: "python",
        location: "decode.py",
        binary: "python",
        line: 10,
        build_id: "build-1",
      },
    ],
  };
  const backend = provider(() => ({ rows: [observation(1)] }));
  const profiles = createDependencyProfileEvidence({
    directory: await directory(),
    ...backend.options,
  });
  expect((await profiles.collect({ ...request, query })).uncovered).toEqual([]);
  expect(backend.calls[0]?.query?.sinks[0]).toMatchObject({
    name: "library.decode",
    observed_name: "decode",
  });
  const bad = await profiles.collect({
    ...request,
    query: { ...query, sinks: [{ ...query.sinks[0], line: 11 }] },
  });
  expect(bad.slices).toMatchObject([{ outcome: "failed" }]);
});

test("foreign workload or image rows do not enter the graph as matching evidence", async () => {
  for (const scope of [
    { service: "foreign" },
    { observed_image: { name: "registry/example", tag: "foreign-build" } },
  ]) {
    const row = observation(1);
    Object.assign(row.scope, scope);
    const backend = provider(() => ({ rows: [row] }));
    const profiles = createDependencyProfileEvidence({
      directory: await directory(),
      ...backend.options,
    });
    const result = await profiles.collect({
      ...request,
      selector: { ...selector, image_tag: "build-a" },
    });
    expect(result.slices).toMatchObject([{ outcome: "failed" }]);
    expect(backend.captured).toHaveLength(0);
  }
});

test("large stack resources stay outside collection replies and identical concurrent requests share work", async () => {
  const rows = Array.from({ length: 100 }, (_, i) =>
    observation(i + 1, [
      "handle",
      ...Array.from({ length: 100 }, (_, j) => `internal_${j}`),
      "decode",
    ]),
  );
  const backend = provider(() => ({ rows }));
  const profiles = createDependencyProfileEvidence({
    directory: await directory(),
    ...backend.options,
  });
  const [one, two] = await Promise.all([
    profiles.collect({ ...request, limit: 100 }),
    profiles.collect({ ...request, limit: 100 }),
  ]);
  expect(one).toEqual(two);
  expect(backend.calls).toHaveLength(1);
  expect(JSON.stringify(one)).not.toContain("internal_");
  expect(backend.captured[0]!.resource.length).toBeGreaterThan(
    JSON.stringify(one).length * 100,
  );
});

test("async follow-ups reuse exact child references and keep the inference caveat on each witness", async () => {
  let mode: "valid" | "child" | "caveat" = "valid";
  const backend = provider((query) =>
    query.query?.kind === "async_parent"
      ? {
          rows: [observation(2, ["handle", "create"])],
          options: {
            wrongChild: mode === "child",
            missingAsyncContext: mode === "caveat",
          },
        }
      : { rows: [observation(1)] },
  );
  const profiles = createDependencyProfileEvidence({
    directory: await directory(),
    ...backend.options,
  });
  const initial = await profiles.collect(request);
  const witness = profiles.witnesses({
    collectionId: initial.slices[0]!.collectionId,
    firstRow: 1,
    lastRow: 1,
  })[0]!;
  const followup = {
    selector,
    window,
    limit: 20,
    query: {
      kind: "async_parent",
      sinks: [{ name: "create", location: "create.py", line: 10 }],
      child: witness.childReference,
      evidence: ["source:create.py:10"],
      taint_dependencies: ["task payload reaches decode"],
    },
  };
  const result = await profiles.collect(followup);
  expect(result.uncovered).toEqual([]);
  expect(backend.calls[1]?.selector).toMatchObject({
    image_name: "registry/example",
    image_tag: "build-a",
  });
  expect(result.slices).toMatchObject([
    {
      joinBasis: "inferred_from_creator_code_and_observed_build",
      instanceCorrelationVerified: false,
    },
  ]);
  const parent = profiles.witnesses({
    collectionId: result.slices[0]!.collectionId,
    firstRow: 1,
    lastRow: 1,
  })[0]!;
  expect(parent.scope["async_context"]).toMatchObject({
    instance_correlation_verified: false,
    child: witness.childReference,
  });
  await expect(
    profiles.collect({
      ...followup,
      selector: { ...selector, image_tag: "foreign" },
    }),
  ).rejects.toThrow("captured child");
  for (const kind of ["child", "caveat"] as const) {
    mode = kind;
    const current = createDependencyProfileEvidence({
      directory: await directory(),
      ...backend.options,
    });
    const rejected = await current.collect({
      ...followup,
      selector: {
        ...selector,
        image_name: "registry/example",
        image_tag: "build-a",
      },
    });
    expect(rejected.slices).toMatchObject([{ outcome: "failed" }]);
  }
});

test("changed async creator evidence and data dependencies receive fresh inference contexts", async () => {
  const backend = provider((query) => ({
    rows: [
      observation(
        query.query?.kind === "async_parent" ? 2 : 1,
        query.query?.kind === "async_parent"
          ? ["handle", "create"]
          : ["handle", "decode"],
      ),
    ],
    options: { partial: null },
  }));
  const profiles = createDependencyProfileEvidence({
    directory: await directory(),
    ...backend.options,
  });
  const seed = await profiles.collect(request);
  const child = profiles.witnesses({
    collectionId: seed.slices[0]!.collectionId,
    firstRow: 1,
    lastRow: 1,
  })[0]!.childReference;
  const followup = {
    selector,
    window,
    limit: 20,
    query: {
      kind: "async_parent",
      sinks: [{ name: "create", location: "create.py", line: 10 }],
      child,
      evidence: ["source-receipt-A"],
      taint_dependencies: ["path-A"],
    },
  };
  const first = await profiles.collect(followup);
  const second = await profiles.collect({
    ...followup,
    query: {
      ...followup.query,
      evidence: ["source-receipt-B"],
      taint_dependencies: ["path-B"],
    },
  });
  expect(backend.calls).toHaveLength(3);
  expect(first.searchId).not.toBe(second.searchId);
  expect(second.slices).toMatchObject([{ cached: false }]);
  const witness = profiles.witnesses({
    collectionId: second.slices[0]!.collectionId,
    firstRow: 1,
    lastRow: 1,
  })[0]!;
  expect(witness.scope["async_context"]).toMatchObject({
    creator_code_evidence: ["source-receipt-B"],
    taint_dependencies: ["path-B"],
  });
  const repeated = await profiles.collect({
    ...followup,
    query: {
      ...followup.query,
      evidence: ["source-receipt-B"],
      taint_dependencies: ["path-B"],
    },
  });
  expect(backend.calls).toHaveLength(3);
  expect(repeated).toMatchObject({ exactQueryReceiptReuse: true });
  expect(repeated.uncovered).toEqual([window]);
  expect(repeated.slices[0]?.receiptId).toBe(second.slices[0]?.receiptId);
});

test("exact successful partial requests reuse their original receipt and preserve unknown coverage", async () => {
  const backend = provider(() => ({
    rows: [observation(1)],
    options: { partial: null },
  }));
  const profiles = createDependencyProfileEvidence({
    directory: await directory(),
    ...backend.options,
  });
  const first = await profiles.collect(request);
  const repeated = await profiles.collect(request);
  expect(backend.calls).toHaveLength(1);
  expect(backend.captured).toHaveLength(1);
  expect(repeated).toMatchObject({
    searchId: first.searchId,
    exactQueryReceiptReuse: true,
    slices: [{ outcome: "incomplete", cached: true, backendPartial: null }],
    uncovered: [window],
  });
  expect(repeated.slices[0]?.receiptId).toBe(first.slices[0]?.receiptId);
  expect(profiles.assess({ findings: [] }).unassessed).toHaveLength(1);
  // A caller cannot mutate the saved receipt into a false coverage claim.
  repeated.uncovered.length = 0;
  expect((await profiles.collect(request)).uncovered).toEqual([window]);
  expect(backend.calls).toHaveLength(1);
  await profiles.collect({ ...request, limit: 21 });
  await profiles.collect({ ...request, measure: true });
  expect(backend.calls).toHaveLength(3);
  const original = profiles.witnesses({
    collectionId: first.slices[0]!.collectionId,
    searchId: first.searchId,
    firstRow: 1,
    lastRow: 1,
  });
  expect(original).toHaveLength(1);
  expect(original[0]?.receiptSelection.receiptId).toBe(
    first.slices[0]?.receiptId,
  );
  expect((await profiles.collect(request)).searchId).toBe(first.searchId);
});

test("changed workload selectors cannot reuse an exact partial receipt", async () => {
  const backend = provider((query) => {
    const row = observation(1);
    row.scope.service = query.selector.service!;
    return { rows: [row], options: { partial: null } };
  });
  const profiles = createDependencyProfileEvidence({
    directory: await directory(),
    ...backend.options,
  });
  const first = await profiles.collect(request);
  const second = await profiles.collect({
    ...request,
    selector: { ...selector, service: "other-frontend" },
  });
  expect(backend.calls).toHaveLength(2);
  expect(second.searchId).not.toBe(first.searchId);
  expect(second.slices).toMatchObject([
    { outcome: "incomplete", cached: false },
  ]);
});

test("failed requests do not enter the successful exact receipt cache", async () => {
  let failed = true;
  const backend = provider(() => {
    if (failed) throw new Error("provider read failed");
    return { rows: [observation(1)], options: { partial: null } };
  });
  const profiles = createDependencyProfileEvidence({
    directory: await directory(),
    ...backend.options,
  });
  expect((await profiles.collect(request)).slices).toMatchObject([
    { outcome: "failed" },
  ]);
  failed = false;
  expect((await profiles.collect(request)).slices).toMatchObject([
    { outcome: "incomplete", cached: false },
  ]);
  expect((await profiles.collect(request)).slices).toMatchObject([
    { outcome: "incomplete", cached: true },
  ]);
  expect(backend.calls).toHaveLength(2);
  expect(backend.captured).toHaveLength(1);
});

test("failed scoped measurements remain retryable while their observed stacks stay retained", async () => {
  let failed = true;
  const backend = provider(() => ({
    rows: [observation(1)],
    options: {
      partial: null,
      measurement: { status: failed ? "failed" : "complete", counts: {} },
    },
  }));
  const profiles = createDependencyProfileEvidence({
    directory: await directory(),
    ...backend.options,
  });
  const measured = { ...request, measure: true };
  const first = await profiles.collect(measured);
  expect(first.slices).toMatchObject([
    { outcome: "incomplete", stackCount: 1 },
  ]);
  failed = false;
  await profiles.collect(measured);
  expect(backend.calls).toHaveLength(2);
  expect(await profiles.collect(measured)).toMatchObject({
    exactQueryReceiptReuse: true,
  });
  expect(backend.calls).toHaveLength(2);
});
