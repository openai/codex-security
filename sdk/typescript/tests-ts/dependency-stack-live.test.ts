import { expect, test } from "bun:test";
import { join } from "node:path";
import { mkdir } from "node:fs/promises";
import { DependencyAttemptStore } from "../src/dependency/attempt-store.js";
import {
  getLiveRun,
  initializeLive,
  liveMetadataGaps,
  livePacket,
  overlayPacket,
  recordObservations,
  supplementalReceipt,
} from "../src/dependency/analyzers/stacks/live.js";
import { stackPacketWorkItems } from "../src/dependency/analyzers/stacks/packet.js";
import {
  prepareRuntimeEvidence,
  readRuntimeStackQueries,
  saveRuntimeEvidence,
} from "../src/dependency/analyzers/stacks/runtime-receipts.js";
import { git } from "./git-fixture.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

async function liveFixture(root: string) {
  const repo = join(root, "target");
  await mkdir(repo);
  git(repo, "init", "--quiet");
  git(
    repo,
    "-c",
    "commit.gpgSign=false",
    "commit",
    "--allow-empty",
    "--quiet",
    "-m",
    "Fixture",
  );
  const store = new DependencyAttemptStore(join(root, "state.sqlite"));
  const sink = {
    id: "decode",
    function: "decode",
    package: "sample",
    versionScheme: "semver",
    affectedVersions: ["<2"],
    preconditions: [],
  };
  const imported = async (result: unknown) =>
    saveRuntimeEvidence(
      store,
      await prepareRuntimeEvidence(
        { kind: "runtime", server: "fixture", tool: "profiles", result },
        repo,
      ),
    );
  const record = (input: unknown) =>
    store.transaction(() => recordObservations(store, input));
  return { repo, store, sink, imported, record };
}

test("interactive attempts pin a revision before advisory metadata is known, then add observations without replacing prior work", async () => {
  await using dir = await scopedTemporaryDirectory("stack-live-");
  const { repo, store, sink, imported, record } = await liveFixture(dir.path);
  try {
    const started = await initializeLive(store, repo);
    expect(started.target.sha).toBe(git(repo, "rev-parse", "HEAD"));
    expect(liveMetadataGaps(store)).toHaveLength(4);
    expect(() => livePacket(store)).toThrow("metadata is incomplete");
    const updated = await initializeLive(store, repo, {
      repository: "example/decoder",
      cve: "CVE-2099-0001",
      advisory: {
        url: "https://example.invalid/advisory",
        summary: "Fixture advisory",
      },
      sinks: [sink],
    });
    expect(updated.inputDigest).toBe(started.inputDigest);
    expect(updated.target.repository).toBe("example/decoder");
    expect(getLiveRun(store)?.runId).toBe(started.runId);
    const base = livePacket(store);
    const query = {
      id: "query",
      scope: {
        service: "sample",
        window: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" },
      },
      selectors: { sources: [], sinks: ["decode"] },
      groups: [
        {
          id: "page-1",
          status: "no_match",
          truncated: false,
          observations: [],
        },
      ],
    };
    const page2 = { ...query, groups: [{ ...query.groups[0], id: "page-2" }] };
    const receipt = await imported({ queries: [query, page2] });
    expect(record({ receiptId: receipt.receiptId, queries: [query] })).toEqual({
      workItemIds: ["query/page-1"],
    });
    expect(record({ receiptId: receipt.receiptId, queries: [page2] })).toEqual({
      workItemIds: ["query/page-2"],
    });
    const items = stackPacketWorkItems(overlayPacket(store, base));
    expect(items.map((item) => item.id)).toEqual([
      "query/page-1",
      "query/page-2",
    ]);
    expect(supplementalReceipt(store, items[0]!)?.sha256).toMatch(
      /^[0-9a-f]{64}$/,
    );
    expect(() =>
      record({ receiptId: receipt.receiptId, queries: [query] }),
    ).toThrow("already recorded");
    await expect(
      initializeLive(store, repo, { cve: "CVE-2099-0002" }),
    ).rejects.toThrow("already recorded differently");
  } finally {
    store.close();
  }
});

test("supplemental observations normalize graph frame order and preserve capture metadata", async () => {
  await using dir = await scopedTemporaryDirectory("stack-live-provenance-");
  const { repo, store, sink, imported, record } = await liveFixture(dir.path);
  const window = { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" };
  try {
    await initializeLive(store, repo, {
      cve: "CVE-2099-0001",
      advisory: { url: "https://example.invalid/advisory", summary: "Fixture" },
      sinks: [sink],
    });
    const graph = {
      format: "codex-security-graph-evidence/v1",
      frame_order: "root_first",
      metadata: {
        clickhouse_query_id: "query-id",
        scope: {
          cluster: "cluster",
          service: "sample",
          start: window.start,
          end: window.end,
          query: {
            kind: "pair",
            sources: [{ name: "request" }],
            sinks: [{ name: "decode" }],
          },
        },
        coverage: { result_complete: true },
        limits: { truncated: false },
      },
      observations: [
        {
          id: "call",
          kind: "sampled_stack",
          scope: {
            cluster: "cluster",
            service: "sample",
            container: "app",
            observed_image: { name: "registry.example/image", tag: "v1" },
            window,
            stack_key: "opaque-stack-key",
            matches: {
              frame_order: "root_first",
              rules: [
                {
                  rule_index: 0,
                  sources: [{ selector_index: 0, frame_index: 0 }],
                  sinks: [{ selector_index: 0, frame_index: 1 }],
                  ordered_pairs: [
                    {
                      sink: { selector_index: 0, frame_index: 1 },
                      source_ancestors: [{ selector_index: 0, frame_index: 0 }],
                    },
                  ],
                  matched: true,
                },
              ],
              matched: true,
            },
          },
          frames: [
            {
              kind: "function",
              name: "request",
              attributes: {
                name: "request",
                language: "javascript",
                offset: "",
              },
            },
            {
              kind: "function",
              name: "decode",
              attributes: {
                name: "decode",
                language: "javascript",
                offset: "0",
              },
            },
          ],
        },
      ],
    };
    const resource = await imported(graph);
    const normalize = (receipt: { receiptId: string }) =>
      readRuntimeStackQueries(store, receipt.receiptId, [sink])[0]!;
    const observation = normalize(resource).groups[0]!.observations[0]!;
    expect(observation.frames.map((frame) => frame.name)).toEqual([
      "decode",
      "request",
    ]);
    expect(observation).toMatchObject({
      sinkIndex: 0,
      sourceIndex: 1,
      sinkMatches: [{ sinkId: "decode", rawIndex: 0 }],
      framesTruncated: false,
      scope: { image_name: "registry.example/image", image_tag: "v1" },
    });
    expect(observation.scope).not.toHaveProperty("image_digest");
    const unlabeledGraph = structuredClone(graph);
    unlabeledGraph.observations[0]!.scope.observed_image = {
      name: "",
      tag: "",
    };
    const unlabeledReceipt = await imported(unlabeledGraph);
    expect(
      normalize(unlabeledReceipt).groups[0]!.observations[0]!.scope,
    ).toEqual({ cluster: "cluster", service: "sample", container: "app" });
    const wrapperGraph = structuredClone(graph);
    wrapperGraph.metadata.scope.query.sinks[0]!.name = "wrapper";
    wrapperGraph.observations[0]!.frames.splice(1, 0, {
      kind: "function",
      name: "wrapper",
      attributes: { name: "wrapper", language: "javascript", offset: "0" },
    });
    const wrapperReceipt = await imported(wrapperGraph);
    expect(normalize(wrapperReceipt).groups[0]!.observations[0]).toMatchObject({
      sinkIndex: 1,
      sourceIndex: 2,
      sinkMatches: [{ sinkId: "decode", rawIndex: 0 }],
    });
    const orderedGraph = structuredClone(graph);
    orderedGraph.observations[0]!.frames.unshift(
      structuredClone(orderedGraph.observations[0]!.frames[1]!),
    );
    const orderedRule = orderedGraph.observations[0]!.scope.matches.rules[0]!;
    orderedRule.sources = [{ selector_index: 0, frame_index: 1 }];
    orderedRule.sinks = [
      { selector_index: 0, frame_index: 0 },
      { selector_index: 0, frame_index: 2 },
    ];
    orderedRule.ordered_pairs = [
      {
        sink: { selector_index: 0, frame_index: 2 },
        source_ancestors: [{ selector_index: 0, frame_index: 1 }],
      },
    ];
    const orderedReceipt = await imported(orderedGraph);
    expect(normalize(orderedReceipt).groups[0]!.observations[0]).toMatchObject({
      sinkIndex: 0,
      sourceIndex: 1,
      sinkMatches: [
        { sinkId: "decode", rawIndex: 0 },
        { sinkId: "decode", rawIndex: 2 },
      ],
    });
    const aliasGraph = structuredClone(graph);
    Object.assign(aliasGraph.metadata.scope.query.sinks[0]!, {
      observed_name: "unverified_alias",
    });
    const aliasFrame = aliasGraph.observations[0]!.frames[1]!;
    aliasFrame.name = "unverified_alias";
    aliasFrame.attributes.name = "unverified_alias";
    const aliasReceipt = await imported(aliasGraph);
    expect(
      normalize(aliasReceipt).groups[0]!.observations[0],
    ).not.toHaveProperty("sinkMatches");
    const scopedGraph = structuredClone(graph);
    Object.assign(scopedGraph.metadata.scope, {
      image_tags: ["v1"],
      image_digest: "sha256:" + "a".repeat(64),
    });
    Object.assign(scopedGraph.observations[0]!.scope, {
      image_digest: "sha256:" + "b".repeat(64),
    });
    const scopedQuery = normalize(await imported(scopedGraph));
    const basePacket = livePacket(store);
    const scopedWork = stackPacketWorkItems({
      ...basePacket,
      stacks: { ...basePacket.stacks, queries: [scopedQuery] },
    })[0]!;
    expect(scopedQuery.scope.image_tags).toEqual(["v1"]);
    expect(
      scopedWork.scopeConflicts.some((conflict) =>
        conflict.startsWith("image_digest:"),
      ),
    ).toBe(true);
    const rulesGraph = structuredClone(graph);
    Object.assign(rulesGraph.metadata.scope, {
      query: {
        kind: "pair",
        rules: [
          { sources: [{ name: "other" }], sinks: [{ name: "decode" }] },
          { sources: [{ name: "request" }], sinks: [{ name: "decode" }] },
        ],
      },
    });
    const matches = rulesGraph.observations[0]!.scope.matches;
    const rule = matches.rules[0]!;
    matches.rules = [
      {
        ...rule,
        rule_index: 0,
        sources: [],
        ordered_pairs: [],
        matched: false,
      },
      { ...rule, rule_index: 1 },
    ];
    const rulesQuery = normalize(await imported(rulesGraph));
    expect(rulesQuery.selectors).toEqual({
      sources: [
        { name: "other", rule_index: 0 },
        { name: "request", rule_index: 1 },
      ],
      sinks: [
        { name: "decode", rule_index: 0 },
        { name: "decode", rule_index: 1 },
      ],
    });
    expect(rulesQuery.groups[0]!.observations[0]).toMatchObject({
      sinkIndex: 0,
      sourceIndex: 1,
    });
    const partialReceipt = await imported({
      ...graph,
      metadata: { ...graph.metadata, coverage: { result_complete: false } },
    });
    expect(normalize(partialReceipt).groups[0]!.truncated).toBe(true);
    const asyncGraph = structuredClone(graph);
    Object.assign(asyncGraph.metadata, {
      join_basis: "inferred_creator_code",
      instance_correlation_verified: false,
    });
    Object.assign(asyncGraph.metadata.scope, {
      query: {
        kind: "async_parent",
        sources: [],
        sinks: [{ name: "decode", location: "src/decode.js", line: 7 }],
      },
    });
    Object.assign(asyncGraph.observations[0]!.frames[1]!.attributes, {
      location: "/repo/src/decode.js:7",
    });
    const asyncQuery = normalize(await imported(asyncGraph));
    expect(asyncQuery.provenance).toEqual({ source: "inferred_creator_code" });
    expect(asyncQuery.groups[0]!.observations[0]).toMatchObject({
      sinkIndex: 0,
      frames: [{ line: 7 }, {}],
    });
    expect(asyncQuery.groups[0]!.observations[0]).not.toHaveProperty(
      "sinkMatches",
    );
    const invalidGraph = structuredClone(graph);
    Object.assign(invalidGraph.metadata.scope.query.sinks[0]!, {
      frame_type: "python",
    });
    const invalidQualifier = await imported(invalidGraph);
    expect(() => normalize(invalidQualifier)).toThrow(
      "selector does not match",
    );
    expect(record({ receiptId: resource.receiptId })).toEqual({
      workItemIds: ["query-id/capture/call"],
    });
    const empty = {
      ...graph,
      observations: [],
      metadata: { ...graph.metadata, status: "no_telemetry" },
    };
    const emptyReceipt = await imported(empty);
    expect(normalize(emptyReceipt).groups[0]!.status).toBe("no_coverage");
    const matched = await imported({
      ...empty,
      metadata: { ...empty.metadata, status: "empty_matches" },
    });
    expect(normalize(matched).groups[0]!.status).toBe("no_match");
  } finally {
    store.close();
  }
});
