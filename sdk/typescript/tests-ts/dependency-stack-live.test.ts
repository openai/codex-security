import { expect, test } from "bun:test";
import { join } from "node:path";
import { mkdir } from "node:fs/promises";
import { DependencyAttemptStore } from "../src/exploitability/attempt-store.js";
import {
  getLiveRun,
  initializeLive,
  liveMetadataGaps,
  livePacket,
  overlayPacket,
  recordObservations,
  supplementalReceipt,
} from "../src/exploitability/analyzers/stacks/live.js";
import { stackPacketWorkItems } from "../src/exploitability/analyzers/stacks/packet.js";
import {
  prepareRuntimeEvidence,
  readRuntimeStackCaptures,
  saveRuntimeEvidence,
} from "../src/exploitability/analyzers/stacks/runtime-receipts.js";
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
    expect(liveMetadataGaps(store).length).toBeGreaterThan(0);
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
    expect(getLiveRun(store)?.runId).toBe(started.runId);
    const base = livePacket(store);
    const page = {
      query: { selectors: { function: "decode" }, coverage: "complete" },
      stacks: [],
    };
    const receipt = await imported({
      format: "codex-security.stacks/v2",
      captures: [page, { ...page, origin: "second search" }],
    });
    const written = record({ receiptId: receipt.receiptId });
    expect(written.workItemIds).toEqual(["captures/0", "captures/1"]);
    const items = stackPacketWorkItems(overlayPacket(store, base));
    expect(items.map((item) => item.id)).toEqual(written.workItemIds);
    expect(supplementalReceipt(store, items[0]!)?.sha256).toMatch(
      /^[0-9a-f]{64}$/,
    );
    expect(() =>
      record({ receiptId: receipt.receiptId, captures: [page] }),
    ).toThrow();
    await expect(
      initializeLive(store, repo, { cve: "CVE-2099-0002" }),
    ).rejects.toThrow("already recorded differently");
  } finally {
    store.close();
  }
});

test("a profiler reply preserves search coverage and leaf-first positions without inventing package evidence", async () => {
  await using dir = await scopedTemporaryDirectory("stack-live-profiler-");
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
          service: "sample",
          start: window.start,
          end: window.end,
          query: {
            kind: "pair",
            sources: [{ name: "request" }],
            sinks: [{ name: "decode" }],
          },
        },
        coverage: { result_complete: false },
        limits: { truncated: false },
      },
      observations: [
        {
          id: "call",
          kind: "sampled_stack",
          scope: { service: "sample", window, stack_key: "opaque-key" },
          frames: ["request", "decode"].map((name) => ({
            kind: "function",
            name,
            attributes: { name, language: "javascript" },
          })),
        },
      ],
    };
    const receipt = await imported(graph);
    const [capture] = readRuntimeStackCaptures(store, receipt.receiptId);
    expect(capture?.query?.coverage).toBe("partial");
    expect(capture?.stacks[0]?.frames.map((frame) => frame.name)).toEqual([
      "decode",
      "request",
    ]);
    expect(capture?.stacks[0]?.frames[0]).not.toHaveProperty("package");
    const base = livePacket(store);
    expect(record({ receiptId: receipt.receiptId })).toMatchObject({
      workItemIds: ["captures/0/stacks/0"],
    });
    const [work] = stackPacketWorkItems(overlayPacket(store, base));
    expect(work).toMatchObject({
      sinkMatches: [],
      leads: [{ sinkId: "decode", rawIndex: 0 }],
    });
    const inferred = await imported({
      ...graph,
      metadata: {
        ...graph.metadata,
        join_basis: "inferred_creator_code",
        instance_correlation_verified: false,
      },
    });
    expect(() => readRuntimeStackCaptures(store, inferred.receiptId)).toThrow();
  } finally {
    store.close();
  }
});
