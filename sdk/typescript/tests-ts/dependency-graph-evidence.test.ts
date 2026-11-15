import { createHash } from "node:crypto";
import { expect, test } from "bun:test";
import {
  createGraphEvidenceIngestion,
  type GraphEvidenceObservations,
} from "../src/dependency-graph-evidence.js";
import {
  createDependencyInventory,
  type DependencyInventoryRpc,
} from "../src/dependency-inventory.js";

function fixture(frameCount = 3) {
  const evidence = {
    format: "codex-security-graph-evidence/v1",
    frame_order: "root_first",
    observations: [
      {
        id: "stack-a",
        kind: "sampled_stack",
        scope: { service: "cache", profile_rows: 4 },
        frames: Array.from({ length: frameCount }, (_, i) => ({
          kind: "function",
          name: "bulk_frame_" + i,
          scope: "build-a",
          attributes: { binary: "cache", location: "source/".repeat(100) + i },
        })),
      },
    ],
    metadata: {
      coverage: { sampling: "cpu", result_complete: false },
      warnings: ["sampled"],
    },
  };
  const text = JSON.stringify(evidence);
  const sha256 = createHash("sha256").update(text).digest("hex");
  const uri = "evidence://profiles/" + sha256;
  const descriptor = { format: evidence.format, uri, sha256 };
  const response = { contents: [{ uri, mimeType: "application/json", text }] };
  return {
    evidence,
    response,
    descriptor,
    result: { structuredContent: { graph_evidence: descriptor } },
  };
}

function setup(data = fixture()) {
  const inventory = createDependencyInventory();
  const parentReceiptId = inventory.record("profiles", data.result, {
    tool: "stacks",
    arguments: { service: "cache" },
  })!;
  const ingested: GraphEvidenceObservations[] = [];
  const ingestion = createGraphEvidenceIngestion({
    record: inventory.record,
    ingest(observations) {
      ingested.push(observations);
      return { received: observations.length, retained: observations.length };
    },
  });
  const reads: string[] = [];
  const rpc: DependencyInventoryRpc = {
    list: async () => ({}),
    call: async () => ({}),
    read: async (server, uri) => {
      reads.push(server + ":" + uri);
      return data.response;
    },
  };
  return { inventory, parentReceiptId, ingested, ingestion, reads, rpc };
}

test("bulk profile resources populate the graph without entering model-facing summaries", async () => {
  const data = fixture(2500);
  const state = setup(data);
  expect(data.response.contents[0]!.text.length).toBeGreaterThan(1_000_000);
  state.ingestion.observe(
    "profiles",
    data.result,
    state.parentReceiptId,
    state.rpc,
  );
  await state.ingestion.flush();
  expect(state.ingested[0]![0]!.frames).toHaveLength(2500);
  const summary = state.ingestion.summary()!;
  expect(summary["loaded"]).toBe(1);
  expect(JSON.stringify(summary).length).toBeLessThan(2048);
  expect(JSON.stringify(summary)).not.toContain("bulk_frame_");
  const receiptId = state.inventory
    .snapshot()
    .find((item) => item.tool === "mcpServer/resource/read")!.id;
  const [bound] = state.inventory.bind(["profiles"], undefined, [
    { receiptId, textBlock: 0, record: ["observations", 0, "frames", 2499] },
  ]);
  expect(bound!.result).toEqual(data.evidence.observations[0]!.frames[2499]);
  expect(bound!.origin.parentReceiptId).toBe(state.parentReceiptId);
});

test("duplicate text and structured descriptors produce a single resource read", async () => {
  const data = fixture();
  const state = setup(data);
  const { format, uri, sha256 } = data.descriptor;
  const result = {
    ...data.result,
    content: [
      {
        type: "text",
        text: JSON.stringify({ graph_evidence: { sha256, uri, format } }),
      },
    ],
  };
  state.ingestion.observe("profiles", result, state.parentReceiptId, state.rpc);
  state.ingestion.observe("profiles", result, state.parentReceiptId, state.rpc);
  await state.ingestion.flush();
  expect(state.reads).toHaveLength(1);
  expect(state.ingested).toHaveLength(1);
});

test("flush waits for resource loading while observe returns immediately", async () => {
  const data = fixture();
  const state = setup(data);
  const read = Promise.withResolvers<unknown>();
  let finished = false;
  state.ingestion.observe("profiles", data.result, state.parentReceiptId, {
    ...state.rpc,
    read: () => read.promise,
  });
  const flushing = state.ingestion.flush().then(() => {
    finished = true;
  });
  await Promise.resolve();
  expect(finished).toBe(false);
  expect(state.ingestion.summary()!["pending"]).toBe(1);
  read.resolve(data.response);
  await flushing;
  expect(finished).toBe(true);
  expect(state.ingested).toHaveLength(1);
});

test("a changed artifact is retained as failed evidence and never populates the graph", async () => {
  const data = fixture();
  const state = setup(data);
  data.response.contents[0]!.text += " ";
  state.ingestion.observe(
    "profiles",
    data.result,
    state.parentReceiptId,
    state.rpc,
  );
  await state.ingestion.flush();
  expect(state.ingested).toHaveLength(0);
  expect(state.ingestion.summary()!["failed"]).toBe(1);
  expect(
    state.inventory.snapshot().some((item) => item.outcome === "failed"),
  ).toBe(true);
});

test("an unsupported resource reader remains an explicit evidence gap", async () => {
  const data = fixture();
  const state = setup(data);
  state.ingestion.observe("profiles", data.result, state.parentReceiptId, {
    list: state.rpc.list,
    call: state.rpc.call,
  });
  await state.ingestion.flush();
  expect(state.ingested).toHaveLength(0);
  expect(state.ingestion.summary()!["failed"]).toBe(1);
});

test("an explicit observation after reconnect retries failed resources and retains the original receipt", async () => {
  const data = fixture();
  const state = setup(data);
  let attempts = 0;
  state.ingestion.observe("profiles", data.result, state.parentReceiptId, {
    ...state.rpc,
    read: async () => {
      attempts++;
      throw new Error("The inventory connection closed.");
    },
  });
  await state.ingestion.flush();
  expect(attempts).toBe(1);
  expect(state.ingested).toHaveLength(0);
  expect(state.ingestion.summary()).toMatchObject({ failed: 1, loaded: 0 });
  const failed = state.inventory
    .snapshot()
    .find((item) => item.outcome === "failed")!;
  expect(failed.current).toBe(true);

  // Repeating the collection lookup can return the same immutable original.
  const parentReceiptId = state.inventory.record("profiles", data.result, {
    tool: "stacks",
    arguments: { service: "cache" },
  })!;
  expect(parentReceiptId).toBe(state.parentReceiptId);
  const reconnected = {
    ...state.rpc,
    read: async (server: string, uri: string) => {
      attempts++;
      return state.rpc.read!(server, uri);
    },
  };
  state.ingestion.observe(
    "profiles",
    data.result,
    parentReceiptId,
    reconnected,
  );
  state.ingestion.observe(
    "profiles",
    data.result,
    parentReceiptId,
    reconnected,
  );
  await state.ingestion.flush();
  expect(attempts).toBe(2);
  expect(state.ingested).toHaveLength(1);
  expect(state.ingestion.summary()).toMatchObject({ failed: 0, loaded: 1 });
  expect(
    state.inventory.snapshot().find((item) => item.id === failed.id),
  ).toMatchObject({
    outcome: "failed",
    current: false,
  });
  const successful = state.inventory
    .snapshot()
    .find(
      (item) =>
        item.tool === "mcpServer/resource/read" && item.outcome !== "failed",
    )!;
  expect(successful.current).toBe(true);
  expect(
    state.inventory.bind(["profiles"], undefined, [
      {
        receiptId: successful.id,
        textBlock: 0,
        record: ["observations", 0, "scope"],
      },
    ])[0]!.result,
  ).toEqual(data.evidence.observations[0]!.scope);
  state.ingestion.observe(
    "profiles",
    data.result,
    parentReceiptId,
    reconnected,
  );
  await state.ingestion.flush();
  expect(attempts).toBe(2);
});

test("refreshing a collection invalidates its previous resource evidence for current claims", async () => {
  const data = fixture();
  const state = setup(data);
  state.ingestion.observe(
    "profiles",
    data.result,
    state.parentReceiptId,
    state.rpc,
  );
  await state.ingestion.flush();
  const receiptId = state.inventory
    .snapshot()
    .find((item) => item.tool === "mcpServer/resource/read")!.id;
  const bound = state.inventory.bind(["profiles"], undefined, [
    { receiptId, textBlock: 0, record: ["observations", 0] },
  ]);
  state.inventory.record(
    "profiles",
    { error: "backend unavailable" },
    { tool: "stacks", arguments: { service: "cache" }, outcome: "failed" },
  );
  expect(state.inventory.staleReason(bound)).toContain("superseded");
  expect(() => state.inventory.bind(["profiles"], [receiptId])).toThrow(
    "superseded",
  );
  expect(
    state.inventory.snapshot().find((item) => item.id === receiptId)!.current,
  ).toBe(false);
});

test("receipt reads and review binding require narrow selections from bulk collection resources", async () => {
  const data = fixture(2500);
  const state = setup(data);
  state.ingestion.observe(
    "profiles",
    data.result,
    state.parentReceiptId,
    state.rpc,
  );
  await state.ingestion.flush();
  const receiptId = state.inventory
    .snapshot()
    .find((item) => item.tool === "mcpServer/resource/read")!.id;
  expect(() => state.inventory.bind(["profiles"], [receiptId])).toThrow(
    "exact receiptSelections",
  );
  expect(() => state.inventory.read({ receiptId, original: true })).toThrow(
    "exact receiptSelections",
  );
  const wide = {
    receiptId,
    textBlock: 0,
    record: ["observations", 0],
  };
  expect(() => state.inventory.read(wide)).toThrow("review context budget");
  expect(() => state.inventory.bind(["profiles"], undefined, [wide])).toThrow(
    "review context budget",
  );
  const selections = [
    { receiptId, textBlock: 0, record: ["observations", 0, "scope"] },
    { receiptId, textBlock: 0, record: ["observations", 0, "frames", 25] },
    { receiptId, textBlock: 0, record: ["observations", 0, "frames", 26] },
  ];
  const narrow = state.inventory.bind(["profiles"], undefined, selections);
  expect(narrow).toHaveLength(3);
  expect(JSON.stringify(narrow).length).toBeLessThan(4096);
  expect(state.inventory.read(selections[1]!)).toMatchObject({
    originalPayloadSha256: narrow[0]!.originalPayloadSha256,
    selection: selections[1],
  });
});
