import assert from "node:assert/strict";
import test from "node:test";
import {
  EvidenceGraph,
  MAX_GRAPH_RESPONSE_BYTES,
} from "../src/dependency-trace/graph.ts";
import type {
  TraceEntity,
  TraceObservation,
} from "../src/dependency-trace/types.ts";
import { loadGraphSession } from "./build-server.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";

const frame = (
  name: string,
  scope = "image:sha256:example/build:one",
): TraceEntity => ({ kind: "symbol", name, scope });
const observation = (
  id: string,
  frames: TraceEntity[],
  scope = {},
): TraceObservation => ({ id, kind: "sampled_stack", scope, frames });

function witnesses(graph: EvidenceGraph) {
  const summary = graph.query();
  assert("witnesses" in summary && summary.witnesses);
  return summary.witnesses;
}

test("sampled calls are deduplicated but never joined across witnesses", () => {
  const graph = new EvidenceGraph();
  const batch = [
    observation("native-one", [frame("entry"), frame("shared")]),
    observation("native-two", [frame("shared"), frame("sink")]),
  ];
  assert.deepEqual(graph.recordObservations(batch, "receipt-one"), {
    received: 2,
    retained: 2,
    already_recorded: 0,
    omitted: 0,
    witnesses_found: 2,
    observed_calls_found: 2,
  });
  const [first, second] = witnesses(graph);
  assert(first && second);
  const both = graph.query("shared");
  assert("witnesses" in both);
  assert.equal(both.witnesses?.length, 2);
  assert(!("observed_calls" in both));
  for (const [id, expected] of [
    [first.id, ["entry", "shared"]],
    [second.id, ["shared", "sink"]],
  ] as const) {
    const result = graph.query("shared", { witness: id });
    assert("observed_calls" in result && result.observed_calls);
    assert.deepEqual(
      result.observed_calls.map(({ from, to }) => [from.name, to.name]),
      [expected],
    );
    assert.deepEqual(result.paths, []);
  }
  assert.deepEqual(graph.query("sink", { witness: first.id }), { matches: [] });
  const reused = graph.recordObservations(batch, "receipt-one");
  assert.equal(reused.already_recorded, 2);
  assert.equal(reused.retained, 0);
  const otherReceipt = graph.recordObservations([batch[0]!], "receipt-two");
  assert.equal(otherReceipt.witnesses_found, 3);
  assert.equal(otherReceipt.observed_calls_found, 2);
  assert.notEqual(witnesses(graph)[2]!.id, first.id);
});

test("recursion keeps ordered repeated frame IDs and occurrence positions", () => {
  const graph = new EvidenceGraph();
  graph.recordObservations(
    [
      observation("recursive", [
        frame("a"),
        frame("b"),
        frame("a"),
        frame("a"),
        frame("b"),
      ]),
    ],
    "receipt-recursive",
  );
  const witness = witnesses(graph)[0]!;
  const stack = graph.query(undefined, { witness: witness.id });
  assert("frames" in stack && stack.frames);
  assert.equal(stack.frame_order, "root_first");
  assert.equal(witness.frame_order, "root_first");
  assert.deepEqual(witness.receiptSelections.at(-1), {
    receiptId: "receipt-recursive",
    textBlock: 0,
    record: ["frame_order"],
  });
  assert.deepEqual(stack.frames, [
    stack.frames[0],
    stack.frames[1],
    stack.frames[0],
    stack.frames[0],
    stack.frames[1],
  ]);
  const calls = graph.query("a", { witness: witness.id });
  assert("observed_calls" in calls && calls.observed_calls);
  assert.deepEqual(
    calls.observed_calls.map(({ from, to, positions }) => [
      from.name,
      to.name,
      positions,
    ]),
    [
      ["a", "b", [0, 3]],
      ["b", "a", [1]],
      ["a", "a", [2]],
    ],
  );
});

test("witness citations select exact receipt records and retain native scope", () => {
  const graph = new EvidenceGraph();
  const scope = {
    image: "example@sha256:one",
    query: { cluster: "test" },
    metadata: { frame_order: "leaf_first" },
  };
  const batch = [
    observation("native-7", [frame("caller"), frame("callee")], scope),
  ];
  const receipt = { result: { frame_order: "root_first", stacks: batch } };
  graph.recordObservations(batch, "receipt-nested", ["result", "stacks"]);
  const witness = witnesses(graph)[0]!;
  const selection = {
    receiptId: "receipt-nested",
    textBlock: 0,
    record: ["result", "stacks", 0],
  };
  assert.equal(witness.native_id, "native-7");
  assert.equal(witness.native_id, receipt.result.stacks[0]!.id);
  assert.notEqual(witness.id, witness.native_id);
  assert.equal(witness.frame_order, receipt.result.frame_order);
  assert.deepEqual(witness.scope, scope);
  const metadataSelections = [
    ...["id", "kind", "scope"].map((field) => ({
      ...selection,
      record: [...selection.record, field],
    })),
    { ...selection, record: ["result", "frame_order"] },
  ];
  assert.deepEqual(witness.receiptSelections, metadataSelections);
  scope.query.cluster = "changed";
  assert.deepEqual(witnesses(graph)[0]!.scope, {
    image: "example@sha256:one",
    query: { cluster: "test" },
    metadata: { frame_order: "leaf_first" },
  });
  const result = graph.query("caller", { witness: witness.id });
  assert("observed_calls" in result && result.observed_calls);
  assert.deepEqual(result.observed_calls[0]!.receiptSelections, [
    ...metadataSelections,
    { ...selection, record: [...selection.record, "frames", 0] },
    { ...selection, record: [...selection.record, "frames", 1] },
  ]);
  const stack = graph.query(undefined, { witness: witness.id });
  assert("frame_receipts" in stack);
  assert.deepEqual(
    stack.frame_receipts.map(({ position, receiptSelections }) => [
      position,
      receiptSelections,
    ]),
    [
      [0, [{ ...selection, record: [...selection.record, "frames", 0] }]],
      [1, [{ ...selection, record: [...selection.record, "frames", 1] }]],
    ],
  );
  graph.recordObservations(batch, "receipt-nested", ["other"]);
  assert.notEqual(witnesses(graph)[1]!.id, witness.id);
});

test("build scopes disambiguate runtime frames and source names remain separate", () => {
  const graph = new EvidenceGraph();
  graph.addTrace(
    {
      complete: true,
      limits: [],
      frontier: [],
      scopes: [
        {
          id: 0,
          hops: 0,
          scope: { kind: "file", package: "example", path: "main.ts" },
          complete: true,
          evidence: [
            {
              source: "main.ts",
              step: {
                from: frame("decode"),
                relation: "candidate_call",
                calleeText: "parse",
              },
            },
          ],
        },
      ],
    },
    false,
  );
  graph.recordObservations(
    [
      observation("one", [frame("decode")]),
      observation("two", [frame("decode", "image:sha256:other/build:two")]),
      observation("unscoped-one", [{ kind: "symbol", name: "local" }]),
      observation("unscoped-two", [{ kind: "symbol", name: "local" }]),
    ],
    "receipt-builds",
  );
  const matches = graph.query("decode");
  assert("matches" in matches);
  assert.equal(matches.matches.length, 3);
  assert.equal(new Set(matches.matches.map(({ id }) => id)).size, 3);
  const local = graph.query("local");
  assert("matches" in local);
  assert.equal(local.matches.length, 2);
  const search = graph.query(undefined, { search: "dec" });
  assert("matches_found" in search);
  assert("witnesses_found" in search);
  assert.equal(search.matches_found, 3);
  assert.equal(search.witnesses_found, 2);
  const first = witnesses(graph)[0]!;
  const scoped = graph.query("decode", { witness: first.id });
  assert("node" in scoped);
  assert.deepEqual(scoped.paths, []);
  assert.deepEqual(graph.query(undefined, { witness: "missing" }), {
    matches: [],
    witness_found: false,
  });
});

test("memory exhaustion omits a whole witness and preserves previous evidence", () => {
  const graph = new EvidenceGraph(16 * 1024);
  graph.recordObservations(
    [observation("small", [frame("a"), frame("b")])],
    "receipt-small",
  );
  const retained = witnesses(graph);
  const result = graph.recordObservations(
    [observation("large", [frame("dropped")], { detail: "x".repeat(20_000) })],
    "receipt-large",
  );
  assert.equal(result.omitted, 1);
  assert.equal(result.retained, 0);
  assert.equal(result.witnesses_found, 1);
  assert.equal(result.observed_calls_found, 1);
  assert.equal(result.truncated, true);
  assert.deepEqual(witnesses(graph), retained);
  assert.deepEqual(graph.query("dropped"), { matches: [], truncated: true });
});

test("shared long stacks charge references and leave room for focused observations", () => {
  const graph = new EvidenceGraph();
  const shared = Array.from({ length: 6 }, (_, index) =>
    frame(`shared-${index}-${"x".repeat(1000)}`),
  );
  const frames = Array.from(
    { length: 1500 },
    (_, index) => shared[index % shared.length]!,
  );
  const result = graph.recordObservations(
    Array.from({ length: 100 }, (_, index) =>
      observation(`sample-${index}`, frames, { image: "example@sha256:one" }),
    ),
    "receipt-shared",
  );
  assert.equal(result.retained, 100);
  assert.equal(result.omitted, 0);
  assert.equal(result.witnesses_found, 100);
  assert.equal(result.observed_calls_found, 6);
  assert.equal(result.truncated, undefined);

  const witness = witnesses(graph)[0]!;
  const stack = graph.query(undefined, { witness: witness.id });
  assert("frames" in stack);
  assert.equal(stack.witness.frame_count, frames.length);
  for (let index = 0; index < stack.frames.length; index++)
    assert.equal(stack.frames[index], stack.frames[index % shared.length]);
  const calls = graph.query(shared[0]!.name, { witness: witness.id });
  assert("observed_calls" in calls && calls.observed_calls);
  assert("node" in calls);
  const outgoing = calls.observed_calls.find(
    ({ from }) => from.id === calls.node.id,
  )!;
  assert.equal(outgoing.occurrences_found, 250);
  assert.deepEqual(
    outgoing.positions,
    Array.from(
      { length: outgoing.positions.length },
      (_, index) => shared.length * index,
    ),
  );
  assert.deepEqual(
    outgoing.receiptSelections[witness.receiptSelections.length]!.record,
    ["observations", 0, "frames", 0],
  );

  const focused = graph.recordObservations(
    [observation("focused", [frame("new-consumer"), frame("specific-decode")])],
    "receipt-focused",
  );
  assert.equal(focused.retained, 1);
  assert.equal(focused.omitted, 0);
  assert.equal(focused.witnesses_found, 101);
  assert.equal(focused.observed_calls_found, 7);
});

test("genuinely unique over-budget stacks leave nodes and memberships unchanged", () => {
  const graph = new EvidenceGraph(4 * 1024 * 1024);
  graph.recordObservations(
    [observation("retained", [frame("first"), frame("second")])],
    "receipt-first",
  );
  const before = witnesses(graph);
  const large = [
    frame("first"),
    frame("second"),
    ...Array.from({ length: 1000 }, (_, index) =>
      frame(`unique-${index}-${"x".repeat(1000)}`),
    ),
  ];
  const result = graph.recordObservations(
    [observation("omitted", large)],
    "receipt-unique",
  );
  assert.equal(result.retained, 0);
  assert.equal(result.omitted, 1);
  assert.equal(result.witnesses_found, 1);
  assert.equal(result.observed_calls_found, 1);
  assert.equal(result.truncated, true);
  assert.deepEqual(witnesses(graph), before);
  assert.deepEqual(graph.query(large[2]!.name), {
    matches: [],
    truncated: true,
  });
  const later = graph.recordObservations(
    [observation("later", [frame("third"), frame("fourth")])],
    "receipt-later",
  );
  assert.equal(later.retained, 1);
  const third = graph.query("third");
  assert("node" in third);
  assert.equal(third.node.id, "node_3");
});

test("successive large collections remain queryable within the response budget", () => {
  const collection = (name: string) => {
    const frames = Array.from({ length: 64 }, (_, index) =>
      frame(`${name}-function-${index}`, `build:${name}`),
    );
    return Array.from({ length: 1000 }, (_, index) =>
      observation(`${name}-sample-${index}`, frames, {
        service: name,
        window: { start: "2026-01-01T00:00:00Z", end: "2026-01-01T00:01:00Z" },
      }),
    );
  };
  const first = collection("first-workload");
  const second = collection("second-workload");
  assert(Buffer.byteLength(JSON.stringify([first, second])) > 4 * 1024 * 1024);
  // Reproduce the capacity failure independently of the default under test.
  const small = new EvidenceGraph(4 * 1024 * 1024);
  assert(small.recordObservations(first, "receipt-first").omitted > 0);

  const graph = new EvidenceGraph();
  for (const [batch, receipt] of [
    [first, "receipt-first"],
    [second, "receipt-second"],
  ] as const) {
    const recorded = graph.recordObservations(batch, receipt);
    assert.equal(recorded.retained, 1000);
    assert.equal(recorded.omitted, 0);
  }
  const summary = graph.query();
  assert("witnesses_found" in summary);
  assert.equal(summary.witnesses_found, 2000);
  assert("observations_omitted" in summary);
  assert.equal(summary.observations_omitted, 0);
  assert(Buffer.byteLength(JSON.stringify(summary)) <= 32 * 1024);

  for (const [name, receipt] of [
    ["first-workload", "receipt-first"],
    ["second-workload", "receipt-second"],
  ] as const) {
    const node = graph.query(`${name}-function-63`);
    assert("node" in node && "witnesses" in node && node.witnesses.length);
    assert.equal(node.witnesses_found, 1000);
    assert.equal(node.witnesses[0]!.native_id, `${name}-sample-0`);
    const calls = graph.query(node.node.id, { witness: node.witnesses[0]!.id });
    assert("observed_calls" in calls && calls.observed_calls?.length);
    assert.equal(calls.observed_calls[0]!.to.name, `${name}-function-63`);
    assert(
      calls.observed_calls[0]!.receiptSelections.some(
        (selection) =>
          selection.receiptId === receipt &&
          JSON.stringify(selection.record) ===
            JSON.stringify(["observations", 0, "frames", 63]),
      ),
    );
    for (const result of [node, calls])
      assert(Buffer.byteLength(JSON.stringify(result)) <= 32 * 1024);
  }
});

test("large graph replies preserve counts and exact citations within the byte budget", () => {
  const graph = new EvidenceGraph();
  const frames = [frame("hub")];
  for (let i = 0; i < 130; i++)
    frames.push(frame(`callee-${i}-${"x".repeat(300)}`), frame("hub"));
  graph.recordObservations(
    [observation("many-calls", frames)],
    "receipt-large-graph",
  );
  const witness = witnesses(graph)[0]!;
  const result = graph.query("hub", { witness: witness.id });
  assert("observed_calls" in result && result.observed_calls);
  assert.equal(result.observed_calls_found, 260);
  assert.equal(result.truncated, true);
  assert(Buffer.byteLength(JSON.stringify(result)) <= MAX_GRAPH_RESPONSE_BYTES);
  assert(
    result.observed_calls.length > 0 && result.observed_calls.length <= 128,
  );
  for (const call of result.observed_calls) {
    assert.deepEqual(
      call.receiptSelections.slice(0, witness.receiptSelections.length),
      witness.receiptSelections,
    );
    assert.deepEqual(
      call.receiptSelections
        .slice(witness.receiptSelections.length)
        .map(({ record }) => record),
      call.positions.flatMap((position) => [
        ["observations", 0, "frames", position],
        ["observations", 0, "frames", position + 1],
      ]),
    );
    assert(
      call.receiptSelections.every(
        ({ record }) => record[0] !== "observations" || record.length > 2,
      ),
    );
  }
  const full = graph.query(undefined, { witness: witness.id });
  assert("frames" in full && full.frames);
  assert.equal(full.witness.frame_count, 261);
  assert(full.frames.length <= 128);
  assert.equal(full.truncated, true);
  assert(Buffer.byteLength(JSON.stringify(full)) <= MAX_GRAPH_RESPONSE_BYTES);
});

test("oversized witness scope is explicitly omitted without clipping its receipt", () => {
  const graph = new EvidenceGraph();
  graph.recordObservations(
    [observation("wide", [frame("a")], { detail: "例".repeat(20_000) })],
    "receipt-wide",
  );
  const result = graph.query();
  assert("witnesses" in result && result.witnesses);
  assert.equal(result.witnesses_found, 1);
  assert.equal(result.truncated, true);
  assert(result.response_omitted_fields);
  assert(Buffer.byteLength(JSON.stringify(result)) <= MAX_GRAPH_RESPONSE_BYTES);
  assert.deepEqual(result.witnesses[0]!.receiptSelections, [
    ...["id", "kind", "scope"].map((field) => ({
      receiptId: "receipt-wide",
      textBlock: 0,
      record: ["observations", 0, field],
    })),
    { receiptId: "receipt-wide", textBlock: 0, record: ["frame_order"] },
  ]);
});

test("host ingestion reuses the existing query tool without exposing a mutation tool", async (t) => {
  const temps = createTemporaryDirectories(true);
  t.after(() => temps.cleanup());
  const checkout = await temps.create("dependency-observations-checkout-");
  const runtime = await temps.create("dependency-observations-session-");
  const { createDependencyGraphSession } = await loadGraphSession(runtime);
  const session = await createDependencyGraphSession(checkout, false);
  t.after(() => session.close());
  assert.equal(session.tools.length, 3);
  assert(!session.tools.some(({ name }) => name === "recordObservations"));
  const recorded = session.recordObservations(
    [observation("host-one", [frame("entry"), frame("read")])],
    "receipt-host",
  );
  assert.equal(recorded.retained, 1);
  const summary = await session.call("query_codex_security_graph", {});
  const [witness] = summary.witnesses as { id: string }[];
  const reply = await session.call("query_codex_security_graph", {
    witness: witness!.id,
    node: "read",
  });
  assert.equal((reply.observed_calls as unknown[]).length, 1);
  assert.equal(reply.service_resolution.catalog_configured, false);
  await assert.rejects(
    session.call("query_codex_security_graph", { observations: [] }),
  );
});
