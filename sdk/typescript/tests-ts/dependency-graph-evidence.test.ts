import { expect, test } from "bun:test";
import {
  createDependencyGraphEvidenceTools,
  type DependencyEvidenceGraph,
} from "../src/exploitability/graph-evidence.js";
import type {
  DependencyEvidenceRecord,
  Sample,
} from "../src/exploitability/evidence-sources.js";

function tools(entries?: DependencyEvidenceRecord[], sample?: Sample) {
  const graph: DependencyEvidenceGraph = {
    tools: [],
    call: async (name, input) => ({ name, input }),
    recordCatalogResolution: (answer) => answer,
    recordObservations: (observations, id, path, block) => ({
      observations,
      id,
      path,
      block,
    }),
  };
  return Object.fromEntries(
    createDependencyGraphEvidenceTools(
      graph,
      entries && ((id) => entries.find((r) => r.sha256 === id)),
      undefined,
      sample,
    ).map((tool) => [tool.name, tool.run]),
  );
}

const resolve = "resolve_codex_security_services";

test("without external sources the investigator can still search local project references", async () => {
  const local = tools();
  expect(local["ingest_dependency_graph_evidence"]).toBeUndefined();
  const input = { project: "jobs" };
  expect(await local[resolve]!(input)).toEqual({ name: resolve, input });
});

test("only a cited declaration can settle a catalog lookup; observed rows survive uncertainty", async () => {
  const row = { id: 93, name: "mailer", full: true };
  const make = (data: object): DependencyEvidenceRecord => ({
    sha256: "receipt",
    server: "service-registry",
    tool: "list",
    arguments: { project: "jobs", token: "do-not-forward" },
    result: { structuredContent: { data } },
  });
  const input = {
    path: "jobs/send.js",
    project: "jobs",
    lookups: [
      {
        receiptId: "receipt",
        textBlock: null,
        target: ["project"],
        records: ["data", "services"],
        id: ["id"],
        name: ["name"],
      },
    ],
  };
  const proof = JSON.stringify({
    coverage: "complete",
    path: ["data", "everyPageRead"],
    value: true,
  });
  let calls = 0;
  const sample: Sample = async (prompt) => {
    calls++;
    expect(prompt).not.toContain("do-not-forward");
    return proof;
  };
  const lookup = (data: object, classify?: Sample) =>
    tools([make(data)], classify)[resolve]!(input);
  const run = tools([make({ services: [], everyPageRead: true })], sample)[
    resolve
  ]!;
  expect(await run(input)).toMatchObject({
    complete: true,
    services: [],
    receiptSelections: [
      { record: ["data", "services"] },
      { record: ["data", "everyPageRead"] },
    ],
  });
  expect(calls).toBe(1);
  // An invented witness never certifies the result, even with real service rows.
  expect(await lookup({ services: [row] }, sample)).toMatchObject({
    complete: false,
    services: [
      {
        scope: "service-registry:93",
        name: "mailer",
        receiptSelections: [{ record: ["data", "services", 0] }],
      },
    ],
  });
  expect(await lookup({ services: [] }, async () => "invalid")).toMatchObject({
    complete: false,
  });
  expect(await lookup({ services: [] })).toMatchObject({ complete: false });
  const linked = {
    ...make({ services: [], everyPageRead: true }),
    tool: "read_mcp_resource",
  };
  expect(await tools([linked], sample)[resolve]!(input)).toMatchObject({
    complete: false,
  });
  const wrong = { ...make({ services: [] }), arguments: { project: "other" } };
  await expect(tools([wrong], sample)[resolve]!(input)).rejects.toThrow(
    /file or its project/,
  );
  expect(calls).toBe(2);
});

test("keeps the exact text block and offset path of the original sampled resource", () => {
  const witness = {
    kind: "sampled_stack",
    id: "request",
    scope: { build: "v1" },
    frames: [
      { kind: "symbol", name: "entry" },
      { kind: "symbol", name: "decode" },
    ],
  };
  const packet = {
    format: "codex-security-graph-evidence/v1",
    frame_order: "root_first",
    observations: [witness],
  };
  const sample = (value: unknown) =>
    tools([
      {
        sha256: "capture",
        server: "sampler",
        tool: "read_mcp_resource",
        arguments: { uri: "example://sample" },
        result: {
          contents: [
            { text: "unrelated" },
            { text: JSON.stringify({ sample: value }) },
          ],
        },
      },
    ]);
  const args = { receiptId: "capture", textBlock: 1, document: ["sample"] };
  const ingest = (value: unknown) =>
    sample(value)["ingest_dependency_graph_evidence"]!(args);
  expect(ingest(packet)).toEqual({
    id: "capture",
    path: ["sample", "observations"],
    block: 1,
    observations: [witness],
  });
  for (const metadata of [
    { join_basis: "inferred_creator_code" },
    { instance_correlation_verified: false },
    { scope: { query: { kind: "async_parent" } } },
  ])
    expect(() => ingest({ ...packet, metadata })).toThrow(
      /inferred graph join/i,
    );
  expect(() => ingest({ ...packet, frame_order: "leaf_first" })).toThrow();
});
