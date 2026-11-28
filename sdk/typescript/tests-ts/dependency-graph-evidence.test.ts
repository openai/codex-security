import { expect, test } from "bun:test";
import {
  createDependencyGraphEvidenceTools,
  type DependencyEvidenceGraph,
} from "../src/exploitability/graph-evidence.js";
import type { DependencyEvidenceRecord } from "../src/exploitability/evidence-sources.js";

function tools(entries?: DependencyEvidenceRecord[]) {
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

test("binds returned service IDs and empty scoped lookups to the consumer", async () => {
  const original = {
    sha256: "receipt",
    server: "service-registry",
    tool: "list",
    arguments: { project: "jobs" },
    result: {
      structuredContent: {
        data: {
          services: [
            { id: 93, name: "mailer", coverage: "partial", nextCursor: "row" },
            { id: 22, name: "nightly" },
          ],
        },
      },
    },
  };
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
  const run = (r: DependencyEvidenceRecord) => tools([r])[resolve]!(input);
  const catalog = (data: object) =>
    run({ ...original, result: { structuredContent: { data } } });
  expect(await run(original)).toMatchObject({
    path: "jobs/send.js",
    project: "jobs",
    services: [
      {
        scope: "service-registry:93",
        name: "mailer",
        receiptSelections: [
          {
            receiptId: "receipt",
            textBlock: null,
            record: ["data", "services", 0],
          },
        ],
      },
      { scope: "service-registry:22", name: "nightly" },
    ],
  });
  expect(await catalog({ services: [] })).toMatchObject({
    services: [],
    receiptSelections: [{ record: ["data", "services"] }],
  });
  await expect(
    run({ ...original, arguments: { project: "other" } }),
  ).rejects.toThrow(/file or its project/);
  for (const flag of [
    { truncated: true },
    { next_page_token: "", nextCursor: "page2" },
    { nextCursor: 0 },
    { coverage: "unknown" },
    { coverage: { available: false } },
    { truncation: { omitted_by_key: { services: 1 } } },
  ]) {
    await expect(catalog({ services: [], ...flag })).rejects.toThrow(
      /incomplete/,
    );
  }
  const content = [{ type: "text", text: '{"metadata":{"has_more":true}}' }];
  await expect(
    run({ ...original, result: { ...original.result, content } }),
  ).rejects.toThrow(/incomplete/);
  await expect(catalog({})).rejects.toThrow(/Selector/);
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
