import { createDependencySourceWorkTools } from "../src/dependency-source-work-tools.js";
import { expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  openDependencyEndpoints,
  withInvestigationGraphTools,
} from "../src/dependency-endpoints.js";
import type { DependencyEndpointConfiguration } from "../src/dependency-caller-scope.js";
import { resolveProjectConfig } from "../src/project-config.js";
const source = {
  id: "input",
  function: "read_input",
  ports: [0, "request"],
  package: "request-fixture",
  symbol: "fixture::read_input",
  path: "src/input",
  file: "input.c",
  binary: "worker",
  line: 10,
  location: "input.c:10",
  evidence: ["fixture-input-contract"],
  relationships: [{ kind: "reaches" as const, endpoint_id: "decode" }],
  scope: "decoder",
};
const sink = {
  id: "decode",
  function: "decode_body",
  file: "codec.c",
  line: 8,
};
const boundaryCases: [
  DependencyEndpointConfiguration,
  "discover" | "supplied",
  "discover" | "supplied",
][] = [
  [{}, "discover", "discover"],
  [{ sources: [source] }, "supplied", "discover"],
  [{ sinks: [sink] }, "discover", "supplied"],
  [{ sources: [source], sinks: [sink] }, "supplied", "supplied"],
  [{ sources: [], sinks: [] }, "supplied", "supplied"],
];

test.each(boundaryCases)(
  "keeps the configured source and sink boundary for %j",
  async (configuration, sourceBoundary, sinkBoundary) => {
    const resolved = resolveProjectConfig({ exploitability: configuration });
    expect(resolved.exploitability).toEqual(configuration);
    const graph = await openDependencyEndpoints({
      configuration: resolved.exploitability,
    });
    await graph.record({
      endpoint: { id: "candidate", function: "receive", role: "source" },
    });
    expect(graph.boundary).toEqual({
      source: sourceBoundary,
      sink: sinkBoundary,
    });
    expect(graph.isBoundaryEndpoint("candidate", "source")).toBe(
      sourceBoundary === "discover",
    );
    if (configuration.sources?.length) {
      expect(graph.get("input")).toEqual({
        ...source,
        role: "source",
        origin: "supplied",
      });
      expect(graph.isBoundaryEndpoint("input", "source")).toBe(true);
    } else {
      expect(graph.isBoundaryEndpoint("input", "source")).toBe(false);
    }
  },
);

test("resolves exact selectors and keeps unresolved IDs and wrapper discoveries explicit", async () => {
  const exact = { name: "read_input", label: "sym.read_input" };
  const graph = await openDependencyEndpoints({
    configuration: {
      sources: [{ ...source, runtime_selectors: [exact] }],
      sinks: [sink],
    },
  });
  const discovery = {
    id: "decode_api",
    function: "decode_api",
    role: "intermediate",
    runtime_selectors: [{ name: "decode_api" }],
    relationships: [{ kind: "reaches", endpoint_id: "decode" }],
  };
  await graph.record({ endpoint: discovery });
  expect(graph.resolveRuntimeSelectors(["input"], "source")).toEqual({
    selectors: [exact],
    gaps: [],
  });
  expect(
    graph.resolveRuntimeSelectors(["decode", "missing", "decode_api"], "sink"),
  ).toEqual({
    selectors: [],
    gaps: [
      {
        endpoint_id: "decode",
        reason: expect.stringContaining("No exact runtime selector"),
      },
      { endpoint_id: "missing", reason: expect.stringContaining("Unknown") },
      { endpoint_id: "decode_api", reason: expect.stringContaining("outside") },
    ],
  });
  const native = { name: "decode_body", location: "codec.c", line: 8 };
  await graph.record({
    endpoint: {
      id: "native",
      role: "sink",
      function: "decode_body",
      evidence: ["source-lines-8-21"],
      relationships: [{ kind: "maps_to", endpoint_id: "decode" }],
      runtime_selectors: [native],
    },
  });
  expect(graph.resolveRuntimeSelectors(["decode"], "sink")).toEqual({
    selectors: [native],
    gaps: [],
  });
  expect(graph.isBoundaryEndpoint("native", "sink")).toBe(false);
  expect(graph.get("decode")).toEqual({
    ...sink,
    role: "sink",
    origin: "supplied",
  });
  const returned = graph.get("input")!;
  returned.runtime_selectors![0]!.name = "different";
  expect(graph.resolveRuntimeSelectors(["input"], "source").selectors).toEqual([
    exact,
  ]);
  await expect(
    graph.record({ endpoint: { ...source, role: "source" } }),
  ).rejects.toThrow("already in use");
  expect(() =>
    graph.record({
      endpoint: { ...source, role: "source", origin: "supplied" },
    }),
  ).toThrow("origin");
});

test("retains advisory provenance without changing a supplied sink boundary", async () => {
  const origin = "advisory" as const;
  const endpoint = {
    id: "advisory-decode",
    role: "sink" as const,
    origin,
    function: "decode_inner",
    evidence: ["advisory-reference", "pinned-source-reference"],
    runtime_selectors: [{ name: "decode_inner" }],
  };
  const root = await mkdtemp(join(tmpdir(), "endpoint-advisory-"));
  try {
    const options = {
      configuration: { sinks: [] },
      snapshotPath: join(root, "graph.json"),
    };
    const graph = await openDependencyEndpoints(options);
    await graph.record({ endpoint });
    expect(graph.query({ origin, id: endpoint.id })["endpoint"]).toEqual(
      endpoint,
    );
    expect(
      graph.query({ origin: "discovered", id: endpoint.id })["endpoint"],
    ).toBeNull();
    expect(graph.query({ origin, role: "sink" })["page"]).toMatchObject({
      total: 1,
      items: [{ id: endpoint.id, origin, role: "sink" }],
    });
    expect(graph.isBoundaryEndpoint(endpoint.id, "sink")).toBe(false);
    expect(graph.resolveRuntimeSelectors([endpoint.id], "sink")).toEqual({
      selectors: [],
      gaps: [
        {
          endpoint_id: endpoint.id,
          reason: expect.stringContaining("outside"),
        },
      ],
    });
    expect(() =>
      graph.record({ endpoint: { ...endpoint, evidence: [] } }),
    ).toThrow("evidence");
    expect(() =>
      graph.record({ endpoint: { ...endpoint, role: "source" } }),
    ).toThrow("role");
    const reopened = await openDependencyEndpoints(options);
    expect(reopened.get(endpoint.id)).toEqual(endpoint);

    const discover = await openDependencyEndpoints();
    await discover.record({ endpoint });
    expect(discover.isBoundaryEndpoint(endpoint.id, "sink")).toBe(true);
    expect(discover.resolveRuntimeSelectors([endpoint.id], "sink")).toEqual({
      selectors: endpoint.runtime_selectors,
      gaps: [],
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("querying supplied endpoints and recording a discovery through the shared graph", async () => {
  const graph = await openDependencyEndpoints({
    configuration: { sources: [source], sinks: [] },
  });
  const sourceWork = createDependencySourceWorkTools();
  const tools = withInvestigationGraphTools(
    [
      {
        name: "query_codex_security_graph",
        description: "Trace graph",
        inputSchema: { type: "object" },
        run: () => "trace result",
      },
    ],
    graph,
    sourceWork,
  );
  const query = tools.find((t) => t.name === "query_codex_security_graph")!;
  expect(await query.run({ endpoints: { role: "source" } })).toMatchObject({
    endpoints: { page: { total: 1 } },
  });
  expect(await query.run({ node: "caller" })).toBe("trace result");
  await tools
    .find((t) => t.name === "record_codex_security_endpoint")!
    .run({ endpoint: { role: "sink", function: "read", id: "new" } });
  expect(graph.isBoundaryEndpoint("new", "sink")).toBe(false);
  expect(
    withInvestigationGraphTools([], graph, sourceWork, true).map((t) => t.name),
  ).toEqual(["query_codex_security_graph"]);
  expect(() =>
    resolveProjectConfig({
      exploitability: { sources: [source], sinks: [source] },
    }),
  ).toThrow("Duplicate supplied endpoint ID");
});
