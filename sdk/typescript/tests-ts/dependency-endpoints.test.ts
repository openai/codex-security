import { expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { JsonObject } from "../src/config.js";
import {
  openDependencyEndpoints,
  type DependencyEndpointConfiguration,
} from "../src/dependency-endpoints.js";
import { openDependencyGraph } from "../src/dependency-graph-tools.js";
import {
  loadProjectConfig,
  resolveProjectConfig,
} from "../src/project-config.js";

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
const runtime = {
  cluster: "fixture-cluster",
  service: "worker",
  container: "decoder",
  image_name: "fixture",
  image_tag: "v1",
  window: {
    start: "2025-01-01T01:00:00+01:00",
    end: "2025-01-01T00:30:00.000Z",
  },
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

test("loads the existing project config shape and validates endpoint, workload and window inputs", async () => {
  const legacy = {
    exploitability: { scope: { exclude_paths: ["generated"] } },
  };
  expect(resolveProjectConfig(legacy).exploitability).toEqual(
    legacy.exploitability,
  );
  expect(resolveProjectConfig({})).not.toHaveProperty("exploitability");
  const root = await mkdtemp(join(tmpdir(), "endpoint-config-"));
  try {
    const file = join(root, "project.json");
    const input = {
      exploitability: { sources: [], sinks: [sink], scope: { runtime } },
    };
    await writeFile(file, JSON.stringify(input));
    expect((await loadProjectConfig(file)).exploitability).toEqual(
      input.exploitability,
    );
    const graph = await openDependencyEndpoints({
      configuration: input.exploitability,
    });
    expect(graph.runtimeScope).toEqual(runtime);
    expect(graph.query({})).not.toHaveProperty("caller_scope");
    graph.runtimeScope!.window.start = runtime.window.end;
    expect(graph.runtimeScope).toEqual(runtime);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
  expect(() =>
    resolveProjectConfig({
      exploitability: {
        sources: [source],
        sinks: [{ ...sink, id: source.id }],
      },
    }),
  ).toThrow("Duplicate supplied endpoint ID");
  expect(() =>
    resolveProjectConfig({
      exploitability: {
        scope: {
          runtime: {
            ...runtime,
            window: { ...runtime.window, end: runtime.window.start },
          },
        },
      },
    }),
  ).toThrow("start must precede end");
  expect(() =>
    resolveProjectConfig({
      exploitability: {
        sinks: [{ ...sink, runtime_selectors: [{ name: "decode", line: 8 }] }],
      },
    }),
  ).toThrow("line requires a location");
});

test("preserves caller scope from normal config independently of runtime scope", async () => {
  const caller = "Callers in the invoice worker";
  const exploitability = { scope: { caller } };
  const root = await mkdtemp(join(tmpdir(), "endpoint-caller-scope-"));
  try {
    const file = join(root, "project.json");
    await writeFile(file, JSON.stringify({ exploitability }));
    const loaded = await loadProjectConfig(file);
    expect(loaded.exploitability).toEqual(exploitability);
    expect(resolveProjectConfig({ exploitability }).exploitability).toEqual(
      exploitability,
    );

    const snapshotPath = join(root, "graph.json");
    const graph = await openDependencyEndpoints({
      configuration: loaded.exploitability,
      snapshotPath,
    });
    const selection = graph.query({});
    expect(selection["caller_scope"]).toBe(caller);
    expect(selection).not.toHaveProperty("runtime_scope");
    expect(
      JSON.parse(await readFile(snapshotPath, "utf8")).configuration,
    ).toEqual(exploitability);
    const reopened = await openDependencyEndpoints({
      configuration: loaded.exploitability,
      snapshotPath,
    });
    expect(reopened.query({})["caller_scope"]).toBe(caller);

    const both = await openDependencyEndpoints({
      configuration: { scope: { caller, runtime } },
    });
    expect(both.query({})).toMatchObject({
      caller_scope: caller,
      runtime_scope: runtime,
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
  expect(() =>
    resolveProjectConfig({ exploitability: { scope: { caller: "" } } }),
  ).toThrow("/exploitability/scope/caller");
});

test("resolves exact selectors and keeps unresolved IDs and wrapper discoveries explicit", async () => {
  const exact = { name: "read_input", observed_name: "sym.read_input" };
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

test("pages compact records in the shared graph and keeps exact discoveries across a reopen", async () => {
  const root = await mkdtemp(join(tmpdir(), "endpoint-graph-"));
  const snapshotPath = join(root, "graph.json");
  const configuration = {
    sources: [{ function: "receive" }],
    scope: { runtime },
  };
  try {
    await mkdir(join(root, "mcp"));
    await writeFile(
      join(root, "mcp", "helpers.mjs"),
      `
      export default {
        createDependencyGraphSession: () => ({
          tools: [{name: "query_codex_security_graph", description: "Query graph.", inputSchema: {type: "object"}}],
          serviceResolutionCoverage: () => ({}),
          close: async () => {},
        }),
      };
    `,
    );
    const graph = await openDependencyGraph(
      root,
      root,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      { configuration, snapshotPath },
    );
    const query = async (endpoints: JsonObject) =>
      (await graph.call("query_codex_security_graph", { endpoints }))[
        "endpoints"
      ] as JsonObject;
    try {
      const candidate = (i: number) => ({
        id: `sink-${i}`,
        role: "sink",
        scope: "decoder",
        function: `decode_${i}`,
        evidence: [`line-${i}`],
      });
      await Promise.all(
        Array.from({ length: 33 }, (_, i) =>
          graph.call("record_codex_security_endpoint", {
            endpoint: candidate(i),
          }),
        ),
      );
      const selection = {
        role: "sink",
        origin: "discovered",
        scope: "decoder",
      };
      const defaultPage = (await query(selection))["page"] as JsonObject;
      expect(defaultPage["total"]).toBe(33);
      expect(defaultPage["items"]).toBeArrayOfSize(25);
      const first = await query({ ...selection, page: { limit: 20 } });
      const firstPage = first["page"] as JsonObject;
      expect(firstPage["items"]).toBeArrayOfSize(20);
      expect((firstPage["items"] as JsonObject[])[0]).not.toHaveProperty(
        "evidence",
      );
      const next = await query({
        ...selection,
        page: { limit: 20, cursor: firstPage["nextCursor"]! },
      });
      const lastPage = next["page"] as JsonObject;
      expect(lastPage["items"]).toBeArrayOfSize(13);
      expect(lastPage["nextCursor"]).toBeNull();
      expect((await query({ id: "sink-32" }))["endpoint"]).toEqual({
        ...candidate(32),
        origin: "discovered",
      });
      expect(
        (await query({ id: "sink-32", scope: "other" }))["endpoint"],
      ).toBeNull();
      expect((await query({ origin: "supplied" }))["page"]).toMatchObject({
        total: 1,
      });
    } finally {
      await graph.close();
    }
    const saved = JSON.parse(await readFile(snapshotPath, "utf8"));
    expect(saved.configuration).toEqual(configuration);
    expect(saved.endpoints).toBeArrayOfSize(34);
    const reopened = await openDependencyEndpoints({
      configuration,
      snapshotPath,
    });
    expect(reopened.get(saved.endpoints[0].id)).toMatchObject({
      function: "receive",
      origin: "supplied",
    });
    expect(reopened.get("sink-32")).toMatchObject({ role: "sink" });
    await expect(
      openDependencyEndpoints({ configuration: {}, snapshotPath }),
    ).rejects.toThrow("different endpoint configuration");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
