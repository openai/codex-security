import { expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { JsonObject } from "../src/config.js";
import {
  openDependencyGraph,
  type DependencyCatalogAnswer,
  type DependencyGraphTools,
} from "../src/dependency-graph-tools.js";
import { createDependencyInventory } from "../src/dependency-inventory.js";
import { createDependencyRuntimeInventory } from "../src/dependency-runtime-inventory.js";

type ResolveCatalog = NonNullable<Parameters<typeof openDependencyGraph>[2]>;
type CatalogRequest = Parameters<ResolveCatalog>[0][number];

async function withGraph(
  resolveCatalog: ResolveCatalog,
  isReceiptCurrent: (id: string) => boolean,
  run: (
    resolve: (paths: string[], project: string) => Promise<unknown>,
    trace: (args: object) => Promise<unknown>,
    graph: DependencyGraphTools,
    repository: string,
  ) => Promise<void>,
  queryPayload: JsonObject = {},
  inventory?: {
    lookup: Parameters<typeof openDependencyGraph>[4];
    read: ReturnType<typeof createDependencyInventory>["read"];
  },
  serviceCoverage?: JsonObject,
  excludedSourcePaths?: string[],
) {
  const root = await mkdtemp(join(tmpdir(), "catalog-cache-test-"));
  try {
    await mkdir(join(root, "mcp"));
    await writeFile(
      join(root, "mcp", "helpers.mjs"),
      `export default {
        createDependencyGraphSession(_checkout, _catalogConfigured, { excludedSourcePaths }) {
          let answers = [];
          let fullQueries = 0;
          const reopened = [];
          return {
            ${serviceCoverage ? `serviceResolutionCoverage: () => (${JSON.stringify(serviceCoverage)}),` : ""}
            tools: [{
              name: "query_codex_security_graph",
              description: "Query the graph.",
              inputSchema: { type: "object", properties: {}, additionalProperties: false },
            }],
            async close() {},
            async call() {
              return {
                ${serviceCoverage ? "fixtureFullQueries: ++fullQueries," : ""}
                ...${JSON.stringify(queryPayload)},
                service_resolution: ${JSON.stringify(queryPayload["service_resolution"] ?? {})},
                answers,
                ...(excludedSourcePaths && { excludedSourcePaths, reopened }),
              };
            },
            pendingCatalogRequests({paths, project}) {
              return [...new Set(paths)].map(path => ({ path, project }));
            },
            recordCatalogResolutions(batch) {
              answers = batch;
              return {};
            },
            includeDiscoveryFile(path) {
              reopened.push(path);
            },
          };
        },
      };`,
    );
    const graph = await openDependencyGraph(
      root,
      root,
      resolveCatalog,
      undefined,
      inventory?.lookup,
      undefined,
      isReceiptCurrent,
      inventory && {
        tools: [],
        call: async () => {
          throw new Error("Unexpected supplemental tool");
        },
        readInventoryReceipt: inventory.read,
      },
      excludedSourcePaths,
    );
    try {
      await run(
        (paths, project) =>
          graph.call("resolve_codex_security_services", { paths, project }),
        (args) => graph.call("trace_codex_security_code", args),
        graph,
        root,
      );
    } finally {
      await graph.close();
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

function mapping(
  path: string,
  receiptId: string,
  name = "worker",
): DependencyCatalogAnswer {
  return {
    path,
    services: [
      {
        name,
        scope: `catalog:${name}`,
        source: `catalog/lookup#${name}`,
        receiptSelections: [{ receiptId, textBlock: null, record: ["worker"] }],
      },
    ],
    source: "catalog/lookup",
    reason: "The catalog verified the worker.",
  };
}

const first = "workers/parser.ts";
const second = "workers/decoder.ts";
const project = "workers";

test("a current catalog selection reopens just its requested source file", async () => {
  await withGraph(
    async () => [
      mapping(first, "current"),
      mapping(second, "stale"),
      mapping("workers/unrequested.ts", "current"),
    ],
    (id) => id === "current",
    async (resolve) => {
      const result = await resolve([first, second], project);
      expect(result).toMatchObject({
        excludedSourcePaths: [project],
        reopened: [first],
      });
    },
    {},
    undefined,
    undefined,
    [project],
  );
});

test("automatic runtime lookups share receipt references and the graph reads exact current evidence on demand", async () => {
  const inventory = createDependencyInventory();
  const lookup = createDependencyRuntimeInventory({
    servers: { runtime: {} },
    plan: async () =>
      JSON.stringify({
        bindings: [
          {
            kind: "running_build",
            server: "runtime",
            tool: "lookup",
            serviceArgument: "service",
            serviceValue: "id",
            pathArgument: null,
            argumentsJson: "{}",
          },
        ],
      }),
    record: inventory.record,
    isReceiptCurrent: inventory.isReceiptCurrent,
    signal: new AbortController().signal,
  });
  const records = [{ revision: "fixture-revision" }];
  const calls: JsonObject[] = [];
  const bulk = "large-runtime-response ".repeat(8192);
  const result = { structuredContent: { records, context: bulk } };
  const rpc = {
    list: async () => ({
      data: [
        {
          name: "runtime",
          tools: {
            lookup: {
              name: "lookup",
              inputSchema: {
                type: "object",
                properties: { service: { type: "string" } },
                required: ["service"],
              },
              annotations: { readOnlyHint: true },
            },
          },
        },
      ],
    }),
    call: async (_server: string, _tool: string, args: JsonObject) => {
      calls.push(args);
      return result;
    },
  };
  await withGraph(
    async (requests) => requests.map(({ path }) => mapping(path, "catalog-1")),
    (id) => id === "catalog-1" || inventory.isReceiptCurrent(id),
    async (_resolve, _trace, graph) => {
      const automatic = await graph.call(
        "resolve_codex_security_services",
        { paths: [first, second], project },
        rpc,
      );
      const receiptId = "inventory-1";
      expect(calls).toEqual([{ service: "worker" }]);
      expect(automatic["runtime_lookups"]).toContainAllValues(
        [first, second].flatMap((path) => [
          {
            kind: "running_build",
            path,
            service: "worker",
            serviceScope: "catalog:worker",
            server: "runtime",
            tool: "lookup",
            receiptId,
            outcome: "captured",
          },
          expect.objectContaining({ path, kind: "caller_access" }),
        ]),
      );
      expect(JSON.stringify(automatic)).not.toContain("large-runtime-response");
      const read = async (inventory: JsonObject) =>
        (await graph.call("query_codex_security_graph", { inventory }))[
          "inventory"
        ];
      const saved = inventory.snapshot()[0]!;
      const selection = { receiptId, textBlock: null, record: ["records", 0] };
      const shape = await read({ receiptId });
      expect(shape).toMatchObject({
        current: true,
        originalPayloadSha256: saved.originalPayloadSha256,
        resultShape: { structuredFields: ["records", "context"] },
      });
      expect(shape).not.toHaveProperty("result");
      expect(await read(selection)).toMatchObject({
        selection,
        result: records[0],
        originalPayloadSha256: saved.originalPayloadSha256,
      });
      expect(await read({ receiptId, original: true })).toMatchObject({
        result,
      });
      await expect(
        read({ ...selection, record: ["records", 2] }),
      ).rejects.toThrow("does not exist");
      const failed = { isError: true, content: [{ type: "text", text: bulk }] };
      const failureId = inventory.record("runtime", failed, {
        tool: "lookup",
        arguments: { service: "worker" },
        outcome: "failed",
      })!;
      await expect(read(selection)).rejects.toThrow("was superseded");
      expect(await read({ receiptId: failureId })).toMatchObject({
        outcome: "failed",
      });
      expect(
        await read({ receiptId: failureId, original: true }),
      ).toMatchObject({
        outcome: "failed",
        result: failed,
      });
      expect(calls).toHaveLength(1);
    },
    {},
    { lookup, read: inventory.read },
  );
});

test("graph reuses verified mappings and only dispatches distinct misses for the exact project", async () => {
  const batches: (readonly CatalogRequest[])[] = [];
  await withGraph(
    async (requests) => {
      batches.push(requests);
      return requests.map(({ path }) => mapping(path, "receipt-1"));
    },
    (id) => id === "receipt-1",
    async (resolve) => {
      await resolve([first], project);
      expect(await resolve([second, first, second], project)).toMatchObject({
        answers: [mapping(second, "receipt-1"), mapping(first, "receipt-1")],
      });
      await resolve([first], "other-project");
      await resolve([first], project);
      expect(batches).toEqual([
        [{ path: first, project }],
        [{ path: second, project }],
        [{ path: first, project: "other-project" }],
      ]);
    },
  );
});

test("graph retries unresolved catalog answers and reuses scoped no-service evidence", async () => {
  let calls = 0;
  const noService = {
    path: first,
    services: [],
    source: "catalog/lookup",
    reason: "The scoped search found no service.",
    receiptSelections: [
      { receiptId: "receipt-1", textBlock: null, record: [] },
    ],
  };
  await withGraph(
    async () => {
      calls++;
      if (calls === 1)
        return [
          { path: first, status: "unresolved", reason: "Catalog timed out." },
        ];
      return [noService];
    },
    (id) => id === "receipt-1",
    async (resolve) => {
      expect(await resolve([first], project)).toMatchObject({
        answers: [{ path: first, status: "unresolved" }],
      });
      expect(await resolve([first], project)).toMatchObject({
        answers: [noService],
      });
      expect(await resolve([first], project)).toMatchObject({
        answers: [noService],
      });
      expect(calls).toBe(2);
    },
  );
});

test("graph rechecks a cache hit if a mixed batch supersedes its receipt", async () => {
  const inventory = createDependencyInventory();
  const batches: (readonly CatalogRequest[])[] = [];
  await withGraph(
    async (requests) => {
      batches.push(requests);
      const name = batches.length === 1 ? "worker" : "replacement";
      const id = inventory.record(
        "catalog",
        { structured_content: { worker: name } },
        { tool: "lookup", arguments: { project } },
      )!;
      return requests.map(({ path }) => mapping(path, id, name));
    },
    inventory.isReceiptCurrent,
    async (resolve) => {
      expect(await resolve([first], project)).toMatchObject({
        answers: [mapping(first, "inventory-1")],
      });
      expect(await resolve([first, second], project)).toMatchObject({
        answers: [
          mapping(first, "inventory-2", "replacement"),
          mapping(second, "inventory-2", "replacement"),
        ],
      });
      expect(batches[1]).toEqual([{ path: second, project }]);
      expect(batches.slice(2).flat()).toContainEqual({ path: first, project });
    },
  );
});

test("source-only traces leave catalog dispatch to explicit requests", async () => {
  const batches: (readonly CatalogRequest[])[] = [];
  await withGraph(
    async (requests) => {
      batches.push(requests);
      return requests.map(({ path }) => mapping(path, "receipt-1"));
    },
    (id) => id === "receipt-1",
    async (resolve, trace) => {
      await trace({ files: [first], source_only: true });
      expect(batches).toEqual([]);
      await resolve([first], project);
      expect(batches).toEqual([[{ path: first, project }]]);
    },
  );
});

test("shared source notes retain host-read excerpts across worker completion and source changes", async () => {
  await withGraph(
    async () => [],
    () => false,
    async (_resolve, _trace, graph, repository) => {
      const source = join(repository, "parser.js");
      await writeFile(source, "export function parse() {\n  return [];\n}\n");
      const input = {
        question: "Does the selected parser include the depth guard?",
        scope: "installed parser copy",
        claim: "This hunk appears to enforce the limit.",
        evidence: [{ path: "parser.js", startLine: 2, endLine: 2 }],
      };
      const first = await graph.call("record_codex_security_evidence", input);
      const reference = first["source_evidence"] as JsonObject;
      expect(reference).toEqual({
        id: expect.stringMatching(/^source-evidence-/u),
      });
      const note = (
        await graph.call("query_codex_security_graph", {
          evidence: { id: reference["id"] },
        })
      )["source_evidence"] as JsonObject;
      expect(note).toMatchObject({
        investigator_assertion: {
          question: input.question,
          scope: input.scope,
          claim: input.claim,
        },
        excerpts: [
          { path: "parser.js", startLine: 2, endLine: 2, text: "  return [];" },
        ],
      });
      expect(await graph.call("record_codex_security_evidence", input)).toEqual(
        first,
      );
      await writeFile(
        source,
        "export function parse() {\n  return input;\n}\n",
      );
      const second = await graph.call("record_codex_security_evidence", input);
      expect(second["source_evidence"]).not.toEqual(reference);
      expect(
        await graph.call("query_codex_security_graph", {
          evidence: { id: note["id"] },
        }),
      ).toMatchObject({
        source_evidence: note,
        source_evidence_count: 2,
        service_resolution: {},
      });
      const listing = await graph.call("query_codex_security_graph", {
        evidence: { search: "depth guard" },
      });
      expect(listing["source_evidence"]).toHaveLength(2);
      expect(JSON.stringify(listing)).not.toContain("excerpts");
      const summary = await graph.call("query_codex_security_graph", {});
      expect(summary).toMatchObject({ source_evidence_count: 2 });
      expect(summary).not.toHaveProperty("source_evidence");

      const otherRun = await openDependencyGraph(repository, repository);
      try {
        expect(
          await otherRun.call("query_codex_security_graph", {
            evidence: { id: note["id"] },
          }),
        ).toMatchObject({ source_evidence: null, source_evidence_count: 0 });
      } finally {
        await otherRun.close();
      }
    },
  );
});

test("source-save acknowledgments stay focused while complete evidence and graph data remain queryable", async () => {
  const coverage = {
    catalog_configured: true,
    revision: 7,
    pending: 1,
    checked: 3,
    unresolved: 1,
    truncated: true,
  };
  const acknowledgments: JsonObject[] = [];
  const capturedText = "export const selectedMode = 'safe';";
  for (const copies of [1, 300]) {
    const payload = {
      service_resolution: {
        ...coverage,
        paths: ["pending-".repeat(copies)],
        unresolved_paths: [
          { path: "source.ts", reason: "Original diagnostic. ".repeat(copies) },
        ],
      },
      ruleExecutions: Array.from({ length: copies }, (_, index) => ({
        id: `execution-${index}`,
        configSha256: "a".repeat(64),
        ruleIds: [`source-rule-${index}`],
      })),
      graph_evidence: {
        resources: [{ receiptId: "receipt-1", uri: "evidence://fixture" }],
      },
    };
    await withGraph(
      async () => [],
      () => false,
      async (_resolve, _trace, graph, repository) => {
        await writeFile(join(repository, "source.ts"), capturedText + "\n");
        const saved = await graph.call("record_codex_security_evidence", {
          question: "Which mode is selected?",
          scope: "fixture source",
          claim: "The source selects safe mode.",
          evidence: [{ path: "source.ts", startLine: 1, endLine: 1 }],
        });
        const reference = saved["source_evidence"] as JsonObject;
        const id = reference["id"]!;
        expect(id).toMatch(/^source-evidence-[a-f0-9]{64}$/u);
        expect(saved).toEqual({
          source_evidence: { id },
          source_evidence_count: 1,
          service_resolution: coverage,
        });
        const read = await graph.call("query_codex_security_graph", {
          evidence: { id },
        });
        expect(read["source_evidence"]).toMatchObject({
          id,
          investigator_assertion: {
            question: "Which mode is selected?",
            scope: "fixture source",
            claim: "The source selects safe mode.",
          },
          excerpts: [
            { path: "source.ts", startLine: 1, endLine: 1, text: capturedText },
          ],
        });
        expect(Object.keys(read).sort()).toEqual([
          "service_resolution",
          "source_evidence",
          "source_evidence_count",
        ]);
        expect(read["service_resolution"]).toEqual(coverage);
        const listing = await graph.call("query_codex_security_graph", {
          evidence: {},
        });
        expect(Object.keys(listing).sort()).toEqual(Object.keys(read).sort());
        expect(listing["source_evidence"]).toEqual([
          {
            id,
            question: "Which mode is selected?",
            scope: "fixture source",
            claim: "The source selects safe mode.",
          },
        ]);
        const full = await graph.call("query_codex_security_graph", {});
        if (copies > 1) expect(full["fixtureFullQueries"]).toBe(1);
        for (const key of [
          "service_resolution",
          "ruleExecutions",
          "graph_evidence",
        ]) {
          expect(full[key]).toEqual(payload[key as keyof typeof payload]);
        }
        acknowledgments.push(saved);
      },
      payload,
      undefined,
      copies > 1 ? coverage : undefined,
    );
  }
  // Repository provenance can change the content-addressed ID between fixtures.
  expect(Buffer.byteLength(JSON.stringify(acknowledgments[1]))).toBe(
    Buffer.byteLength(JSON.stringify(acknowledgments[0])),
  );
});

test("source notes reject invalid ranges and outside paths without retaining partial notes", async () => {
  await withGraph(
    async () => [],
    () => false,
    async (_resolve, _trace, graph, repository) => {
      await writeFile(join(repository, "parser.js"), "return [];\n");
      const input = {
        question: "Which copy contains this control?",
        scope: "parser",
        claim: "The parser returns early.",
      };
      await expect(
        graph.call("record_codex_security_evidence", {
          ...input,
          evidence: [
            { path: "parser.js", startLine: 1, endLine: 1 },
            { path: "parser.js", startLine: 2, endLine: 3 },
          ],
        }),
      ).rejects.toThrow("Invalid evidence range");
      await expect(
        graph.call("record_codex_security_evidence", {
          ...input,
          evidence: [{ path: "../other.js", startLine: 1, endLine: 1 }],
        }),
      ).rejects.toThrow();
      expect(
        await graph.call("query_codex_security_graph", { evidence: {} }),
      ).toMatchObject({ source_evidence: [], source_evidence_count: 0 });
      const queryTool = graph.tools.find(
        ({ name }) => name === "query_codex_security_graph",
      );
      expect(queryTool?.inputSchema["properties"]).toHaveProperty("evidence");
    },
  );
});

test("source notes return the actual ranges when an excerpt ends at EOF", async () => {
  await withGraph(
    async () => [],
    () => false,
    async (_resolve, _trace, graph, repository) => {
      await writeFile(
        join(repository, "parser.js"),
        "const input = read();\nparse(input);\n",
      );
      const input = {
        question: "Which parser handles the input?",
        scope: "parser",
        claim: "The parsed value comes from read().",
      };
      const clipped = await graph.call("record_codex_security_evidence", {
        ...input,
        evidence: [
          { path: "parser.js", startLine: 1, endLine: 1 },
          { path: "parser.js", startLine: 2, endLine: 6 },
        ],
      });
      const exact = await graph.call("record_codex_security_evidence", {
        ...input,
        evidence: [
          { path: "parser.js", startLine: 1, endLine: 1 },
          { path: "parser.js", startLine: 2, endLine: 2 },
        ],
      });
      const { id } = exact["source_evidence"] as JsonObject;
      expect(clipped).toMatchObject({
        source_evidence: {
          id,
          ranges: [
            { path: "parser.js", startLine: 1, endLine: 1 },
            { path: "parser.js", startLine: 2, endLine: 2 },
          ],
          warnings: [expect.stringContaining("parser.js:2-6 ended at line 2")],
        },
        source_evidence_count: 1,
      });
      expect(
        await graph.call("query_codex_security_graph", { evidence: { id } }),
      ).toMatchObject({
        source_evidence: {
          excerpts: [
            {
              path: "parser.js",
              startLine: 1,
              endLine: 1,
              text: "const input = read();",
            },
            {
              path: "parser.js",
              startLine: 2,
              endLine: 2,
              text: "parse(input);",
            },
          ],
        },
      });
    },
  );
});

test("the graph retains exact source work with compact receipts and checked pagination", async () => {
  await withGraph(
    async () => [],
    () => false,
    async (_resolve, _trace, graph) => {
      const mutation = "record_codex_security_source_work";
      const query = (sourceWork: JsonObject) =>
        graph.call("query_codex_security_graph", { sourceWork });
      const paths = Array.from(
        { length: 300 },
        (_, index) => "work/file-" + index.toString().padStart(3, "0") + ".ts",
      );
      const initial = {
        operation: "append_roster_page",
        id: "decoder-discovery",
        owner: "discovery",
        paths,
        declaredComplete: false,
        gaps: [
          {
            id: "next",
            description: "The next source partition is not yet ingested.",
          },
        ],
        search: "List paths importing the decoder",
        sourceRefs: ["search-result-1"],
      };
      const first = await graph.call(mutation, { work: initial });
      expect(first).toMatchObject({
        source_work: {
          id: initial.id,
          matchedFileCount: 300,
          declaredComplete: false,
          gapCount: 1,
        },
      });
      expect(JSON.stringify(first)).not.toContain(paths[0]!);
      expect(
        graph.tools.find((tool) => tool.name === mutation)?.inputSchema,
      ).toMatchObject({
        type: "object",
        required: ["work"],
      });
      const read = await query({
        rosterId: initial.id,
        page: { view: "unassigned", limit: 2 },
      });
      const result = read["source_work"] as JsonObject;
      const page = result["page"] as JsonObject;
      expect(page).toMatchObject({ items: paths.slice(0, 2), total: 300 });
      expect(page["nextCursor"]).not.toBeNull();
      expect(
        await query({
          rosterId: initial.id,
          page: { view: "unassigned", limit: 2, cursor: page["nextCursor"]! },
        }),
      ).toMatchObject({ source_work: { page: { items: paths.slice(2, 4) } } });

      await graph.call(mutation, {
        work: {
          operation: "assign_partition",
          id: "small-worker",
          owner: "first-investigator",
          rosterId: initial.id,
          paths: paths.slice(0, 2),
        },
      });
      await expect(
        query({
          rosterId: initial.id,
          page: { view: "unassigned", limit: 2, cursor: page["nextCursor"]! },
        }),
      ).rejects.toThrow("changed since this cursor");
      expect(
        await query({
          rosterId: initial.id,
          page: { view: "pages", limit: 1 },
        }),
      ).toMatchObject({
        source_work: {
          page: {
            total: 1,
            items: [
              {
                search: initial.search,
                sourceRefs: initial.sourceRefs,
                gaps: initial.gaps,
              },
            ],
            nextCursor: null,
          },
        },
      });
      expect(await query({})).toMatchObject({
        source_work: {
          incompleteRosterCount: 1,
          gapCount: 1,
          unassignedFileCount: 298,
          remainingFileCount: 2,
          pendingHandoffCount: 0,
        },
      });
      expect(
        await graph.call("query_codex_security_graph", { evidence: {} }),
      ).toMatchObject({
        source_evidence: [],
      });
    },
  );
});
