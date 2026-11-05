import { expect, mock, test } from "bun:test";
import type { McpToolCallItem } from "@openai/codex-sdk";
import { resolveDependencyServices } from "../src/dependency-service-catalog.js";
import { runReadOnlyCodex } from "../src/scan-comparison.js";
import { CODEX_SECURITY_THREAD_SOURCES } from "../src/thread-source.js";

const servers = {
  catalog: { command: "synthetic-catalog", enabled_tools: ["lookup"] },
};
const repository = "/synthetic";
const request = { path: "workers/parser/index.ts", project: "workers/parser" };
const options = { servers, repository, requests: [request], runtime: {} };
const lookup = {
  requestId: "request-0",
  reason: "The catalog worker metadata associates it with the parser project.",
  server: "catalog",
  tool: "lookup",
  argumentsJson: JSON.stringify({ target: "catalog-worker", namespace: "ops" }),
  textBlock: null,
  services: [
    {
      record: ["rows", 0],
      name: ["identity", "name"],
      id: ["key"],
      nameValue: "catalog-worker",
      idValue: "worker-id",
    },
  ],
};
const catalogRecord = {
  key: "worker-id",
  identity: { name: "catalog-worker" },
};

function receipt(overrides: Partial<McpToolCallItem> = {}): McpToolCallItem {
  return {
    id: "call-1",
    type: "mcp_tool_call",
    status: "completed",
    server: "catalog",
    tool: "lookup",
    arguments: { namespace: "ops", target: "catalog-worker" },
    result: { structured_content: { rows: [catalogRecord] }, content: [] },
    ...overrides,
  };
}

function runReturning(
  lookups: unknown[],
  receipts: readonly McpToolCallItem[],
  workingDirectory = repository,
  unresolved: unknown[] = [],
  notFound: unknown[] = [],
): typeof runReadOnlyCodex {
  return async (_prompt, _schema, run) => {
    expect(run.workingDirectory).toBe(workingDirectory);
    expect(run.catalogLookup?.servers).toEqual(servers);
    for (const item of receipts) run.catalogLookup?.onResult(item);
    return JSON.stringify({ lookups, notFound, unresolved });
  };
}

test("does not start a resolver when no service catalog is configured", async () => {
  const run = mock<typeof runReadOnlyCodex>();
  expect(
    await resolveDependencyServices({ ...options, servers: {}, run }),
  ).toEqual([]);
  expect(run).not.toHaveBeenCalled();
});

test("maps a graph input to the catalog's actual identity using the agent's association", async () => {
  const workingDirectory = "/synthetic-scratch";
  expect(
    await resolveDependencyServices({
      ...options,
      runtime: { workingDirectory },
      run: runReturning([lookup], [receipt()], workingDirectory),
    }),
  ).toEqual([
    {
      path: request.path,
      source: "catalog/lookup",
      reason: lookup.reason,
      services: [
        {
          name: "catalog-worker",
          scope: "catalog:worker-id",
          source: "catalog/lookup#worker-id",
        },
      ],
    },
  ]);
});

test("reports unverifiable mappings as unresolved", async () => {
  const otherTarget = { target: "other/project", namespace: "ops" };
  for (const [lookups, receipts] of [
    [[lookup], []],
    [
      [{ ...lookup, server: "unconfigured" }],
      [receipt({ server: "unconfigured" })],
    ],
    [[lookup], [receipt({ status: "failed" })]],
    [[{ ...lookup, argumentsJson: JSON.stringify(otherTarget) }], [receipt()]],
    [
      [{ ...lookup, services: [{ ...lookup.services[0], name: ["package"] }] }],
      [receipt()],
    ],
  ] as const) {
    expect(
      await resolveDependencyServices({
        ...options,
        run: runReturning([...lookups], receipts),
      }),
    ).toEqual([
      {
        path: request.path,
        status: "unresolved",
        reason: expect.any(String),
      },
    ]);
  }
});

test("distinguishes a scoped no-service conclusion from an unresolved search", async () => {
  const notFound = {
    requestId: lookup.requestId,
    reason:
      "The dedicated path lookup covers this project and reports no consuming services.",
    server: "catalog",
    tool: "lookup_path",
    argumentsJson: JSON.stringify({ path: request.path }),
    textBlock: 0,
    coverageField: [],
  };
  const emptyReceipt = receipt({
    tool: notFound.tool,
    arguments: { path: request.path },
    result: {
      structured_content: null,
      content: [{ type: "text", text: "[]" }],
    },
  });
  expect(
    await resolveDependencyServices({
      ...options,
      run: runReturning([], [emptyReceipt], repository, [], [notFound]),
    }),
  ).toEqual([
    {
      path: request.path,
      services: [],
      source: "catalog/lookup_path",
      reason: notFound.reason,
    },
  ]);
  const reason =
    "The exploratory name search was empty and broader catalog coverage remains unknown.";
  expect(
    await resolveDependencyServices({
      ...options,
      run: runReturning(
        [],
        [receipt({ result: emptyReceipt.result })],
        repository,
        [{ requestId: lookup.requestId, reason }],
      ),
    }),
  ).toEqual([
    {
      path: request.path,
      status: "unresolved",
      reason,
    },
  ]);
});

test("the read-only runtime forwards only completed selected catalog items", async () => {
  const onResult = mock((_item: McpToolCallItem) => {});
  const valid = receipt();
  expect(
    await runReadOnlyCodex(
      "Resolve the source path.",
      {},
      {
        catalogLookup: { servers, onResult },
        codex: {
          startThread() {
            return {
              async run() {
                return {
                  finalResponse: "{}",
                  items: [
                    receipt({ status: "failed" }),
                    receipt({ server: "unconfigured" }),
                    valid,
                  ],
                };
              },
            };
          },
        },
      },
      {
        surface: "cli",
        command: "exploitability check",
        threadSource: CODEX_SECURITY_THREAD_SOURCES.scan,
      },
    ),
  ).toBe("{}");
  expect(onResult.mock.calls).toEqual([[valid]]);
});
