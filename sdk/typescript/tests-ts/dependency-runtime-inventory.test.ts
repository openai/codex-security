import { expect, test } from "bun:test";
import type { DependencyCatalogAnswer } from "../src/dependency-graph-tools.js";
import { createDependencyInventory } from "../src/dependency-inventory.js";
import { createDependencyRuntimeInventory } from "../src/dependency-runtime-inventory.js";
import { exploitabilityMcpConfiguration } from "../src/project-config.js";

const paths: DependencyCatalogAnswer[] = ["app/main.ts", "app/handler.ts"].map(
  (path) => ({
    path,
    services: [
      { name: "preview", scope: "catalog:svc-42", source: "catalog/services" },
    ],
    source: "catalog/services",
    reason: "The catalog lists both files in the preview service.",
  }),
);
const inputSchema = {
  type: "object",
  properties: { service: { type: "string" } },
  required: ["service"],
  additionalProperties: false,
};
const tool = (name: string) => ({
  name,
  inputSchema,
  annotations: { readOnlyHint: true },
});
const binding = (kind: "running_build" | "caller_access", tool = kind) => ({
  kind,
  server: "inventory",
  tool,
  serviceArgument: "service",
  serviceValue: "id",
  pathArgument: null,
  argumentsJson: "{}",
});

test("the host queries each service once and binds the original outcomes to its paths", async () => {
  const calls: unknown[] = [];
  const receipts: unknown[] = [];
  const lookup = createDependencyRuntimeInventory({
    servers: { inventory: {} },
    plan: async () =>
      JSON.stringify({
        bindings: [binding("running_build"), binding("caller_access")],
      }),
    record: (server, result, origin) => {
      receipts.push({ server, result, origin });
      return `receipt-${receipts.length}`;
    },
    signal: new AbortController().signal,
  });
  const outcomes = await lookup(paths, {
    list: async () => ({
      data: [
        {
          name: "inventory",
          tools: {
            running_build: tool("running_build"),
            caller_access: tool("caller_access"),
          },
        },
      ],
    }),
    call: async (server, name, args) => {
      calls.push({ server, name, args });
      if (name === "caller_access") throw new Error("inventory timed out");
      return { structuredContent: { sourceRevision: "fixture-revision" } };
    },
  });
  expect(calls).toEqual([
    { server: "inventory", name: "running_build", args: { service: "svc-42" } },
    { server: "inventory", name: "caller_access", args: { service: "svc-42" } },
  ]);
  expect(receipts).toHaveLength(2);
  expect(
    outcomes
      .filter((outcome) => outcome["kind"] === "running_build")
      .map((outcome) => outcome["receiptId"]),
  ).toEqual(["receipt-1", "receipt-1"]);
  expect(
    outcomes.filter((outcome) => outcome["kind"] === "caller_access"),
  ).toEqual(
    paths.map(({ path }) =>
      expect.objectContaining({
        path,
        outcome: "failed",
        receiptId: "receipt-2",
      }),
    ),
  );
});

test("refreshes a superseded runtime receipt and shares the refresh across callers", async () => {
  const inventory = createDependencyInventory();
  const lookup = createDependencyRuntimeInventory({
    servers: { inventory: {} },
    plan: async () => JSON.stringify({ bindings: [binding("running_build")] }),
    record: inventory.record,
    isReceiptCurrent: inventory.isReceiptCurrent,
    signal: new AbortController().signal,
  });
  const refreshed = { structuredContent: { revision: "new" } };
  let calls = 0;
  const rpc = {
    list: async () => ({
      data: [
        { name: "inventory", tools: { running_build: tool("running_build") } },
      ],
    }),
    call: async () =>
      ++calls === 1 ? { structuredContent: { revision: "old" } } : refreshed,
  };
  const [first] = await lookup(paths.slice(0, 1), rpc);
  expect(first).toMatchObject({ receiptId: "inventory-1" });
  const [reused] = await lookup(paths.slice(1), rpc);
  expect(reused).toMatchObject({ receiptId: "inventory-1" });
  expect(calls).toBe(1);
  const refreshedId = inventory.record("inventory", refreshed, {
    tool: "running_build",
    arguments: { service: "svc-42" },
  });
  expect(inventory.isReceiptCurrent("inventory-1")).toBe(false);

  const outcomes = await Promise.all(paths.map((path) => lookup([path], rpc)));
  expect(calls).toBe(2);
  for (const [outcome] of outcomes) {
    expect(outcome).toMatchObject({
      result: refreshed,
      receiptId: refreshedId,
    });
  }
});

test.each(["isError", "is_error"])(
  "preserves the original %s response as a failed runtime receipt",
  async (errorField) => {
    const inventory = createDependencyInventory();
    const lookup = createDependencyRuntimeInventory({
      servers: { inventory: {} },
      plan: async () =>
        JSON.stringify({ bindings: [binding("running_build")] }),
      record: inventory.record,
      signal: new AbortController().signal,
    });
    const response = {
      [errorField]: true,
      structuredContent: { message: "No reliable inventory result" },
    };
    const [outcome] = await lookup(paths.slice(0, 1), {
      list: async () => ({
        data: [
          {
            name: "inventory",
            tools: { running_build: tool("running_build") },
          },
        ],
      }),
      call: async () => response,
    });
    expect(outcome).toMatchObject({
      outcome: "failed",
      receiptId: "inventory-1",
      result: response,
    });
    expect(inventory.bind(["inventory"], ["inventory-1"])).toMatchObject([
      { receiptId: "inventory-1", outcome: "failed", result: response },
    ]);
  },
);

test("a plan cannot dispatch a disabled inventory tool", async () => {
  const lookup = createDependencyRuntimeInventory({
    servers: { inventory: { disabled_tools: ["caller_access"] } },
    plan: async () =>
      JSON.stringify({ bindings: [binding("running_build", "caller_access")] }),
    record: () => {
      throw new Error("Unexpected receipt");
    },
    signal: new AbortController().signal,
  });
  const outcomes = await lookup(paths.slice(0, 1), {
    list: async () => ({
      data: [
        {
          name: "inventory",
          tools: {
            running_build: tool("running_build"),
            caller_access: tool("caller_access"),
          },
        },
      ],
    }),
    call: async () => {
      throw new Error("Unexpected lookup");
    },
  });
  expect(outcomes.map((outcome) => outcome["outcome"])).toEqual([
    "unavailable",
    "unavailable",
  ]);
});

test("uses server guidance for extra arguments and preserves partial inventory receipts", async () => {
  const instructions =
    'For running_build, pass include_partial="true" and retain coverage.';
  const configured = exploitabilityMcpConfiguration({
    exploitability: { service_catalog_mcps: ["inventory"] },
    codex: {
      mcp_servers: {
        inventory: { url: "https://inventory.invalid/mcp", instructions },
      },
    },
  });
  const calls: unknown[] = [];
  const receipts: unknown[] = [];
  const partial = {
    structuredContent: {
      revision: "fixture-revision",
      metadata: { partial: true, unavailableClusters: ["fixture-cluster"] },
    },
  };
  const lookup = createDependencyRuntimeInventory({
    ...configured,
    plan: async (prompt) => {
      expect(prompt).toContain(JSON.stringify({ inventory: instructions }));
      return JSON.stringify({
        bindings: [
          {
            ...binding("running_build"),
            pathArgument: "source_path",
            argumentsJson: JSON.stringify({
              include_partial: "true",
              service: "incorrect-service",
              source_path: "incorrect-path",
            }),
          },
        ],
      });
    },
    record: (server, result, origin) => {
      receipts.push({ server, result, origin });
      return "partial-receipt";
    },
    signal: new AbortController().signal,
  });
  const outcomes = await lookup(paths.slice(0, 1), {
    list: async () => ({
      data: [
        {
          name: "inventory",
          tools: {
            running_build: {
              ...tool("running_build"),
              inputSchema: {
                ...inputSchema,
                properties: {
                  ...inputSchema.properties,
                  include_partial: { type: "string", enum: ["true", "false"] },
                  source_path: { type: "string" },
                },
              },
            },
          },
        },
      ],
    }),
    call: async (server, name, args) => {
      calls.push({ server, name, args });
      return partial;
    },
  });
  const args = {
    service: "svc-42",
    include_partial: "true",
    source_path: "app/main.ts",
  };
  expect(calls).toEqual([{ server: "inventory", name: "running_build", args }]);
  expect(receipts).toEqual([
    {
      server: "inventory",
      result: partial,
      origin: {
        tool: "running_build",
        arguments: args,
        startedAt: expect.any(String),
        finishedAt: expect.any(String),
      },
    },
  ]);
  expect(outcomes[0]).toMatchObject({
    result: partial,
    receiptId: "partial-receipt",
  });
});

test("does not call a tool when additional arguments violate its schema", async () => {
  const lookup = createDependencyRuntimeInventory({
    servers: { inventory: {} },
    plan: async () =>
      JSON.stringify({
        bindings: [
          {
            ...binding("running_build"),
            argumentsJson: JSON.stringify({ unsupported: true }),
          },
        ],
      }),
    record: () => {
      throw new Error("Unexpected receipt");
    },
    signal: new AbortController().signal,
  });
  const outcomes = await lookup(paths.slice(0, 1), {
    list: async () => ({
      data: [
        { name: "inventory", tools: { running_build: tool("running_build") } },
      ],
    }),
    call: async () => {
      throw new Error("Unexpected lookup");
    },
  });
  expect(outcomes[0]).toMatchObject({ outcome: "unavailable" });
});
