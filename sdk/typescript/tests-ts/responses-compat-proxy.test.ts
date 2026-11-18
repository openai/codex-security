import { expect, test } from "bun:test";
import { createServer, type RequestListener } from "node:http";
import { once } from "node:events";
import {
  responsesCompatRequest,
  startResponsesCompatProxy,
} from "../src/responses-compat-proxy.js";

async function listen(handler: RequestListener) {
  const server = createServer(handler);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address() as { port: number };
  return {
    url: `http://127.0.0.1:${address.port}`,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      }),
  };
}

async function readNodeJson(request: NodeJS.ReadableStream) {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<
    string,
    unknown
  >;
}

function sseEvents(text: string): Record<string, unknown>[] {
  return text
    .split("\n\n")
    .map((frame) => frame.replace(/^data: /m, ""))
    .filter(Boolean)
    .map((data) => JSON.parse(data) as Record<string, unknown>);
}

/** A Responses endpoint that rejects the `namespace` and `custom` tool types. */
function rejectingUpstream() {
  return listen(async (request, response) => {
    const body = await readNodeJson(request);
    const tools = Array.isArray(body["tools"]) ? body["tools"] : [];
    const rejected = (tools as Array<Record<string, unknown>>).find(
      (tool) => tool["type"] !== "function",
    );
    if (rejected) {
      response.writeHead(422, { "content-type": "application/json" }).end(
        JSON.stringify({
          error: {
            message: `400 Unknown type: ${rejected["type"]}`,
            type: "invalid_request_error",
          },
        }),
      );
      return;
    }
    const flat = (tools as Array<Record<string, unknown>>).find((tool) =>
      String(tool["description"] ?? "").startsWith(
        "collaboration.spawn_agent:",
      ),
    );
    const name = String(flat?.["name"] ?? "spawn_agent");
    const call = {
      type: "function_call",
      id: "fc_1",
      call_id: "call_1",
      name,
      arguments: '{"task_name":"/root/probe_task"}',
    };
    if (body["stream"] === true) {
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.write(
        `data: ${JSON.stringify({ type: "response.created", response: { id: "resp_1", status: "in_progress", output: [] } })}\n\n`,
      );
      response.write(
        `data: ${JSON.stringify({ type: "response.output_item.added", output_index: 0, item: { ...call, arguments: "" } })}\n\n`,
      );
      response.write(
        `data: ${JSON.stringify({ type: "response.function_call_arguments.delta", output_index: 0, item_id: "fc_1", delta: '{"task_name":"/root/probe_task"}' })}\n\n`,
      );
      response.write(
        `data: ${JSON.stringify({ type: "response.output_item.done", output_index: 0, item: call })}\n\n`,
      );
      response.write(
        `data: ${JSON.stringify({ type: "response.completed", response: { id: "resp_1", status: "completed", output: [call] } })}\n\n`,
      );
      response.end();
      return;
    }
    response.writeHead(200, { "content-type": "application/json" }).end(
      JSON.stringify({
        id: "resp_1",
        status: "completed",
        output: [call],
      }),
    );
  });
}

const plainTool = {
  type: "function",
  name: "record_finding",
  description: "Record a finding",
  parameters: { type: "object", properties: {} },
  strict: true,
};

const collaborationTools = {
  type: "namespace",
  name: "collaboration",
  description: "Delegate work to sub-agents",
  tools: [
    {
      type: "function",
      name: "spawn_agent",
      description: "Spawn a sub-agent",
      parameters: {
        type: "object",
        properties: { task: { type: "string" } },
        required: ["task"],
      },
      strict: true,
    },
    {
      type: "function",
      name: "wait_agent",
      description: "Wait for a sub-agent",
      parameters: {
        type: "object",
        properties: { task_name: { type: "string" } },
        required: ["task_name"],
      },
      strict: true,
    },
  ],
};

const longMcpTool = {
  type: "namespace",
  name: "mcp__codex_security",
  description: "Codex Security MCP tools",
  tools: [
    {
      type: "function",
      name: "record_codex_security_candidate_validations",
      description: "Record candidate validation results",
      parameters: { type: "object", properties: {} },
      strict: true,
    },
  ],
};

const webSearchTool = { type: "web_search" };

const customReviewTools = {
  type: "namespace",
  name: "review",
  description: "Review",
  tools: [
    {
      type: "custom",
      name: "freeform",
      description: "Freeform tool",
      format: { type: "text" },
    },
  ],
};

/** A Responses endpoint that streams a flattened custom-tool call. */
function customStreamingUpstream() {
  return listen(async (request, response) => {
    const body = await readNodeJson(request);
    const tools = Array.isArray(body["tools"]) ? body["tools"] : [];
    const rejected = (tools as Array<Record<string, unknown>>).find(
      (tool) => tool["type"] !== "function",
    );
    if (rejected) {
      response.writeHead(422, { "content-type": "application/json" }).end(
        JSON.stringify({
          error: {
            message: `400 Unknown type: ${rejected["type"]}`,
            type: "invalid_request_error",
          },
        }),
      );
      return;
    }
    const flat = (tools as Array<Record<string, unknown>>).find((tool) =>
      String(tool["description"] ?? "").startsWith("review.freeform:"),
    );
    const name = String(flat?.["name"] ?? "freeform");
    const call = {
      type: "function_call",
      id: "fc_9",
      call_id: "call_9",
      name,
      arguments: JSON.stringify({ input: "freeform payload" }),
    };
    response.writeHead(200, { "content-type": "text/event-stream" });
    response.write(
      `data: ${JSON.stringify({ type: "response.created", response: { id: "resp_9", status: "in_progress", output: [] } })}\n\n`,
    );
    response.write(
      `data: ${JSON.stringify({ type: "response.output_item.added", output_index: 0, item: { ...call, arguments: "" } })}\n\n`,
    );
    response.write(
      `data: ${JSON.stringify({ type: "response.function_call_arguments.delta", output_index: 0, item_id: "fc_9", delta: '{"input":"freeform ' })}\n\n`,
    );
    response.write(
      `data: ${JSON.stringify({ type: "response.function_call_arguments.delta", output_index: 0, item_id: "fc_9", delta: 'payload"}' })}\n\n`,
    );
    response.write(
      `data: ${JSON.stringify({ type: "response.output_item.done", output_index: 0, item: call })}\n\n`,
    );
    response.write(
      `data: ${JSON.stringify({ type: "response.completed", response: { id: "resp_9", status: "completed", output: [call] } })}\n\n`,
    );
    response.end();
  });
}

test("flattens namespace tools and keeps plain function tools byte-identical", () => {
  const { body } = responsesCompatRequest({
    tools: [plainTool, collaborationTools, longMcpTool, webSearchTool],
    input: "Review",
  });
  const tools = body["tools"] as Array<Record<string, unknown>>;
  expect(tools).toHaveLength(5);
  expect(tools[0]).toEqual(plainTool);
  expect(tools[1]).toMatchObject({
    type: "function",
    description: "collaboration.spawn_agent: Spawn a sub-agent",
    parameters: collaborationTools.tools[0]!.parameters,
    strict: true,
  });
  expect(tools[3]).toMatchObject({
    type: "function",
    description:
      "mcp__codex_security.record_codex_security_candidate_validations: Record candidate validation results",
  });
  for (const tool of tools.slice(1, 4)) {
    expect(tool["name"]).toMatch(/^[a-zA-Z0-9_-]{1,64}$/);
    expect(tool["name"]).not.toBe("spawn_agent");
  }
  expect(tools[4]).toEqual(webSearchTool);
  // The longest namespaced name stays within the 64-character function limit.
  expect(String(tools[3]!["name"]).length).toBeLessThanOrEqual(64);
});

test("aliases are deterministic and distinct per namespace", () => {
  const request = {
    tools: [
      collaborationTools,
      {
        type: "namespace",
        name: "other",
        description: "Another namespace",
        tools: [
          {
            type: "function",
            name: "spawn_agent",
            description: "Spawn something else",
            parameters: { type: "object", properties: {} },
          },
        ],
      },
    ],
    input: "Review",
  };
  const first = responsesCompatRequest(request).body["tools"] as Array<
    Record<string, unknown>
  >;
  const second = responsesCompatRequest(request).body["tools"] as Array<
    Record<string, unknown>
  >;
  expect(first[0]!["name"]).toBe(second[0]!["name"]);
  expect(first[0]!["name"]).not.toBe(first[2]!["name"]);
});

test("rewrites replayed history: calls, agent_message, reasoning, tool_choice", () => {
  const { body, output } = responsesCompatRequest({
    tools: [plainTool, collaborationTools],
    tool_choice: {
      type: "function",
      name: "spawn_agent",
      namespace: "collaboration",
    },
    input: [
      {
        type: "function_call",
        namespace: "collaboration",
        name: "spawn_agent",
        call_id: "call_1",
        arguments: '{"task":"probe"}',
      },
      {
        type: "function_call",
        name: "record_finding",
        call_id: "call_2",
        arguments: "{}",
      },
      { type: "function_call_output", call_id: "call_1", output: "ok" },
      {
        type: "agent_message",
        id: "amsg_1",
        content: [
          { type: "input_text", text: "Message Type: FINAL_ANSWER\n" },
          { type: "encrypted_content", encrypted_content: "Done." },
        ],
      },
      { type: "reasoning", id: "rs_1", content: null },
      { type: "message", role: "user", content: "keep me" },
    ],
  });
  const tools = body["tools"] as Array<Record<string, unknown>>;
  const flatSpawn = String(tools[1]!["name"]);
  expect(body["tool_choice"]).toEqual({ type: "function", name: flatSpawn });
  const input = body["input"] as Array<Record<string, unknown>>;
  expect(input[0]).toEqual({
    type: "function_call",
    name: flatSpawn,
    call_id: "call_1",
    arguments: '{"task":"probe"}',
  });
  expect(input[0]).not.toHaveProperty("namespace");
  expect(input[1]).toEqual({
    type: "function_call",
    name: "record_finding",
    call_id: "call_2",
    arguments: "{}",
  });
  expect(input[3]).toEqual({
    type: "message",
    role: "user",
    id: "amsg_1",
    content: [
      { type: "input_text", text: "Message Type: FINAL_ANSWER\n" },
      { type: "input_text", text: "Done." },
    ],
  });
  expect(input[4]).toEqual({ type: "reasoning", id: "rs_1" });
  expect(input[5]).toEqual({
    type: "message",
    role: "user",
    content: "keep me",
  });
  expect(
    output({
      type: "function_call",
      call_id: "call_1",
      name: flatSpawn,
      arguments: '{"task":"probe"}',
    }),
  ).toEqual({
    type: "function_call",
    call_id: "call_1",
    name: "spawn_agent",
    namespace: "collaboration",
    arguments: '{"task":"probe"}',
  });
});

test("drops tool_choice when the translated request has no tools", () => {
  const { body } = responsesCompatRequest({
    tools: [],
    tool_choice: "auto",
    input: "Review",
  });
  expect(body).not.toHaveProperty("tool_choice");
  const forced = responsesCompatRequest({
    tools: [plainTool],
    tool_choice: { type: "function", name: "record_finding" },
    input: "Review",
  });
  expect(forced.body["tool_choice"]).toEqual({
    type: "function",
    name: "record_finding",
  });
});

test("custom tools round-trip through the input-string parameter", () => {
  const custom = {
    type: "custom",
    name: "freeform",
    description: "Freeform tool",
    format: { type: "text" },
  };
  const { body, output } = responsesCompatRequest({
    tools: [
      {
        type: "namespace",
        name: "review",
        description: "Review",
        tools: [custom],
      },
    ],
    input: [
      {
        type: "custom_tool_call",
        namespace: "review",
        name: "freeform",
        call_id: "call_9",
        input: "freeform payload",
      },
    ],
  });
  const tools = body["tools"] as Array<Record<string, unknown>>;
  expect(tools[0]).toMatchObject({
    type: "function",
    description: "review.freeform: Freeform tool",
    strict: true,
  });
  const flat = String(tools[0]!["name"]);
  expect(body["input"]).toEqual([
    {
      type: "function_call",
      name: flat,
      call_id: "call_9",
      arguments: JSON.stringify({ input: "freeform payload" }),
    },
  ]);
  expect(
    output({
      type: "function_call",
      call_id: "call_9",
      name: flat,
      arguments: JSON.stringify({ input: "freeform payload" }),
    }),
  ).toEqual({
    type: "custom_tool_call",
    call_id: "call_9",
    name: "freeform",
    namespace: "review",
    input: "freeform payload",
  });
});

test("a past tool call remains valid history after the tool is removed", () => {
  const { body, output } = responsesCompatRequest({
    tools: [plainTool],
    input: [
      {
        type: "function_call",
        namespace: "collaboration",
        name: "spawn_agent",
        call_id: "call_1",
        arguments: "{}",
      },
    ],
  });
  const input = body["input"] as Array<Record<string, unknown>>;
  expect(String(input[0]!["name"])).toMatch(/^collaboration__spawn_agent_/);
  expect(input[0]).not.toHaveProperty("namespace");
  expect(() =>
    output({
      type: "function_call",
      call_id: "call_1",
      name: String(input[0]!["name"]),
      arguments: "{}",
    }),
  ).toThrow("returned an unknown tool");
  expect(() =>
    output({
      type: "function_call",
      call_id: "call_2",
      name: "record_finding",
      arguments: "{}",
    }),
  ).not.toThrow();
});

test("a namespace-rejecting endpoint fails without the proxy", async () => {
  const upstream = await rejectingUpstream();
  try {
    const response = await fetch(`${upstream.url}/responses`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "fixture",
        stream: false,
        tools: [collaborationTools],
        input: "Review",
      }),
    });
    expect(response.status).toBe(422);
    expect(await response.json()).toMatchObject({
      error: { message: expect.stringContaining("Unknown type: namespace") },
    });
  } finally {
    await upstream.close();
  }
});

test("proxy flattens namespaces and restores the call over streaming SSE", async () => {
  const upstream = await rejectingUpstream();
  const adapter = await startResponsesCompatProxy(`${upstream.url}/v1`);
  try {
    const response = await fetch(`${adapter.baseUrl}/responses`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer synthetic-upstream-key",
      },
      body: JSON.stringify({
        model: "fixture",
        stream: true,
        tools: [plainTool, collaborationTools, longMcpTool],
        input: "Review",
      }),
    });
    expect(response.status).toBe(200);
    const events = sseEvents(await response.text());
    expect(events.map((event) => event["type"])).toEqual([
      "response.created",
      "response.output_item.added",
      "response.function_call_arguments.delta",
      "response.output_item.done",
      "response.completed",
    ]);
    const done = events[3]!["item"] as Record<string, unknown>;
    expect(done).toEqual({
      type: "function_call",
      id: "fc_1",
      call_id: "call_1",
      name: "spawn_agent",
      namespace: "collaboration",
      arguments: '{"task_name":"/root/probe_task"}',
    });
    const completed = events[4]!["response"] as Record<string, unknown>;
    expect(completed["output"]).toEqual([done]);
    // The upstream never saw a namespace tool.
    expect(JSON.stringify(events)).not.toContain("collaboration__spawn_agent");
  } finally {
    await adapter.close();
    await upstream.close();
  }
});

test("proxy restores custom tools over streaming SSE without parsing arguments on added", async () => {
  const upstream = await customStreamingUpstream();
  const adapter = await startResponsesCompatProxy(`${upstream.url}/v1`);
  try {
    const response = await fetch(`${adapter.baseUrl}/responses`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "fixture",
        stream: true,
        tools: [customReviewTools],
        input: "Review",
      }),
    });
    expect(response.status).toBe(200);
    const events = sseEvents(await response.text());
    expect(events.map((event) => event["type"])).toEqual([
      "response.created",
      "response.output_item.added",
      "response.function_call_arguments.delta",
      "response.function_call_arguments.delta",
      "response.output_item.done",
      "response.completed",
    ]);
    const added = events[1]!["item"] as Record<string, unknown>;
    expect(added).toEqual({
      type: "custom_tool_call",
      id: "fc_9",
      call_id: "call_9",
      name: "freeform",
      namespace: "review",
      input: "",
    });
    const done = events[4]!["item"] as Record<string, unknown>;
    expect(done).toEqual({
      type: "custom_tool_call",
      id: "fc_9",
      call_id: "call_9",
      name: "freeform",
      namespace: "review",
      input: "freeform payload",
    });
    const completed = events[5]!["response"] as Record<string, unknown>;
    expect(completed["output"]).toEqual([done]);
    // The upstream never saw a custom tool, and no flat alias leaks out.
    expect(JSON.stringify(events)).not.toContain("review__freeform");
  } finally {
    await adapter.close();
    await upstream.close();
  }
});

test("proxy restores calls in non-streaming JSON responses", async () => {
  const upstream = await rejectingUpstream();
  const adapter = await startResponsesCompatProxy(`${upstream.url}/v1`);
  try {
    const response = await fetch(`${adapter.baseUrl}/responses`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "fixture",
        stream: false,
        tools: [collaborationTools],
        input: "Review",
      }),
    });
    expect(response.status).toBe(200);
    const payload = (await response.json()) as Record<string, unknown>;
    expect(payload["output"]).toEqual([
      {
        type: "function_call",
        id: "fc_1",
        call_id: "call_1",
        name: "spawn_agent",
        namespace: "collaboration",
        arguments: '{"task_name":"/root/probe_task"}',
      },
    ]);
  } finally {
    await adapter.close();
    await upstream.close();
  }
});

test("proxy preserves upstream errors and diagnostics", async () => {
  const upstream = await listen((_request, response) => {
    response
      .writeHead(429, { "content-type": "application/json" })
      .end(JSON.stringify({ error: { message: "synthetic rate limit" } }));
  });
  const adapter = await startResponsesCompatProxy(`${upstream.url}/v1`);
  try {
    const response = await fetch(`${adapter.baseUrl}/responses`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "fixture", input: "Review" }),
    });
    expect(response.status).toBe(429);
    expect(await response.json()).toEqual({
      error: { message: "synthetic rate limit" },
    });
  } finally {
    await adapter.close();
    await upstream.close();
  }
});

test("proxy reports an unknown tool as a failed stream event", async () => {
  const upstream = await listen((_request, response) => {
    response.writeHead(200, { "content-type": "text/event-stream" });
    response.write(
      `data: ${JSON.stringify({ type: "response.output_item.done", output_index: 0, item: { type: "function_call", call_id: "call_1", name: "not_a_tool", arguments: "{}" } })}` +
        "\n\n",
    );
    response.end();
  });
  const adapter = await startResponsesCompatProxy(`${upstream.url}/v1`);
  try {
    const response = await fetch(`${adapter.baseUrl}/responses`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "fixture",
        stream: true,
        tools: [plainTool],
        input: "Review",
      }),
    });
    expect(response.status).toBe(200);
    const events = sseEvents(await response.text());
    expect(events).toHaveLength(1);
    expect(events[0]).toEqual({
      type: "response.failed",
      response: {
        status: "failed",
        error: {
          message:
            "Responses compat proxy returned an unknown tool: not_a_tool",
        },
      },
    });
  } finally {
    await adapter.close();
    await upstream.close();
  }
});

test("proxy rejects bad requests and routes, and close stops the server", async () => {
  const upstream = await rejectingUpstream();
  const adapter = await startResponsesCompatProxy(`${upstream.url}/v1`);
  try {
    expect((await fetch(`${adapter.baseUrl}/other`)).status).toBe(404);
    const bad = await fetch(`${adapter.baseUrl}/responses`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "not json",
    });
    expect(bad.status).toBe(400);
    expect(await bad.json()).toMatchObject({
      error: { message: expect.any(String) },
    });
    expect(adapter.baseUrl).toMatch(
      /^http:\/\/127\.0\.0\.1:\d+\/[0-9a-f-]+\/v1$/,
    );
  } finally {
    await adapter.close();
    await adapter.close();
    await upstream.close();
  }
  await expect(
    fetch(`${adapter.baseUrl}/responses`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    }),
  ).rejects.toThrow();
});

test("concurrent proxies stay isolated", async () => {
  const first = await listen((_request, response) => {
    response
      .writeHead(200, { "content-type": "application/json" })
      .end(JSON.stringify({ id: "first", status: "completed", output: [] }));
  });
  const second = await listen((_request, response) => {
    response
      .writeHead(200, { "content-type": "application/json" })
      .end(JSON.stringify({ id: "second", status: "completed", output: [] }));
  });
  const firstAdapter = await startResponsesCompatProxy(`${first.url}/v1`);
  const secondAdapter = await startResponsesCompatProxy(`${second.url}/v1`);
  try {
    expect(firstAdapter.baseUrl).not.toBe(secondAdapter.baseUrl);
    const post = (baseUrl: string) =>
      fetch(`${baseUrl}/responses`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "fixture", input: "Review" }),
      }).then((response) => response.json());
    const [a, b] = await Promise.all([
      post(firstAdapter.baseUrl),
      post(secondAdapter.baseUrl),
    ]);
    expect((a as Record<string, unknown>)["id"]).toBe("first");
    expect((b as Record<string, unknown>)["id"]).toBe("second");
  } finally {
    await firstAdapter.close();
    await secondAdapter.close();
    await first.close();
    await second.close();
  }
});

test("a provider redirect cannot replay scan inputs to another origin", async () => {
  const other = await listen((_request, response) => {
    response.writeHead(200).end("redirect target");
  });
  const upstream = await listen((_request, response) => {
    response.writeHead(302, { location: `${other.url}/responses` }).end();
  });
  const adapter = await startResponsesCompatProxy(`${upstream.url}/v1`);
  try {
    const response = await fetch(`${adapter.baseUrl}/responses`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "fixture", input: "Review" }),
    });
    expect(response.status).toBe(502);
  } finally {
    await adapter.close();
    await upstream.close();
    await other.close();
  }
});

test("split SSE frames reassemble across chunk boundaries", async () => {
  const upstream = await listen((_request, response) => {
    response.writeHead(200, { "content-type": "text/event-stream" });
    const event =
      `data: ${JSON.stringify({ type: "response.completed", response: { id: "resp_1", status: "completed", output: [{ type: "message", content: "héllo" }] } })}` +
      "\n\n";
    const bytes = Buffer.from(event, "utf8");
    // Split mid-character and mid-frame.
    response.write(bytes.subarray(0, 20));
    response.write(bytes.subarray(20, 42));
    response.write(bytes.subarray(42));
    response.end();
  });
  const adapter = await startResponsesCompatProxy(`${upstream.url}/v1`);
  try {
    const response = await fetch(`${adapter.baseUrl}/responses`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "fixture", stream: true, input: "Review" }),
    });
    expect(response.status).toBe(200);
    const events = sseEvents(await response.text());
    expect(events).toHaveLength(1);
    expect(events[0]!["type"]).toBe("response.completed");
  } finally {
    await adapter.close();
    await upstream.close();
  }
});
