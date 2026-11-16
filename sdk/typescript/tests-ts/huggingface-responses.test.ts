import { expect, test } from "bun:test";
import { createServer, type RequestListener } from "node:http";
import { once } from "node:events";
import {
  huggingFaceRequest,
  startHuggingFaceResponsesAdapter,
} from "../src/huggingface-responses.js";

async function listen(handler: RequestListener) {
  const server = createServer(handler);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address() as { port: number };
  return {
    url: `http://127.0.0.1:${address.port}`,
    [Symbol.asyncDispose]: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      }),
  };
}

function streamingRequest(baseUrl: string, signal?: AbortSignal) {
  return fetch(`${baseUrl}/responses`, {
    method: "POST",
    signal,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "fixture", stream: true, input: "Review" }),
  });
}

const tool = {
  type: "function",
  name: "finish",
  description: "Complete a review",
  parameters: { type: "object", properties: {} },
  strict: true,
};

test("flattens namespaces without losing identical tool names or call history", () => {
  const history = {
    type: "function_call",
    namespace: "review",
    name: "finish",
    call_id: "call_1",
    arguments: "{}",
  };
  const request = huggingFaceRequest({
    tools: [tool, { type: "namespace", name: "review", tools: [tool] }],
    input: [
      history,
      { type: "function_call_output", call_id: "call_1", output: "ok" },
    ],
  });
  const flat = request.body.tools as (typeof tool)[];
  expect(flat.every((entry) => entry.type === "function")).toBe(true);
  expect(flat[0]!.name).not.toBe(flat[1]!.name);
  expect(request.body.input).toEqual([
    { ...history, namespace: undefined, name: flat[1]!.name },
    { type: "function_call_output", call_id: "call_1", output: "ok" },
  ]);
  expect(
    request.output({ ...history, namespace: undefined, name: flat[1]!.name }),
  ).toEqual(history);
  // A past tool call remains valid history after the tool is removed.
  const later = huggingFaceRequest({ tools: [tool], input: [history] });
  expect(later.body.input).toEqual([
    { ...history, namespace: undefined, name: flat[1]!.name },
  ]);
  expect(() => later.output({ ...history, name: flat[1]!.name })).toThrow(
    "unknown tool",
  );
});

test("restores freeform tools from streamed function arguments and retransmits history", () => {
  const custom = {
    type: "custom",
    name: "exec",
    description: "Execute JavaScript",
  };
  const request = huggingFaceRequest({
    tools: [{ type: "namespace", name: "functions", tools: [custom] }],
    input: [],
  });
  const flat = request.body.tools as (typeof tool)[];
  const item = {
    type: "function_call",
    name: flat[0]!.name,
    id: "fc_1",
    call_id: "call_1",
    arguments: "",
  };
  const done = request.output({
    ...item,
    arguments: JSON.stringify({ input: "text('hello')" }),
  });
  expect(done).toMatchObject({
    type: "custom_tool_call",
    namespace: "functions",
    name: "exec",
    input: "text('hello')",
  });
  expect(done).not.toHaveProperty("arguments");
  expect(() => request.output({ ...item, arguments: '{"input":9}' })).toThrow(
    "invalid input for custom tool exec",
  );
  const next = huggingFaceRequest({
    tools: [{ type: "namespace", name: "functions", tools: [custom] }],
    input: [
      done,
      { type: "custom_tool_call_output", call_id: "call_1", output: "hello" },
    ],
  });
  expect(next.body.input).toMatchObject([
    {
      type: "function_call",
      name: flat[0]!.name,
      arguments: JSON.stringify({ input: "text('hello')" }),
    },
    { type: "function_call_output", output: "hello" },
  ]);
});

test("rejects unsupported hosted tools rather than silently removing them", () => {
  expect(() => huggingFaceRequest({ tools: [{ type: "web_search" }] })).toThrow(
    "does not support",
  );
});

test("adapter forwards authentication, streams split UTF-8 events, and closes", async () => {
  let authorization: string | undefined;
  let billTo: string | undefined;
  const grammar = {
    type: "grammar",
    syntax: "lark",
    definition: 'start: "done"',
  };
  await using upstream = await listen(async (req, res) => {
    authorization = req.headers.authorization;
    billTo = req.headers["x-hf-bill-to"] as string;
    expect(req.url).toBe("/v1/chat/completions?api-version=test&client=x");
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    const body = JSON.parse(Buffer.concat(chunks).toString());
    expect(
      body.tools.every((entry: { type: string }) => entry.type === "function"),
    ).toBe(true);
    expect(
      body.tools[1].function.parameters.properties.input.description,
    ).toContain(grammar.definition);
    res.writeHead(200, { "content-type": "text/event-stream" });
    const item = {
      type: "function_call",
      name: body.tools[0].function.name,
      arguments: '{"result":"雪"}',
      call_id: "call_1",
    };
    const event = Buffer.from(
      `data: ${JSON.stringify({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "call_1", function: { name: item.name, arguments: item.arguments } }] }, finish_reason: "tool_calls" }], usage: { prompt_tokens: 10, completion_tokens: 2, total_tokens: 12 } })}\r\n\r\ndata: [DONE]\r\n\r\n`,
    );
    const offset = event.indexOf(Buffer.from("雪")) + 1;
    res.write(event.subarray(0, offset));
    res.end(event.subarray(offset));
  });
  const adapter = await startHuggingFaceResponsesAdapter(
    `${upstream.url}/v1?api-version=test`,
  );
  try {
    const response = await fetch(`${adapter.baseUrl}/responses?client=x`, {
      method: "POST",
      headers: {
        Authorization: "Bearer synthetic-token",
        "X-HF-Bill-To": "synthetic-team",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        tools: [
          { type: "namespace", name: "review", tools: [tool] },
          { type: "custom", name: "record", format: grammar },
        ],
        input: "Review the fixture",
        stream: true,
      }),
    });
    expect(response.status).toBe(200);
    const text = await response.text();
    expect(text).toContain('"namespace":"review"');
    expect(text).toContain('"name":"finish"');
    expect(text).toContain("雪");
    expect(text).toContain('"input_tokens":10');
    expect(authorization).toBe("Bearer synthetic-token");
    expect(billTo).toBe("synthetic-team");
    expect((await fetch(`${adapter.baseUrl}/other`)).status).toBe(404);
  } finally {
    await adapter.close();
  }
  await expect(fetch(`${adapter.baseUrl}/responses`)).rejects.toThrow();
});

test("translates forced namespaced tool choice to the advertised function", () => {
  const request = huggingFaceRequest({
    tools: [{ type: "namespace", name: "review", tools: [tool] }],
    tool_choice: { type: "function", namespace: "review", name: "finish" },
    input: [],
  });
  expect(request.body.tool_choice).toEqual({
    type: "function",
    function: { name: (request.body.tools[0] as { name: string }).name },
  });
});

test.each([
  [
    {
      choices: [
        { index: 0, delta: { content: "partial" }, finish_reason: "length" },
      ],
    },
    { message: "HF generation did not complete (finish_reason=length)." },
  ],
  [
    {
      error: { code: "context_length_exceeded", message: "Shorten the input" },
    },
    { code: "context_length_exceeded", message: "Shorten the input" },
  ],
])(
  "stream failures retain the provider diagnostic and error code",
  async (chunk, error) => {
    await using upstream = await listen((_req, res) => {
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.end(`data: ${JSON.stringify(chunk)}\n\ndata: [DONE]\n\n`);
    });
    const adapter = await startHuggingFaceResponsesAdapter(
      `${upstream.url}/v1`,
    );
    try {
      const response = await streamingRequest(adapter.baseUrl);
      const text = await response.text();
      const events = text
        .split("\n")
        .filter((line) => line.startsWith("data: "))
        .map((line) => JSON.parse(line.slice(6)));
      expect(events).toEqual([
        { type: "response.failed", response: { status: "failed", error } },
      ]);
    } finally {
      await adapter.close();
    }
  },
);

test("finishes on the SSE done marker while the provider keeps the HTTP connection open", async () => {
  const disconnected = Promise.withResolvers<void>();
  await using upstream = await listen((_req, res) => {
    res.on("close", disconnected.resolve);
    res.writeHead(200, { "content-type": "Text/Event-Stream; charset=utf-8" });
    const data = {
      choices: [
        { index: 0, delta: { content: "finished" }, finish_reason: "stop" },
      ],
    };
    res.write(`data: ${JSON.stringify(data)}\r\rdata: [DONE]\r\r`);
  });
  const adapter = await startHuggingFaceResponsesAdapter(upstream.url);
  try {
    const response = await streamingRequest(adapter.baseUrl);
    expect(await response.text()).toContain('"type":"response.completed"');
    await disconnected.promise;
  } finally {
    await adapter.close();
  }
});

test.each(["client abort", "adapter shutdown"])(
  "cancels upstream work on %s",
  async (action) => {
    const accepted = Promise.withResolvers<void>();
    const disconnected = Promise.withResolvers<void>();
    await using upstream = await listen((_req, res) => {
      res.on("close", disconnected.resolve);
      accepted.resolve();
    });
    const adapter = await startHuggingFaceResponsesAdapter(upstream.url);
    const controller = new AbortController();
    try {
      const request = streamingRequest(
        adapter.baseUrl,
        controller.signal,
      ).catch((error) => error);
      await accepted.promise;
      if (action === "client abort") controller.abort();
      else await Promise.all([adapter.close(), adapter.close()]);
      expect(await request).toBeInstanceOf(Error);
      await disconnected.promise;
    } finally {
      await adapter.close();
    }
  },
);

test("preserves retry headers and diagnostics on HTTP failures and non-streaming responses", async () => {
  let status = 429;
  await using upstream = await listen((_req, res) => {
    res.writeHead(status, {
      "content-type": "application/json",
      "retry-after": "11",
      "x-request-id": "hf-123",
    });
    res.end('{"error":{"message":"provider diagnostic"}}');
  });
  const adapter = await startHuggingFaceResponsesAdapter(upstream.url);
  try {
    const busy = await streamingRequest(adapter.baseUrl);
    expect(busy.status).toBe(429);
    expect(busy.headers.get("retry-after")).toBe("11");
    expect(busy.headers.get("x-request-id")).toBe("hf-123");
    expect(await busy.json()).toEqual({
      error: { message: "provider diagnostic" },
    });
    status = 200;
    const invalid = await streamingRequest(adapter.baseUrl);
    expect(invalid.status).toBe(502);
    expect((await invalid.json()).error.message).toContain(
      "provider diagnostic",
    );
  } finally {
    await adapter.close();
  }
});

test("a provider redirect cannot replay scan inputs or custom credentials to another origin", async () => {
  let followed = false;
  await using other = await listen((_req, res) => {
    followed = true;
    res.end("redirected");
  });
  await using upstream = await listen((_req, res) => {
    res.writeHead(307, { location: other.url }).end();
  });
  const adapter = await startHuggingFaceResponsesAdapter(upstream.url);
  try {
    const result = await fetch(`${adapter.baseUrl}/responses`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-provider-token": "synthetic",
      },
      body: JSON.stringify({ stream: true, input: "scan contents" }),
    });
    expect(result.status).toBe(502);
    expect(followed).toBe(false);
  } finally {
    await adapter.close();
  }
});
