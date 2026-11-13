import { expect, test } from "bun:test";
import { createServer } from "node:http";
import { once } from "node:events";
import {
  huggingFaceRequest,
  startHuggingFaceResponsesAdapter,
} from "../src/huggingface-responses.js";

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
  const response = {
    output: [{ ...history, namespace: undefined, name: flat[1]!.name }],
    usage: { input_tokens: 12, output_tokens: 3 },
  };
  expect(request.response(response)).toEqual({
    ...response,
    output: [history],
  });
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
  expect(
    request.event({ type: "response.output_item.added", item }),
  ).toMatchObject({
    item: {
      type: "custom_tool_call",
      namespace: "functions",
      name: "exec",
      input: "",
    },
  });
  expect(
    request.event({
      type: "response.function_call_arguments.delta",
      item_id: "fc_1",
      delta: "{",
    }),
  ).toBeNull();
  const done = request.event({
    type: "response.output_item.done",
    item: { ...item, arguments: JSON.stringify({ input: "text('hello')" }) },
  }) as { item: Record<string, unknown> };
  expect(done.item).toMatchObject({
    type: "custom_tool_call",
    namespace: "functions",
    name: "exec",
    input: "text('hello')",
  });
  expect(done.item).not.toHaveProperty("arguments");
  const next = huggingFaceRequest({
    tools: [{ type: "namespace", name: "functions", tools: [custom] }],
    input: [
      done.item,
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
  const upstream = createServer(async (req, res) => {
    authorization = req.headers.authorization;
    billTo = req.headers["x-hf-bill-to"] as string;
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    const body = JSON.parse(Buffer.concat(chunks).toString());
    expect(
      body.tools.every((entry: { type: string }) => entry.type === "function"),
    ).toBe(true);
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
  upstream.listen(0, "127.0.0.1");
  await once(upstream, "listening");
  const address = upstream.address() as { port: number };
  const adapter = await startHuggingFaceResponsesAdapter(
    `http://127.0.0.1:${address.port}/v1`,
  );
  try {
    const response = await fetch(`${adapter.baseUrl}/responses`, {
      method: "POST",
      headers: {
        Authorization: "Bearer synthetic-token",
        "X-HF-Bill-To": "synthetic-team",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        tools: [{ type: "namespace", name: "review", tools: [tool] }],
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
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
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

test("stream failures remain failures with the provider diagnostic", async () => {
  const upstream = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.end(
      `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: "partial" }, finish_reason: "length" }] })}\n\ndata: [DONE]\n\n`,
    );
  });
  upstream.listen(0, "127.0.0.1");
  await once(upstream, "listening");
  const adapter = await startHuggingFaceResponsesAdapter(
    `http://127.0.0.1:${(upstream.address() as { port: number }).port}/v1`,
  );
  try {
    const response = await fetch(`${adapter.baseUrl}/responses`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "synthetic/model",
        stream: true,
        tools: [],
        input: "Review",
      }),
    });
    const result = await response.text();
    expect(result).toContain('"type":"response.failed"');
    expect(result).toContain("finish_reason=length");
    expect(result).not.toContain('"type":"response.completed"');
  } finally {
    await adapter.close();
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
  }
});
