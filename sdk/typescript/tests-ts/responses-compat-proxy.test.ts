import { expect, test } from "bun:test";
import {
  responsesCompatRequest,
  startResponsesCompatProxy,
} from "../src/responses-compat-proxy.js";

const plain = { type: "function", name: "lookup" };
const spawn = {
  type: "function",
  name: "spawn_agent",
  parameters: {
    type: "object",
    properties: { message: { type: "string", encrypted: true } },
  },
  strict: true,
};
const custom = {
  type: "custom",
  name: "edit",
  format: { type: "grammar", syntax: "lark", definition: "start: WORD" },
};
const namespace = {
  type: "namespace",
  name: "collaboration",
  tools: [spawn, custom],
};
const web = { type: "web_search" };
const tools = [plain, namespace, web];
const call = {
  type: "function_call",
  name: "spawn_agent",
  namespace: "collaboration",
  arguments: '{"message":"Review this"}',
  encrypted_function_args: [],
  call_id: "1",
};
const edit = {
  type: "custom_tool_call",
  name: "edit",
  namespace: "collaboration",
  input: "payload",
  call_id: "2",
};
const flat = responsesCompatRequest({ tools, input: [call, edit] }).body[
  "input"
] as { name: string; arguments: string }[];

test("round-trips tools and preserves call IDs, choices and historical aliases", () => {
  const { body, output } = responsesCompatRequest({
    tools,
    tool_choice: { ...spawn, namespace: namespace.name },
  });
  expect(body["tools"]).toMatchObject([
    plain,
    {
      type: "function",
      strict: true,
      name: flat[0]!.name,
      parameters: { properties: { message: { type: "string" } } },
    },
    { type: "function", name: flat[1]!.name, strict: true },
    web,
  ]);
  expect(JSON.stringify(body["tools"])).not.toContain("encrypted");
  expect(flat[0]).not.toHaveProperty("encrypted_function_args");
  expect(() =>
    output({ ...flat[0], encrypted_function_args: ["message"] }),
  ).toThrow(/plaintext/);
  expect(body["tool_choice"]).toEqual({
    type: "function",
    name: flat[0]!.name,
  });
  const plainCall = {
    type: "function_call",
    name: plain.name,
    arguments: "{}",
  };
  expect(output(plainCall)).toEqual(plainCall);
  expect(() => output({ ...flat[0], name: [flat[0]!.name] })).toThrow(
    /unknown tool/,
  );
  expect(() => output({ ...flat[1], arguments: [flat[1]!.arguments] })).toThrow(
    /invalid xai input/i,
  );
  expect(flat.map((item) => output(item))).toEqual([call, edit]);
  expect(JSON.parse(flat[1]!.arguments)).toEqual({ input: edit.input });
  expect(JSON.stringify(body["tools"])).toContain(custom.format.definition);
  const history = responsesCompatRequest({
    input: [call, edit],
    tool_choice: "auto",
  });
  expect(history.body["input"]).toEqual(flat);
  expect(history.body).not.toHaveProperty("tool_choice");
  expect(() => history.output(flat[0]!)).toThrow(/unknown tool/);
});

test("long namespace aliases remain distinct and cannot shadow plain tools", () => {
  const namespaced = ["a", "b"].map((suffix) => ({
    ...namespace,
    name: "_".repeat(62) + suffix,
    tools: [spawn],
  }));
  const { body } = responsesCompatRequest({ tools: namespaced });
  const names = (body["tools"] as { name: string }[]).map((tool) => tool.name);
  for (const name of names) expect(name).toMatch(/^[a-zA-Z0-9_-]{1,64}$/);
  expect(new Set(names).size).toBe(2);
  expect(() =>
    responsesCompatRequest({
      tools: [...namespaced, { ...plain, name: names[0] }],
    }),
  ).toThrow(/collides/);
});

test("replays agent messages with both identities and never as user instructions", () => {
  const message = {
    type: "agent_message",
    id: "amsg",
    author: "/root/reviewer",
    recipient: "/root",
    content: [
      { type: "input_text", text: "Report" },
      { type: "input_text", text: "Done." },
    ],
  };
  const user = { type: "message", role: "user", content: "Review" };
  const { body } = responsesCompatRequest({
    input: [
      user,
      message,
      { type: "reasoning", content: null },
      { type: "custom_tool_call_output", call_id: "2", output: "ok" },
    ],
  });
  expect(body["input"]).toEqual([
    user,
    {
      type: "message",
      role: "assistant",
      id: "amsg",
      content: 'Agent message from "/root/reviewer" to "/root"\nReport\nDone.',
    },
    { type: "reasoning" },
    { type: "function_call_output", call_id: "2", output: "ok" },
  ]);
  expect(() =>
    responsesCompatRequest({
      input: [
        {
          ...message,
          content: [{ type: "encrypted_content", encrypted_content: "opaque" }],
        },
      ],
    }),
  ).toThrow(/plaintext/i);
});

async function fixture(
  fetch: (request: Request) => Response | Promise<Response>,
) {
  const server = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch });
  const proxy = await startResponsesCompatProxy(server.url.href);
  const url = proxy.baseUrl + "/responses";
  return {
    url,
    post: () =>
      globalThis.fetch(url + "?example=1", {
        method: "POST",
        headers: { authorization: "Bearer synthetic-key" },
        body: JSON.stringify({ tools }),
      }),
    async [Symbol.asyncDispose]() {
      await proxy.close();
      await server.stop(true);
    },
  };
}

test("forwards credentials and query parameters to the configured endpoint and restores JSON calls", async () => {
  await using proxy = await fixture(async (request) => {
    expect(request.headers.get("authorization")).toBe("Bearer synthetic-key");
    expect(new URL(request.url).search).toBe("?example=1");
    const { tools } = (await request.json()) as { tools: { type: string }[] };
    if (tools.some(({ type }) => type === "namespace" || type === "custom"))
      return new Response(null, { status: 422 });
    return Response.json({ output: flat });
  });
  expect(await (await proxy.post()).json()).toEqual({ output: [call, edit] });
});

function stream(events: unknown[]) {
  return new Response(
    new ReadableStream({
      start(controller) {
        for (const event of events) {
          const data = JSON.stringify(event);
          for (const part of [
            "data: " + data.slice(0, 5),
            data.slice(5) + "\r\n\r",
            "\n",
          ]) {
            controller.enqueue(new TextEncoder().encode(part));
          }
        }
        controller.close();
      },
    }),
    {
      headers: {
        "content-type": "text/event-stream",
        "x-request-id": "synthetic",
      },
    },
  );
}

async function readEvents(response: Response) {
  return (await response.text())
    .trim()
    .split("\n\n")
    .map((item) => JSON.parse(item.slice(6)));
}

test("streaming preserves headers and restores empty, completed and repeated tool calls", async () => {
  const delta = {
    type: "response.function_call_arguments.delta",
    delta: flat[0]!.arguments,
  };
  await using proxy = await fixture(() =>
    stream([
      {
        type: "response.output_item.added",
        item: { ...flat[1], arguments: "" },
      },
      delta,
      ...flat.map((item) => ({ type: "response.output_item.done", item })),
      { type: "response.completed", response: { output: flat } },
    ]),
  );
  const result = await proxy.post();
  expect(result.headers.get("x-request-id")).toBe("synthetic");
  expect(await readEvents(result)).toEqual([
    { type: "response.output_item.added", item: { ...edit, input: "" } },
    delta,
    { type: "response.output_item.done", item: call },
    { type: "response.output_item.done", item: edit },
    { type: "response.completed", response: { output: [call, edit] } },
  ]);
});

test("unfinished calls cannot dispatch or mask the reason a response stopped", async () => {
  const partial = { ...flat[1], arguments: '{"input":"', status: "incomplete" };
  const incomplete = {
    status: "incomplete",
    incomplete_details: { reason: "max_output_tokens" },
    output: [partial],
  };
  const failed = {
    status: "failed",
    error: { code: "server_error", message: "Please retry" },
    output: [partial],
  };
  for (const response of [incomplete, failed]) {
    const terminal = { type: `response.${response.status}`, response };
    await using proxy = await fixture(() =>
      stream([
        {
          type: "response.output_item.done",
          item: { ...flat[0], status: "incomplete" },
        },
        terminal,
      ]),
    );
    expect(await readEvents(await proxy.post())).toEqual([terminal]);
  }
  await using proxy = await fixture(() => Response.json(incomplete));
  expect(await (await proxy.post()).json()).toEqual(incomplete);
});

test("completed responses keep finished parallel calls and omit unfinished ones", async () => {
  const response = {
    status: "completed",
    output: [
      { ...flat[0], status: "completed" },
      { ...flat[1], call_id: "3", arguments: "{", status: "in_progress" },
      flat[1],
    ],
  };
  const expected = {
    ...response,
    output: [{ ...call, status: "completed" }, edit],
  };
  await using json = await fixture(() => Response.json(response));
  expect(await (await json.post()).json()).toEqual(expected);
  const type = "response.completed";
  await using sse = await fixture(() => stream([{ type, response }]));
  expect(await readEvents(await sse.post())).toEqual([
    { type, response: expected },
  ]);
});

test("unknown tools fail the stream", async () => {
  await using proxy = await fixture(() =>
    stream([
      {
        type: "response.output_item.done",
        item: { ...flat[0], name: "undeclared" },
      },
    ]),
  );
  expect(await readEvents(await proxy.post())).toMatchObject([
    { type: "response.failed" },
  ]);
});

test("invalid routes and bodies fail locally and upstream errors remain intact", async () => {
  let requests = 0;
  await using proxy = await fixture(() => {
    requests++;
    return new Response("retry later", {
      status: 429,
      headers: { "retry-after": "7" },
    });
  });
  expect((await fetch(proxy.url)).status).toBe(404);
  expect((await fetch(proxy.url + "/other", { method: "POST" })).status).toBe(
    404,
  );
  expect((await fetch(proxy.url, { method: "POST", body: "{" })).status).toBe(
    400,
  );
  const result = await proxy.post();
  expect(result.status).toBe(429);
  expect(result.headers.get("retry-after")).toBe("7");
  expect(await result.text()).toBe("retry later");
  expect(requests).toBe(1);
});

test("independent profiles cannot redirect scan inputs or credentials to another origin", async () => {
  let requests = 0;
  await using other = await fixture(() => {
    requests++;
    return Response.json({ output: [] });
  });
  await using proxy = await fixture(() => Response.redirect(other.url, 307));
  const responses = await Promise.all([proxy.post(), other.post()]);
  expect(responses.map((response) => response.status)).toEqual([502, 200]);
  expect(requests).toBe(1);
});
