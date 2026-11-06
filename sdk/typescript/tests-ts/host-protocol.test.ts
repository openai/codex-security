import { expect, test } from "bun:test";
import { PassThrough } from "node:stream";
import { runHostProtocol } from "../src/host-protocol.js";

type Message = {
  id?: string;
  method?: string;
  params?: Record<string, unknown>;
  result?: unknown;
  error?: unknown;
};

function host(
  operation: Parameters<typeof runHostProtocol>[2],
  params: unknown = {},
) {
  const input = new PassThrough();
  const messages: Message[] = [];
  const queued: Message[] = [];
  let waiting: ((message: Message) => void) | undefined;
  const finished = runHostProtocol(
    input,
    {
      write(line) {
        const message = JSON.parse(String(line)) as Message;
        messages.push(message);
        if (waiting) {
          const resolve = waiting;
          waiting = undefined;
          resolve(message);
        } else queued.push(message);
        return true;
      },
    },
    operation,
  );
  const send = (message: unknown) =>
    input.write(`${JSON.stringify(message)}\n`);
  send({ jsonrpc: "2.0", id: "scan", method: "run", params });
  return {
    input,
    messages,
    finished,
    send,
    reply(id: string, result: unknown) {
      send({ jsonrpc: "2.0", id, result });
    },
    next(): Promise<Message> {
      const message = queued.shift();
      if (message) return Promise.resolve(message);
      return new Promise((resolve) => {
        waiting = resolve;
      });
    },
  };
}

test.each([
  undefined,
  false,
  (params: unknown) => (params as { version: number }).version === 3,
])(
  "v2 keeps a single pending execution (%p)",
  async (allowConcurrentExecutions) => {
    const peer = host(
      {
        label: "Scan",
        requestMethod: "execution.run",
        allowConcurrentExecutions,
        async run(_params, execute) {
          const first = execute("first", {});
          await expect(execute("second", {})).rejects.toThrow(
            "already pending",
          );
          await first;
          return { status: "completed" };
        },
      },
      { version: 2 },
    );
    expect(await peer.next()).toMatchObject({
      id: "first",
      method: "execution.run",
    });
    peer.reply("first", { status: "completed" });
    expect(await peer.finished).toBe(0);
    expect(
      peer.messages.filter((message) => message.method === "execution.run"),
    ).toHaveLength(1);
    peer.input.destroy();
  },
);

test("concurrent executions correlate progress, out-of-order receipts, and release", async () => {
  const events: Record<string, unknown[]> = { first: [], second: [] };
  const peer = host(
    {
      label: "Scan",
      requestMethod: "execution.run",
      awaitCancellationReceipt: true,
      allowConcurrentExecutions: (params) =>
        (params as { version: number }).version === 3,
      async run(_params, execute) {
        const first = execute("first", {}, (event) =>
          events["first"]!.push(event),
        );
        const second = execute("second", {}, (event) =>
          events["second"]!.push(event),
        );
        const firstResult = await first;
        const release = execute(
          "release",
          { threadId: "thread-first" },
          undefined,
          "execution.release",
        );
        const [secondResult, released] = await Promise.all([second, release]);
        return { status: "completed", firstResult, secondResult, released };
      },
    },
    { version: 3 },
  );
  expect(await peer.next()).toMatchObject({ id: "first" });
  expect(await peer.next()).toMatchObject({ id: "second" });
  peer.send({
    jsonrpc: "2.0",
    method: "execution.progress",
    params: { requestId: "second", event: { step: 2 } },
  });
  peer.send({
    jsonrpc: "2.0",
    method: "execution.progress",
    params: { requestId: "first", event: { step: 1 } },
  });
  peer.reply("first", { usage: 11 });
  expect(await peer.next()).toMatchObject({
    id: "release",
    method: "execution.release",
  });
  peer.reply("release", { released: true });
  peer.reply("second", { usage: 22 });
  expect(await peer.finished).toBe(0);
  expect(events).toEqual({ first: [{ step: 1 }], second: [{ step: 2 }] });
  expect(peer.messages.at(-1)?.result).toEqual({
    status: "completed",
    firstResult: { usage: 11 },
    secondResult: { usage: 22 },
    released: { released: true },
  });
  peer.input.destroy();
});

test("request and run cancellation retain every receipt and allow final cleanup", async () => {
  const requestCancellation = new AbortController();
  const peer = host({
    label: "Scan",
    requestMethod: "execution.run",
    awaitCancellationReceipt: true,
    allowConcurrentExecutions: true,
    async run(_params, execute) {
      const receipts = await Promise.all([
        execute("first", {}, undefined, undefined, requestCancellation.signal),
        execute("second", {}),
      ]);
      await expect(execute("new-work", {})).rejects.toThrow("canceled");
      await execute(
        "cleanup",
        { threadId: "thread-first" },
        undefined,
        "execution.release",
      );
      return { status: "canceled", receipts };
    },
  });
  await peer.next();
  await peer.next();
  requestCancellation.abort(new Error("Discovery stopped"));
  expect(await peer.next()).toMatchObject({
    method: "execution.cancel",
    params: { requestId: "first" },
  });
  peer.send({ jsonrpc: "2.0", method: "cancel", params: { id: "scan" } });
  expect(await peer.next()).toMatchObject({
    method: "execution.cancel",
    params: { requestId: "second" },
  });
  peer.reply("second", { status: "canceled", usage: 22 });
  peer.reply("first", { status: "completed", usage: 11 });
  expect(await peer.next()).toMatchObject({
    id: "cleanup",
    method: "execution.release",
  });
  peer.reply("cleanup", { released: true });
  expect(await peer.finished).toBe(1);
  expect(
    peer.messages.filter((message) => message.method === "execution.cancel"),
  ).toHaveLength(2);
  expect(peer.messages.at(-1)?.result).toEqual({
    status: "canceled",
    receipts: [
      { status: "completed", usage: 11 },
      { status: "canceled", usage: 22 },
    ],
  });
  peer.input.destroy();
});

test.each(["disconnect", "unknown response"])(
  "%s rejects all pending requests without replay",
  async (scenario) => {
    const settled = Promise.withResolvers<PromiseSettledResult<unknown>[]>();
    const peer = host({
      label: "Scan",
      requestMethod: "execution.run",
      allowConcurrentExecutions: true,
      async run(_params, execute) {
        settled.resolve(
          await Promise.allSettled([
            execute("first", {}),
            execute("second", {}),
          ]),
        );
        return { status: "incomplete" };
      },
    });
    await peer.next();
    await peer.next();
    if (scenario === "disconnect") peer.input.end();
    else peer.reply("unknown", { status: "completed" });
    expect(await peer.finished).toBe(2);
    expect((await settled.promise).map((result) => result.status)).toEqual([
      "rejected",
      "rejected",
    ]);
    expect(
      peer.messages.filter((message) => message.method === "execution.run"),
    ).toHaveLength(2);
    peer.input.destroy();
  },
);
