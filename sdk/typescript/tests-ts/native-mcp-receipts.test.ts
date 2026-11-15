import { expect, mock, test } from "bun:test";
import { PassThrough, Writable } from "node:stream";
import { readSkillCommandOutput } from "../src/cli.js";
import { createDependencyInventory } from "../src/dependency-inventory.js";
import { CODEX_SECURITY_THREAD_SOURCES } from "../src/thread-source.js";

type Event = Record<string, unknown>;

function setup() {
  return [
    { id: 1, result: {} },
    { id: 4, result: { config: {}, layers: [] } },
    {
      id: 2,
      result: {
        thread: { id: "root", ephemeral: false },
        activePermissionProfile: { id: "restricted" },
        model: "synthetic",
        modelProvider: "openai",
      },
    },
    { id: 3, result: { turn: { id: "root-turn" } } },
  ];
}

function receipt(
  threadId: string,
  id: string,
  value: string,
  extra: Event = {},
) {
  return {
    method: "item/completed",
    params: {
      threadId,
      turnId: threadId === "root" ? "root-turn" : `${threadId}-turn`,
      item: {
        type: "mcpToolCall",
        id,
        server: "records",
        tool: "get_record",
        arguments: { artifact: "selected" },
        status: "completed",
        result: {
          structuredContent: { value },
          content: [{ type: "text", text: value }],
        },
        ...extra,
      },
    },
  };
}

function call(id: string, namespace: string, tool: string, threadId = "root") {
  return {
    id,
    method: "item/tool/call",
    params: {
      threadId,
      turnId: `${threadId}-turn`,
      namespace,
      tool,
      arguments: {},
    },
  };
}

function fixture(
  onRead: (request: Event, emit: (event: Event) => void) => void,
  onReply?: (request: Event) => void,
) {
  const stream = new PassThrough();
  const requests: Event[] = [];
  const inventory = createDependencyInventory();
  const record = mock(inventory.record);
  const graph = mock(async () => ({
    receipts: inventory.snapshot().map(({ id, current }) => ({ id, current })),
  }));
  const submit = mock(async () => ({ accepted: true, feedback: "Accepted" }));
  const status = mock(async () => ({ receipts: inventory.snapshot() }));
  const emit = (event: Event) => {
    stream.write(JSON.stringify(event) + "\n");
  };
  const result = readSkillCommandOutput(stream, {
    directory: "/synthetic",
    prompt: "Synthetic advisory",
    sandbox: "read-only",
    permissionProfile: "restricted",
    cyberAccessProgram: "standard",
    threadSource: CODEX_SECURITY_THREAD_SOURCES.validation,
    dependencyGraph: {
      tools: [
        {
          name: "query_codex_security_graph",
          description: "Query",
          inputSchema: { type: "object" },
        },
      ],
      call: graph,
      close: async () => {},
    },
    dependencyReport: {
      recordInventory: record,
      recordGraphEvent() {},
      continuationPrompt: () => undefined,
      submit,
      status,
    },
    input: new Writable({
      write(chunk, _encoding, done) {
        const request = JSON.parse(String(chunk)) as Event;
        requests.push(request);
        if (request["method"] === "thread/read") onRead(request, emit);
        if (request["method"] === undefined) onReply?.(request);
        done();
      },
      final(done) {
        stream.end();
        done();
      },
    }),
  });
  for (const event of setup()) emit(event);
  return {
    stream,
    result,
    emit,
    requests,
    inventory,
    record,
    graph,
    submit,
    status,
  };
}

function complete() {
  return {
    method: "turn/completed",
    params: {
      threadId: "root",
      turn: { id: "root-turn", status: "completed" },
    },
  };
}

test("authenticates the first ordinary child receipt even when later metadata is idle", async () => {
  const firstRead = Promise.withResolvers<Event>();
  let count = 0;
  const run = fixture((request, emit) => {
    if (count++ === 0) firstRead.resolve(request);
    else
      emit({
        id: request["id"],
        result: {
          thread: {
            id: "child",
            parentThreadId: "root",
            status: { type: "idle" },
          },
        },
      });
  });
  try {
    run.emit({
      method: "thread/status/changed",
      params: { threadId: "child", status: { type: "active" } },
    });
    run.emit({
      method: "turn/started",
      params: { threadId: "child", turn: { id: "child-turn" } },
    });
    run.emit(receipt("child", "first", "original"));
    const lookup = await firstRead.promise;
    expect(run.record).not.toHaveBeenCalled();
    run.emit({
      id: lookup["id"],
      result: {
        thread: {
          id: "child",
          parentThreadId: "root",
          status: { type: "idle" },
        },
      },
    });
    run.emit(
      call(
        "child-call",
        "codex_security_dependency",
        "query_codex_security_graph",
        "child",
      ),
    );
    run.emit(
      call(
        "final",
        "codex_security_reports",
        "produce_codex_security_exploit_report",
      ),
    );
    run.emit(complete());
    expect(await run.result).toEqual({ completed: true });
    expect(run.record).toHaveBeenCalledWith(
      "records",
      {
        structuredContent: { value: "original" },
        content: [{ type: "text", text: "original" }],
      },
      {
        tool: "get_record",
        arguments: { artifact: "selected" },
        itemId: "first",
        finishedAt: expect.any(String),
      },
    );
    expect(run.record.mock.calls[0]?.[2]?.finishedAt).toMatch(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u,
    );
    expect(run.graph).not.toHaveBeenCalled();
    expect(run.requests.find((r) => r["id"] === "child-call")).toHaveProperty(
      "error.code",
      -32601,
    );
    expect(run.submit).toHaveBeenCalledTimes(1);
  } finally {
    run.stream.destroy();
  }
});

test("keeps receipt arrival order and waits for ingestion at graph, report and turn end", async () => {
  const firstRead = Promise.withResolvers<Event>();
  let count = 0;
  const run = fixture((request, emit) => {
    if (count++ === 0) firstRead.resolve(request);
    else
      emit({
        id: request["id"],
        result: {
          thread: {
            id: "child",
            parentThreadId: "root",
            status: { type: "idle" },
          },
        },
      });
  });
  try {
    run.emit(receipt("child", "older", "old"));
    const lookup = await firstRead.promise;
    run.emit(receipt("root", "newer", "new"));
    run.emit(
      call("graph", "codex_security_dependency", "query_codex_security_graph"),
    );
    run.emit(
      call(
        "status",
        "codex_security_reports",
        "get_codex_security_review_status",
      ),
    );
    run.emit(
      call(
        "final",
        "codex_security_reports",
        "produce_codex_security_exploit_report",
      ),
    );
    run.emit(complete());
    expect(run.graph).not.toHaveBeenCalled();
    expect(run.submit).not.toHaveBeenCalled();
    run.emit({
      id: lookup["id"],
      result: {
        thread: {
          id: "child",
          parentThreadId: "root",
          status: { type: "idle" },
        },
      },
    });
    expect(await run.result).toEqual({ completed: true });
    expect(run.record.mock.calls.map((x) => x[2]?.itemId)).toEqual([
      "older",
      "newer",
    ]);
    expect(run.inventory.snapshot().map((x) => [x.itemId, x.current])).toEqual([
      ["older", false],
      ["newer", true],
    ]);
    expect(run.inventory.bind(["records"], ["inventory-2"])[0]?.result).toEqual(
      {
        structuredContent: { value: "new" },
        content: [{ type: "text", text: "new" }],
      },
    );
    expect(run.graph).toHaveBeenCalledTimes(1);
    await expect(run.graph.mock.results[0]?.value).resolves.toMatchObject({
      receipts: [{ current: false }, { current: true }],
    });
    expect(run.status).toHaveBeenCalledTimes(1);
    expect(run.submit).toHaveBeenCalledTimes(1);
  } finally {
    run.stream.destroy();
  }
});

test("rejects unrelated ordinary receipts despite root claims in their arguments", async () => {
  const run = fixture((request, emit) =>
    emit({
      id: request["id"],
      result: {
        thread: {
          id: "foreign",
          parentThreadId: null,
          status: { type: "active" },
        },
      },
    }),
  );
  try {
    run.emit(
      receipt("foreign", "foreign", "foreign", {
        arguments: { parentThreadId: "root" },
      }),
    );
    run.emit(
      call(
        "final",
        "codex_security_reports",
        "produce_codex_security_exploit_report",
      ),
    );
    run.emit(complete());
    expect(await run.result).toEqual({ completed: true });
    expect(run.record).not.toHaveBeenCalled();
    expect(run.submit).toHaveBeenCalledTimes(1);
  } finally {
    run.stream.destroy();
  }
});

test("surfaces a live ancestry lookup error without authenticating its receipt", async () => {
  const run = fixture((request, emit) => {
    emit({
      id: request["id"],
      error: { code: -32000, message: "Native metadata unavailable" },
    });
  });
  try {
    run.emit(receipt("child", "unverified", "unverified"));
    await expect(run.result).rejects.toThrow("Native metadata unavailable");
    expect(
      run.requests.filter((r) => r["method"] === "thread/read"),
    ).toHaveLength(1);
    expect(run.record).not.toHaveBeenCalled();
    expect(run.submit).not.toHaveBeenCalled();
  } finally {
    run.stream.destroy();
  }
});

test("authenticates through retained ancestors whose root link was not yet known", async () => {
  const run = fixture((request, emit) => {
    const { threadId } = request["params"] as { threadId: string };
    const parent = { grandchild: "child", child: "parent", parent: "root" }[
      threadId
    ];
    emit({
      id: request["id"],
      result: {
        thread: {
          id: threadId,
          parentThreadId: parent,
          status: { type: "idle" },
        },
      },
    });
  });
  try {
    for (const [parent, child] of [
      ["child", "grandchild"],
      ["parent", "child"],
    ]) {
      run.emit({
        method: "item/completed",
        params: {
          threadId: parent,
          item: {
            type: "subAgentActivity",
            kind: "started",
            agentThreadId: child,
          },
        },
      });
    }
    run.emit(receipt("grandchild", "nested", "nested"));
    run.emit(
      call(
        "final",
        "codex_security_reports",
        "produce_codex_security_exploit_report",
      ),
    );
    run.emit(complete());
    expect(await run.result).toEqual({ completed: true });
    expect(
      run.requests
        .filter((r) => r["method"] === "thread/read")
        .slice(0, 3)
        .map((r) => (r["params"] as { threadId: string }).threadId),
    ).toEqual(["grandchild", "child", "parent"]);
    expect(run.record).toHaveBeenCalledTimes(1);
    expect(run.inventory.snapshot()[0]?.itemId).toBe("nested");
    expect(run.submit).toHaveBeenCalledTimes(1);
  } finally {
    run.stream.destroy();
  }
});

test("an early grandchild edge still blocks finalization after its parent finishes", async () => {
  const early = Promise.withResolvers<Event>();
  const run = fixture(
    (request, emit) => {
      const { threadId } = request["params"] as { threadId: string };
      emit({
        id: request["id"],
        result: {
          thread: {
            id: threadId,
            parentThreadId: threadId === "child" ? "root" : "child",
            status: { type: "idle" },
          },
        },
      });
    },
    (reply) => {
      if (reply["id"] === "early") early.resolve(reply);
    },
  );
  const activity = (parent: string, child: string, kind: string) => ({
    method: "item/completed",
    params: {
      threadId: parent,
      item: { type: "subAgentActivity", kind, agentThreadId: child },
    },
  });
  try {
    run.emit(activity("child", "grandchild", "started"));
    run.emit(activity("root", "child", "started"));
    run.emit(activity("root", "child", "completed"));
    run.emit(
      call(
        "early",
        "codex_security_reports",
        "produce_codex_security_exploit_report",
      ),
    );
    expect(await early.promise).toHaveProperty("result.success", false);
    expect(run.submit).not.toHaveBeenCalled();
    run.emit(activity("child", "grandchild", "completed"));
    run.emit(
      call(
        "final",
        "codex_security_reports",
        "produce_codex_security_exploit_report",
      ),
    );
    run.emit(complete());
    expect(await run.result).toEqual({ completed: true });
    expect(run.submit).toHaveBeenCalledTimes(1);
  } finally {
    run.stream.destroy();
  }
});

for (const initialStatus of ["active", "idle"]) {
  test(`checks retained unowned ancestry before a first dynamic call (${initialStatus})`, async () => {
    const reply = Promise.withResolvers<Event>();
    let grandchildStatus = initialStatus;
    const run = fixture(
      (request, emit) => {
        const id = (request["params"] as { threadId: string }).threadId;
        emit({
          id: request["id"],
          result: {
            thread: {
              id,
              parentThreadId: id === "grandchild" ? "child" : "root",
              status: { type: id === "grandchild" ? grandchildStatus : "idle" },
            },
          },
        });
      },
      (response) => {
        if (response["id"] === "grand-call") reply.resolve(response);
      },
    );
    try {
      run.emit({
        method: "item/completed",
        params: {
          threadId: "child",
          turnId: "child-turn",
          item: {
            type: "subAgentActivity",
            kind: "started",
            agentThreadId: "grandchild",
          },
        },
      });
      run.emit({
        method: "turn/started",
        params: { threadId: "grandchild", turn: { id: "grandchild-turn" } },
      });
      run.emit(
        call(
          "grand-call",
          "codex_security_dependency",
          "query_codex_security_graph",
          "grandchild",
        ),
      );
      const response = await reply.promise;
      expect(
        run.requests
          .filter((r) => r["method"] === "thread/read")
          .map((r) => (r["params"] as { threadId: string }).threadId),
      ).toEqual(["grandchild", "child"]);
      if (initialStatus === "active") {
        expect(response).toHaveProperty("result.success", true);
        expect(run.graph).toHaveBeenCalledTimes(1);
      } else {
        expect(response).toHaveProperty("error.code", -32601);
        expect(run.graph).not.toHaveBeenCalled();
      }
      grandchildStatus = "idle";
      run.emit({
        method: "thread/status/changed",
        params: { threadId: "grandchild", status: { type: "idle" } },
      });
      run.emit(
        call(
          "final",
          "codex_security_reports",
          "produce_codex_security_exploit_report",
        ),
      );
      run.emit(complete());
      expect(await run.result).toEqual({ completed: true });
      expect(run.submit).toHaveBeenCalledTimes(1);
    } finally {
      run.stream.destroy();
    }
  });
}
