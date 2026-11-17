import { expect, mock, test } from "bun:test";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { PassThrough, Readable, Writable } from "node:stream";
import { readSkillCommandOutput } from "../src/cli.js";
import { createDependencyCandidates } from "../src/dependency-candidates.js";
import {
  dependencyGraphNamespace,
  openDependencyGraph,
  type DependencyGraphTools,
} from "../src/dependency-graph-tools.js";
import { createDependencyNativeSession } from "../src/dependency-native-session.js";
import type { DependencyUseProof } from "../src/dependency-report-proof.js";
import { createDependencyReportSubmission } from "../src/dependency-report-submission.js";
import { CODEX_SECURITY_THREAD_SOURCES } from "../src/thread-source.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

const thread = { threadId: "check", turnId: "turn" };
const reportTool = {
  namespace: "codex_security_reports",
  tool: "produce_codex_security_exploit_report",
};
function submission(id: string, draft: unknown, overrides: object = {}) {
  return {
    method: "item/tool/call",
    id,
    params: {
      ...thread,
      ...reportTool,
      callId: id,
      arguments: draft,
      ...overrides,
    },
  };
}
function setup(daybreak = false) {
  return [
    { id: 1, result: {} },
    {
      id: 4,
      result: { config: daybreak ? { daybreak: true } : {}, layers: [] },
    },
    {
      id: 2,
      result: {
        thread: {
          id: "check",
          ephemeral: false,
          path: "/synthetic-sessions/check.jsonl",
        },
        activePermissionProfile: { id: "restricted" },
        model: "investigator-model",
        modelProvider: "openai",
      },
    },
    { id: 3, result: { turn: { id: "turn" } } },
  ];
}
function replay(
  events: object[] | Readable,
  submit:
    | ((draft: unknown) => Promise<{ accepted: boolean; feedback: string }>)
    | undefined,
  continuationPrompt: () => string | undefined = () => undefined,
  cyberAccessProgram: "standard" | "daybreak_blue" = "standard",
  reviewQueue?: Pick<
    ReturnType<typeof createDependencyReportSubmission>,
    "queue" | "readStatus"
  >,
  hooks: {
    request?: (value: Record<string, unknown>) => void;
    event?: (value: Readonly<Record<string, unknown>>) => void;
    graph?: DependencyGraphTools;
  } = {},
) {
  const requests: Record<string, unknown>[] = [];
  const bindReviewer = mock(() => requests.length);
  const onAccessProgram = mock(() => requests.length);
  const recordInventory = mock(
    (_name: string, _payload: unknown, _metadata?: unknown) => undefined,
  );
  const recordInventoryStartup = mock<
    ReturnType<
      typeof createDependencyReportSubmission
    >["recordInventoryStartup"]
  >(() => {});
  const onUsage = mock(() => {});
  const result = readSkillCommandOutput(
    Array.isArray(events)
      ? Readable.from(events.map((event) => JSON.stringify(event) + "\n"))
      : events,
    {
      directory: "/synthetic-check",
      prompt: "Review dependency",
      sandbox: "read-only",
      permissionProfile: "restricted",
      cyberAccessProgram,
      ...(hooks.event ? { onEvent: hooks.event } : {}),
      ...(hooks.graph ? { dependencyGraph: hooks.graph } : {}),
      bindReviewer,
      threadSource: CODEX_SECURITY_THREAD_SOURCES.validation,
      dependencyReport: {
        ...reviewQueue,
        ...(reviewQueue && {
          status: (value: unknown) => reviewQueue.readStatus(value),
        }),
        ...(submit && { submit }),
        recordInventory,
        recordInventoryStartup,
        continuationPrompt,
        onAccessProgram,
        recordGraphEvent() {},
      },
      input: new Writable({
        write(chunk, _encoding, callback) {
          const request = JSON.parse(String(chunk)) as Record<string, unknown>;
          requests.push(request);
          hooks.request?.(request);
          callback();
        },
      }),
    },
    onUsage,
  );
  return {
    result,
    requests,
    bindReviewer,
    onAccessProgram,
    recordInventory,
    recordInventoryStartup,
    onUsage,
  };
}

function complete(turnId: string) {
  return {
    method: "turn/completed",
    params: { threadId: "check", turn: { id: turnId, status: "completed" } },
  };
}

function started(turnId: string) {
  return {
    method: "turn/started",
    params: { threadId: "check", turn: { id: turnId } },
  };
}

test("binds standard dependency helpers to the model selected by the native thread", async () => {
  const run = replay([...setup(), complete("turn")], async () => ({
    accepted: true,
    feedback: "Accepted.",
  }));
  expect(await run.result).toEqual({ completed: true });
  expect(run.onAccessProgram).toHaveBeenCalledWith("standard");
  expect(run.bindReviewer).toHaveBeenCalledTimes(1);
  expect(run.bindReviewer).toHaveBeenCalledWith(
    "openai",
    { model: "investigator-model" },
    "standard",
  );
  const turn = run.requests.findIndex((r) => r["method"] === "turn/start");
  expect(run.bindReviewer.mock.results[0]?.value).toBeLessThanOrEqual(turn);
});

test("starts a fresh persistent Daybreak dependency thread and binds its reviewer before the turn", async () => {
  const run = replay(
    [...setup(true), complete("turn")],
    async () => ({ accepted: true, feedback: "Accepted." }),
    undefined,
    "daybreak_blue",
  );
  expect(await run.result).toEqual({ completed: true });
  const starts = run.requests.filter((r) => r["method"] === "thread/start");
  expect(starts).toHaveLength(1);
  expect(starts[0]).toMatchObject({
    params: { permissions: "restricted", daybreakEnabled: true },
  });
  expect(starts[0]).not.toHaveProperty("params.ephemeral", true);
  expect(run.onAccessProgram).toHaveBeenCalledWith("daybreak_blue");
  expect(run.bindReviewer).toHaveBeenCalledTimes(1);
  expect(run.bindReviewer).toHaveBeenCalledWith(
    "openai",
    {
      model: "investigator-model",
      daybreak: true,
      features: { cli_daybreak: true },
    },
    "daybreak_blue",
  );
  const turn = run.requests.findIndex((r) => r["method"] === "turn/start");
  expect(run.bindReviewer.mock.results[0]?.value).toBeLessThanOrEqual(turn);
  expect(run.requests[turn]).toMatchObject({
    params: { threadId: "check", cyberAccessProgram: "daybreakBlue" },
  });
});

test("native report tools expose and preserve reviewed use proof", async () => {
  await using repo = await scopedTemporaryDirectory("native-report-proof-");
  const source = "decode(entrée);\n";
  await writeFile(join(repo.path, "decoder.ts"), source);
  const bytes = Buffer.from([0x00, 0xff, 0x80]);
  const inspection = {
    structuredContent: {
      bytes: bytes.toString("base64"),
      sha256: createHash("sha256").update(bytes).digest("hex"),
    },
  };
  let reviewerPrompt = "";
  const proof: DependencyUseProof = {
    sink: {
      function: "decode",
      callSite: { path: "decoder.ts", line: 1 },
    },
    conditions: [
      {
        label: "Calls the decoder",
        status: "met",
        explanation: "The cited source calls decode.",
        citations: [{ path: "decoder.ts", line: 1 }],
      },
      {
        label: "Selected affected copy",
        status: "unknown",
        explanation: "The source does not identify the installed copy.",
        citations: [],
      },
    ],
  };
  const use = {
    location: "decoder.ts:1",
    component: "decoder",
    version: null,
    verdict: "unknown",
    deployment: "unknown",
    reason: "The call is present, but its installed copy is unknown.",
    evidence: [{ path: "decoder.ts", startLine: 1, endLine: 1, supports: [] }],
    observations: [
      { server: "runtime", record: "binary inspection", supports: [] },
    ],
    proof,
  };
  const state = createDependencyReportSubmission({
    repository: repo.path,
    advisory: { cve: "CVE-2000-0001", advisories: [] },
    inventoryServers: { runtime: ["inspect_artifact"] },
    review: async (prompt) => {
      reviewerPrompt = prompt;
      const packet = JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1));
      expect(packet.items[0].use.proof).toEqual(proof);
      expect(packet.excerpts[packet.items[0].excerptIds[0]].text).toBe(
        source.trimEnd(),
      );
      expect(packet.receipts[packet.items[0].receiptIds[0]].result).toEqual(
        inspection,
      );
      return JSON.stringify({
        items: packet.items.map(
          (item: {
            id: string;
            revision: number;
            hash: string;
            excerptIds: string[];
            receiptIds: string[];
          }) => ({
            id: item.id,
            revision: item.revision,
            hash: item.hash,
            accepted: true,
            reason:
              "decoder.ts establishes the call and leaves its copy unknown.",
            citedVersion: null,
            evidenceIds: [...item.excerptIds, ...item.receiptIds],
          }),
        ),
      });
    },
  });
  const receipt = state.recordInventory("runtime", inspection, {
    tool: "inspect_artifact",
    arguments: { artifact: "synthetic.bin" },
  });
  try {
    const run = replay(
      [
        ...setup(),
        submission(
          "queue-proof",
          {
            items: [
              {
                id: "decoder-use",
                kind: "use",
                candidateIds: [],
                receiptIds: [receipt],
                use,
              },
            ],
          },
          { tool: "queue_codex_security_dependency_assessments" },
        ),
        submission("save-proof", {
          reviewItems: [{ id: "decoder-use", revision: 1 }],
          candidateGeneration: 0,
          limitations: [],
        }),
        complete("turn"),
      ],
      state.submit,
      state.continuationPrompt,
      "standard",
      state,
    );
    expect(await run.result).toEqual({ completed: true });
    expect(state.acceptedReport().uses[0]!.proof).toEqual(proof);
    const ack = run.requests.find((request) => request["id"] === "queue-proof");
    expect(ack).toHaveProperty("result.success", true);
    const content = (ack?.["result"] as { contentItems: { text: string }[] })
      .contentItems[0]!.text;
    const queueResult = JSON.parse(content);
    expect(queueResult).toMatchObject({
      queued: true,
      items: [{ id: "decoder-use", revision: 1 }],
    });
    expect(queueResult).not.toHaveProperty("status");
    const start = run.requests.find(
      (request) => request["method"] === "thread/start",
    );
    const params = start!["params"] as {
      dynamicTools: {
        tools: { name: string; description: string; inputSchema: unknown }[];
      }[];
    };
    const queue = params.dynamicTools
      .flatMap((namespace) => namespace.tools)
      .find(
        (tool) => tool.name === "queue_codex_security_dependency_assessments",
      )!;
    const submit = params.dynamicTools
      .flatMap((namespace) => namespace.tools)
      .find((tool) => tool.name === reportTool.tool);
    expect(submit?.inputSchema).toMatchObject({
      required: ["reviewItems", "candidateGeneration", "limitations"],
    });
    expect(submit?.inputSchema).not.toHaveProperty("properties.uses");
    const contract = queue.description
      .split("\n")
      .find((line) => line.startsWith("Review-evidence contract:"));
    expect(contract).toBeDefined();
    expect(
      reviewerPrompt.split("\n").filter((line) => line === contract),
    ).toHaveLength(1);
    const tools = JSON.stringify(start);
    expect(tools).toContain('"proof"');
    expect(tools).toContain('"callSite"');
    expect(tools).toContain('"conditions"');
  } finally {
    await state.close();
  }
});

test("dispatches graph tools in their own namespace and records the coverage they return", async () => {
  await using repo = await scopedTemporaryDirectory("report-tool-search-");
  const file = "project.yml";
  await writeFile(join(repo.path, file), "project: example\n");
  const candidates = await createDependencyCandidates(repo.path);
  const namespace = "codex_security_dependency";
  const tool = {
    name: "resolve_codex_security_services",
    description: "Resolve a path through the configured service catalogs.",
    inputSchema: { type: "object" },
  };
  const snapshot = {
    project: "example",
    references: [{ path: file, line: 1 }],
    service_resolution: { revision: 1, pending: 0 },
  };
  const call = mock<DependencyGraphTools["call"]>(async () => snapshot);
  const recordGraphEvent = mock(() => {});
  const args = { project: "example" };
  const replies: Record<string, unknown>[] = [];
  const responded = Promise.withResolvers<void>();
  async function* events() {
    for (const event of [
      ...setup(),
      {
        method: "item/completed",
        params: {
          ...thread,
          item: {
            id: "external",
            type: "mcpToolCall",
            server: namespace,
            status: "completed",
            result: { structuredContent: snapshot },
          },
        },
      },
      {
        method: "item/completed",
        params: {
          ...thread,
          item: {
            id: "search",
            type: "commandExecution",
            cwd: repo.path,
            command: "rg -n example",
            aggregatedOutput: `${file}:1:project: example`,
          },
        },
      },
      submission("lookup", args, { namespace, tool: tool.name }),
    ]) {
      yield JSON.stringify(event) + "\n";
    }
    await responded.promise;
    yield JSON.stringify(complete("turn")) + "\n";
  }
  const result = await readSkillCommandOutput(events(), {
    input: new Writable({
      write(chunk, _encoding, callback) {
        const reply = JSON.parse(String(chunk));
        replies.push(reply);
        if (reply.id === "lookup") responded.resolve();
        callback();
      },
    }),
    directory: repo.path,
    prompt: "Review dependency",
    sandbox: "read-only",
    permissionProfile: "restricted",
    cyberAccessProgram: "standard",
    threadSource: CODEX_SECURITY_THREAD_SOURCES.validation,
    dependencyGraph: { tools: [tool], call, close: async () => {} },
    dependencyReport: {
      ...candidates,
      submit: async () => ({ accepted: true, feedback: "Accepted" }),
      recordInventory: () => undefined,
      recordGraphEvent,
      continuationPrompt: () => undefined,
    },
  });
  expect(result).toEqual({ completed: true });
  expect(
    replies.find((reply) => reply["method"] === "thread/start"),
  ).toHaveProperty(
    "params.dynamicTools.0",
    expect.objectContaining({
      name: namespace,
      tools: [{ ...tool, type: "function" }],
    }),
  );
  expect(call.mock.calls).toEqual([[tool.name, args]]);
  expect(candidates.snapshot().candidates).toEqual([]);
  expect(replies.find((reply) => reply["id"] === "lookup")).toMatchObject({
    result: {
      success: true,
      contentItems: [{ type: "inputText", text: JSON.stringify(snapshot) }],
    },
  });
  expect(recordGraphEvent).toHaveBeenNthCalledWith(
    1,
    "item/started",
    expect.objectContaining({ id: "lookup", server: namespace }),
  );
  expect(recordGraphEvent).toHaveBeenNthCalledWith(
    2,
    "item/completed",
    expect.objectContaining({
      id: "lookup",
      server: namespace,
      status: "completed",
      result: { structuredContent: snapshot },
    }),
  );
  expect(recordGraphEvent).toHaveBeenCalledTimes(2);
});

test("native activity-only investigators share evidence while the coordinator owns submission", async () => {
  const namespace = "codex_security_dependency";
  const tool = {
    name: "trace_codex_security_code",
    description: "Trace a synthetic dependency use.",
    inputSchema: { type: "object" },
  };
  const call = mock<DependencyGraphTools["call"]>(async () => ({
    evidence: "shared",
  }));
  const queue = mock(async (_draft: unknown) => ({
    queued: true as const,
    items: [],
    feedback: "Queued",
  }));
  const submit = mock(async (_draft: unknown) => ({
    accepted: true,
    feedback: "Accepted",
  }));
  const recordInventory = mock(() => "inventory-1");
  const replies: Record<string, unknown>[] = [];
  const finished = Promise.withResolvers<void>();
  const earlyFinal = Promise.withResolvers<void>();
  const finalRead = Promise.withResolvers<Record<string, unknown>>();
  const unrelatedRead = Promise.withResolvers<Record<string, unknown>>();
  const expectedReplies = new Set([
    "root-lookup",
    "child-lookup",
    "child-queue",
    "child-final",
    "unrelated-lookup",
    "root-final",
    "root-early",
  ]);
  async function* events() {
    for (const event of [
      ...setup(),
      {
        method: "item/completed",
        params: {
          ...thread,
          item: {
            type: "subAgentActivity",
            kind: "started",
            agentThreadId: "investigator",
            agentPath: "/root/worker",
          },
        },
      },
      {
        method: "thread/started",
        params: { thread: { id: "unrelated", parentThreadId: null } },
      },
      {
        method: "turn/started",
        params: { threadId: "unrelated", turn: { id: "unrelated-turn" } },
      },
      submission(
        "root-lookup",
        { path: "service.py" },
        { namespace, tool: tool.name },
      ),
      submission(
        "child-lookup",
        { path: "parser.py" },
        {
          namespace,
          tool: tool.name,
          threadId: "investigator",
          turnId: "investigator-turn",
        },
      ),
      {
        method: "item/completed",
        params: {
          threadId: "investigator",
          turnId: "investigator-turn",
          item: {
            id: "child-receipt",
            type: "mcpToolCall",
            server: "fixture-inventory",
            tool: "running_build",
            arguments: { service: "worker" },
            status: "completed",
            result: { structuredContent: { revision: "patched-copy" } },
          },
        },
      },
      submission(
        "child-queue",
        { items: [] },
        {
          tool: "queue_codex_security_dependency_assessments",
          threadId: "investigator",
          turnId: "investigator-turn",
        },
      ),
      submission(
        "child-final",
        {},
        {
          threadId: "investigator",
          turnId: "investigator-turn",
        },
      ),
      submission(
        "unrelated-lookup",
        {},
        {
          namespace,
          tool: tool.name,
          threadId: "unrelated",
          turnId: "unrelated-turn",
        },
      ),
      submission("root-early", { status: "ruled_out" }),
    ])
      yield JSON.stringify(event) + "\n";
    await earlyFinal.promise;
    const unrelatedRequest = await unrelatedRead.promise;
    yield JSON.stringify({
      id: unrelatedRequest["id"],
      result: {
        thread: {
          id: "unrelated",
          parentThreadId: null,
          status: { type: "active" },
        },
      },
    }) + "\n";
    yield JSON.stringify({
      method: "item/completed",
      params: {
        ...thread,
        item: {
          type: "subAgentActivity",
          kind: "completed",
          agentThreadId: "investigator",
          agentPath: "/root/worker",
        },
      },
    }) + "\n";
    yield JSON.stringify({
      method: "item/completed",
      params: {
        ...thread,
        item: {
          type: "subAgentActivity",
          kind: "interacted",
          agentThreadId: "investigator",
          agentPath: "/root/worker",
        },
      },
    }) + "\n";
    yield JSON.stringify(submission("root-final", { status: "ruled_out" })) +
      "\n";
    const metadataRequest = await finalRead.promise;
    yield JSON.stringify({
      id: metadataRequest["id"],
      result: {
        thread: {
          id: "investigator",
          parentThreadId: "check",
          status: { type: "idle" },
        },
      },
    }) + "\n";
    await finished.promise;
    yield JSON.stringify(complete("turn")) + "\n";
  }

  const result = await readSkillCommandOutput(events(), {
    directory: "/synthetic-check",
    prompt: "Review dependency",
    sandbox: "read-only",
    permissionProfile: "restricted",
    cyberAccessProgram: "standard",
    threadSource: CODEX_SECURITY_THREAD_SOURCES.validation,
    dependencyGraph: { tools: [tool], call, close: async () => {} },
    dependencyReport: {
      queue,
      submit,
      recordInventory,
      recordGraphEvent() {},
      continuationPrompt: () => undefined,
    },
    input: new Writable({
      write(chunk, _encoding, callback) {
        const reply = JSON.parse(String(chunk)) as Record<string, unknown>;
        replies.push(reply);
        if (reply["method"] === "thread/read") {
          const params = reply["params"] as { threadId: string };
          if (params.threadId === "unrelated") unrelatedRead.resolve(reply);
          else finalRead.resolve(reply);
        }
        if (reply["id"] === "root-early") earlyFinal.resolve();
        if (typeof reply["id"] === "string")
          expectedReplies.delete(reply["id"]);
        if (expectedReplies.size === 0) finished.resolve();
        callback();
      },
    }),
  });

  expect(result).toEqual({ completed: true });
  expect(call.mock.calls).toEqual([
    [tool.name, { path: "service.py" }],
    [tool.name, { path: "parser.py" }],
  ]);
  expect(replies.find((reply) => reply["id"] === "root-early")).toHaveProperty(
    "result.success",
    false,
  );
  expect(queue).toHaveBeenCalledTimes(1);
  expect((await finalRead.promise)["params"]).toEqual({
    threadId: "investigator",
    includeTurns: false,
  });
  expect(submit.mock.calls).toEqual([[{ status: "ruled_out" }]]);
  expect(recordInventory).toHaveBeenCalledWith(
    "fixture-inventory",
    { structuredContent: { revision: "patched-copy" } },
    {
      tool: "running_build",
      arguments: { service: "worker" },
      itemId: "child-receipt",
      finishedAt: expect.any(String),
    },
  );
  expect(replies.find((reply) => reply["id"] === "child-final")).toHaveProperty(
    "result.success",
    false,
  );
  expect(
    replies.find((reply) => reply["id"] === "unrelated-lookup"),
  ).toHaveProperty("error.code", -32601);
});

test("waits for an investigator resumed during review and reconciles its new use", async () => {
  await using repo = await scopedTemporaryDirectory("native-finalization-");
  await writeFile(
    join(repo.path, "worker.ts"),
    "decode(input);\ndecode(other);\n",
  );
  const reviewStarted = Promise.withResolvers<void>();
  const submitStarted = Promise.withResolvers<void>();
  const releaseReview = Promise.withResolvers<void>();
  const firstReply = Promise.withResolvers<Record<string, unknown>>();
  const finalReply = Promise.withResolvers<Record<string, unknown>>();
  const continuation = Promise.withResolvers<Record<string, unknown>>();
  const reviewed: string[][] = [];
  const state = createDependencyReportSubmission({
    repository: repo.path,
    advisory: { cve: "CVE-2000-0001", advisories: [] },
    review: async (prompt) => {
      const packet = JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1)) as {
        items: {
          id: string;
          revision: number;
          hash: string;
          excerptIds: string[];
        }[];
      };
      reviewed.push(packet.items.map((item) => item.id));
      if (reviewed.length === 1) {
        reviewStarted.resolve();
        await releaseReview.promise;
      }
      return JSON.stringify({
        items: packet.items.map((item) => ({
          id: item.id,
          revision: item.revision,
          hash: item.hash,
          accepted: true,
          reason: "The cited call and missing selected copy are supported.",
          citedVersion: null,
          evidenceIds: item.excerptIds,
        })),
      });
    },
  });
  const use = {
    location: "worker.ts:1",
    component: "decoder",
    version: null,
    verdict: "unknown",
    deployment: "unknown",
    reason: "The source calls decode but does not identify the selected copy.",
    evidence: [{ path: "worker.ts", startLine: 1, endLine: 1, supports: [] }],
    observations: [],
  };
  const session = createDependencyNativeSession();
  const stream = new PassThrough();
  const emit = (event: object) => stream.write(JSON.stringify(event) + "\n");
  let childActive = false;
  let inputClosed = false;
  let turns = 0;
  const input = new Writable({
    write(chunk, _encoding, done) {
      const request = JSON.parse(String(chunk)) as Record<string, unknown>;
      if (request["method"] === "thread/read")
        emit({
          id: request["id"],
          result: {
            thread: {
              id: "investigator",
              parentThreadId: "check",
              status: { type: childActive ? "active" : "idle" },
            },
          },
        });
      if (request["method"] === "turn/start" && ++turns === 2)
        continuation.resolve(request);
      if (request["id"] === "first-final") firstReply.resolve(request);
      if (request["id"] === "final-after-follow-up")
        finalReply.resolve(request);
      done();
    },
    final(done) {
      inputClosed = true;
      stream.end();
      done();
    },
  });
  const result = readSkillCommandOutput(stream, {
    directory: repo.path,
    prompt: "Synthetic advisory",
    sandbox: "read-only",
    permissionProfile: "restricted",
    cyberAccessProgram: "standard",
    threadSource: CODEX_SECURITY_THREAD_SOURCES.validation,
    recovery: {
      session,
      usage: new Map(),
      finishedTurns: new Set(),
      completedTurnNotifications: new Set(),
    },
    dependencyGraph: {
      tools: [],
      call: async () => ({}),
      flush: async () => {},
      close: async () => {},
    },
    dependencyReport: {
      submit: (value) => {
        submitStarted.resolve();
        return state.submit(value);
      },
      recordInventory: state.recordInventory,
      recordGraphEvent: state.recordGraphEvent,
      continuationPrompt: state.continuationPrompt,
    },
    input,
  });
  try {
    expect(
      await state.queue({
        items: [{ id: "first-use", kind: "use", candidateIds: [], use }],
      }),
    ).toMatchObject({ queued: true });
    const draft = {
      reviewItems: [{ id: "first-use", revision: 1 }],
      candidateGeneration: 0,
      limitations: [],
    };
    for (const event of [
      ...setup(),
      {
        method: "thread/started",
        params: {
          thread: {
            id: "investigator",
            parentThreadId: "check",
            status: { type: "idle" },
          },
        },
      },
      submission("first-final", draft),
    ])
      emit(event);
    await Promise.all([reviewStarted.promise, submitStarted.promise]);
    childActive = true;
    emit({
      method: "turn/started",
      params: { threadId: "investigator", turn: { id: "child-follow-up" } },
    });
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(session.hasActiveInvestigators()).toBe(true);
    releaseReview.resolve();
    expect(await firstReply.promise).toHaveProperty("result.success", true);
    emit(complete("turn"));
    expect(
      await Promise.race([
        continuation.promise.then(() => "continued"),
        result.then(() => "closed"),
      ]),
    ).toBe("continued");
    expect(inputClosed).toBe(false);
    const followUp = await continuation.promise;
    expect(followUp).toHaveProperty(
      "params.input.0.text",
      expect.stringContaining("Wait for the active native investigators"),
    );
    emit({ id: followUp["id"], result: { turn: { id: "follow-up" } } });
    const discoveredUse = {
      ...use,
      location: "worker.ts:2",
      evidence: [{ path: "worker.ts", startLine: 2, endLine: 2, supports: [] }],
    };
    expect(
      await state.queue({
        items: [
          {
            id: "second-use",
            kind: "use",
            candidateIds: [],
            use: discoveredUse,
          },
        ],
      }),
    ).toMatchObject({ queued: true });
    expect(() => state.acceptedReport()).toThrow();
    childActive = false;
    emit({
      method: "turn/completed",
      params: {
        threadId: "investigator",
        turn: { id: "child-follow-up", status: "completed" },
      },
    });
    emit(
      submission(
        "final-after-follow-up",
        {
          ...draft,
          reviewItems: [
            ...draft.reviewItems,
            { id: "second-use", revision: 1 },
          ],
        },
        { turnId: "follow-up" },
      ),
    );
    expect(await finalReply.promise).toHaveProperty("result.success", true);
    emit(complete("follow-up"));
    expect(await result).toEqual({ completed: true });
    expect(inputClosed).toBe(true);
    expect(session.hasActiveInvestigators()).toBe(false);
    expect(state.acceptedReport().uses.map((entry) => entry.location)).toEqual([
      "worker.ts:1",
      "worker.ts:2",
    ]);
    expect(reviewed).toEqual([["first-use"], ["second-use"]]);
  } finally {
    releaseReview.resolve();
    stream.end();
    await result.catch(() => {});
    await state.close();
  }
});

test("verifies native child metadata when the first graph request precedes startup notifications", async () => {
  const namespace = "codex_security_dependency";
  const tool = {
    name: "trace_codex_security_code",
    description: "Trace a synthetic dependency use.",
    inputSchema: { type: "object" },
  };
  const call = mock<DependencyGraphTools["call"]>(async () => ({
    evidence: "shared",
  }));
  const submit = mock(async () => ({ accepted: true, feedback: "Accepted" }));
  const earlyFinalReply = Promise.withResolvers<void>();
  const finalReply = Promise.withResolvers<void>();
  const finalRead = Promise.withResolvers<Record<string, unknown>>();
  let childReads = 0;
  const childRead = Promise.withResolvers<Record<string, unknown>>();
  const followupRead = Promise.withResolvers<Record<string, unknown>>();
  const followupReply = Promise.withResolvers<void>();
  const foreignRead = Promise.withResolvers<Record<string, unknown>>();
  const childReply = Promise.withResolvers<void>();
  const foreignReply = Promise.withResolvers<void>();
  const replies: Record<string, unknown>[] = [];
  async function* events() {
    for (const event of setup()) yield JSON.stringify(event) + "\n";
    yield JSON.stringify(
      submission(
        "child-lookup",
        {},
        {
          namespace,
          tool: tool.name,
          threadId: "child",
          turnId: "child-turn",
        },
      ),
    ) + "\n";
    const childRequest = await childRead.promise;
    yield JSON.stringify(submission("root-before-metadata", {})) + "\n";
    await earlyFinalReply.promise;
    yield JSON.stringify({
      id: childRequest["id"],
      result: {
        thread: {
          id: "child",
          parentThreadId: "check",
          status: { type: "active" },
        },
      },
    }) + "\n";
    await childReply.promise;
    yield JSON.stringify({
      method: "thread/status/changed",
      params: { threadId: "child", status: { type: "idle" } },
    }) + "\n";
    yield JSON.stringify({
      method: "item/completed",
      params: {
        ...thread,
        item: {
          type: "subAgentActivity",
          kind: "interacted",
          agentThreadId: "child",
          agentPath: "/root/worker",
        },
      },
    }) + "\n";
    yield JSON.stringify(
      submission(
        "child-followup",
        {},
        {
          namespace,
          tool: tool.name,
          threadId: "child",
          turnId: "followup-turn",
        },
      ),
    ) + "\n";
    const followupRequest = await followupRead.promise;
    yield JSON.stringify({
      id: followupRequest["id"],
      result: {
        thread: {
          id: "child",
          parentThreadId: "check",
          status: { type: "active" },
        },
      },
    }) + "\n";
    await followupReply.promise;
    yield JSON.stringify(
      submission(
        "foreign-lookup",
        {},
        {
          namespace,
          tool: tool.name,
          threadId: "foreign",
          turnId: "foreign-turn",
        },
      ),
    ) + "\n";
    const foreignRequest = await foreignRead.promise;
    yield JSON.stringify({
      id: foreignRequest["id"],
      result: {
        thread: {
          id: "foreign",
          parentThreadId: null,
          status: { type: "active" },
        },
      },
    }) + "\n";
    await foreignReply.promise;
    yield JSON.stringify({
      method: "item/completed",
      params: {
        ...thread,
        item: {
          type: "subAgentActivity",
          kind: "completed",
          agentThreadId: "child",
          agentPath: "/root/worker",
        },
      },
    }) + "\n";
    yield JSON.stringify(submission("root-after-metadata", {})) + "\n";
    const finalRequest = await finalRead.promise;
    yield JSON.stringify({
      id: finalRequest["id"],
      result: {
        thread: {
          id: "child",
          parentThreadId: "check",
          status: { type: "idle" },
        },
      },
    }) + "\n";
    await finalReply.promise;
    yield JSON.stringify(complete("turn")) + "\n";
  }
  const result = await readSkillCommandOutput(events(), {
    directory: "/synthetic-check",
    prompt: "Review dependency",
    sandbox: "read-only",
    permissionProfile: "restricted",
    cyberAccessProgram: "standard",
    threadSource: CODEX_SECURITY_THREAD_SOURCES.validation,
    dependencyGraph: { tools: [tool], call, close: async () => {} },
    dependencyReport: {
      submit,
      recordInventory: () => undefined,
      recordGraphEvent() {},
      continuationPrompt: () => undefined,
    },
    input: new Writable({
      write(chunk, _encoding, callback) {
        const reply = JSON.parse(String(chunk)) as Record<string, unknown>;
        replies.push(reply);
        if (reply["method"] === "thread/read") {
          const params = reply["params"] as { threadId: string };
          if (params.threadId === "child") {
            [childRead, followupRead, finalRead][childReads++]!.resolve(reply);
          } else foreignRead.resolve(reply);
        }
        if (reply["id"] === "root-before-metadata") earlyFinalReply.resolve();
        if (reply["id"] === "root-after-metadata") finalReply.resolve();
        if (reply["id"] === "child-lookup") childReply.resolve();
        if (reply["id"] === "child-followup") followupReply.resolve();
        if (reply["id"] === "foreign-lookup") foreignReply.resolve();
        callback();
      },
    }),
  });
  expect(result).toEqual({ completed: true });
  expect(call).toHaveBeenCalledTimes(2);
  expect(submit).toHaveBeenCalledTimes(1);
  expect(
    replies.find((reply) => reply["id"] === "root-before-metadata"),
  ).toHaveProperty("result.success", false);
  expect(
    replies.find((reply) => reply["id"] === "root-after-metadata"),
  ).toHaveProperty("result.success", true);
  expect(
    replies.find((reply) => reply["id"] === "child-lookup"),
  ).toHaveProperty("result.success", true);
  expect(
    replies.find((reply) => reply["id"] === "foreign-lookup"),
  ).toHaveProperty("error.code", -32601);
  expect(
    replies.filter((reply) => reply["method"] === "thread/read"),
  ).toHaveLength(4);
  expect(
    replies.find((reply) => reply["id"] === "child-followup"),
  ).toHaveProperty("result.success", true);
});

test("finalization checks live investigator status after messages and preserves metadata failures", async () => {
  const reads = Array.from({ length: 3 }, () =>
    Promise.withResolvers<Record<string, unknown>>(),
  );
  const answers = Array.from({ length: 3 }, () =>
    Promise.withResolvers<void>(),
  );
  const replies: Record<string, unknown>[] = [];
  const submit = mock(async () => ({ accepted: true, feedback: "Accepted" }));
  let readIndex = 0;
  async function* events() {
    for (const event of setup()) yield JSON.stringify(event) + "\n";
    yield JSON.stringify({
      method: "thread/started",
      params: {
        thread: {
          id: "child",
          parentThreadId: "check",
          status: { type: "idle" },
        },
      },
    }) + "\n";
    for (let index = 0; index < reads.length; index++) {
      yield JSON.stringify({
        method: "item/completed",
        params: {
          ...thread,
          item: {
            type: "subAgentActivity",
            kind: "interacted",
            agentThreadId: "child",
            agentPath: "/root/worker",
          },
        },
      }) + "\n";
      yield JSON.stringify(submission(`final-${index}`, {})) + "\n";
      const request = await reads[index]!.promise;
      yield JSON.stringify(
        index === 1
          ? {
              id: request["id"],
              error: { code: -32000, message: "Native metadata unavailable" },
            }
          : {
              id: request["id"],
              result: {
                thread: {
                  id: "child",
                  parentThreadId: "check",
                  status: { type: index === 0 ? "active" : "idle" },
                },
              },
            },
      ) + "\n";
      await answers[index]!.promise;
      yield JSON.stringify({
        method: "thread/status/changed",
        params: { threadId: "child", status: { type: "idle" } },
      }) + "\n";
    }
    yield JSON.stringify(complete("turn")) + "\n";
  }
  const result = await readSkillCommandOutput(events(), {
    directory: "/synthetic-check",
    prompt: "Review dependency",
    sandbox: "read-only",
    permissionProfile: "restricted",
    cyberAccessProgram: "standard",
    threadSource: CODEX_SECURITY_THREAD_SOURCES.validation,
    dependencyReport: {
      submit,
      recordInventory: () => undefined,
      recordGraphEvent() {},
      continuationPrompt: () => undefined,
    },
    input: new Writable({
      write(chunk, _encoding, callback) {
        const reply = JSON.parse(String(chunk)) as Record<string, unknown>;
        replies.push(reply);
        if (reply["method"] === "thread/read")
          reads[readIndex++]!.resolve(reply);
        for (let index = 0; index < answers.length; index++)
          if (reply["id"] === `final-${index}`) answers[index]!.resolve();
        callback();
      },
    }),
  });
  expect(result).toEqual({ completed: true });
  expect(submit).toHaveBeenCalledTimes(1);
  expect(replies.find((reply) => reply["id"] === "final-0")).toHaveProperty(
    "result.success",
    false,
  );
  expect(replies.find((reply) => reply["id"] === "final-1")).toHaveProperty(
    "result.success",
    false,
  );
  expect(
    JSON.stringify(replies.find((reply) => reply["id"] === "final-1")),
  ).toContain("Native metadata unavailable");
  expect(replies.find((reply) => reply["id"] === "final-2")).toHaveProperty(
    "result.success",
    true,
  );
});

test("processes parallel host inventory replies while a graph tool is waiting", async () => {
  const namespace = "codex_security_dependency";
  const tool = {
    name: "trace_codex_security_code",
    description: "Trace a synthetic dependency use.",
    inputSchema: { type: "object" },
  };
  const inventory = { data: [{ name: "fixture", tools: {} }] };
  const build = { content: [], structuredContent: { revision: "fixture-1" } };
  type Request = { id: string; method?: string; params?: unknown };
  const discovery = Promise.withResolvers<Request>();
  const callsSent = Promise.withResolvers<void>();
  const graphReplied = Promise.withResolvers<Request>();
  const calls: Request[] = [];
  async function* events() {
    for (const event of [
      ...setup(),
      submission("trace", {}, { namespace, tool: tool.name }),
    ]) {
      yield JSON.stringify(event) + "\n";
    }
    const list = await discovery.promise;
    yield JSON.stringify({ id: list.id, result: inventory }) + "\n";
    await callsSent.promise;
    yield JSON.stringify({
      id: calls[1]!.id,
      error: { code: -32000, message: "Fixture access lookup failed" },
    }) + "\n";
    yield JSON.stringify({ id: calls[0]!.id, result: build }) + "\n";
    await graphReplied.promise;
    yield JSON.stringify(complete("turn")) + "\n";
  }
  const result = await readSkillCommandOutput(events(), {
    directory: "/synthetic-check",
    prompt: "Review dependency",
    sandbox: "read-only",
    permissionProfile: "restricted",
    cyberAccessProgram: "standard",
    threadSource: CODEX_SECURITY_THREAD_SOURCES.validation,
    allowedMcpServers: ["fixture"],
    dependencyReport: {
      submit: async () => ({ accepted: true, feedback: "Accepted" }),
      recordInventory: () => undefined,
      recordGraphEvent() {},
      continuationPrompt: () => undefined,
    },
    dependencyGraph: {
      tools: [tool],
      async call(_name, _args, rpc) {
        expect(await rpc!.list()).toEqual(inventory);
        const replies = await Promise.allSettled([
          rpc!.call("fixture", "running_build", { service: "worker" }),
          rpc!.call("fixture", "caller_access", { service: "worker" }),
        ]);
        expect(replies[0]).toEqual({ status: "fulfilled", value: build });
        expect(replies[1]).toMatchObject({
          status: "rejected",
          reason: { message: "Fixture access lookup failed" },
        });
        return { service: "worker" };
      },
      close: async () => {},
    },
    input: new Writable({
      write(chunk, _encoding, callback) {
        const request = JSON.parse(String(chunk)) as Request;
        if (request.method === "mcpServerStatus/list")
          discovery.resolve(request);
        if (request.method === "mcpServer/tool/call") {
          calls.push(request);
          if (calls.length === 2) callsSent.resolve();
        }
        if (request.id === "trace") graphReplied.resolve(request);
        callback();
      },
    }),
  });
  expect(result).toEqual({ completed: true });
  expect((await discovery.promise).params).toEqual({
    threadId: "check",
    detail: "full",
  });
  expect(calls.map(({ params }) => params)).toEqual(
    ["running_build", "caller_access"].map((tool) => ({
      threadId: "check",
      server: "fixture",
      tool,
      arguments: { service: "worker" },
    })),
  );
  expect(await graphReplied.promise).toHaveProperty("result.success", true);
});

test("imports a native resource before reports and turn completion without returning its bulk payload", async () => {
  const uri = "fixture://collections/profile-1";
  const descriptor = {
    structuredContent: {
      graph_evidence: { format: "fixture-observations", version: 1, uri },
    },
  };
  const resource = {
    contents: [
      {
        uri,
        mimeType: "application/json",
        text: JSON.stringify({
          observations: [
            { id: "sample-1", detail: "bulk-only-".repeat(20_000) },
          ],
        }),
      },
    ],
  };
  type Request = {
    id: string;
    method?: string;
    params?: Record<string, unknown>;
  };
  const groupPlan = {
    generation: 1,
    strategy: "component",
    groups: [
      { id: "group-1", kind: "component", scope: "src", candidateCount: 1 },
    ],
    nextOffset: null,
  };
  const resourceRequested = Promise.withResolvers<Request>();
  const inputEnded = Promise.withResolvers<void>();
  const replies: Request[] = [];
  const order: string[] = [];
  let imported = false;
  let importWork = Promise.resolve();
  const observeInventory = mock<
    NonNullable<DependencyGraphTools["observeInventory"]>
  >((server, result, receiptId, rpc) => {
    expect(result).toEqual(descriptor);
    expect(receiptId).toBe("inventory-1");
    importWork = rpc.read!(server, uri).then((value) => {
      expect(value).toEqual(resource);
      imported = true;
      order.push("import");
    });
  });
  const continuationPrompt = mock(() => {
    expect(imported).toBe(true);
    order.push("complete");
    return undefined;
  });
  const input = new Writable({
    write(chunk, _encoding, callback) {
      const request = JSON.parse(String(chunk)) as Request;
      replies.push(request);
      if (request.method === "mcpServer/resource/read")
        resourceRequested.resolve(request);
      callback();
    },
    final(callback) {
      inputEnded.resolve();
      callback();
    },
  });
  async function* events() {
    for (const event of [
      ...setup(),
      {
        method: "item/completed",
        params: {
          ...thread,
          item: {
            id: "collection",
            type: "mcpToolCall",
            server: "fixture",
            tool: "profiles.stacks",
            status: "completed",
            result: descriptor,
          },
        },
      },
      submission(
        "status",
        { groups: {} },
        { tool: "get_codex_security_review_status" },
      ),
      submission(
        "queue",
        {},
        { tool: "queue_codex_security_dependency_assessments" },
      ),
      submission("final", {}),
      complete("turn"),
      complete("turn"),
    ]) {
      yield JSON.stringify(event) + "\n";
    }
    const request = await resourceRequested.promise;
    expect(order).toEqual([]);
    expect(input.writable).toBe(true);
    yield JSON.stringify({ id: request.id, result: resource }) + "\n";
    await inputEnded.promise;
  }
  const result = await readSkillCommandOutput(events(), {
    input,
    directory: "/synthetic-check",
    prompt: "Review dependency",
    sandbox: "read-only",
    permissionProfile: "restricted",
    cyberAccessProgram: "standard",
    threadSource: CODEX_SECURITY_THREAD_SOURCES.validation,
    allowedMcpServers: ["fixture"],
    dependencyReport: {
      recordInventory: () => "inventory-1",
      recordGraphEvent() {},
      continuationPrompt,
      status: async (value) => {
        expect(imported).toBe(true);
        expect(value).toEqual({ groups: {} });
        order.push("status");
        return { groupPlan };
      },
      queue: async () => {
        expect(imported).toBe(true);
        order.push("queue");
        return {
          queued: true,
          items: [],
          feedback: "Queued",
        };
      },
      submit: async () => {
        expect(imported).toBe(true);
        order.push("submit");
        return { accepted: true, feedback: "Accepted" };
      },
    },
    dependencyGraph: {
      tools: [],
      call: async () => ({}),
      observeInventory,
      flush: () => importWork,
      close: async () => {},
    },
  });
  expect(result).toEqual({ completed: true });
  expect((await resourceRequested.promise).params).toEqual({
    server: "fixture",
    uri,
    threadId: "check",
  });
  expect(order).toEqual(["import", "status", "queue", "submit", "complete"]);
  expect(observeInventory).toHaveBeenCalledTimes(1);
  expect(continuationPrompt).toHaveBeenCalledTimes(1);
  expect(JSON.stringify(replies)).not.toContain("bulk-only-");
  expect(
    replies.find((reply) => reply.method === "thread/start"),
  ).not.toHaveProperty(
    "params.dynamicTools.1.tools.1.inputSchema.properties.groups",
  );
  expect(replies.find((reply) => reply.id === "status")).toMatchObject({
    result: {
      success: true,
      contentItems: [
        {
          type: "inputText",
          text: JSON.stringify({ groupPlan }),
        },
      ],
    },
  });
  expect(
    replies.filter((reply) => ["status", "queue", "final"].includes(reply.id)),
  ).toHaveLength(3);
});

test("continues the same thread after a rejection and publishes a tenth-attempt correction", async () => {
  await using repo = await scopedTemporaryDirectory("report-tool-revisions-");
  await writeFile(
    join(repo.path, "scope.txt"),
    Array.from(
      { length: 10 },
      (_, index) =>
        `Consumer inspection ${index + 1}: no selected dependency version.`,
    ).join("\n"),
  );
  const gap = "The selected dependency version is unresolved.";
  const limitations = ["Consumer selection unresolved."];
  const draft = (revision: number) => ({
    candidateGeneration: 0,
    reviewItems: [{ id: "scope", revision }],
    limitations,
  });
  let reviews = 0;
  let submitted = 0;
  const submissionState = createDependencyReportSubmission({
    advisory: { cve: "CVE-2000-0001", advisories: [] },
    repository: repo.path,
    review: async (prompt) => {
      const packet = JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1)) as {
        items: {
          id: string;
          revision: number;
          hash: string;
          excerptIds: string[];
        }[];
      };
      const accepted = ++reviews === 10;
      return JSON.stringify({
        items: packet.items.map((item) => ({
          id: item.id,
          revision: item.revision,
          hash: item.hash,
          accepted,
          reason: gap,
          citedVersion: null,
          evidenceIds: item.excerptIds,
        })),
      });
    },
  });
  const run = replay(
    [
      ...setup(),
      submission("first", draft(1)),
      complete("turn"),
      started("correction"),
      complete("turn"),
      submission("stale", draft(2)),
      ...Array.from({ length: 9 }, (_, i) =>
        submission(`revision-${i}`, draft(i + 2), { turnId: "correction" }),
      ),
      complete("correction"),
    ],
    async (value) => {
      // Each correction adds source context; identical rejected packets stay cached.
      expect(
        await submissionState.queue({
          items: [
            {
              id: "scope",
              kind: "unresolved",
              candidateIds: [],
              reason: limitations[0],
              evidence: [
                {
                  path: "scope.txt",
                  startLine: 1,
                  endLine: ++submitted,
                  supports: [],
                },
              ],
              observations: [],
            },
          ],
        }),
      ).toMatchObject({ queued: true });
      return submissionState.submit(value);
    },
    submissionState.continuationPrompt,
    undefined,
    submissionState,
  );
  expect(await run.result).toEqual({ completed: true });
  expect(
    run.requests.find((request) => request["method"] === "thread/start"),
  ).toMatchObject({
    params: {
      dynamicTools: [
        {
          name: "codex_security_reports",
          tools: [
            { name: "queue_codex_security_dependency_assessments" },
            { name: "queue_claims" },
            { name: "query_claims" },
            { name: "get_codex_security_review_status" },
            { name: reportTool.tool },
            { name: "abort_codex_security_investigation" },
          ],
        },
      ],
    },
  });
  const turns = run.requests.filter((r) => r["method"] === "turn/start");
  expect(turns).toHaveLength(2);
  expect(turns[1]).toMatchObject({
    params: {
      threadId: "check",
      input: [{ text: expect.stringContaining(gap) }],
    },
  });
  expect(run.requests.find((r) => r["id"] === "stale")).toHaveProperty(
    "error.code",
    -32601,
  );
  expect(reviews).toBe(10);
  expect(submissionState.acceptedReport()).toEqual({
    status: "unknown",
    uses: [],
    coverage: [
      {
        kind: "unresolved",
        reason: "Consumer selection unresolved.",
        evidence: [
          { path: "scope.txt", startLine: 1, endLine: 10, supports: [] },
        ],
        observations: [],
        decidingEvidence: [
          { kind: "source", path: "scope.txt", startLine: 1, endLine: 10 },
        ],
        conclusionClaim: {
          id: "application:scope",
          revision: 10,
          hash: expect.stringMatching(/^[a-f0-9]{64}$/u),
        },
      },
    ],
    limitations: [
      ...limitations,
      "Consumer selection unresolved. Unresolved source locations: scope.txt:1-10.",
    ],
  });
});

test("ends after ten completed turns without a report submission", async () => {
  const submissionState = createDependencyReportSubmission({
    advisory: { cve: "CVE-2000-0001", advisories: [] },
    repository: "/synthetic-check",
    review: async () => {
      throw new Error("Unexpected review");
    },
  });
  const run = replay(
    [
      ...setup(),
      complete("turn"),
      ...Array.from({ length: 9 }, (_, i) => [
        started(`reminder-${i}`),
        complete(`reminder-${i}`),
      ]).flat(),
    ],
    submissionState.submit,
    submissionState.continuationPrompt,
  );
  await expect(run.result).rejects.toThrow(/10/);
  expect(run.requests.filter((r) => r["method"] === "turn/start")).toHaveLength(
    10,
  );
});

test("returns specific rejection feedback inside the current turn and ignores substitute reports", async () => {
  const receipt = {
    structuredContent: { name: "real runtime observation" },
    content: [],
  };
  const item = {
    type: "mcpToolCall",
    status: "completed",
    tool: "inventory",
    server: "selected",
    result: receipt,
  };
  const event = (
    item: object,
    options: object = {},
    method = "item/completed",
  ) => ({ method, params: { ...thread, ...options, item } });
  const startupFailure = {
    method: "mcpServer/startupStatus/updated",
    params: {
      threadId: "check",
      name: "inventory",
      status: "failed",
      error: "unavailable",
    },
  };
  const usage = {
    method: "thread/tokenUsage/updated",
    params: {
      ...thread,
      tokenUsage: {
        total: {
          inputTokens: 25,
          cachedInputTokens: 10,
          cacheWriteInputTokens: 2,
          outputTokens: 8,
          reasoningOutputTokens: 3,
        },
      },
    },
  };
  const submit = mock(async (draft: unknown) => {
    const accepted = draft === "revised";
    return {
      accepted,
      feedback: accepted ? "Accepted." : "Missing runtime receipt.",
    };
  });
  const run = replay(
    [
      ...setup(),
      {
        method: "thread/started",
        params: { thread: { id: "other", parentThreadId: null } },
      },
      {
        ...startupFailure,
        params: { ...startupFailure.params, threadId: "other" },
      },
      startupFailure,
      {
        ...startupFailure,
        params: {
          ...startupFailure.params,
          threadId: null,
          status: "ready",
          error: null,
        },
      },
      event(item, { turnId: "old" }),
      event(item, {}, "item/started"),
      event({ ...item, status: "failed" }),
      event({ ...item, error: { message: "unavailable" } }),
      event({ ...item, result: { ...receipt, isError: true } }),
      event({ ...item, result: { content: [] } }),
      event(item),
      submission("foreign", "ignored", { threadId: "other" }),
      {
        id: "dependency-thread-0",
        result: {
          thread: {
            id: "other",
            parentThreadId: null,
            status: { type: "active" },
          },
        },
      },
      submission("spoof", "ignored", { namespace: "other" }),
      submission("first", "draft"),
      submission("second", "revised"),
      event({ type: "agentMessage", text: "ungraded replacement" }),
      { ...usage, params: { ...usage.params, turnId: "foreign" } },
      usage,
      {
        method: "turn/completed",
        params: {
          threadId: "check",
          turn: { id: "turn", status: "completed" },
        },
      },
    ],
    submit,
  );
  expect(await run.result).toEqual({ completed: true });
  const start = run.requests.find((r) => r["method"] === "thread/start")![
    "params"
  ];
  expect(start).toMatchObject({
    permissions: "restricted",
    approvalPolicy: "never",
    ephemeral: false,
  });
  expect(start).not.toHaveProperty("sandbox");
  expect(start).toHaveProperty("dynamicTools.0.tools.0.name", reportTool.tool);
  expect(run.recordInventoryStartup.mock.calls).toEqual([
    ["inventory", "failed", "unavailable"],
    ["inventory", "ready", null],
  ]);
  const lookup = {
    tool: "inventory",
    arguments: undefined,
    finishedAt: expect.any(String),
  };
  expect(run.recordInventory.mock.calls).toEqual([
    ["selected", receipt, { ...lookup, outcome: "failed" }],
    [
      "selected",
      { result: receipt, error: { message: "unavailable" } },
      { ...lookup, outcome: "failed" },
    ],
    [
      "selected",
      { ...receipt, isError: true },
      { ...lookup, outcome: "failed" },
    ],
    ["selected", { content: [] }, { ...lookup, outcome: "empty" }],
    ["selected", receipt, lookup],
  ]);
  expect(submit.mock.calls).toEqual([["draft"], ["revised"]]);
  expect(run.requests.find((r) => r["id"] === "foreign")).toHaveProperty(
    "error.code",
    -32601,
  );
  expect(run.requests.find((r) => r["id"] === "spoof")).toHaveProperty(
    "error.code",
    -32601,
  );
  expect(run.requests.find((r) => r["id"] === "first")).toMatchObject({
    result: {
      success: false,
      contentItems: [{ type: "inputText", text: "Missing runtime receipt." }],
    },
  });
  expect(run.requests.find((r) => r["id"] === "second")).toHaveProperty(
    "result.success",
    true,
  );
  expect(run.onUsage).toHaveBeenCalledTimes(1);
  expect(run.onUsage).toHaveBeenCalledWith(
    expect.objectContaining({
      input_tokens: 25,
      cached_input_tokens: 10,
      cache_write_input_tokens: 2,
      output_tokens: 8,
      reasoning_output_tokens: 3,
    }),
  );
});

test("propagates review failure and prevents use of an unverified permission profile", async () => {
  const fail = mock(async () => {
    throw new Error("Review unavailable");
  });
  const events = setup();
  await expect(
    replay([...events, submission("first", {})], fail).result,
  ).rejects.toThrow("Review unavailable");
  const wrongProfile = {
    id: 2,
    result: {
      thread: {
        id: "check",
        ephemeral: false,
        path: "/synthetic-sessions/check.jsonl",
      },
      activePermissionProfile: { id: ":workspace" },
    },
  };
  await expect(
    replay([...events.slice(0, 2), wrongProfile], fail).result,
  ).rejects.toThrow("read-only permission profile");
  expect(fail).toHaveBeenCalledTimes(1);
});

test("closing a live app-server pipe preserves the terminal rejection", async () => {
  const events = [
    ...setup(),
    submission("first", "draft"),
    submission("second", "revised"),
    submission("third", "must not review after failure"),
  ];
  const child = spawn(process.execPath, [
    "-e",
    // The app-server waits for responses after sending its requests.
    "process.stdout.write(process.argv[1]); process.stdin.resume();",
    events.map((event) => JSON.stringify(event) + "\n").join(""),
  ]);
  const closed = once(child, "close");
  const gap = "The worker's installed version is still unsupported.";
  const submit = mock(async (draft: unknown) => {
    if (draft === "revised") throw new Error(gap);
    return { accepted: false, feedback: gap };
  });
  try {
    await expect(
      readSkillCommandOutput(child.stdout, {
        input: child.stdin,
        prompt: "Assess the dependency",
        permissionProfile: "restricted",
        threadSource: CODEX_SECURITY_THREAD_SOURCES.validation,
        cyberAccessProgram: "standard",
        dependencyReport: {
          submit,
          recordInventory: () => undefined,
          recordGraphEvent() {},
          continuationPrompt: () => undefined,
        },
        dependencyGraph: {
          tools: [],
          call: async () => ({}),
          flush: async () => {},
          close: async () => {},
        },
      }),
    ).rejects.toThrow(gap);
    expect(submit.mock.calls).toEqual([["draft"], ["revised"]]);
  } finally {
    child.stdout.destroy();
    child.kill();
    await closed;
  }
});

test("an app-server stdin error rejects its pending inventory request and leaves another session running", async () => {
  const output = new PassThrough();
  const pipeError = Object.assign(new Error("write EPIPE"), { code: "EPIPE" });
  const inventoryFailure = mock((_failure: unknown) => {});
  const input = new Writable({
    write(chunk, _encoding, callback) {
      const request = JSON.parse(String(chunk));
      callback(
        request.method === "mcpServer/resource/read" ? pipeError : undefined,
      );
    },
  });
  const broken = readSkillCommandOutput(output, {
    directory: "/synthetic-check",
    input,
    prompt: "Assess the dependency",
    permissionProfile: "restricted",
    threadSource: CODEX_SECURITY_THREAD_SOURCES.validation,
    cyberAccessProgram: "standard",
    allowedMcpServers: ["fixture"],
    dependencyReport: {
      recordInventory: () => undefined,
      recordGraphEvent() {},
      continuationPrompt: () => undefined,
    },
    dependencyGraph: {
      tools: [],
      call: async (_tool, _arguments, inventoryRpc) => {
        try {
          await inventoryRpc!.read!("fixture", "fixture://evidence");
          return {};
        } catch (failure) {
          inventoryFailure(failure);
          throw failure;
        }
      },
      close: async () => {},
    },
  });
  const healthy = replay([...setup(), complete("turn")], undefined);
  try {
    output.write(
      [
        ...setup(),
        submission(
          "graph",
          {},
          {
            namespace: "codex_security_dependency",
            tool: "query_codex_security_graph",
          },
        ),
      ]
        .map((event) => JSON.stringify(event) + "\n")
        .join(""),
    );
    await expect(broken).rejects.toThrow("write EPIPE");
    expect(inventoryFailure).toHaveBeenCalledWith(
      expect.objectContaining({ message: "The inventory connection closed." }),
    );
    expect(await healthy.result).toEqual({ completed: true });
  } finally {
    output.destroy();
    input.destroy();
  }
});

test("carries the latest valid native plan into a dependency follow-up", async () => {
  const plan = [
    { step: "Locate the deployed copy", status: "completed" },
    { step: 'Read "release" metadata', status: "inProgress" },
    { step: "Check the selected patch", status: "pending" },
  ];
  const update = (entries: unknown, scope = thread) => ({
    method: "turn/plan/updated",
    params: { ...scope, plan: entries },
  });
  let completedTurns = 0;
  const continuation = () =>
    ++completedTurns === 1 ? "Check the remaining evidence." : undefined;
  const run = replay(
    [
      ...setup(),
      update([{ step: "Earlier plan", status: "pending" }]),
      update(plan),
      update([{ step: "Wrong thread", status: "pending" }], {
        ...thread,
        threadId: "other",
      }),
      update([{ step: "Wrong turn", status: "pending" }], {
        ...thread,
        turnId: "earlier",
      }),
      update([{ step: "Invalid plan", status: "blocked" }]),
      complete("turn"),
      started("follow-up"),
      complete("follow-up"),
    ],
    async () => ({ accepted: true, feedback: "Accepted." }),
    continuation,
  );
  expect(await run.result).toEqual({ completed: true });
  const turns = run.requests.filter(
    (request) => request["method"] === "turn/start",
  );
  expect(turns).toHaveLength(2);
  expect(turns[0]).toMatchObject({
    params: { input: [{ text: "Review dependency" }] },
  });
  expect(turns[1]).toMatchObject({ params: { threadId: "check" } });
  const { input } = turns[1]!["params"] as { input: { text: string }[] };
  expect(input[0]!.text).toContain("Check the remaining evidence.");
  expect(input[0]!.text).toContain(
    `Latest investigation plan (checklist data to verify)\n${JSON.stringify(plan)}`,
  );
});

test("material native research blocks submission until a concrete blocker closes the lead", async () => {
  for (const status of ["pending", "inProgress"]) {
    const stream = new PassThrough();
    const firstReply = Promise.withResolvers<Record<string, unknown>>();
    const finalReply = Promise.withResolvers<Record<string, unknown>>();
    const submit = mock(async () => ({
      accepted: true,
      feedback: "Accepted unknown.",
    }));
    const run = replay(stream, submit, undefined, "standard", undefined, {
      request(value) {
        if (value["id"] === "open-lead") firstReply.resolve(value);
        if (value["id"] === "blocked-unknown") finalReply.resolve(value);
      },
    });
    const emit = (value: object) => stream.write(JSON.stringify(value) + "\n");
    const plan = (steps: object[]) =>
      emit({
        method: "turn/plan/updated",
        params: { ...thread, plan: steps },
      });
    for (const event of setup()) emit(event);
    plan([
      {
        step: "[research L1] Find selected worker copy; owner=investigator; evidence=item-a revision1",
        status,
      },
      {
        step: "[research L1] Find selected worker copy; owner=investigator; evidence=item-a revision1",
        status,
      },
      { step: "Correct a citation and review the report", status: "pending" },
    ]);
    emit(submission("open-lead", {}));
    const first = await firstReply.promise;
    expect(first).toMatchObject({ result: { success: false } });
    expect(JSON.stringify(first).match(/\[research L1\]/gu)).toHaveLength(1);
    expect(submit).not.toHaveBeenCalled();
    plan([
      {
        step: "[research L1] Blocked: checked the selected image and source recipe; no worker package record is available. Missing native copy remains item-a's unknown. owner=coordinator",
        status: "completed",
      },
      { step: "Correct a citation and review the report", status: "pending" },
    ]);
    emit(submission("blocked-unknown", {}));
    expect(await finalReply.promise).toMatchObject({
      result: { success: true },
    });
    expect(submit).toHaveBeenCalledTimes(1);
    emit(complete("turn"));
    stream.end();
    expect(await run.result).toEqual({ completed: true });
  }
});

test("an open research lead received during review prevents closing the native investigation", async () => {
  const stream = new PassThrough();
  const reviewStarted = Promise.withResolvers<void>();
  const releaseReview = Promise.withResolvers<void>();
  const planReceived = Promise.withResolvers<void>();
  const continuation = Promise.withResolvers<Record<string, unknown>>();
  let turns = 0;
  const submit = mock(async () => {
    reviewStarted.resolve();
    await releaseReview.promise;
    return { accepted: true, feedback: "Current evidence accepted." };
  });
  const run = replay(stream, submit, undefined, "standard", undefined, {
    graph: {
      tools: [],
      call: async () => ({}),
      flush: async () => {},
      close: async () => {},
    },
    request(value) {
      if (value["method"] === "turn/start" && ++turns === 2)
        continuation.resolve(value);
    },
    event(value) {
      if (value["method"] === "turn/plan/updated") planReceived.resolve();
    },
  });
  const emit = (value: object) => stream.write(JSON.stringify(value) + "\n");
  for (const event of setup()) emit(event);
  emit(submission("reviewing", {}));
  await reviewStarted.promise;
  emit({
    method: "turn/plan/updated",
    params: {
      ...thread,
      plan: [
        {
          step: "[research L2] Check the raw overwrite writer and storage namespace; owner=investigator",
          status: "inProgress",
        },
      ],
    },
  });
  await planReceived.promise;
  emit(complete("turn"));
  releaseReview.resolve();
  const next = await continuation.promise;
  expect(JSON.stringify(next)).toContain("[research L2]");
  let settled = false;
  void run.result.then(() => {
    settled = true;
  });
  expect(settled).toBe(false);
  emit(started("follow-up"));
  emit({
    method: "turn/plan/updated",
    params: {
      threadId: "check",
      turnId: "follow-up",
      plan: [
        {
          step: "[research L2] Answered: the selected writer encodes the stored input; evidence=source-note-2. owner=coordinator",
          status: "completed",
        },
        { step: "Review the final report", status: "pending" },
      ],
    },
  });
  for (const scope of [
    thread,
    { threadId: "investigator", turnId: "child-turn" },
  ])
    emit({
      method: "turn/plan/updated",
      params: {
        ...scope,
        plan: [
          {
            step: "[research stale] Superseded evidence question",
            status: "pending",
          },
        ],
      },
    });
  emit(complete("follow-up"));
  stream.end();
  expect(await run.result).toEqual({ completed: true });
  expect(submit).toHaveBeenCalledTimes(1);
  expect(
    run.requests.filter((value) => value["method"] === "turn/start"),
  ).toHaveLength(2);
});

test("finalizes after native source work calls and preserves known remaining coverage", async () => {
  await using repo = await scopedTemporaryDirectory("native-source-work-");
  await mkdir(join(repo.path, "mcp"));
  await writeFile(join(repo.path, "worker.ts"), 'saveImage("PNG");\n');
  await writeFile(
    join(repo.path, "mcp", "helpers.mjs"),
    [
      "export default { createDependencyGraphSession: () => ({",
      "  tools: [{ name: 'query_codex_security_graph', description: 'Query', inputSchema: { type: 'object', properties: {} } }],",
      "  serviceResolutionCoverage: () => ({ revision: 0, pending: 0 }),",
      "  async call() { throw new Error('An ordinary graph query must not repair coverage.'); },",
      "  async close() {},",
      "}) };",
    ].join("\n"),
  );
  const graph = await openDependencyGraph(repo.path, repo.path);
  const state = createDependencyReportSubmission({
    repository: repo.path,
    advisory: { cve: "CVE-2000-0001", advisories: [] },
    sourceWorkCoverage: () => graph.sourceWorkCoverage,
    review: async (prompt) => {
      const packet = JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1)) as {
        items: {
          id: string;
          revision: number;
          hash: string;
          excerptIds: string[];
        }[];
      };
      return JSON.stringify({
        items: packet.items.map(({ id, revision, hash, excerptIds }) => ({
          id,
          revision,
          hash,
          accepted: true,
          reason: "The fixed format excludes this call.",
          citedVersion: null,
          evidenceIds: excerptIds,
        })),
      });
    },
  });
  try {
    const reviewed = await state.queue({
      items: [
        {
          id: "fixed-format",
          kind: "use",
          candidateIds: [],
          use: {
            location: "worker.ts:1",
            component: "image-library",
            version: null,
            verdict: "ruled_out",
            deployment: "unknown",
            reason: "The call selects a format outside the advisory.",
            evidence: [
              { path: "worker.ts", startLine: 1, endLine: 1, supports: [] },
            ],
            observations: [],
          },
        },
      ],
    });
    expect(reviewed).toMatchObject({ queued: true });
    const tool = "record_codex_security_source_work";
    const write = {
      operation: "append_roster_page",
      id: "format-dispatch",
      owner: "discovery",
      paths: ["worker.ts", "worker-extra.ts"],
      declaredComplete: false,
      gaps: [
        { id: "remaining", description: "Remaining worker search timed out." },
      ],
      search: "Find image library calls",
      sourceRefs: ["search-receipt-1"],
    };
    const mutation = Promise.withResolvers<void>();
    const query = Promise.withResolvers<void>();
    const final = Promise.withResolvers<void>();
    async function* events() {
      for (const event of setup()) yield JSON.stringify(event) + "\n";
      yield JSON.stringify(
        submission(
          "source-work-write",
          { work: write },
          {
            namespace: dependencyGraphNamespace,
            tool,
          },
        ),
      ) + "\n";
      await mutation.promise;
      yield JSON.stringify(
        submission(
          "source-work-read",
          { sourceWork: {} },
          {
            namespace: dependencyGraphNamespace,
            tool: "query_codex_security_graph",
          },
        ),
      ) + "\n";
      await query.promise;
      yield JSON.stringify(
        submission("source-work-final", {
          reviewItems: [{ id: "fixed-format", revision: 1 }],
          candidateGeneration: 0,
          limitations: [],
        }),
      ) + "\n";
      await final.promise;
      yield JSON.stringify(complete("turn")) + "\n";
    }
    const responses = new Map<string, Record<string, unknown>>();
    expect(
      await readSkillCommandOutput(Readable.from(events()), {
        directory: repo.path,
        prompt: "Review dependency",
        sandbox: "read-only",
        permissionProfile: "restricted",
        cyberAccessProgram: "standard",
        threadSource: CODEX_SECURITY_THREAD_SOURCES.validation,
        dependencyGraph: graph,
        dependencyReport: {
          submit: state.submit,
          recordInventory: state.recordInventory,
          recordGraphEvent: state.recordGraphEvent,
          continuationPrompt: state.continuationPrompt,
        },
        input: new Writable({
          write(chunk, _encoding, done) {
            const reply = JSON.parse(String(chunk)) as Record<string, unknown>;
            if (typeof reply["id"] === "string")
              responses.set(reply["id"], reply);
            if (reply["id"] === "source-work-write") mutation.resolve();
            if (reply["id"] === "source-work-read") query.resolve();
            if (reply["id"] === "source-work-final") final.resolve();
            done();
          },
        }),
      }),
    ).toEqual({ completed: true });
    for (const id of [
      "source-work-write",
      "source-work-read",
      "source-work-final",
    ])
      expect(responses.get(id)).toHaveProperty("result.success", true);
    const report = state.acceptedReport();
    expect(report.status).toBe("unknown");
    expect(report.uses[0]?.verdict).toBe("ruled_out");
    expect(state.publicReport().limitations).toEqual([
      expect.stringContaining('["worker-extra.ts","worker.ts"]'),
    ]);
    expect(report.limitations[0]).toContain(
      "Remaining worker search timed out.",
    );
    expect(report.limitations[0]).toContain("search-receipt-1");
    await graph.call(tool, {
      work: {
        operation: "assign_partition",
        id: "worker-check",
        rosterId: write.id,
        owner: "worker",
        paths: ["worker.ts"],
      },
    });
    expect(() => state.acceptedReport()).toThrow(
      "Coverage or report evidence changed after finalization",
    );
  } finally {
    state.close();
    await graph.close();
  }
});

test("native shared claim tools register object schemas and preserve opaque JSON", async () => {
  await using repo = await scopedTemporaryDirectory("native-claims-");
  await writeFile(join(repo.path, "writer.ts"), 'saveImage(output, "PNG");\n');
  const state = createDependencyReportSubmission({
    repository: repo.path,
    advisory: { cve: "CVE-2024-1000", advisories: [] },
    review: async (prompt) => {
      const packet = JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1)) as {
        items: {
          id: string;
          revision: number;
          hash: string;
          excerptIds: string[];
        }[];
      };
      return JSON.stringify({
        items: packet.items.map((row) => ({
          id: row.id,
          revision: row.revision,
          hash: row.hash,
          accepted: true,
          reason: "writer.ts establishes the selected fixture statement.",
          citedVersion: null,
          evidenceIds: row.excerptIds,
        })),
      });
    },
  });
  const payload = {
    state: "approved",
    id: "opaque-only",
    nested: [null, false, 17, { modes: ["PNG", "JPEG"] }],
  };
  try {
    const run = replay(
      [
        ...setup(),
        submission(
          "claim-save",
          {
            claims: [
              {
                id: "writer-mode",
                payload,
                scope: { repository: "fixture", modes: ["PNG", "JPEG"] },
                evidence: [{ path: "writer.ts", startLine: 1, endLine: 1 }],
              },
            ],
          },
          { tool: "queue_claims" },
        ),
        submission(
          "claim-read",
          { ids: ["writer-mode"] },
          { tool: "query_claims" },
        ),
        complete("turn"),
      ],
      undefined,
      () => undefined,
      "standard",
      state,
    );
    expect(await run.result).toEqual({ completed: true });
    const start = run.requests.find(
      (request) => request["method"] === "thread/start",
    ) as {
      params: {
        dynamicTools: {
          name: string;
          tools: {
            name: string;
            inputSchema: { type: string; properties: unknown };
          }[];
        }[];
      };
    };
    const reportTools = start.params.dynamicTools.find(
      (namespace) => namespace.name === "codex_security_reports",
    )!.tools;
    for (const name of ["queue_claims", "query_claims"]) {
      const definition = reportTools.find((tool) => tool.name === name)!;
      expect(definition.inputSchema.type).toBe("object");
      expect(definition.inputSchema.properties).toBeDefined();
    }
    const response = run.requests.find(
      (request) => request["id"] === "claim-read",
    ) as {
      result: { success: boolean; contentItems: { text: string }[] };
    };
    expect(response.result.success).toBe(true);
    expect(JSON.parse(response.result.contentItems[0]!.text)).toMatchObject({
      claims: [{ id: "writer-mode", payload }],
    });
    expect(
      (await state.queryClaims({ ids: ["writer-mode"] })).claims[0]!.id,
    ).toBe("writer-mode");
  } finally {
    await state.close();
  }
});
