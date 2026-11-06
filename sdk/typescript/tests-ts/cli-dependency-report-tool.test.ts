import { expect, mock, test } from "bun:test";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Readable, Writable } from "node:stream";
import { readSkillCommandOutput } from "../src/cli.js";
import { createDependencyCandidates } from "../src/dependency-candidates.js";
import type { DependencyGraphTools } from "../src/dependency-graph-tools.js";
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
          ephemeral: !daybreak,
          path: daybreak ? "/synthetic-sessions/check.jsonl" : null,
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
  events: object[],
  submit: (draft: unknown) => Promise<{ accepted: boolean; feedback: string }>,
  continuationPrompt: () => string | undefined = () => undefined,
  cyberAccessProgram: "standard" | "daybreak_blue" = "standard",
  reviewQueue?: Pick<
    ReturnType<typeof createDependencyReportSubmission>,
    "queue" | "status"
  >,
) {
  const requests: Record<string, unknown>[] = [];
  const bindReviewer = mock(() => requests.length);
  const recordInventory = mock(
    (_name: string, _payload: unknown, _metadata?: unknown) => {},
  );
  const onUsage = mock(() => {});
  const result = readSkillCommandOutput(
    Readable.from(events.map((event) => JSON.stringify(event) + "\n")),
    {
      directory: "/synthetic-check",
      prompt: "Review dependency",
      sandbox: "read-only",
      permissionProfile: "restricted",
      cyberAccessProgram,
      bindReviewer,
      threadSource: CODEX_SECURITY_THREAD_SOURCES.validation,
      dependencyReport: {
        ...reviewQueue,
        submit,
        recordInventory,
        continuationPrompt,
        recordGraphEvent() {},
      },
      input: new Writable({
        write(chunk, _encoding, callback) {
          requests.push(JSON.parse(String(chunk)));
          callback();
        },
      }),
    },
    onUsage,
  );
  return { result, requests, bindReviewer, recordInventory, onUsage };
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
      recordInventory() {},
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
  const draft = {
    status: "unknown" as const,
    uses: [],
    limitations: ["Consumer selection unresolved."],
  };
  let reviews = 0;
  let submitted = 0;
  const submissionState = createDependencyReportSubmission({
    advisory: { cve: "CVE-2000-0001", advisories: [] },
    repository: repo.path,
    review: async (prompt) => {
      const packet = JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1)) as {
        items: { id: string; revision: number; excerptIds: string[] }[];
      };
      const accepted = ++reviews === 10;
      return JSON.stringify({
        items: packet.items.map((item) => ({
          id: item.id,
          revision: item.revision,
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
      submission("first", draft),
      complete("turn"),
      started("correction"),
      complete("turn"),
      submission("stale", draft),
      ...Array.from({ length: 9 }, (_, i) =>
        submission(`revision-${i}`, draft, { turnId: "correction" }),
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
              reason: draft.limitations[0],
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
            { name: "get_codex_security_review_status" },
            { name: reportTool.tool },
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
    ...draft,
    limitations: [
      ...draft.limitations,
      expect.stringContaining("scope.txt:1-10"),
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
      event(item, { turnId: "old" }),
      event(item, {}, "item/started"),
      event({ ...item, status: "failed" }),
      event({ ...item, error: { message: "unavailable" } }),
      event({ ...item, result: { ...receipt, isError: true } }),
      event({ ...item, result: { content: [] } }),
      event(item),
      submission("foreign", "ignored", { threadId: "other" }),
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
    ephemeral: true,
  });
  expect(start).not.toHaveProperty("sandbox");
  expect(start).toHaveProperty("dynamicTools.0.tools.0.name", reportTool.tool);
  expect(run.recordInventory.mock.calls).toEqual([
    ["selected", receipt, { tool: "inventory", arguments: undefined }],
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
      thread: { id: "check", ephemeral: true, path: null },
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
  ];
  const child = spawn(process.execPath, [
    "-e",
    // The app-server waits for our response after the second tool request.
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
          recordInventory() {},
          recordGraphEvent() {},
          continuationPrompt: () => undefined,
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
