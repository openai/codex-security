import { expect, mock, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { PassThrough, Readable, Writable } from "node:stream";
import { main, readSkillCommandOutput } from "../src/cli.js";
import type { DependencyGraphTools } from "../src/dependency-graph-tools.js";
import {
  createDependencyReportSubmission,
  DependencyInvestigationBlockedError,
} from "../src/dependency-report-submission.js";
import { dependencyCheckOutputSchema } from "../src/dependency-reachability.js";
import { CODEX_SECURITY_THREAD_SOURCES } from "../src/thread-source.js";
import { dependencies, FakeSignals, type OnCodex } from "./cli-fixtures.js";
import { git } from "./git-fixture.js";
import { createCliTest } from "./support/cli-run.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

const advisory = { cve: "CVE-2024-1000", advisories: [] };
const declaration =
  "The provider's required artifact dataset is unavailable for all selected production executors.";
const selection = {
  receiptId: "inventory-1",
  textBlock: null,
  record: ["coverage", "message"],
};
const blocker = {
  reason:
    "Broad required artifact data is unavailable across the requested production scope.",
  category: "widespread_required_data_unavailable",
  tool: { server: "runtime", name: "artifact" },
  affectedScope: "Artifact validation for all selected production executors",
  coverage: {
    basis: "provider_declared",
    scope: "All selected production executors",
    declaration,
    selection,
    representativeness:
      "The provider explicitly covers the entire required executor dataset, not an exploratory alias or one missing image.",
  },
  scopeImpact:
    "The investigation cannot validate any executor artifact in its required runtime scope; independent source findings have been retained.",
  unblockCondition:
    "Restore the configured artifact dataset and start a new investigation.",
  evidenceReferences: ["source-note-1"],
};
type NativeRequest = {
  id?: string | number;
  method?: string;
  result?: { success?: boolean; [key: string]: unknown };
  [key: string]: unknown;
};
function recordBroadLoss(
  state: Pick<
    ReturnType<typeof createDependencyReportSubmission>,
    "recordInventory"
  >,
) {
  return state.recordInventory(
    "runtime",
    { structuredContent: { coverage: { message: declaration } } },
    {
      tool: "artifact",
      arguments: { scope: "selected-production-executors" },
      outcome: "unavailable",
    },
  );
}
function abortState(
  options: Parameters<typeof createDependencyReportSubmission>[0],
) {
  const state = createDependencyReportSubmission({
    ...options,
    inventoryServers: { runtime: ["artifact"], ...options.inventoryServers },
  });
  recordBroadLoss(state);
  return state;
}
async function writeRuntimeConfig(directory: string) {
  const path = join(directory, "runtime.json");
  await writeFile(
    path,
    JSON.stringify({
      exploitability: { runtime_mcps: ["runtime"] },
      codex: {
        mcp_servers: {
          runtime: { command: "fixture-runtime", enabled_tools: ["artifact"] },
        },
      },
    }),
  );
  return path;
}
function approve(prompt: string) {
  const packet = JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1));
  return JSON.stringify({
    items: packet.items.map(
      (item: {
        id: string;
        revision: number;
        excerptIds: string[];
        receiptIds: string[];
      }) => ({
        id: item.id,
        revision: item.revision,
        accepted: true,
        reason:
          "The submitted source supports the scope and missing deciding fact.",
        citedVersion: null,
        evidenceIds: [...item.excerptIds, ...item.receiptIds],
      }),
    ),
  });
}
const gapItem = {
  id: "source-gap",
  kind: "unresolved",
  candidateIds: [],
  reason: "The selected runtime copy is not established by this source call.",
  evidence: [{ path: "worker.ts", startLine: 1, endLine: 1, supports: [] }],
  observations: [],
};
const root = { threadId: "check", turnId: "turn" };
function call(id: string, tool: string, args: unknown, overrides = {}) {
  return {
    id,
    method: "item/tool/call",
    params: {
      ...root,
      namespace: "codex_security_reports",
      tool,
      callId: id,
      arguments: args,
      ...overrides,
    },
  };
}
function setup() {
  return [
    { id: 1, result: {} },
    { id: 4, result: { config: {}, layers: [] } },
    {
      id: 2,
      result: {
        thread: {
          id: "check",
          ephemeral: false,
          path: "/sessions/check.jsonl",
        },
        activePermissionProfile: { id: "restricted" },
        model: "test-model",
        modelProvider: "openai",
      },
    },
    { id: 3, result: { turn: { id: "turn" } } },
  ];
}
function completed() {
  return {
    method: "turn/completed",
    params: { threadId: "check", turn: { id: "turn", status: "completed" } },
  };
}
function nativeRun(
  events: object[] | Readable,
  state: ReturnType<typeof createDependencyReportSubmission>,
  graph?: DependencyGraphTools,
  onRequest?: (request: NativeRequest) => void,
  inventory = false,
) {
  const requests: NativeRequest[] = [];
  const turnStarted = Promise.withResolvers<void>();
  const continuing = mock(state.continuationPrompt);
  const result = readSkillCommandOutput(
    Array.isArray(events)
      ? Readable.from(events.map((event) => JSON.stringify(event) + "\n"))
      : events,
    {
      directory: "/synthetic-check",
      prompt: "Investigate",
      sandbox: "read-only",
      permissionProfile: "restricted",
      cyberAccessProgram: "standard",
      threadSource: CODEX_SECURITY_THREAD_SOURCES.validation,
      dependencyReport: {
        abort: state.abort,
        blockedOutcome: state.blockedOutcome,
        submit: state.submit,
        queue: state.queue,
        status: state.readStatus,
        continuationPrompt: continuing,
        recordGraphEvent: state.recordGraphEvent,
        recordInventory: state.recordInventory,
      },
      ...(graph ? { dependencyGraph: graph } : {}),
      ...(inventory ? { allowedMcpServers: ["runtime"] } : {}),
      input: new Writable({
        write(chunk, _encoding, done) {
          const request = JSON.parse(String(chunk));
          requests.push(request);
          onRequest?.(request);
          if (request.method === "turn/start") turnStarted.resolve();
          done();
        },
      }),
    },
  );
  return { result, requests, continuing, turnStarted: turnStarted.promise };
}

test("abort preserves known revisions and receipts, prevents further work, and closes once", async () => {
  await using temp = await scopedTemporaryDirectory("blocked-state-");
  await writeFile(join(temp.path, "worker.ts"), "decode(input);\n");
  const stopped = mock(() => {});
  const state = abortState({
    repository: temp.path,
    advisory,
    review: async (prompt) => approve(prompt),
    onBlocked: stopped,
  });
  const receipt = state.recordInventory(
    "runtime",
    { error: "Access denied" },
    { tool: "artifact", outcome: "failed" },
  );
  const queued = await state.queue({ items: [gapItem] });
  expect(queued).toMatchObject({ queued: true });
  const outcome = state.abort(blocker, "check");
  expect(outcome).toMatchObject({
    status: "blocked",
    code: "INVESTIGATION_BLOCKED",
    nativeThreadId: "check",
    retainedEvidence: {
      assessmentRevisions: [{ id: "source-gap", revision: 1 }],
      inventoryReceiptIds: ["inventory-1", receipt],
    },
  });
  expect(dependencyCheckOutputSchema.safeParse(outcome).success).toBe(false);
  expect(state.abort(blocker)).toBe(outcome);
  expect(stopped).toHaveBeenCalledTimes(1);
  expect(await state.queue({ items: [gapItem] })).toMatchObject({
    queued: false,
  });
  await expect(
    state.submit({ reviewItems: [], candidateGeneration: 0, limitations: [] }),
  ).rejects.toBeInstanceOf(DependencyInvestigationBlockedError);
  expect(() => state.continuationPrompt()).toThrow(
    DependencyInvestigationBlockedError,
  );
  expect(() => state.publicReport()).toThrow(
    DependencyInvestigationBlockedError,
  );
  expect(state.readStatus().items).toHaveLength(1);
  const closing = state.close();
  expect(state.close()).toBe(closing);
  await closing;
  expect(state.readStatus().items).toHaveLength(1);
});

test("an invalid abort request leaves the investigation available", async () => {
  await using temp = await scopedTemporaryDirectory("blocked-input-");
  const state = abortState({
    repository: temp.path,
    advisory,
    review: async (prompt) => approve(prompt),
  });
  try {
    expect(() => state.abort({ reason: "stop" })).toThrow();
    expect(state.blockedOutcome()).toBeUndefined();
  } finally {
    await state.close();
  }
});

test("native coordinator broad-data abort is terminal despite open research and later calls", async () => {
  const category = blocker.category;
  await using temp = await scopedTemporaryDirectory("blocked-native-");
  const state = abortState({
    repository: temp.path,
    advisory,
    review: async (prompt) => approve(prompt),
  });
  const graphCall = mock(async () => ({ ok: true }));
  const graph = {
    tools: [
      {
        name: "trace_codex_security_code",
        description: "Trace",
        inputSchema: { type: "object" },
      },
    ],
    call: graphCall,
    close: async () => {},
  } as unknown as DependencyGraphTools;
  const events = new PassThrough();
  const run = nativeRun(events, state, graph);
  for (const event of setup()) events.write(JSON.stringify(event) + "\n");
  await run.turnStarted;
  for (const event of [
    {
      method: "thread/started",
      params: {
        thread: {
          id: "child",
          parentThreadId: "check",
          status: { type: "active" },
        },
      },
    },
    {
      method: "turn/started",
      params: { threadId: "child", turn: { id: "child-turn" } },
    },
    call("child-abort", "abort_codex_security_investigation", blocker, {
      threadId: "child",
      turnId: "child-turn",
    }),
    {
      method: "turn/plan/updated",
      params: {
        ...root,
        plan: [
          {
            step: "[research R1] Restore required runtime capability",
            status: "pending",
          },
        ],
      },
    },
    call("root-abort", "abort_codex_security_investigation", {
      ...blocker,
      category,
    }),
    call(
      "late-graph",
      "trace_codex_security_code",
      {},
      { namespace: "codex_security_dependency" },
    ),
    call("late-submit", "produce_codex_security_exploit_report", {}),
    completed(),
  ])
    events.write(JSON.stringify(event) + "\n");
  events.end();
  try {
    const result = await run.result;
    expect(result).toMatchObject({
      completed: false,
      blocked: { status: "blocked", category, nativeThreadId: "check" },
    });
    expect(run.requests.find((r) => r.id === "child-abort")).toMatchObject({
      result: { success: false },
    });
    expect(run.requests.find((r) => r.id === "root-abort")).toMatchObject({
      result: { success: true },
    });
    expect(graphCall).not.toHaveBeenCalled();
    expect(run.continuing).not.toHaveBeenCalled();
    expect(run.requests.filter((r) => r.method === "turn/start")).toHaveLength(
      1,
    );
  } finally {
    await state.close();
  }
});

test("abort bypasses an in-flight submission and cancels its reviewer without publishing", async () => {
  await using temp = await scopedTemporaryDirectory("blocked-race-");
  await writeFile(join(temp.path, "worker.ts"), "decode(input);\n");
  const reviewing = Promise.withResolvers<void>();
  let reviewCancelled = 0;
  const state = abortState({
    repository: temp.path,
    advisory,
    review: (_prompt, _schema, signal) =>
      new Promise((_resolve, reject) => {
        reviewing.resolve();
        const abort = () => {
          reviewCancelled++;
          reject(signal!.reason);
        };
        if (signal!.aborted) abort();
        else signal!.addEventListener("abort", abort, { once: true });
      }),
  });
  const queued = await state.queue({ items: [gapItem] });
  expect(queued.queued).toBe(true);
  if (!queued.queued) throw new Error(queued.feedback);
  const events = new PassThrough();
  const graph = {
    tools: [],
    call: async () => ({}),
    flush: async () => {},
    close: async () => {},
  } as unknown as DependencyGraphTools;
  const run = nativeRun(events, state, graph);
  for (const event of [
    ...setup(),
    call("pending-submit", "produce_codex_security_exploit_report", {
      reviewItems: queued.items,
      candidateGeneration: 0,
      limitations: [gapItem.reason],
    }),
  ])
    events.write(JSON.stringify(event) + "\n");
  await reviewing.promise;
  events.write(
    JSON.stringify(
      call("root-abort", "abort_codex_security_investigation", blocker),
    ) + "\n",
  );
  events.end(JSON.stringify(completed()) + "\n");
  try {
    expect(await run.result).toMatchObject({ blocked: { status: "blocked" } });
    expect(reviewCancelled).toBe(1);
    expect(run.requests.find((r) => r.id === "root-abort")).toMatchObject({
      result: { success: true },
    });
    expect(
      run.requests.filter(
        (r) => r.id === "pending-submit" && r.result?.success,
      ),
    ).toEqual([]);
    expect(run.continuing).not.toHaveBeenCalled();
    expect(() => state.publicReport()).toThrow(
      DependencyInvestigationBlockedError,
    );
  } finally {
    await state.close();
  }
});

test.each([
  { rows: [], complete: true },
  { status: "missing", complete: true },
  { artifact: "different-image", environment: "stage" },
  { artifact: "selected-image", capturedAt: "2001-01-01T00:00:00Z" },
])(
  "healthy evidence gaps yield reviewed unknown rather than operational abort: %j",
  async (result) => {
    await using temp = await scopedTemporaryDirectory("healthy-gap-");
    await writeFile(join(temp.path, "worker.ts"), "decode(input);\n");
    const stopped = mock(() => {});
    const state = createDependencyReportSubmission({
      repository: temp.path,
      advisory,
      inventoryServers: { runtime: ["lookup"] },
      review: async (prompt) => approve(prompt),
      onBlocked: stopped,
    });
    try {
      state.recordInventory("runtime", result, {
        tool: "lookup",
        arguments: { artifact: "selected-image", environment: "prod" },
      });
      const queued = await state.queue({ items: [gapItem] });
      if (!queued.queued) throw new Error(queued.feedback);
      expect(
        await state.submit({
          reviewItems: queued.items,
          candidateGeneration: 0,
          limitations: [gapItem.reason],
        }),
      ).toMatchObject({ accepted: true });
      expect(state.acceptedReport().status).toBe("unknown");
      expect(state.blockedOutcome()).toBeUndefined();
      expect(stopped).not.toHaveBeenCalled();
    } finally {
      await state.close();
    }
  },
);

test("optional catalog startup failure does not block a source-proven PNG exclusion", async () => {
  await using temp = await scopedTemporaryDirectory("optional-catalog-");
  await writeFile(
    join(temp.path, "writer.py"),
    'image.save("out.png", format="PNG")\n',
  );
  const state = createDependencyReportSubmission({
    repository: temp.path,
    advisory,
    inventoryServers: { catalog: ["lookup"] },
    catalogServerNames: ["catalog"],
    review: async (prompt) => approve(prompt),
  });
  try {
    state.recordInventoryStartup("catalog", "failed", "Transport unavailable");
    const queued = await state.queue({
      items: [
        {
          id: "png-writer",
          kind: "use",
          candidateIds: [],
          use: {
            location: "writer.py:1",
            component: "image-writer",
            version: null,
            verdict: "ruled_out",
            deployment: "configured",
            reason:
              "The selected PNG output does not invoke the advisory's TIFF writer.",
            evidence: [
              { path: "writer.py", startLine: 1, endLine: 1, supports: [] },
            ],
            observations: [],
          },
        },
      ],
    });
    if (!queued.queued) throw new Error(queued.feedback);
    expect(
      await state.submit({
        reviewItems: queued.items,
        candidateGeneration: 0,
        limitations: [],
      }),
    ).toMatchObject({ accepted: true });
    expect(state.publicReport().uses[0]?.verdict).toBe("ruled_out");
    expect(state.blockedOutcome()).toBeUndefined();
  } finally {
    await state.close();
  }
});

test("CLI returns structured BLOCKED and nonzero after the coordinator aborts, not a report or signal exit", async () => {
  await using temp = await scopedTemporaryDirectory("blocked-cli-");
  git(temp.path, "init", "--quiet");
  const config = await writeRuntimeConfig(temp.path);
  const onCodex = mock<OnCodex>((_args, output) => {
    const tool = output!.appServer!.dependencyReport!;
    expect(tool.abort).toBeFunction();
    recordBroadLoss(tool);
    tool.abort!(blocker, "native-root");
    expect(output!.signal?.aborted).toBe(true);
    return 143;
  });
  const deps = dependencies({ currentDirectory: temp.path, onCodex });
  deps.lookupDependencyAdvisory = async () => advisory;
  const { runCli, stdout, stderr } = createCliTest(main);
  expect(
    await runCli(
      ["exploitability", "check", advisory.cve, "--json", "--config", config],
      deps,
    ),
    stderr.text(),
  ).toBe(2);
  const result = JSON.parse(stdout.text());
  expect(result).toMatchObject({
    status: "blocked",
    code: "INVESTIGATION_BLOCKED",
    affectedScope: blocker.affectedScope,
  });
  expect(result).not.toHaveProperty("uses");
  expect(result).not.toHaveProperty("checks");
  expect(onCodex).toHaveBeenCalledTimes(1);
});

test("ordinary OpenGrep startup failure does not invoke exceptional data-loss abort", async () => {
  await using temp = await scopedTemporaryDirectory("blocked-preflight-");
  git(temp.path, "init", "--quiet");
  const onCodex = mock<OnCodex>(() => 0);
  const deps = dependencies({
    currentDirectory: temp.path,
    onCodex,
    onRepositoryCommand: async () => {
      throw new Error("Required structural tool is unavailable");
    },
  });
  deps.lookupDependencyAdvisory = mock(async () => advisory);
  const { runCli, stdout, stderr } = createCliTest(main);
  expect(
    await runCli(["exploitability", "check", advisory.cve, "--json"], deps),
    stderr.text(),
  ).toBe(2);
  expect(stdout.text()).not.toContain("INVESTIGATION_BLOCKED");
  expect(onCodex).not.toHaveBeenCalled();
  expect(deps.lookupDependencyAdvisory).not.toHaveBeenCalled();
});

test("a valid accepted report wins over a later abort", async () => {
  await using temp = await scopedTemporaryDirectory("accepted-before-abort-");
  const stopped = mock(() => {});
  const state = abortState({
    repository: temp.path,
    advisory,
    review: async (prompt) => approve(prompt),
    onBlocked: stopped,
  });
  try {
    expect(
      await state.submit({
        reviewItems: [],
        candidateGeneration: 0,
        limitations: [
          "Discovery found no material calls in this source scope.",
        ],
      }),
    ).toMatchObject({ accepted: true });
    expect(() => state.abort(blocker)).toThrow("accepted report is final");
    expect(state.blockedOutcome()).toBeUndefined();
    expect(state.publicReport().uses).toEqual([]);
    expect(stopped).not.toHaveBeenCalled();
  } finally {
    await state.close();
  }
});

test("a queue preparing source when abort occurs cannot commit late revisions", async () => {
  await using temp = await scopedTemporaryDirectory("queue-abort-race-");
  await writeFile(join(temp.path, "worker.ts"), "decode(input);\n");
  let state: ReturnType<typeof createDependencyReportSubmission>;
  let scheduled = false;
  state = abortState({
    repository: temp.path,
    advisory,
    review: async (prompt) => approve(prompt),
    candidates: {
      snapshot: () => {
        if (!scheduled) {
          scheduled = true;
          queueMicrotask(() => state.abort(blocker));
        }
        return {
          generation: 0,
          candidates: [],
          scope: "Selected source",
          limitations: [],
        };
      },
    },
  });
  try {
    expect(await state.queue({ items: [gapItem] })).toMatchObject({
      queued: false,
    });
    expect(
      state.blockedOutcome()?.retainedEvidence.assessmentRevisions,
    ).toEqual([]);
    expect(state.readStatus().items).toEqual([]);
  } finally {
    await state.close();
  }
});

test("a delayed root call from a completed turn cannot abort during finalization", async () => {
  await using temp = await scopedTemporaryDirectory("stale-root-abort-");
  const state = abortState({
    repository: temp.path,
    advisory,
    review: async (prompt) => approve(prompt),
  });
  await state.submit({
    reviewItems: [],
    candidateGeneration: 0,
    limitations: ["No material calls in the selected scope."],
  });
  const abort = mock(state.abort);
  state.abort = abort;
  const flushing = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const denied = Promise.withResolvers<NativeRequest>();
  const graph = {
    tools: [],
    call: async () => ({}),
    flush: async () => {
      flushing.resolve();
      await release.promise;
    },
    close: async () => {},
  } as unknown as DependencyGraphTools;
  const events = new PassThrough();
  const run = nativeRun(events, state, graph, (request) => {
    if (request.id === "stale-abort") denied.resolve(request);
  });
  for (const event of setup()) events.write(JSON.stringify(event) + "\n");
  await run.turnStarted;
  events.write(JSON.stringify(completed()) + "\n");
  await flushing.promise;
  events.write(
    JSON.stringify(
      call("stale-abort", "abort_codex_security_investigation", blocker),
    ) + "\n",
  );
  expect(await denied.promise).toMatchObject({ result: { success: false } });
  expect(abort).not.toHaveBeenCalled();
  release.resolve();
  events.end();
  try {
    expect(await run.result).toMatchObject({ completed: true });
  } finally {
    await state.close();
  }
});

test("package checks retain successful advisories and continue independent work after one abort", async () => {
  await using temp = await scopedTemporaryDirectory("blocked-package-");
  git(temp.path, "init", "--quiet");
  const config = await writeRuntimeConfig(temp.path);
  await writeFile(join(temp.path, "worker.ts"), "decode(input);\n");
  let invocation = 0;
  const onCodex = mock<OnCodex>(async (_args, output) => {
    const tool = output!.appServer!.dependencyReport!;
    if (++invocation === 2) {
      recordBroadLoss(tool);
      tool.abort!(blocker, "blocked-native-root");
      return 143;
    }
    const queued = await tool.queue!({ items: [gapItem] });
    if (!queued.queued) throw new Error(queued.feedback);
    expect(
      await tool.submit!({
        reviewItems: queued.items,
        candidateGeneration: 0,
        limitations: [gapItem.reason],
      }),
    ).toMatchObject({ accepted: true });
    return 0;
  });
  const deps = dependencies({ currentDirectory: temp.path, onCodex });
  deps.lookupPackageAdvisories = async () =>
    ["issue-a", "issue-b", "issue-c"].map((id) => ({ id, advisories: [] }));
  deps.reviewDependencyReport = async (prompt) => approve(prompt);
  const { runCli, stdout, stderr } = createCliTest(main);
  expect(
    await runCli(
      [
        "exploitability",
        "check",
        "npm:sample-decoder",
        "--json",
        "--config",
        config,
      ],
      deps,
    ),
    stderr.text(),
  ).toBe(2);
  const result = JSON.parse(stdout.text());
  expect(result.status).toBe("blocked");
  expect(
    result.checks.map((check: { advisoryId: string }) => check.advisoryId),
  ).toEqual(["issue-a", "issue-b", "issue-c"]);
  expect(result.checks[0].schemaVersion).toBe(2);
  expect(result.checks[1]).toMatchObject({
    status: "blocked",
    code: "INVESTIGATION_BLOCKED",
  });
  expect(result.checks[2].schemaVersion).toBe(2);
  expect(dependencyCheckOutputSchema.safeParse(result).success).toBe(false);
  expect(onCodex).toHaveBeenCalledTimes(3);
});

test("CLI schema preserves first-level scientific branches and separately exposes blocked output", async () => {
  const { runCli, stdout, stderr } = createCliTest(main);
  expect(
    await runCli(
      ["exploitability", "check", "--schema", "--json"],
      dependencies(),
    ),
    stderr.text(),
  ).toBe(0);
  const schema = JSON.parse(stdout.text());
  expect(
    schema.output.anyOf.some((branch: { required?: string[] }) =>
      branch.required?.includes("cve"),
    ),
  ).toBe(true);
  expect(
    schema.output.anyOf.some((branch: { required?: string[] }) =>
      branch.required?.includes("package"),
    ),
  ).toBe(true);
  expect(
    schema.output.anyOf.some(
      (branch: { properties?: { status?: { const?: string } } }) =>
        branch.properties?.status?.const === "blocked",
    ),
  ).toBe(true);
});

test.each(["SIGINT", "SIGTERM"] as const)(
  "%s retains priority over a concurrent blocked outcome",
  async (signal) => {
    await using temp = await scopedTemporaryDirectory("blocked-user-signal-");
    git(temp.path, "init", "--quiet");
    const config = await writeRuntimeConfig(temp.path);
    const signals = new FakeSignals();
    const deps = dependencies({
      currentDirectory: temp.path,
      signals,
      onCodex: (_args, output) => {
        recordBroadLoss(output!.appServer!.dependencyReport!);
        output!.appServer!.dependencyReport!.abort!(blocker, "native-root");
        signals.emit(signal);
        return signal === "SIGINT" ? 130 : 143;
      },
    });
    deps.lookupDependencyAdvisory = async () => advisory;
    const { runCli, stdout } = createCliTest(main);
    expect(
      await runCli(
        ["exploitability", "check", advisory.cve, "--json", "--config", config],
        deps,
      ),
    ).toBe(signal === "SIGINT" ? 130 : 143);
    expect(stdout.text()).not.toContain("INVESTIGATION_BLOCKED");
    expect(signals.listeners.get(signal)?.size ?? 0).toBe(0);
  },
);

test("ordinary nonblocked child failures preserve their existing exit code", async () => {
  await using temp = await scopedTemporaryDirectory(
    "ordinary-investigation-failure-",
  );
  git(temp.path, "init", "--quiet");
  const deps = dependencies({ currentDirectory: temp.path, onCodex: () => 47 });
  deps.lookupDependencyAdvisory = async () => advisory;
  const { runCli, stdout } = createCliTest(main);
  expect(
    await runCli(["exploitability", "check", advisory.cve, "--json"], deps),
  ).toBe(47);
  expect(stdout.text()).not.toContain("INVESTIGATION_BLOCKED");
});

test("abort settles an in-flight MCP request and does not capture a buffered late receipt", async () => {
  await using temp = await scopedTemporaryDirectory("blocked-pending-mcp-");
  const state = abortState({
    repository: temp.path,
    advisory,
    inventoryServers: { runtime: ["artifact"] },
    review: async (prompt) => approve(prompt),
  });
  const requested = Promise.withResolvers<void>();
  const events = new PassThrough();
  const callGraph = mock<DependencyGraphTools["call"]>(
    async (_tool, _args, rpc) => {
      await rpc!.call("runtime", "artifact", { artifact: "selected-image" });
      return { service_resolution: { revision: 1, pending: 0 } };
    },
  );
  const graph = {
    tools: [
      {
        name: "trace_codex_security_code",
        description: "Trace",
        inputSchema: { type: "object" },
      },
    ],
    call: callGraph,
    close: async () => {},
  } as unknown as DependencyGraphTools;
  const run = nativeRun(
    events,
    state,
    graph,
    (request) => {
      if (request.method === "mcpServer/tool/call") requested.resolve();
    },
    true,
  );
  for (const event of setup()) events.write(JSON.stringify(event) + "\n");
  await run.turnStarted;
  events.write(
    JSON.stringify(
      call(
        "source-check",
        "trace_codex_security_code",
        {},
        { namespace: "codex_security_dependency" },
      ),
    ) + "\n",
  );
  await requested.promise;
  events.write(
    JSON.stringify(
      call("root-abort", "abort_codex_security_investigation", blocker),
    ) + "\n",
  );
  events.write(
    JSON.stringify({
      method: "item/completed",
      params: {
        ...root,
        item: {
          id: "late-receipt",
          type: "mcpToolCall",
          server: "runtime",
          tool: "artifact",
          arguments: { artifact: "selected-image" },
          status: "completed",
          result: { structuredContent: { late: true } },
        },
      },
    }) + "\n",
  );
  events.end(JSON.stringify(completed()) + "\n");
  try {
    expect(await run.result).toMatchObject({
      completed: false,
      blocked: {
        status: "blocked",
        retainedEvidence: { inventoryReceiptIds: ["inventory-1"] },
      },
    });
    expect(callGraph).toHaveBeenCalledTimes(1);
    expect(
      state.readStatus({ inventoryReceipts: true }).inventoryReceipts,
    ).toHaveLength(1);
    expect(run.continuing).not.toHaveBeenCalled();
  } finally {
    await state.close();
  }
});

function observedLoss(
  state: ReturnType<typeof createDependencyReportSubmission>,
  healthy = false,
) {
  const checks = ["executor-a", "executor-b", "executor-c"].map(
    (requiredRecord) => {
      const receiptId = state.recordInventory(
        "runtime",
        {
          structuredContent: {
            record: healthy
              ? { id: requiredRecord, image: "selected-image" }
              : null,
          },
        },
        { tool: "artifact", arguments: { requiredRecord } },
      )!;
      return {
        requiredRecord,
        selection: { receiptId, textBlock: null, record: ["record"] },
        missing: true,
      };
    },
  );
  return {
    ...blocker,
    coverage: {
      basis: "observed_scope",
      scope: "The three enumerated required executor records",
      checked: checks.length,
      missing: checks.length,
      checks,
      representativeness:
        "These exact required records were enumerated before querying; they are not speculative aliases.",
    },
  };
}

test("exceptional observed loss binds distinct required checks and original missing results", async () => {
  await using temp = await scopedTemporaryDirectory("observed-data-loss-");
  const state = createDependencyReportSubmission({
    repository: temp.path,
    advisory,
    inventoryServers: { runtime: ["artifact"] },
    review: async (prompt) => approve(prompt),
  });
  try {
    expect(state.abort(observedLoss(state))).toMatchObject({
      status: "blocked",
      coverage: { checked: 3, missing: 3 },
    });
  } finally {
    await state.close();
  }
});

test.each([
  "isolated",
  "duplicate",
  "invented-count",
  "healthy-populated",
] as const)(
  "abort rejects unsupported observed coverage: %s",
  async (failure) => {
    await using temp = await scopedTemporaryDirectory("unsupported-data-loss-");
    const state = createDependencyReportSubmission({
      repository: temp.path,
      advisory,
      inventoryServers: { runtime: ["artifact"] },
      review: async (prompt) => approve(prompt),
    });
    try {
      const request = observedLoss(state, failure === "healthy-populated");
      if (failure === "isolated") {
        request.coverage.checks = request.coverage.checks.slice(0, 1);
        request.coverage.checked = 1;
        request.coverage.missing = 1;
      }
      if (failure === "duplicate")
        request.coverage.checks[1] = request.coverage.checks[0]!;
      if (failure === "invented-count") request.coverage.missing = 4;
      expect(() => state.abort(request)).toThrow();
      expect(state.blockedOutcome()).toBeUndefined();
    } finally {
      await state.close();
    }
  },
);

test("recovered data invalidates a stale broad-loss declaration", async () => {
  await using temp = await scopedTemporaryDirectory("recovered-data-");
  const state = abortState({
    repository: temp.path,
    advisory,
    review: async (prompt) => approve(prompt),
  });
  try {
    state.recordInventory(
      "runtime",
      {
        structuredContent: {
          coverage: { message: "The dataset is complete and available." },
        },
      },
      {
        tool: "artifact",
        arguments: { scope: "selected-production-executors" },
      },
    );
    expect(() => state.abort(blocker)).toThrow(/superseded/);
    expect(state.blockedOutcome()).toBeUndefined();
  } finally {
    await state.close();
  }
});

test.each([
  "undeclared",
  "wrong-tool",
  "disabled",
  "generic-no-progress",
  "invented-declaration",
] as const)(
  "abort rejects a nonqualifying tool or explanation: %s",
  async (failure) => {
    await using temp = await scopedTemporaryDirectory(
      "nonqualifying-data-loss-",
    );
    const state = abortState({
      repository: temp.path,
      advisory,
      review: async (prompt) => approve(prompt),
      ...(failure === "disabled" ? { isConfiguredTool: () => false } : {}),
    });
    try {
      const request = {
        ...blocker,
        tool: { ...blocker.tool },
        coverage: { ...blocker.coverage },
      };
      if (failure === "undeclared") request.tool.server = "another-server";
      if (failure === "wrong-tool") request.tool.name = "another-tool";
      if (failure === "generic-no-progress") request.category = "no_progress";
      if (failure === "invented-declaration")
        request.coverage.declaration = "No progress has been made.";
      expect(() => state.abort(request)).toThrow();
      expect(state.blockedOutcome()).toBeUndefined();
    } finally {
      await state.close();
    }
  },
);

test.each(["not_recorded", "unsupported_tool"])(
  "bare archived %s cannot authorize provider-data-loss abort",
  async (status) => {
    await using temp = await scopedTemporaryDirectory("archive-availability-");
    const state = createDependencyReportSubmission({
      repository: temp.path,
      advisory,
      inventoryServers: { runtime: ["artifact"] },
      review: async (prompt) => approve(prompt),
    });
    try {
      const receiptId = state.recordInventory(
        "runtime",
        {
          structuredContent: {
            status,
            message: "This request is not available in the finite capture.",
          },
        },
        { tool: "artifact", outcome: "failed" },
      )!;
      const request = {
        ...blocker,
        coverage: {
          ...blocker.coverage,
          declaration: "This request is not available in the finite capture.",
          selection: { receiptId, textBlock: null, record: ["message"] },
        },
      };
      expect(() => state.abort(request)).toThrow(/archived requests/);
      expect(state.blockedOutcome()).toBeUndefined();
    } finally {
      await state.close();
    }
  },
);

test("a provider-wide startup declaration binds its exact original metadata field", async () => {
  await using temp = await scopedTemporaryDirectory(
    "declared-startup-data-loss-",
  );
  const state = createDependencyReportSubmission({
    repository: temp.path,
    advisory,
    inventoryServers: { runtime: ["artifact"] },
    review: async (prompt) => approve(prompt),
  });
  try {
    state.recordInventoryStartup("runtime", "failed", declaration);
    expect(
      state.abort({
        ...blocker,
        coverage: {
          ...blocker.coverage,
          selection: {
            receiptId: "inventory-1",
            textBlock: null,
            record: ["error"],
          },
        },
      }),
    ).toMatchObject({ status: "blocked" });
  } finally {
    await state.close();
  }
});

test("coverage validation projects metadata without returning a retained bulk resource", async () => {
  await using temp = await scopedTemporaryDirectory("bulk-coverage-metadata-");
  const state = createDependencyReportSubmission({
    repository: temp.path,
    advisory,
    inventoryServers: { runtime: ["artifact"] },
    review: async (prompt) => approve(prompt),
  });
  const bulk = JSON.stringify({
    observations: Array.from({ length: 10000 }, () => ({
      frame: "retained-stack-frame",
      count: 1,
    })),
  });
  try {
    state.recordInventory(
      "runtime",
      {
        structuredContent: { coverage: { message: declaration } },
        contents: [{ uri: "dependency-profile://collection-1", text: bulk }],
      },
      { tool: "artifact", outcome: "unavailable" },
    );
    const outcome = state.abort(blocker);
    expect(outcome.status).toBe("blocked");
    expect(JSON.stringify(outcome)).not.toContain("retained-stack-frame");
    expect(outcome.retainedEvidence.inventoryReceiptIds).toEqual([
      "inventory-1",
    ]);
  } finally {
    await state.close();
  }
});

test.each([
  { status: "not_recorded", basis: "provider_declared" },
  { status: "unsupported_tool", basis: "provider_declared" },
  { status: "not_recorded", basis: "observed_scope" },
  { status: "unsupported_tool", basis: "observed_scope" },
])(
  "JSON-text archive %j cannot authorize provider-data-loss abort",
  async ({ status, basis }) => {
    await using temp = await scopedTemporaryDirectory(
      "text-archive-availability-",
    );
    const state = createDependencyReportSubmission({
      repository: temp.path,
      advisory,
      inventoryServers: { runtime: ["artifact"] },
      review: async (prompt) => approve(prompt),
    });
    const reason = "This request is unavailable in the finite capture.";
    try {
      const checks = ["executor-a", "executor-b"].map((requiredRecord) => {
        const receiptId = state.recordInventory(
          "runtime",
          {
            isError: true,
            content: [
              { type: "text", text: JSON.stringify({ status, reason }) },
            ],
          },
          {
            tool: "artifact",
            arguments: { requiredRecord },
            outcome: "failed",
          },
        )!;
        return {
          requiredRecord,
          selection: { receiptId, textBlock: 0, record: ["reason"] },
          missing: true,
        };
      });
      const coverage =
        basis === "provider_declared"
          ? {
              ...blocker.coverage,
              declaration: reason,
              selection: checks[0]!.selection,
            }
          : {
              basis,
              scope: "Two enumerated required records",
              checked: 2,
              missing: 2,
              checks,
              representativeness:
                "The exact required records were selected before these lookups.",
            };
      expect(() => state.abort({ ...blocker, coverage })).toThrow(
        /archived requests/,
      );
      expect(state.blockedOutcome()).toBeUndefined();
    } finally {
      await state.close();
    }
  },
);

test("a selected JSON text block cannot bypass an authoritative structured archive status", async () => {
  await using temp = await scopedTemporaryDirectory(
    "mixed-archive-availability-",
  );
  const state = createDependencyReportSubmission({
    repository: temp.path,
    advisory,
    inventoryServers: { runtime: ["artifact"] },
    review: async (prompt) => approve(prompt),
  });
  const reason = "This request is unavailable in the finite capture.";
  try {
    const receiptId = state.recordInventory(
      "runtime",
      {
        structuredContent: { status: "not_recorded", reason },
        content: [{ type: "text", text: JSON.stringify({ reason }) }],
        isError: true,
      },
      { tool: "artifact", outcome: "failed" },
    )!;
    const coverage = {
      ...blocker.coverage,
      declaration: reason,
      selection: { receiptId, textBlock: 0, record: ["reason"] },
    };
    expect(() => state.abort({ ...blocker, coverage })).toThrow(
      /archived requests/,
    );
    expect(state.blockedOutcome()).toBeUndefined();
  } finally {
    await state.close();
  }
});

test("a genuine JSON-text provider declaration remains usable", async () => {
  await using temp = await scopedTemporaryDirectory(
    "text-provider-declaration-",
  );
  const state = createDependencyReportSubmission({
    repository: temp.path,
    advisory,
    inventoryServers: { runtime: ["artifact"] },
    review: async (prompt) => approve(prompt),
  });
  try {
    const receiptId = state.recordInventory(
      "runtime",
      {
        content: [
          {
            type: "text",
            text: JSON.stringify({ coverage: { message: declaration } }),
          },
        ],
      },
      { tool: "artifact", outcome: "unavailable" },
    )!;
    const coverage = {
      ...blocker.coverage,
      selection: { receiptId, textBlock: 0, record: ["coverage", "message"] },
    };
    expect(state.abort({ ...blocker, coverage }).status).toBe("blocked");
  } finally {
    await state.close();
  }
});
