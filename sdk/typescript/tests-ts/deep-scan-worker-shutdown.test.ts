import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { brotliDecompressSync } from "node:zlib";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

type WorkerEvent =
  | { type: "thread.started"; thread_id: string }
  | { type: "item.completed"; item: { type: "agent_message"; text: string } }
  | { type: "turn.completed" }
  | { type: "turn.failed"; error: { message: string } };

type WorkerExecutorConstructor = new (settings: {
  parentSandbox: { filesystem: "workspace-write"; network: "restricted" };
}) => {
  run(request: {
    kind: "discovery";
    promptPath: string;
    workingDirectory: string;
    subagents: number;
    signal: AbortSignal;
    onThreadStarted?: () => void;
  }): Promise<{ finalResponse: string; threadId?: string }>;
};

async function bundledWorkerExecutor(
  events: (signal: AbortSignal) => AsyncGenerator<WorkerEvent>,
): Promise<WorkerExecutorConstructor> {
  const chunks = await Promise.all(
    ["000", "001"].map((part) =>
      readFile(join(PLUGIN_ROOT, "mcp", `server.mjs.br.part-${part}`)),
    ),
  );
  const runtime = brotliDecompressSync(Buffer.concat(chunks)).toString("utf8");
  const source = /var CodexSdkWorkerExecutor = class \{[\s\S]*?\n\};/u.exec(
    runtime,
  )?.[0];
  if (source === undefined) {
    throw new Error("Bundled Deep Scan worker executor was not found.");
  }

  class FakeCodex {
    startThread() {
      return {
        id: "fixture-worker-thread",
        async runStreamed(_input: string, options: { signal: AbortSignal }) {
          return { events: events(options.signal) };
        },
      };
    }
  }

  return new Function(
    "Codex",
    "import_node_fs11",
    "assertVerifiedParentSandbox",
    "resolveCodexPath",
    "workerSubagentConfig",
    "appendSafeItemDiagnostic",
    "classifyCodexWorkerError",
    `${source}\nreturn CodexSdkWorkerExecutor;`,
  )(
    FakeCodex,
    { promises: { readFile: async () => "fixture worker prompt" } },
    () => {},
    () => "/fixture/codex",
    () => ({}),
    () => {},
    (error: unknown) => error,
  ) as WorkerExecutorConstructor;
}

function runWorker(
  WorkerExecutor: WorkerExecutorConstructor,
  signal: AbortSignal,
  onThreadStarted?: () => void,
) {
  return new WorkerExecutor({
    parentSandbox: { filesystem: "workspace-write", network: "restricted" },
  }).run({
    kind: "discovery",
    promptPath: "/fixture/prompt.md",
    workingDirectory: "/fixture/artifacts",
    subagents: 0,
    signal,
    ...(onThreadStarted ? { onThreadStarted } : {}),
  });
}

test("settles completed bundled Deep Scan workers during coordinator cancellation", async () => {
  const parentController = new AbortController();
  let workerSignal: AbortSignal | undefined;
  let iteratorClosed = false;
  const WorkerExecutor = await bundledWorkerExecutor(async function* (
    signal: AbortSignal,
  ) {
    workerSignal = signal;
    try {
      yield { type: "thread.started", thread_id: "fixture-worker-thread" };
      yield {
        type: "item.completed",
        item: { type: "agent_message", text: "worker completed" },
      };
      yield { type: "turn.completed" };
      await new Promise<void>(() => {});
    } finally {
      iteratorClosed = true;
      parentController.abort(
        "coordinator canceled its remaining workers during cleanup",
      );
    }
  });
  const timeout = setTimeout(() => {
    parentController.abort("completed bundled worker remained pending");
  }, 1_000);

  try {
    const result = await runWorker(WorkerExecutor, parentController.signal);

    expect(result).toEqual({
      finalResponse: "worker completed",
      threadId: "fixture-worker-thread",
    });
    expect(iteratorClosed).toBe(true);
    expect(parentController.signal.aborted).toBe(true);
    expect(workerSignal).not.toBe(parentController.signal);
    expect(workerSignal?.aborted).toBe(false);
  } finally {
    clearTimeout(timeout);
  }
});

test("forwards coordinator cancellation to active bundled Deep Scan workers", async () => {
  const parentController = new AbortController();
  const cancellation = new Error("coordinator canceled an active worker");
  let workerSignal: AbortSignal | undefined;
  let iteratorClosed = false;
  const WorkerExecutor = await bundledWorkerExecutor(async function* (
    signal: AbortSignal,
  ) {
    workerSignal = signal;
    try {
      yield { type: "thread.started", thread_id: "fixture-worker-thread" };
      signal.throwIfAborted();
      yield { type: "turn.completed" };
    } finally {
      iteratorClosed = true;
    }
  });

  await expect(
    runWorker(WorkerExecutor, parentController.signal, () => {
      parentController.abort(cancellation);
    }),
  ).rejects.toThrow(cancellation.message);
  expect(iteratorClosed).toBe(true);
  expect(workerSignal).not.toBe(parentController.signal);
  expect(workerSignal?.aborted).toBe(true);
  expect(workerSignal?.reason).toBe(cancellation);
});

test("preserves cancellation when a bundled Deep Scan worker starts aborted", async () => {
  const cancellation = new Error("coordinator canceled before worker startup");
  const parentController = new AbortController();
  parentController.abort(cancellation);
  let workerSignal: AbortSignal | undefined;
  const WorkerExecutor = await bundledWorkerExecutor(async function* (
    signal: AbortSignal,
  ) {
    workerSignal = signal;
    signal.throwIfAborted();
    yield { type: "turn.completed" };
  });

  await expect(
    runWorker(WorkerExecutor, parentController.signal),
  ).rejects.toThrow(cancellation.message);
  expect(workerSignal).not.toBe(parentController.signal);
  expect(workerSignal?.aborted).toBe(true);
  expect(workerSignal?.reason).toBe(cancellation);
});

test("detaches bundled Deep Scan worker cancellation after terminal failure", async () => {
  const parentController = new AbortController();
  let workerSignal: AbortSignal | undefined;
  let iteratorClosed = false;
  const WorkerExecutor = await bundledWorkerExecutor(async function* (
    signal: AbortSignal,
  ) {
    workerSignal = signal;
    try {
      yield {
        type: "turn.failed",
        error: { message: "fixture worker failed" },
      };
    } finally {
      iteratorClosed = true;
    }
  });

  await expect(
    runWorker(WorkerExecutor, parentController.signal),
  ).rejects.toThrow("fixture worker failed");
  expect(iteratorClosed).toBe(true);
  parentController.abort("coordinator canceled after terminal failure");
  expect(workerSignal?.aborted).toBe(false);
});
