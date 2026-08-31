import { expect, test } from "bun:test";
import { loadBundledRuntime } from "./plugin-root.js";

type WorkerEvent =
  | { type: "thread.started"; thread_id: string }
  | { type: "item.completed"; item: { type: "agent_message"; text: string } }
  | { type: "turn.completed" }
  | { type: "turn.failed"; error: { message: string } };

type WorkerExecutorConstructor = new (settings: {
  parentSandbox: { filesystemDenies: string[] };
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
  preflight = async () => {},
): Promise<WorkerExecutorConstructor> {
  const runtime = await loadBundledRuntime();
  const source = /var CodexSdkWorkerExecutor = class \{[\s\S]*?\n\};/u.exec(
    runtime,
  )?.[0];
  if (source === undefined) {
    throw new Error("Bundled Deep Scan worker executor was not found.");
  }
  const fileSystemImport = /\b(import_node_fs\d*)\.promises\.readFile\(/u.exec(
    source,
  )?.[1];
  expect(fileSystemImport).toBeDefined();

  class FakeCodex {
    startThread(options: { threadSource: string }) {
      expect(options.threadSource).toBe("security_scan");
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
    fileSystemImport!,
    "workerPermissionProfile",
    "workerPermissionProfileConfigOverrides",
    "snapshotWorkerEnvironment",
    "preflightDeepScanWorkerPermissionProfile",
    "DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID",
    "deepScanPermissionProfileFallbackError",
    "resolveCodexPath",
    "executablePathForSpawn",
    "workerSubagentConfig",
    "appendSafeItemDiagnostic",
    "classifyCodexWorkerError",
    `${source}\nreturn CodexSdkWorkerExecutor;`,
  )(
    FakeCodex,
    { promises: { readFile: async () => "fixture worker prompt" } },
    () => ({}),
    () => [],
    async () => ({}),
    preflight,
    "codex_security_deep_scan_worker",
    () => undefined,
    () => "/fixture/codex",
    (path: string) => path,
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
    parentSandbox: { filesystemDenies: [] },
  }).run({
    kind: "discovery",
    promptPath: "/fixture/prompt.md",
    workingDirectory: "/fixture/artifacts",
    subagents: 0,
    signal,
    ...(onThreadStarted ? { onThreadStarted } : {}),
  });
}

test("does not start a bundled worker when its permission profile check fails", async () => {
  let started = false;
  const WorkerExecutor = await bundledWorkerExecutor(
    async function* () {
      started = true;
      yield { type: "turn.completed" };
    },
    async () => {
      throw new Error("worker permission profile rejected");
    },
  );
  await expect(
    runWorker(WorkerExecutor, new AbortController().signal),
  ).rejects.toThrow("worker permission profile rejected");
  expect(started).toBe(false);
});

test("drains completed bundled Deep Scan workers during coordinator cancellation", async () => {
  const parentController = new AbortController();
  const draining = Promise.withResolvers<void>();
  const releaseDrain = Promise.withResolvers<void>();
  let workerSignal: AbortSignal | undefined;
  let iteratorClosed = false;
  let settled = false;
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
      draining.resolve();
      await releaseDrain.promise;
    } finally {
      iteratorClosed = true;
    }
  });
  const outcome = runWorker(WorkerExecutor, parentController.signal).finally(
    () => {
      settled = true;
    },
  );

  try {
    await Promise.race([
      draining.promise,
      outcome.then(() => {
        throw new Error("Worker settled before its SDK stream drained.");
      }),
    ]);
    expect(settled).toBe(false);
    expect(iteratorClosed).toBe(false);
    parentController.abort(
      "coordinator canceled its remaining workers during cleanup",
    );
    expect(workerSignal).not.toBe(parentController.signal);
    expect(workerSignal?.aborted).toBe(false);
    releaseDrain.resolve();
    expect(await outcome).toEqual({
      finalResponse: "worker completed",
      threadId: "fixture-worker-thread",
    });
    expect(iteratorClosed).toBe(true);
    expect(parentController.signal.aborted).toBe(true);
  } finally {
    releaseDrain.resolve();
    await outcome.catch(() => {});
  }
});

test("propagates bundled Deep Scan worker shutdown failures", async () => {
  const WorkerExecutor = await bundledWorkerExecutor(async function* () {
    yield { type: "turn.completed" };
    throw new Error("Synthetic worker shutdown failure");
  });

  await expect(
    runWorker(WorkerExecutor, new AbortController().signal),
  ).rejects.toThrow("Synthetic worker shutdown failure");
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
