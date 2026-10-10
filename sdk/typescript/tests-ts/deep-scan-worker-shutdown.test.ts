import { expect, test } from "bun:test";
import {
  spawn,
  type ChildProcess,
  type SpawnOptions,
} from "node:child_process";
import { createInterface } from "node:readline";
import { getEventListeners } from "node:events";
import { loadBundledRuntime } from "./plugin-root.js";
import { nodeCommand } from "./support/shell.js";
import { profileConfigOverrides } from "../../../plugins/codex-security/scripts/codex_profile.mjs";

type WorkerExecutorConstructor = new (settings: {
  parentSandbox: { filesystemDenies: string[] };
}) => {
  run(request: {
    kind: "discovery";
    promptPath: string;
    workingDirectory: string;
    subagents: number;
    signal: AbortSignal;
    onThreadStarted?: (threadId: string) => void;
  }): Promise<{ threadId?: string }>;
};

// This peer controls only the child protocol and exit. The extracted bundle
// owns RPC parsing, interruption, terminal handling, EOF, and cleanup.
const peer = `
const { createInterface } = require("node:readline");
const mode = process.env.SYNTHETIC_WORKER_MODE;
const holdClose = process.env.SYNTHETIC_WORKER_HOLD_CLOSE === "true";
const send = (message) => process.stdout.write(JSON.stringify(message) + "\\n");
const observe = (event) => process.send(event);
const terminal = (status) => send({ method: "turn/completed", params: {
  threadId: "fixture-worker-thread", turn: {
    id: "fixture-turn", status,
    ...(status === "failed" ? { error: { message: "fixture worker failed" } } : {}),
  },
} });
const finish = () => {
  if (mode === "shutdown-failure") {
    process.stderr.write("Synthetic worker shutdown failure", () => process.exit(7));
  } else {
    process.disconnect();
  }
};
process.on("message", (message) => {
  if (message === "release") finish();
});
createInterface({ input: process.stdin }).on("line", (line) => {
  const message = JSON.parse(line);
  observe({ event: "request", method: message.method, params: message.params });
  const reply = (result) => send({ id: message.id, result });
  if (message.method === "initialize") reply({});
  else if (message.method === "thread/start") reply({ thread: { id: "fixture-worker-thread" } });
  else if (message.method === "turn/start") {
    reply({ turn: { id: "fixture-turn" } });
    send({ method: "turn/started", params: {
      threadId: "fixture-worker-thread", turn: { id: "fixture-turn" },
    } });
    if (mode === "missing-terminal") process.stdout.write("", () => process.exit(0));
    else if (mode !== "active") terminal(mode === "failed" ? "failed" : "completed");
  } else if (message.method === "turn/interrupt") {
    reply({});
    terminal("interrupted");
  }
}).on("close", () => {
  observe({ event: "eof" });
  if (!holdClose) finish();
});
`;

async function bundledWorkerExecutor(
  options: {
    mode?:
      | "completed"
      | "active"
      | "failed"
      | "shutdown-failure"
      | "missing-terminal";
    holdClose?: boolean;
    drainSessionRecords?: boolean;
    preflight?: () => Promise<{ useOpenAiApiKey: boolean }>;
  } = {},
) {
  const runtime = await loadBundledRuntime();
  const node = nodeCommand().command;
  const extract = (pattern: RegExp) => {
    const source = pattern.exec(runtime)?.[0];
    if (source === undefined)
      throw new Error(
        `Bundled worker implementation was not found: ${pattern}`,
      );
    return source;
  };
  const source = extract(/var CodexSdkWorkerExecutor = class \{[\s\S]*?\n\};/u);
  const transport = extract(/async function runAppServerWorker\([\s\S]*?\n\}/u);
  const diagnostic = extract(/function workerDiagnosticItem\([\s\S]*?\n\}/u);
  const abort = extract(/function abortError\([\s\S]*?\n\}/u);
  const record = extract(/function asRecord\([\s\S]*?\n\}/u);
  const fileSystemImport = /\b(import_node_fs\d*)\.promises\.readFile\(/u.exec(
    source,
  )?.[1];
  const childProcessImport = /\b(import_node_child_process\d*)\.spawn\b/u.exec(
    transport,
  )?.[1];
  const readlineImport = /\b(import_node_readline\d*)\.createInterface\b/u.exec(
    transport,
  )?.[1];
  const version = /\bversion: (\w+)/u.exec(transport)?.[1];
  expect(fileSystemImport).toBeDefined();
  expect(childProcessImport).toBeDefined();
  expect(readlineImport).toBeDefined();
  expect(version).toBeDefined();
  const requests: Array<{ method: string; params: Record<string, unknown> }> =
    [];
  const eof = Promise.withResolvers<void>();
  let child: ChildProcess | undefined;
  let closed: Promise<void> | undefined;
  let spawnCount = 0;
  const WorkerExecutor = new Function(
    fileSystemImport!,
    childProcessImport!,
    readlineImport!,
    version!,
    "workerPermissionProfile",
    "profileConfigOverrides",
    "DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID",
    "snapshotWorkerEnvironment",
    "workerRuntimeSettings",
    "environmentVariable",
    "preflightDeepScanWorkerPermissionProfile",
    "deepScanPermissionProfileFallbackError",
    "resolveCodexPath",
    "executablePathForSpawn",
    "workerSubagentConfig",
    "appendItemDiagnostic",
    "classifyCodexWorkerError",
    "isRecord",
    `${record}\n${abort}\n${diagnostic}\n${transport}\n${source}\nreturn CodexSdkWorkerExecutor;`,
  )(
    { promises: { readFile: async () => "fixture worker prompt" } },
    {
      spawn(file: string, args: string[], spawnOptions: SpawnOptions) {
        spawnCount++;
        expect(file).toBe(node);
        expect(args.slice(-2)).toEqual(["app-server", "--stdio"]);
        expect(spawnOptions?.stdio).toEqual(["pipe", "pipe", "pipe"]);
        child = spawn(node, ["-e", peer], {
          ...spawnOptions,
          stdio: ["pipe", "pipe", "pipe", "ipc"],
        });
        closed = new Promise<void>((resolve) =>
          child!.once("close", () => resolve()),
        );
        child.on("message", (message) => {
          const event = message as {
            event: string;
            method: string;
            params: Record<string, unknown>;
          };
          if (event.event === "eof") eof.resolve();
          else requests.push({ method: event.method, params: event.params });
        });
        return child;
      },
    },
    { createInterface },
    "fixture-version",
    () => ({}),
    profileConfigOverrides,
    "codex_security_deep_scan_worker",
    async () => ({
      ...process.env,
      SYNTHETIC_WORKER_MODE: options.mode ?? "completed",
      SYNTHETIC_WORKER_HOLD_CLOSE: String(options.holdClose ?? false),
    }),
    async () => ({
      config: {},
      drainSessionRecords: options.drainSessionRecords ?? false,
    }),
    () => undefined,
    options.preflight ?? (async () => ({ useOpenAiApiKey: false })),
    () => undefined,
    () => node,
    (path: string) => path,
    () => ({}),
    () => {},
    (error: unknown) => error,
    (value: unknown) =>
      typeof value === "object" && value !== null && !Array.isArray(value),
  ) as WorkerExecutorConstructor;
  return {
    requests,
    eof: eof.promise,
    get spawnCount() {
      return spawnCount;
    },
    release() {
      child?.send("release");
    },
    async cleanup() {
      if (child?.connected) child.send("release");
      await closed;
    },
    run(signal: AbortSignal, onThreadStarted?: (threadId: string) => void) {
      return new WorkerExecutor({
        parentSandbox: { filesystemDenies: [] },
      }).run({
        kind: "discovery",
        promptPath: "/fixture/prompt.md",
        workingDirectory: process.cwd(),
        subagents: 0,
        signal,
        ...(onThreadStarted ? { onThreadStarted } : {}),
      });
    },
  };
}

test("does not start a bundled worker when its permission profile check fails", async () => {
  const fixture = await bundledWorkerExecutor({
    preflight: async () => {
      throw new Error("worker permission profile rejected");
    },
  });
  await expect(fixture.run(new AbortController().signal)).rejects.toThrow(
    "worker permission profile rejected",
  );
  expect(fixture.spawnCount).toBe(0);
});

test("settles completed bundled Deep Scan workers after terminal and EOF", async () => {
  const controller = new AbortController();
  const fixture = await bundledWorkerExecutor();
  try {
    expect(await fixture.run(controller.signal)).toEqual({
      threadId: "fixture-worker-thread",
    });
    await fixture.eof;
    expect(getEventListeners(controller.signal, "abort")).toEqual([]);
    controller.abort("coordinator canceled after cleanup");
    expect(
      fixture.requests.some(({ method }) => method === "turn/interrupt"),
    ).toBe(false);
    expect(
      fixture.requests.find(({ method }) => method === "thread/start")?.params,
    ).toMatchObject({
      threadSource: "security_scan",
      permissions: "codex_security_deep_scan_worker",
    });
  } finally {
    await fixture.cleanup();
  }
});

test.each([false, true])(
  "drains completed bundled Deep Scan workers during coordinator cancellation (drain=%p)",
  async (drainSessionRecords) => {
    const controller = new AbortController();
    const cancellation = new Error(
      "coordinator canceled its remaining workers during cleanup",
    );
    const fixture = await bundledWorkerExecutor({
      holdClose: true,
      drainSessionRecords,
    });
    let settled = false;
    const outcome = fixture.run(controller.signal).finally(() => {
      settled = true;
    });
    const observed = outcome.then(
      (result) => ({ result }),
      (error: unknown) => ({ error }),
    );
    try {
      await fixture.eof;
      expect(settled).toBe(false);
      controller.abort(cancellation);
      expect(settled).toBe(false);
      fixture.release();
      expect(await observed).toMatchObject({
        error: { name: "AbortError", cause: cancellation },
      });
      expect(
        fixture.requests.some(({ method }) => method === "turn/interrupt"),
      ).toBe(false);
    } finally {
      await fixture.cleanup();
      await outcome.catch(() => {});
    }
  },
);

test("propagates bundled Deep Scan worker shutdown failures", async () => {
  const fixture = await bundledWorkerExecutor({ mode: "shutdown-failure" });
  try {
    await expect(fixture.run(new AbortController().signal)).rejects.toThrow(
      "Synthetic worker shutdown failure",
    );
    await fixture.eof;
  } finally {
    await fixture.cleanup();
  }
});

test("forwards coordinator cancellation to active bundled Deep Scan workers", async () => {
  const controller = new AbortController();
  const cancellation = new Error("coordinator canceled an active worker");
  const fixture = await bundledWorkerExecutor({
    mode: "active",
    holdClose: true,
  });
  let settled = false;
  const outcome = fixture
    .run(controller.signal, (threadId) => {
      expect(threadId).toBe("fixture-worker-thread");
      controller.abort(cancellation);
    })
    .finally(() => {
      settled = true;
    });
  const observed = outcome.then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );
  try {
    await fixture.eof;
    expect(settled).toBe(false);
    expect(
      fixture.requests.filter(({ method }) => method === "turn/interrupt"),
    ).toEqual([
      {
        method: "turn/interrupt",
        params: { threadId: "fixture-worker-thread", turnId: "fixture-turn" },
      },
    ]);
    fixture.release();
    expect(await observed).toMatchObject({
      error: { name: "AbortError", cause: cancellation },
    });
  } finally {
    await fixture.cleanup();
    await outcome.catch(() => {});
  }
});

test("preserves cancellation when a bundled Deep Scan worker starts aborted", async () => {
  const cancellation = new Error("coordinator canceled before worker startup");
  const controller = new AbortController();
  controller.abort(cancellation);
  const fixture = await bundledWorkerExecutor();
  await expect(fixture.run(controller.signal)).rejects.toMatchObject({
    name: "AbortError",
    cause: cancellation,
  });
  expect(fixture.spawnCount).toBe(0);
});

test("detaches bundled Deep Scan worker cancellation after terminal failure", async () => {
  const controller = new AbortController();
  const fixture = await bundledWorkerExecutor({ mode: "failed" });
  try {
    await expect(fixture.run(controller.signal)).rejects.toThrow(
      "fixture worker failed",
    );
    await fixture.eof;
    expect(getEventListeners(controller.signal, "abort")).toEqual([]);
    controller.abort("coordinator canceled after terminal failure");
    expect(
      fixture.requests.some(({ method }) => method === "turn/interrupt"),
    ).toBe(false);
  } finally {
    await fixture.cleanup();
  }
});

test("rejects bundled worker EOF without a terminal turn", async () => {
  const fixture = await bundledWorkerExecutor({ mode: "missing-terminal" });
  try {
    await expect(fixture.run(new AbortController().signal)).rejects.toThrow(
      "Codex worker stream ended before turn.completed",
    );
  } finally {
    await fixture.cleanup();
  }
});
