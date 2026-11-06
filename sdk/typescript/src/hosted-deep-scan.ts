import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { z } from "zod";
import { DIRECT_DEEP_SCAN_CONTROL_USAGE } from "./deep-scan.js";
import { CodexSecurityError, errorMessage } from "./errors.js";
import { executablePathForSpawn, isDisconnectedChildStdin } from "./runtime.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";
import {
  ScanExecutionResultSchema,
  type DeepScanExecutionRequest,
  type ScanExecutionEvent,
  type HostedScanExecutor,
  type StandardScanExecutionRequest,
} from "./scan-executor.js";

const workerRequest = z.strictObject({
  workerId: z.string().min(1),
  kind: z.enum(["discovery", "comparison"]),
  prompt: z.string(),
  subagents: z.number().int().nonnegative(),
  resumeSessionId: z.string().min(1).optional(),
  artifactContext: z
    .strictObject({
      root: z.string(),
      layout: z.literal("worker"),
      discoveryBoard: z
        .strictObject({ root: z.string(), author: z.string() })
        .optional(),
    })
    .optional(),
  outputSchema: z.record(z.string(), z.unknown()).optional(),
});
const engineMessage = z.discriminatedUnion("method", [
  z.strictObject({
    id: z.string(),
    method: z.literal("execution.run"),
    params: workerRequest,
  }),
  z.strictObject({
    id: z.string(),
    method: z.literal("execution.release"),
    params: z.strictObject({ version: z.literal(3), sessionId: z.string() }),
  }),
  z.strictObject({
    method: z.literal("execution.cancel"),
    params: z.strictObject({ requestId: z.string() }),
  }),
  z.strictObject({
    method: z.literal("coordinator.status"),
    params: z.strictObject({
      status: z.enum(["succeeded", "failed", "canceled"]),
    }),
  }),
]);

/** Isolate the existing coordinator's environment while the host runs its workers. */
export async function* runHostedDeepScan(options: {
  context: StandardScanExecutionRequest;
  executor: HostedScanExecutor;
  signal: AbortSignal;
  onCoordinatorStarted(id: string): void;
  onEvent(event: ScanExecutionEvent): void;
  onCoordinatorStatus(status: "succeeded" | "failed" | "canceled"): void;
}): AsyncGenerator<{ type: string; [key: string]: unknown }> {
  const { context, executor, signal } = options;
  if (executor.release === undefined)
    throw new CodexSecurityError(
      "Hosted Deep scans require session release support.",
    );
  signal.throwIfAborted();
  const node = process.versions["bun"]
    ? await resolveTrustedExecutable("node", context.runtime.environment, [
        context.repository,
      ])
    : undefined;
  if (node === null)
    throw new CodexSecurityError("Node.js is not available on PATH.");
  // This identifies the coordinator's durable state, never a model execution.
  const coordinatorId = randomUUID();
  options.onCoordinatorStarted(coordinatorId);
  yield { type: "thread.started", thread_id: coordinatorId };
  const child = spawn(
    executablePathForSpawn(node?.executable ?? process.execPath),
    [
      join(context.runtime.pluginRoot, "mcp", "server.mjs"),
      "--deep-scan-engine",
    ],
    {
      env: node?.environment ?? context.runtime.environment,
      windowsHide: true,
      serialization: "json",
      stdio: ["pipe", "pipe", "pipe", "ipc"],
    },
  ) as ChildProcessWithoutNullStreams;
  const active = new Map<string, AbortController>();
  const pending = new Set<Promise<void>>();
  let stdout = "";
  let stderr = "";
  let processError: Error | undefined;
  const send = (message: object) => {
    if (child.connected) child.send(message, () => {});
  };
  const handle = async (value: unknown) => {
    const message = engineMessage.parse(value);
    if (message.method === "coordinator.status") {
      options.onCoordinatorStatus(message.params.status);
      return;
    }
    if (message.method === "execution.cancel") {
      active.get(message.params.requestId)?.abort();
      return;
    }
    if (message.method === "execution.release") {
      try {
        await executor.release!(message.params.sessionId);
        send({
          id: message.id,
          result: { status: "completed", sessionId: message.params.sessionId },
        });
      } catch (error) {
        send({ id: message.id, error: { message: errorMessage(error) } });
      }
      return;
    }
    if (signal.aborted) {
      // No host request was submitted, so cancellation is already known.
      send({
        id: message.id,
        result: { requestId: message.id, status: "canceled" },
      });
      return;
    }
    const controller = new AbortController();
    if (active.has(message.id))
      throw new Error("Deep coordinator reused an active request ID.");
    active.set(message.id, controller);
    const request: DeepScanExecutionRequest = {
      ...context,
      ...message.params,
      version: 3,
      requestId: message.id,
    };
    try {
      const result = ScanExecutionResultSchema.parse(
        await executor.run(request, {
          signal: AbortSignal.any([signal, controller.signal]),
          onEvent(event) {
            send({
              method: "execution.progress",
              params: { requestId: message.id, event },
            });
            options.onEvent(event);
          },
        }),
      );
      if (result.requestId !== request.requestId)
        throw new Error(
          "Execution response does not match the active request.",
        );
      send({ id: message.id, result });
    } catch (error) {
      // Transport failure cannot establish whether the host accepted execution.
      send({
        id: message.id,
        result: {
          requestId: message.id,
          status: "acceptance_unknown",
          message: errorMessage(error),
        },
      });
    } finally {
      active.delete(message.id);
    }
  };
  const cancel = () => child.stdin.end();
  child.on("message", (message) => {
    const task = handle(message).catch((error: unknown) => {
      processError = new Error(errorMessage(error));
      cancel();
    });
    pending.add(task);
    void task.finally(() => pending.delete(task));
  });
  child.stdout.setEncoding("utf8").on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.setEncoding("utf8").on("data", (chunk) => {
    stderr += chunk;
  });
  child.once("error", (error) => {
    processError = error;
  });
  child.stdin.on("error", (error: NodeJS.ErrnoException) => {
    if (!isDisconnectedChildStdin(error)) processError = error;
  });
  const exited = new Promise<number | null>((resolve) =>
    child.once("close", resolve),
  );
  signal.addEventListener("abort", cancel, { once: true });
  child.stdin.write(
    JSON.stringify({
      hosted: true,
      scanId: context.scanId,
      threadId: coordinatorId,
      model: context.model,
      reasoningEffort: context.reasoningEffort,
    }) + "\n",
  );
  if (signal.aborted) cancel();
  try {
    const code = await exited;
    for (const controller of active.values()) controller.abort();
    await Promise.all(pending);
    signal.throwIfAborted();
    if (processError) throw processError;
    if (code !== 0)
      throw new CodexSecurityError(
        stderr.trim() || `Deep Scan engine exited with code ${code}.`,
      );
    const completed = z
      .object({ scanId: z.string(), manifestPath: z.string() })
      .parse(JSON.parse(stdout));
    if (
      completed.scanId !== context.scanId ||
      completed.manifestPath !==
        join(context.runtime.outputDirectory, "scan-manifest.json")
    )
      throw new CodexSecurityError(
        "Deep Scan engine returned results for a different scan.",
      );
    yield {
      type: "turn.completed",
      usage: { ...DIRECT_DEEP_SCAN_CONTROL_USAGE },
    };
  } finally {
    signal.removeEventListener("abort", cancel);
    cancel();
    for (const controller of active.values()) controller.abort();
    await Promise.all(pending);
    await exited;
  }
}
