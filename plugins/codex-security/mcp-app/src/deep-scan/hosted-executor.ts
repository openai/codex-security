import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { asRecord } from "../record.js";
import { DeepScanNonRetryableError } from "./errors.js";
import type {
  CodexWorkerExecutor,
  CodexWorkerRequest,
  CodexWorkerResult,
  WorkerTelemetryOptions,
} from "./types.js";
import { workerTokenUsage } from "./usage-receipt.js";

/** The private engine channel shares no credentials with worker processes. */
export interface HostedEngineChannel {
  send(message: unknown, callback: (error: Error | null) => void): void;
  on(event: "message", listener: (message: unknown) => void): unknown;
  on(event: "disconnect", listener: () => void): unknown;
  off(event: "message", listener: (message: unknown) => void): unknown;
  off(event: "disconnect", listener: () => void): unknown;
}

interface HostedReceipt {
  status: "completed" | "failed" | "canceled" | "acceptance_unknown";
  sessionId?: string;
  turnId?: string;
  finalResponse?: string;
  usage?: unknown;
  message?: string;
}

interface PendingRequest {
  resolve: (receipt: HostedReceipt) => void;
  reject: (error: Error) => void;
  progress: Promise<void>;
  sessionId?: string;
  onThreadStarted?: WorkerTelemetryOptions["onThreadStarted"];
  onNonRetryableError?: CodexWorkerRequest["onNonRetryableError"];
}

/** Run the existing coordinator's workers through its host-owned inference bridge. */
export class HostedDeepScanExecutor implements CodexWorkerExecutor {
  private readonly pending = new Map<string, PendingRequest>();
  private readonly workers = new Map<string, string>();
  private closed = false;

  private observeSession(pending: PendingRequest, sessionId: string): void {
    if (pending.sessionId === sessionId) return;
    pending.sessionId = sessionId;
    pending.progress = pending.progress.then(async () => {
      await pending.onThreadStarted?.(sessionId);
    });
    void pending.progress.catch(() => {});
  }

  constructor(private readonly channel: HostedEngineChannel) {
    channel.on("message", this.receive);
    channel.on("disconnect", this.disconnect);
  }

  private readonly disconnect = () => {
    this.closed = true;
    for (const pending of this.pending.values()) {
      const error = new DeepScanNonRetryableError(
        "Hosted execution disconnected before its outcome was confirmed; do not resubmit.",
      );
      pending.onNonRetryableError?.(error);
      pending.reject(error);
    }
    this.pending.clear();
  };

  private readonly receive = (message: unknown) => {
    const value = asRecord(message);
    if (!value) return;
    if (value.method === "execution.progress") {
      const params = asRecord(value.params);
      const event = asRecord(params?.event);
      const pending =
        typeof params?.requestId === "string"
          ? this.pending.get(params.requestId)
          : undefined;
      if (
        pending &&
        event?.type === "session.started" &&
        typeof event.sessionId === "string"
      ) {
        this.observeSession(pending, event.sessionId);
      }
      return;
    }
    if (typeof value.id !== "string") return;
    const pending = this.pending.get(value.id);
    if (!pending) return;
    this.pending.delete(value.id);
    const result = asRecord(value.result);
    const failure = asRecord(value.error);
    // Progress is optional; a terminal receipt still owns a session that must
    // be retained for continuation or released after failure/cancellation.
    if (typeof result?.sessionId === "string") {
      this.observeSession(pending, result.sessionId);
    }
    void pending.progress.then(
      () => {
        if (failure || !result) {
          const error = new DeepScanNonRetryableError(
            typeof failure?.message === "string"
              ? failure.message
              : "Hosted execution returned no receipt.",
          );
          pending.onNonRetryableError?.(error);
          pending.reject(error);
          return;
        }
        const receipt = result as unknown as HostedReceipt;
        if (receipt.status === "acceptance_unknown") {
          const error = new DeepScanNonRetryableError(
            receipt.message ??
              "Hosted execution acceptance is unknown; do not resubmit.",
          );
          pending.onNonRetryableError?.(error);
          pending.reject(error);
        } else {
          pending.resolve(receipt);
        }
      },
      (error: Error) => pending.reject(error),
    );
  };

  private request(
    method: "execution.run" | "execution.release",
    params: Record<string, unknown>,
    signal?: AbortSignal,
    telemetry?: WorkerTelemetryOptions,
    onNonRetryableError?: CodexWorkerRequest["onNonRetryableError"],
  ): Promise<HostedReceipt> {
    if (this.closed)
      return Promise.reject(
        new DeepScanNonRetryableError("Hosted execution channel is closed."),
      );
    if (signal?.aborted)
      return Promise.reject(signal.reason ?? new Error("Deep Scan canceled."));
    const id = randomUUID();
    const abort = () => {
      try {
        this.channel.send(
          { method: "execution.cancel", params: { requestId: id } },
          (error) => {
            if (error) this.disconnect();
          },
        );
      } catch {
        this.disconnect();
      }
    };
    const response = new Promise<HostedReceipt>((resolve, reject) => {
      this.pending.set(id, {
        resolve,
        reject,
        progress: Promise.resolve(),
        onThreadStarted: telemetry?.onThreadStarted,
        onNonRetryableError,
      });
      const sent = (error: Error | null) => {
        if (!error) return;
        const pending = this.pending.get(id);
        if (!pending) return;
        this.pending.delete(id);
        const failure = new DeepScanNonRetryableError(
          "Hosted execution delivery was not confirmed.",
          { cause: error },
        );
        onNonRetryableError?.(failure);
        reject(failure);
      };
      try {
        this.channel.send({ id, method, params }, sent);
      } catch (error) {
        sent(error instanceof Error ? error : new Error(String(error)));
      }
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted) abort();
    });
    return response.finally(() => signal?.removeEventListener("abort", abort));
  }

  async run(request: CodexWorkerRequest): Promise<CodexWorkerResult> {
    const root = request.artifactContext?.root ?? request.workingDirectory;
    let workerId = this.workers.get(root);
    if (!workerId) {
      workerId = randomUUID();
      this.workers.set(root, workerId);
    }
    const receipt = await this.request(
      "execution.run",
      {
        workerId,
        kind: "discovery",
        prompt:
          request.continuationPrompt ??
          (await readFile(request.promptPath, "utf8")),
        subagents: request.subagents,
        ...(request.resumeThreadId && {
          resumeSessionId: request.resumeThreadId,
        }),
        ...(request.artifactContext && {
          artifactContext: request.artifactContext,
        }),
      },
      request.signal,
      request,
      request.onNonRetryableError,
    );
    const usage = workerTokenUsage(receipt.usage);
    await request.onUsage?.(usage, receipt.turnId);
    if (receipt.status !== "completed")
      throw new Error(receipt.message ?? `Hosted worker ${receipt.status}.`);
    return { threadId: receipt.sessionId, turnId: receipt.turnId, usage };
  }

  async compareFindings(
    prompt: string,
    _workingDirectory: string,
    signal: AbortSignal,
    schema: Record<string, unknown>,
    telemetry?: WorkerTelemetryOptions,
  ): Promise<string> {
    let sessionId: string | undefined;
    try {
      const receipt = await this.request(
        "execution.run",
        {
          workerId: randomUUID(),
          kind: "comparison",
          prompt,
          subagents: 0,
          outputSchema: schema,
        },
        signal,
        {
          ...telemetry,
          onThreadStarted: async (value) => {
            sessionId = value;
            await telemetry?.onThreadStarted?.(value);
          },
        },
      );
      sessionId = receipt.sessionId ?? sessionId;
      await telemetry?.onUsage?.(
        workerTokenUsage(receipt.usage),
        receipt.turnId,
      );
      if (receipt.status !== "completed") {
        throw new Error(
          receipt.message ?? `Hosted comparison ${receipt.status}.`,
        );
      }
      if (typeof receipt.finalResponse !== "string") {
        throw new Error(
          receipt.message ??
            "Hosted comparison did not return a structured response.",
        );
      }
      return receipt.finalResponse;
    } finally {
      if (sessionId) await this.releaseSession(sessionId);
    }
  }

  async releaseSession(sessionId: string): Promise<void> {
    const receipt = await this.request("execution.release", {
      version: 3,
      sessionId,
    });
    if (receipt.status !== "completed" || receipt.sessionId !== sessionId) {
      throw new DeepScanNonRetryableError(
        "Hosted session cleanup was not confirmed.",
      );
    }
  }

  close(): void {
    this.channel.off("message", this.receive);
    this.channel.off("disconnect", this.disconnect);
    this.disconnect();
  }
}
