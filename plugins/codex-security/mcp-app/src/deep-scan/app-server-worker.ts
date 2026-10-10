import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { version as MCP_APP_VERSION } from "../../package.json";
import { asRecord } from "../record.js";
import type { JsonObject } from "../types.js";
import { abortError } from "./errors.js";
import { executablePathForSpawn } from "./executable-path.js";
import type { CodexWorkerRequest } from "./types.js";
import { DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID } from "./permission-profile-preflight.js";

interface WorkerThreadOptions {
  codexPath: string;
  environment: Record<string, string>;
  configOverrides: readonly string[];
  providerConfigOverrides?: readonly string[];
  privateProviders?: Record<string, unknown>;
  apiKey?: string;
  model?: string;
  cyberAccessProgram?: string;
  request: CodexWorkerRequest;
  input: string;
  onDiagnostic: (item: unknown) => void;
}

/** One owning native connection per worker, including interrupted and resumed turns. */
export async function runAppServerWorker(
  options: WorkerThreadOptions,
): Promise<{ threadId: string }> {
  const { request } = options;
  if (request.signal.aborted) throw abortError(request.signal.reason);
  const cyberAccessProgram =
    options.cyberAccessProgram === "daybreak_blue"
      ? "daybreakBlue"
      : options.cyberAccessProgram === "daybreak_red"
        ? "daybreakRed"
        : options.cyberAccessProgram;
  const args = [
    ...options.configOverrides.flatMap((value) => ["--config", value]),
    ...(options.providerConfigOverrides ?? []).flatMap((value) => [
      "--config",
      value,
    ]),
    ...(options.apiKey === undefined
      ? []
      : ["--config", 'cli_auth_credentials_store="ephemeral"']),
    "app-server",
    "--stdio",
  ];
  const child = spawn(executablePathForSpawn(options.codexPath), args, {
    cwd: request.workingDirectory,
    env: options.environment,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
  const pending = new Map<
    number,
    {
      resolve: (result: JsonObject) => void;
      reject: (error: Error) => void;
    }
  >();
  const terminal = Promise.withResolvers<JsonObject>();
  // Startup failures can arrive before the turn's terminal promise is awaited.
  void terminal.promise.catch(() => {});
  let sequence = 0;
  let threadId: string | undefined;
  let turnId: string | undefined;
  let turnRequested = false;
  let turnFinished = false;
  let ending = false;
  let failure: Error | undefined;
  let interruption: Promise<void> | undefined;
  let registration: Promise<void> | undefined;
  let lastStreamError: string | undefined;

  const endInput = () => {
    ending = true;
    if (!child.stdin.destroyed && !child.stdin.writableEnded) child.stdin.end();
  };
  const fail = (error: Error) => {
    failure ??= error;
    for (const waiter of pending.values()) waiter.reject(failure);
    pending.clear();
    terminal.reject(failure);
    endInput();
  };
  const closed = new Promise<void>((resolve) => {
    child.once("close", (code, signal) => {
      if (code !== 0 || signal) {
        fail(
          new Error(
            `Codex app-server exited with ${signal ? `signal ${signal}` : `code ${code ?? 1}`}: ${Buffer.concat(stderr).toString("utf8")}`,
          ),
        );
      } else if (!ending && !turnFinished && !request.signal.aborted) {
        fail(
          new Error(
            `Codex worker stream ended before turn.completed${lastStreamError ? `: ${lastStreamError}` : ""}`,
          ),
        );
      }
      for (const waiter of pending.values()) {
        waiter.reject(failure ?? abortError(request.signal.reason));
      }
      pending.clear();
      if (!turnFinished)
        terminal.reject(failure ?? abortError(request.signal.reason));
      resolve();
    });
  });
  child.on("error", fail);
  child.stdin.on("error", fail);
  const write = (message: JsonObject) => {
    child.stdin.write(`${JSON.stringify(message)}\n`, (error) => {
      if (error) fail(error);
    });
  };
  const rpc = (method: string, params: JsonObject): Promise<JsonObject> => {
    if (failure) return Promise.reject(failure);
    if (ending) return Promise.reject(abortError(request.signal.reason));
    const id = ++sequence;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      write({ jsonrpc: "2.0", id, method, params });
    });
  };
  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  lines.on("error", fail);
  lines.on("line", (line) => {
    if (!line.trim()) return;
    try {
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch (cause) {
        throw new Error(`Failed to parse item: ${line}`, { cause });
      }
      const message = asRecord(parsed);
      if (!message) throw new Error("Codex app-server returned invalid JSON.");
      if (typeof message.method === "string") {
        if (message.id !== undefined) {
          // Deep workers are headless and never grant interactive requests.
          write({
            jsonrpc: "2.0",
            id: message.id,
            error: {
              code: -32601,
              message:
                "Interactive requests are unavailable in a Deep Scan worker.",
            },
          });
          return;
        }
        const params = asRecord(message.params) ?? {};
        if (message.method === "warning") {
          options.onDiagnostic({ type: "error", message: params.message });
        } else if (message.method === "configWarning") {
          options.onDiagnostic({ type: "error", message: params.summary });
        } else if (message.method === "error") {
          const error = asRecord(params.error);
          if (typeof error?.message === "string") {
            lastStreamError = error.message;
            options.onDiagnostic({ type: "error", message: error.message });
          }
        } else if (threadId !== undefined && params.threadId === threadId) {
          if (message.method === "turn/started") {
            const turn = asRecord(params.turn);
            if (typeof turn?.id === "string") {
              turnId = turn.id;
              // A thread/start ID is only allocated. Native TurnStarted records
              // the accepted turn before publishing this notification.
              if (registration === undefined) {
                registration = Promise.resolve(
                  request.onThreadStarted?.(threadId),
                );
                void registration.catch(fail);
              }
            }
          } else if (message.method === "turn/completed") {
            const turn = asRecord(params.turn);
            if (!turn || typeof turn.id !== "string")
              throw new Error(
                "Codex worker returned an invalid terminal turn.",
              );
            if (turnId !== undefined && turn.id !== turnId) return;
            turnId = turn.id;
            turnFinished = true;
            terminal.resolve(turn);
          } else if (message.method === "item/completed") {
            options.onDiagnostic(workerDiagnosticItem(params.item));
          }
        }
        return;
      }
      if (failure) return;
      const waiter =
        typeof message.id === "number" ? pending.get(message.id) : undefined;
      if (!waiter)
        throw new Error("Codex app-server returned an unexpected response.");
      if (message.error !== undefined) {
        pending.delete(message.id as number);
        const error = asRecord(message.error);
        waiter.reject(
          new Error(
            typeof error?.message === "string"
              ? error.message
              : JSON.stringify(message.error),
          ),
        );
      } else {
        const result = asRecord(message.result);
        if (!result)
          throw new Error("Codex app-server returned an invalid response.");
        pending.delete(message.id as number);
        waiter.resolve(result);
      }
    } catch (error) {
      fail(error instanceof Error ? error : new Error(String(error)));
    }
  });
  const onAbort = () => {
    if (interruption || ending) return;
    if (threadId === undefined || !turnRequested) {
      endInput();
      return;
    }
    if (turnFinished) return;
    const startup = turnId === undefined;
    interruption = rpc("turn/interrupt", { threadId, turnId: turnId ?? "" })
      .then(() => {
        if (startup) endInput();
      })
      .catch((error: unknown) => {
        if (!turnFinished)
          fail(error instanceof Error ? error : new Error(String(error)));
      });
  };
  request.signal.addEventListener("abort", onAbort, { once: true });
  if (request.signal.aborted) onAbort();
  try {
    await rpc("initialize", {
      clientInfo: {
        name: "codex_security_deep_scan",
        title: "Codex Security Deep Scan",
        version: MCP_APP_VERSION,
      },
      capabilities: { experimentalApi: true },
    });
    write({ jsonrpc: "2.0", method: "initialized", params: {} });
    if (options.apiKey !== undefined) {
      await rpc("account/login/start", {
        type: "apiKey",
        apiKey: options.apiKey,
      });
    }
    if (request.signal.aborted) throw abortError(request.signal.reason);
    const thread = await rpc(
      request.resumeThreadId ? "thread/resume" : "thread/start",
      {
        ...(request.resumeThreadId
          ? { threadId: request.resumeThreadId }
          : { threadSource: "security_scan" }),
        cwd: request.workingDirectory,
        permissions: DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID,
        ...(options.model === undefined ? {} : { model: options.model }),
        ...(options.privateProviders === undefined
          ? {}
          : { config: { model_providers: options.privateProviders } }),
      },
    );
    const startedThread = asRecord(thread.thread);
    if (typeof startedThread?.id !== "string")
      throw new Error("Codex worker did not return a thread ID.");
    threadId = startedThread.id;
    if (request.signal.aborted) throw abortError(request.signal.reason);
    turnRequested = true;
    const started = await rpc("turn/start", {
      threadId,
      input: [{ type: "text", text: options.input, text_elements: [] }],
      ...(cyberAccessProgram === undefined ? {} : { cyberAccessProgram }),
    });
    const startedTurn = asRecord(started.turn);
    if (typeof startedTurn?.id !== "string")
      throw new Error("Codex worker did not return a turn ID.");
    turnId ??= startedTurn.id;
    const result = await terminal.promise;
    await interruption;
    // Native shutdown flushes the terminal rollout after the notification.
    endInput();
    await closed;
    await registration;
    if (request.signal.aborted) throw abortError(request.signal.reason);
    if (failure) throw failure;
    if (result.status !== "completed") {
      const error = asRecord(result.error);
      throw new Error(
        typeof error?.message === "string"
          ? error.message
          : (lastStreamError ?? `Codex worker turn ${String(result.status)}`),
      );
    }
    return { threadId };
  } catch (error) {
    if (request.signal.aborted) throw abortError(request.signal.reason);
    throw error;
  } finally {
    request.signal.removeEventListener("abort", onAbort);
    endInput();
    await closed;
    await registration?.catch(() => {});
    lines.close();
  }
}

function workerDiagnosticItem(value: unknown): unknown {
  const item = asRecord(value);
  if (!item) return value;
  const type =
    item.type === "commandExecution"
      ? "command_execution"
      : item.type === "fileChange"
        ? "file_change"
        : item.type === "mcpToolCall"
          ? "mcp_tool_call"
          : item.type;
  return {
    ...item,
    type,
    ...(item.aggregatedOutput === undefined
      ? {}
      : { aggregated_output: item.aggregatedOutput }),
  };
}
