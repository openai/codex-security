import { randomUUID } from "node:crypto";
import type { ScanSessionEvent, ScanUsageMeasurement } from "./cost.js";
import type { ScanArtifactRestorer } from "./runtime.js";
import { isRecord } from "./record.js";
import {
  analyzeToolReadCoverage,
  type ObservableToolRead,
} from "./tool-read-coverage.js";

interface ScanDiagnosticsOptions {
  scanId: string;
  repository: string;
  /** Initial working directory of the root Codex process, when known. */
  scanDirectory?: string;
  scopePaths?: readonly string[];
  mode: string;
  model: string;
  reasoningEffort?: string;
  pluginVersion: string;
  authentication?: {
    method: string;
    credentialType?: string;
    verified?: boolean;
  };
  maxTimeMinutes?: number;
  maxCostUsd?: number;
  scopeFileCount?: number;
  deepScan?: {
    workers?: number;
    subagents?: number;
    stopAfterNoNew?: number;
    stopAfterConsecutiveErrors?: number;
    maxDiscoveryRuns?: number;
    maxTimeHours?: number;
  };
}

export interface ScanDiagnosticOutcome {
  status: "completed" | "failed" | "canceled";
  turnStatus: "completed" | "failed" | "interrupted" | null;
  stopReason:
    | "cost_limit"
    | "caller_abort"
    | "turn_failed"
    | "completed"
    | "error"
    | "unknown";
  error?: string;
  maxCostUsd?: number;
  measurement?: ScanUsageMeasurement;
  modelReportedCoverage?: {
    filesCompleted?: number;
    filesTotal?: number;
  };
}

type RecordValue = Record<string, unknown>;
const USAGE_FIELDS = [
  "input_tokens",
  "cached_input_tokens",
  "cache_write_input_tokens",
  "output_tokens",
  "reasoning_output_tokens",
  "total_tokens",
] as const;

/** Retains observable evidence for one scan attempt, without changing execution. */
export class ScanDiagnostics {
  readonly attemptId = randomUUID();
  readonly #startedAt = new Date().toISOString();
  readonly #events: RecordValue[] = [];
  readonly #reads: ObservableToolRead[] = [];
  readonly #calls = new Map<
    string,
    { name: string; input: unknown; cwd?: string }
  >();
  readonly #threads = new Set<string>();
  readonly #responses = new Set<string>();
  readonly #traces = new Set<string>();
  readonly #workingDirectories = new Map<string, string>();
  readonly #options: ScanDiagnosticsOptions;
  #sdkThreadId: string | undefined;
  #rootThreadId: string | undefined;

  constructor(options: ScanDiagnosticsOptions) {
    this.#options = options;
  }

  recordSdk(event: RecordValue, threadId?: string): void {
    if (
      event["type"] === "thread.started" &&
      typeof event["thread_id"] === "string"
    ) {
      this.#sdkThreadId = event["thread_id"];
    }
    threadId ??= this.#sdkThreadId;
    if (threadId !== undefined) {
      this.#rootThreadId ??= threadId;
      if (
        threadId === this.#rootThreadId &&
        !this.#workingDirectories.has(threadId) &&
        this.#options.scanDirectory !== undefined
      ) {
        this.#workingDirectories.set(threadId, this.#options.scanDirectory);
      }
    }
    const type = event["type"];
    if (typeof type !== "string") return;
    let payload: RecordValue;
    if (
      type === "item.started" ||
      type === "item.updated" ||
      type === "item.completed"
    ) {
      if (!isRecord(event["item"])) return;
      const item = observableItem(event["item"], false);
      if (item === null) return;
      payload = { type, item };
      if (type === "item.completed") this.#capturedTool(item, threadId);
    } else if (type === "turn.completed") {
      payload = { type, usage: numericFields(event["usage"], USAGE_FIELDS) };
    } else if (type === "turn.failed" || type === "error") {
      payload = {
        type,
        ...scalars(event, ["message"]),
        error: errorMetadata(event["error"]),
      };
    } else if (type === "thread.started" || type === "turn.started") {
      payload = { type };
    } else return;
    this.#append("sdk", payload, threadId);
  }

  recordSession(observation: ScanSessionEvent): void {
    const { event, threadId, parentThreadId, worker } = observation;
    const payload = event["payload"];
    if (!isRecord(payload)) return;
    const envelope = {
      ...scalars(event, ["timestamp"]),
      parentThreadId,
      ...(worker === undefined ? {} : { worker }),
    };
    if (event["type"] === "session_meta" || event["type"] === "turn_context") {
      if (typeof payload["cwd"] === "string")
        this.#workingDirectories.set(threadId, payload["cwd"]);
      this.#append(
        "session",
        {
          ...envelope,
          type: event["type"],
          ...scalars(payload, [
            "id",
            "session_id",
            "turn_id",
            "cwd",
            "cli_version",
            "model_provider",
          ]),
        },
        threadId,
      );
      return;
    }
    if (event["type"] === "token_usage_record") {
      if (typeof payload["response_id"] === "string")
        this.#responses.add(payload["response_id"]);
      this.#append(
        "session",
        {
          ...envelope,
          type: "token_usage_record",
          ...scalars(payload, [
            "session_id",
            "thread_id",
            "turn_id",
            "root_turn_id",
            "response_id",
          ]),
          usage: numericFields(payload["usage"], USAGE_FIELDS),
          turn_token_usage: numericFields(
            payload["turn_token_usage"],
            USAGE_FIELDS,
          ),
          thread_token_usage: numericFields(
            payload["thread_token_usage"],
            USAGE_FIELDS,
          ),
        },
        threadId,
      );
      return;
    }
    if (event["type"] === "response_item") {
      const type = payload["type"];
      const callId = payload["call_id"];
      if (
        type === "local_shell_call" &&
        typeof callId === "string" &&
        isRecord(payload["action"])
      ) {
        const action = payload["action"];
        const command = Array.isArray(action["command"])
          ? action["command"].filter(
              (part): part is string => typeof part === "string",
            )
          : [];
        const cwd =
          typeof action["working_directory"] === "string"
            ? action["working_directory"]
            : this.#workingDirectories.get(threadId);
        const input = {
          command,
          ...scalars(action, ["working_directory", "timeout_ms"]),
        };
        this.#calls.set(`${threadId}:${callId}`, {
          name: "local_shell",
          input,
          ...(cwd === undefined ? {} : { cwd }),
        });
        this.#append("session", { ...envelope, type, callId, input }, threadId);
      } else if (
        (type === "function_call" || type === "custom_tool_call") &&
        typeof callId === "string" &&
        typeof payload["name"] === "string"
      ) {
        const input =
          type === "function_call" ? payload["arguments"] : payload["input"];
        this.#calls.set(`${threadId}:${callId}`, {
          name: payload["name"],
          input: parseInput(input),
          cwd: this.#workingDirectories.get(threadId),
        });
        this.#append(
          "session",
          {
            ...envelope,
            type,
            callId,
            name: payload["name"],
            input,
            cwd: this.#workingDirectories.get(threadId),
          },
          threadId,
        );
      } else if (
        (type === "function_call_output" ||
          type === "custom_tool_call_output" ||
          type === "local_shell_call_output") &&
        typeof callId === "string"
      ) {
        const id = `${threadId}:${callId}`;
        const call = this.#calls.get(id);
        this.#append(
          "session",
          {
            ...envelope,
            type,
            callId,
            output: payload["output"],
            outputSource: "model_tool_response",
            paired: call !== undefined,
          },
          threadId,
        );
        if (call !== undefined)
          this.#reads.push({
            id,
            threadId,
            ...call,
            output: payload["output"],
            outputSource: "model_tool_response",
          });
      } else if (
        type === "message" &&
        payload["role"] === "assistant" &&
        payload["channel"] !== "analysis"
      ) {
        this.#append(
          "session",
          {
            ...envelope,
            type,
            ...scalars(payload, ["id", "role", "phase"]),
            content: messageText(payload["content"]),
          },
          threadId,
        );
      } else if (type === "reasoning") {
        const summary = Array.isArray(payload["summary"])
          ? payload["summary"]
              .filter(isRecord)
              .filter((part) => part["type"] === "summary_text")
              .map((part) => part["text"])
              .filter((text): text is string => typeof text === "string")
          : [];
        this.#append(
          "session",
          {
            ...envelope,
            type: "reasoning_summary",
            ...scalars(payload, ["id"]),
            summary,
          },
          threadId,
        );
      }
      return;
    }
    if (event["type"] !== "event_msg") return;
    const type = payload["type"];
    if (type === "item_completed" || type === "item_started") {
      if (!isRecord(payload["item"])) return;
      const item = observableItem(payload["item"], true);
      if (item === null) return;
      this.#append(
        "session",
        {
          ...envelope,
          type,
          item,
          ...scalars(payload, ["turn_id", "started_at_ms", "completed_at_ms"]),
        },
        threadId,
      );
      if (type === "item_completed") this.#capturedTool(item, threadId);
    } else if (
      type === "task_started" ||
      type === "task_complete" ||
      type === "turn_aborted" ||
      type === "error"
    ) {
      if (type === "task_started" && typeof payload["trace_id"] === "string")
        this.#traces.add(payload["trace_id"]);
      this.#append(
        "session",
        {
          ...envelope,
          type,
          ...scalars(payload, [
            "turn_id",
            "root_turn_id",
            "trace_id",
            "started_at",
            "completed_at",
            "duration_ms",
            "time_to_first_token_ms",
            "model_context_window",
            "collaboration_mode_kind",
            "reason",
            "message",
            "last_agent_message",
          ]),
          ...(type === "error" ? errorMetadata(payload) : {}),
          ...(type === "task_complete" && isRecord(payload["error"])
            ? { error: errorMetadata(payload["error"]) }
            : {}),
        },
        threadId,
      );
    } else if (type === "raw_response_completed") {
      if (typeof payload["response_id"] === "string")
        this.#responses.add(payload["response_id"]);
      this.#append(
        "session",
        {
          ...envelope,
          type,
          ...scalars(payload, ["response_id"]),
          token_usage: numericFields(payload["token_usage"], USAGE_FIELDS),
        },
        threadId,
      );
    } else if (type === "token_count") {
      const info = isRecord(payload["info"]) ? payload["info"] : {};
      this.#append(
        "session",
        {
          ...envelope,
          type,
          ...scalars(info, ["model_context_window"]),
          total_token_usage: numericFields(
            info["total_token_usage"],
            USAGE_FIELDS,
          ),
          last_token_usage: numericFields(
            info["last_token_usage"],
            USAGE_FIELDS,
          ),
        },
        threadId,
      );
    }
  }

  async finish(
    writer: ScanArtifactRestorer,
    outcome: ScanDiagnosticOutcome,
  ): Promise<{ eventsPath: string; summaryPath: string }> {
    const eventsPath = `scan-diagnostics-${this.attemptId}.jsonl`;
    const summaryPath = `scan-diagnostics-${this.attemptId}.json`;
    this.#append("recorder", {
      type: "attempt_finished",
      ...scalars(outcome, [
        "status",
        "turnStatus",
        "stopReason",
        "error",
        "maxCostUsd",
      ]),
    });
    // Persist evidence first so a coverage-analysis failure does not lose it.
    await writer.restore(
      eventsPath,
      Buffer.from(
        this.#events.map((event) => JSON.stringify(event)).join("\n") + "\n",
      ),
    );
    const modelToolReads = this.#reads.filter(
      (read) => read.outputSource === "model_tool_response",
    );
    const coverage = await analyzeToolReadCoverage(modelToolReads, {
      repository: this.#options.repository,
      ...(this.#options.scopePaths === undefined
        ? {}
        : { scopePaths: this.#options.scopePaths }),
    });
    const summary = {
      schemaVersion: 1,
      scanId: this.#options.scanId,
      attemptId: this.attemptId,
      startedAt: this.#startedAt,
      finishedAt: new Date().toISOString(),
      configuration: {
        ...scalars(this.#options, [
          "repository",
          "scanDirectory",
          "mode",
          "model",
          "reasoningEffort",
          "pluginVersion",
          "scopeFileCount",
        ]),
        maxTimeMinutes: this.#options.maxTimeMinutes ?? null,
        maxCostUsd: this.#options.maxCostUsd ?? null,
        timeLimitEnforced: this.#options.mode === "deep",
        scopePaths: this.#options.scopePaths,
        authentication: scalars(this.#options.authentication, [
          "method",
          "credentialType",
          "verified",
        ]),
        ...(this.#options.deepScan === undefined
          ? {}
          : {
              deepScan: numericFields(this.#options.deepScan, [
                "workers",
                "subagents",
                "stopAfterNoNew",
                "stopAfterConsecutiveErrors",
                "maxDiscoveryRuns",
                "maxTimeHours",
              ]),
            }),
      },
      termination: scalars(outcome, [
        "status",
        "turnStatus",
        "stopReason",
        "error",
        "maxCostUsd",
      ]),
      measurement: measurement(outcome.measurement),
      modelReportedCoverage:
        outcome.modelReportedCoverage === undefined
          ? undefined
          : {
              ...numericFields(outcome.modelReportedCoverage, [
                "filesCompleted",
                "filesTotal",
              ]),
              basis:
                "Model-reported progress, separate from observable source delivery.",
            },
      threadIds: [...this.#threads],
      responseIds: [...this.#responses],
      traceIds: [...this.#traces],
      requestIds: [],
      requestIdsUnavailableReason:
        "The observed SDK and session records do not expose upstream request IDs. Response, trace, and item IDs are separate identifiers.",
      modelExecutionCapture: {
        requestedByDiagnostics: false,
        serverStatus: "unverified",
        reason:
          "Local diagnostics do not request server-side model capture. Capture requires an authorized route and verification at the receiving service.",
      },
      viewers: {
        links: [],
        unavailableReason:
          "The observed runtime records do not provide diagnostic viewer links.",
      },
      evidence: {
        eventsPath,
        eventCount: this.#events.length,
        modelToolResponses: this.#events.filter(
          (event) => event["outputSource"] === "model_tool_response",
        ).length,
        pairedModelToolResponses: modelToolReads.length,
        capturedProcessOutputs: this.#reads.filter(
          (read) => read.outputSource === "captured_process_output",
        ).length,
      },
      coverage,
    };
    await writer.restore(
      summaryPath,
      Buffer.from(JSON.stringify(summary, null, 2) + "\n"),
    );
    return { eventsPath, summaryPath };
  }

  #append(
    source: "sdk" | "session" | "recorder",
    event: RecordValue,
    threadId?: string,
  ): void {
    if (threadId !== undefined) this.#threads.add(threadId);
    this.#events.push({
      sequence: this.#events.length + 1,
      observedAt: new Date().toISOString(),
      source,
      threadId,
      ...event,
    });
  }

  #capturedTool(item: RecordValue, threadId?: string): void {
    if (typeof item["id"] !== "string") return;
    if (item["type"] === "command_execution") {
      this.#reads.push({
        id: `${threadId ?? "unknown"}:${item["id"]}`,
        threadId,
        name: "exec_command",
        input: { cmd: item["command"] },
        output: item["aggregated_output"] ?? item["stdout"],
        cwd:
          typeof item["cwd"] === "string"
            ? item["cwd"]
            : threadId === undefined
              ? undefined
              : this.#workingDirectories.get(threadId),
        outputSource: "captured_process_output",
      });
    }
  }
}

function scalars(value: unknown, keys: readonly string[]): RecordValue {
  if (!isRecord(value)) return {};
  return Object.fromEntries(
    keys
      .filter(
        (key) =>
          value[key] === null ||
          typeof value[key] === "string" ||
          typeof value[key] === "boolean" ||
          (typeof value[key] === "number" && Number.isFinite(value[key])),
      )
      .map((key) => [key, value[key]]),
  );
}

function numericFields(value: unknown, keys: readonly string[]): RecordValue {
  if (!isRecord(value)) return {};
  return Object.fromEntries(
    keys
      .filter(
        (key) => typeof value[key] === "number" && Number.isFinite(value[key]),
      )
      .map((key) => [key, value[key]]),
  );
}

function parseInput(input: unknown): unknown {
  if (typeof input !== "string") return input;
  try {
    return JSON.parse(input);
  } catch {
    return input;
  }
}

function errorMetadata(value: unknown): RecordValue {
  if (!isRecord(value)) return {};
  const metadata = scalars(value, ["message", "codex_error_info"]);
  const info = value["codex_error_info"];
  if (isRecord(info)) {
    const variants = [
      "http_connection_failed",
      "response_stream_connection_failed",
      "response_stream_disconnected",
      "response_too_many_failed_attempts",
      "active_turn_not_steerable",
    ];
    metadata["codex_error_info"] = Object.fromEntries(
      variants
        .filter((variant) => isRecord(info[variant]))
        .map((variant) => [
          variant,
          scalars(info[variant], ["http_status_code", "turn_kind"]),
        ]),
    );
  }
  return metadata;
}

function messageText(content: unknown): string[] {
  if (!Array.isArray(content)) return [];
  return content
    .filter(isRecord)
    .filter((part) =>
      ["Text", "text", "output_text", "input_text"].includes(
        String(part["type"]),
      ),
    )
    .map((part) => part["text"])
    .filter((text): text is string => typeof text === "string");
}

function observableItem(
  item: RecordValue,
  session: boolean,
): RecordValue | null {
  const type = session
    ? (
        {
          CommandExecution: "command_execution",
          McpToolCall: "mcp_tool_call",
          AgentMessage: "agent_message",
          Reasoning: "reasoning",
          FileChange: "file_change",
          WebSearch: "web_search",
          Plan: "plan",
        } as Record<string, string>
      )[String(item["type"])]
    : item["type"];
  const base = { type, ...scalars(item, ["id", "status"]) };
  switch (type) {
    case "reasoning":
      return {
        ...base,
        ...(session
          ? {
              summary: Array.isArray(item["summary_text"])
                ? item["summary_text"].filter(
                    (text): text is string => typeof text === "string",
                  )
                : [],
            }
          : scalars(item, ["text"])),
      };
    case "agent_message":
      return {
        ...base,
        ...(session
          ? { content: messageText(item["content"]) }
          : scalars(item, ["text"])),
      };
    case "command_execution":
      return {
        ...base,
        ...scalars(item, [
          "cwd",
          "aggregated_output",
          "stdout",
          "stderr",
          "exit_code",
          "process_id",
        ]),
        command:
          typeof item["command"] === "string"
            ? item["command"]
            : Array.isArray(item["command"])
              ? item["command"].filter(
                  (part): part is string => typeof part === "string",
                )
              : undefined,
      };
    case "mcp_tool_call": {
      const result = isRecord(item["result"]) ? item["result"] : {};
      return {
        ...base,
        ...scalars(item, ["server", "tool"]),
        arguments: item["arguments"],
        result: {
          content: result["content"],
          structured_content:
            result["structured_content"] ?? result["structuredContent"],
        },
        error: errorMetadata(item["error"]),
      };
    }
    case "web_search":
      return { ...base, ...scalars(item, ["query"]) };
    case "plan":
    case "error":
      return { ...base, ...scalars(item, ["text", "message"]) };
    case "file_change":
      return {
        ...base,
        changes: Array.isArray(item["changes"])
          ? item["changes"].map((change) => scalars(change, ["path", "kind"]))
          : [],
      };
    case "todo_list":
      return {
        ...base,
        items: Array.isArray(item["items"])
          ? item["items"].map((todo) => scalars(todo, ["text", "completed"]))
          : [],
      };
    default:
      return null;
  }
}

function measurement(
  value: ScanUsageMeasurement | undefined,
): RecordValue | undefined {
  if (value === undefined) return;
  return {
    ...scalars(value, [
      "coverage",
      "observedAt",
      "threadCount",
      "missingThreadCount",
    ]),
    usage: numericFields(value.usage, USAGE_FIELDS),
    cost: scalars(value.cost, [
      "model",
      "inputTokens",
      "cachedInputTokens",
      "cacheWriteInputTokens",
      "outputTokens",
      "estimatedUsd",
    ]),
    coverageScope: value.coverageScope,
    warnings: value.warnings,
  };
}
