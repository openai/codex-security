import type {
  ScanAuthentication,
  ScanObserverName,
  ScanReconnectDetails,
  ScanTrustedAccessStatus,
} from "./api.js";
import type { CodexThreadLike, ScanEvent } from "./execution-preparation.js";
import {
  CodexSecurityError,
  IncompleteScanError,
  ScanCostLimitExceededError,
  ScanInterruptedError,
} from "./errors.js";
import {
  ScanPermissionError,
  ScanTransportClosedError,
} from "./scan-execution.js";
import { ScanCostTrackingError } from "./deep-scan.js";
import type { ScanExpectation } from "./contract.js";
import type { ScanResult } from "./result.js";
import { collectResult, type CompletedScanTurn } from "./scan-publication.js";
import { scanActivitiesFromEvent, type ScanActivity } from "./scan-activity.js";
import {
  scanProgressUpdatesFromEvent,
  workerStatusFromEvent,
  type ScanProgress,
  type ScanWorkerStatus,
} from "./worker-progress.js";

const PERSONAL_TRUSTED_ACCESS_URL = "https://chatgpt.com/cyber";
const ORGANIZATIONAL_TRUSTED_ACCESS_URL =
  "https://openai.com/form/enterprise-trusted-access-for-cyber/";
interface ScanEventRunOptions {
  thread: CodexThreadLike;
  events: AsyncGenerator<ScanEvent>;
  signal: AbortSignal;
  scanDir: string;
  pluginRoot: string;
  expectation: ScanExpectation;
  authentication?: ScanAuthentication;
  workbenchValidated?: boolean;
  model?: string;
  expectedFilesTotal?: number;
  onFinalize?: (usage: unknown) => Promise<unknown>;
  onThreadStarted?: (threadId: string) => Promise<void> | void;
  onScanStarted?: () => void;
  onTrustedAccessStatus?: (status: ScanTrustedAccessStatus) => void;
  onReconnect?: (
    attempt: number,
    maxAttempts: number,
    details?: ScanReconnectDetails,
  ) => void;
  onActivity?: (activity: ScanActivity) => void;
  onProgress?: (progress: ScanProgress) => void;
  onWorkerStatus?: (status: ScanWorkerStatus) => void;
  onWarning?: (warning: string) => void;
  onObserverError?: (observer: ScanObserverName, error: unknown) => void;
}

/** @internal */
export function reportScanActivities(
  event: ScanEvent,
  repository: string,
  options: Pick<ScanEventRunOptions, "onActivity" | "onObserverError">,
): void {
  for (const activity of scanActivitiesFromEvent(event, repository)) {
    notifyObserver(
      "onActivity",
      options.onActivity,
      options.onObserverError,
      activity,
    );
  }
}

/** @internal */
export function scanReconnectObserver(
  options: Pick<ScanEventRunOptions, "onReconnect" | "onObserverError">,
) {
  return (message: string, attempts: [number, number]): void =>
    notifyObserver(
      "onReconnect",
      options.onReconnect,
      options.onObserverError,
      ...attempts,
      reconnectDetails(message),
    );
}

function throwScanFailure(
  error: unknown,
  options: Pick<ScanEventRunOptions, "signal" | "scanDir">,
): never {
  if (
    options.signal.reason instanceof ScanCostLimitExceededError ||
    options.signal.reason instanceof ScanCostTrackingError ||
    options.signal.reason instanceof ScanPermissionError ||
    options.signal.reason instanceof ScanTransportClosedError
  )
    throw options.signal.reason;
  if (options.signal.aborted && !(error instanceof ScanInterruptedError)) {
    throw new ScanInterruptedError(
      `Codex Security scan was interrupted; partial output remains at ${options.scanDir}.`,
      options.scanDir,
      { cause: error },
    );
  }
  throw error;
}

/** @internal */
export async function runScanEvents(
  options: ScanEventRunOptions,
): Promise<ScanResult> {
  try {
    const completed = await runScanTurn(options);
    const result = await collectResult(
      options,
      completed,
      options.workbenchValidated,
    );
    throwIfAborted(options.signal, options.scanDir);
    return result;
  } catch (error) {
    throwScanFailure(error, options);
  }
}
/** @internal */
export async function runScanTurn(
  options: ScanEventRunOptions,
): Promise<CompletedScanTurn> {
  let scanStarted = false;
  let tacStatusReported = false;
  try {
    const turn = await readCodexTurn({
      thread: options.thread,
      events: options.events,
      onEvent: async (event) => {
        if (!tacStatusReported) {
          const tacStatus = trustedAccessStatusFromEvent(event);
          if (tacStatus !== null) {
            tacStatusReported = true;
            notifyObserver(
              "onTrustedAccessStatus",
              options.onTrustedAccessStatus,
              options.onObserverError,
              tacStatus,
            );
            if (tacStatus !== "granted") {
              notifyObserver(
                "onWarning",
                options.onWarning,
                options.onObserverError,
                trustedAccessWarning(tacStatus, options.authentication),
              );
            }
          }
        }
        reportScanActivities(event, options.expectation.repository, options);
        for (const progress of scanProgressUpdatesFromEvent(event)) {
          if (
            options.expectedFilesTotal !== undefined &&
            progress.filesTotal !== options.expectedFilesTotal
          ) {
            continue;
          }
          notifyObserver(
            "onProgress",
            options.onProgress,
            options.onObserverError,
            progress,
          );
        }
        const workerStatus = workerStatusFromEvent(event);
        if (workerStatus !== null) {
          notifyObserver(
            "onWorkerStatus",
            options.onWorkerStatus,
            options.onObserverError,
            workerStatus,
          );
        }
        if (event.type === "thread.started") {
          const startedThreadId = event["thread_id"];
          if (typeof startedThreadId === "string") {
            await options.onThreadStarted?.(startedThreadId);
          }
          if (!scanStarted) {
            scanStarted = true;
            notifyObserver(
              "onScanStarted",
              options.onScanStarted,
              options.onObserverError,
            );
          }
        }
      },
      onReconnect: scanReconnectObserver(options),
    });
    const { status, threadId, finalResponse, lastStreamError } = turn;
    let { usage } = turn;
    throwIfAborted(options.signal, options.scanDir);
    if (status !== "completed") {
      throw new IncompleteScanError(
        lastStreamError ??
          "Codex Security event stream ended before the turn completed.",
      );
    }
    if (threadId === null) {
      throw new IncompleteScanError(
        "Codex Security did not report a thread ID.",
      );
    }
    if (options.onFinalize !== undefined) {
      const finalizedUsage = await options.onFinalize(usage);
      if (finalizedUsage !== undefined) usage = finalizedUsage;
    }
    throwIfAborted(options.signal, options.scanDir);
    return {
      threadId,
      turnResult: {
        status,
        finalResponse,
        usage,
        ...(options.model === undefined ? {} : { model: options.model }),
      },
    };
  } catch (error) {
    throwScanFailure(error, options);
  }
}

/** @internal */
export async function readCodexTurn(options: {
  thread: CodexThreadLike;
  events: AsyncGenerator<ScanEvent>;
  onEvent?: (event: ScanEvent) => Promise<void> | void;
  onReconnect?: (message: string, attempts: [number, number]) => void;
}): Promise<{
  threadId: string | null;
  status: "in_progress" | "completed";
  finalResponse: string;
  usage: unknown;
  lastStreamError: string | null;
}> {
  let threadId = options.thread.id;
  let status: "in_progress" | "completed" = "in_progress";
  let finalResponse = "";
  let usage: unknown = null;
  let lastStreamError: string | null = null;
  for await (const event of eventsWithOptionalUsage(options.events)) {
    await options.onEvent?.(event);
    if (
      event.type === "thread.started" &&
      typeof event["thread_id"] === "string"
    ) {
      threadId = event["thread_id"];
    } else if (
      event.type === "item.completed" &&
      isRecord(event["item"]) &&
      event["item"]["type"] === "agent_message" &&
      typeof event["item"]["text"] === "string"
    ) {
      finalResponse = event["item"]["text"];
    } else if (event.type === "turn.completed") {
      status = "completed";
      usage = event["usage"];
    } else if (event.type === "turn.failed") {
      throw new CodexSecurityError(turnFailureMessage(event["error"]));
    } else if (event.type === "error" && typeof event["message"] === "string") {
      const message = event["message"];
      const classification = classifyConnectionFailure(message);
      if (classification === "unauthorized" || classification === "forbidden") {
        throw new CodexSecurityError(message);
      }
      const reconnect = reconnectAttempt(message);
      if (reconnect === null) throw new CodexSecurityError(message);
      lastStreamError = message;
      options.onReconnect?.(message, reconnect);
    }
  }
  return { threadId, status, finalResponse, usage, lastStreamError };
}

async function* eventsWithOptionalUsage(
  events: AsyncGenerator<ScanEvent>,
): AsyncGenerator<ScanEvent> {
  try {
    yield* events;
  } catch (error) {
    if (
      error instanceof TypeError &&
      /\b(?:null|undefined)\b/u.test(error.message) &&
      /\bcache_write_input_tokens\b/u.test(error.message)
    ) {
      yield { type: "turn.completed", usage: null };
      return;
    }
    throw error;
  }
}

function trustedAccessStatusFromEvent(
  event: ScanEvent,
): ScanTrustedAccessStatus | null {
  if (event.type !== "item.completed" || !isRecord(event["item"])) {
    return null;
  }

  const item = event["item"];
  if (
    item["type"] !== "mcp_tool_call" ||
    item["server"] !== "codex_apps" ||
    item["tool"] !== "get_tac_status"
  ) {
    return null;
  }

  if (item["status"] !== "completed" || !isRecord(item["result"])) {
    return "unknown";
  }

  const result = item["result"]["structured_content"];
  if (
    !isRecord(result) ||
    result["schemaVersion"] !== 1 ||
    !Array.isArray(result["grants"]) ||
    typeof result["checkedAt"] !== "string" ||
    Number.isNaN(Date.parse(result["checkedAt"])) ||
    result["stale"] !== false
  ) {
    return "unknown";
  }

  const status = result["status"];
  if (
    status !== "granted" &&
    status !== "not_granted" &&
    status !== "unknown"
  ) {
    return "unknown";
  }
  if (
    result["grants"].some((grant) => !isTrustedAccessGrant(grant)) ||
    (status === "granted") !== result["grants"].length > 0
  ) {
    return "unknown";
  }
  return status;
}

function isTrustedAccessGrant(grant: unknown): boolean {
  if (!isRecord(grant)) return false;
  const level = grant["level"];
  const source = grant["source"];
  return (
    (source === "user" && (level === "tac1" || level === "tac2")) ||
    (source === "current_account" &&
      (level === "tac1" || level === "tac3" || level === "government"))
  );
}

function trustedAccessWarning(
  status: Exclude<ScanTrustedAccessStatus, "granted">,
  authentication?: ScanAuthentication,
): string {
  const apiOrganization =
    (authentication?.method === "api_key" &&
      (authentication.source === "OPENAI_API_KEY" ||
        authentication.source === "CODEX_API_KEY")) ||
    (authentication?.method === "stored_credentials" &&
      authentication.credentialType === "api_key");
  const applicationUrl = apiOrganization
    ? ORGANIZATIONAL_TRUSTED_ACCESS_URL
    : PERSONAL_TRUSTED_ACCESS_URL;
  if (status === "not_granted") {
    const account = apiOrganization ? "your API organization" : "your account";
    return `Some cybersecurity requests or findings may be refused because ${account} does not have Trusted Access for Cyber. Apply at ${applicationUrl}.`;
  }
  const access = apiOrganization
    ? "Trusted Access for Cyber for your API organization"
    : "your Trusted Access for Cyber status";
  const action = apiOrganization ? "your organization's access" : "your access";
  return `Some cybersecurity requests or findings may be refused because ${access} could not be verified. Check ${action} or apply at ${applicationUrl}.`;
}

function reconnectAttempt(message: string): [number, number] | null {
  const match =
    /^Reconnecting(?:\.\.\.|…)[ \t]+([1-9]\d{0,2})\/([1-9]\d{0,2})(?=[ \t(]|$)/u.exec(
      message,
    );
  if (match === null) return null;
  const attempt = Number(match[1]);
  const maxAttempts = Number(match[2]);
  return attempt <= maxAttempts ? [attempt, maxAttempts] : null;
}

export function reconnectDetails(
  message: string,
): ScanReconnectDetails | undefined {
  const classification = classifyConnectionFailure(message);
  if (classification !== "rate_limited") {
    if (classification === "network_error") return { reason: "network" };
    if (classification === "unauthorized") return { reason: "authentication" };
    if (classification === "forbidden") return { reason: "authorization" };
    return undefined;
  }
  const delay =
    /\b(?:try again|retry)\s+in\s+(\d{1,6}(?:\.\d{1,3})?)\s*(?:s\b|seconds?\b)/iu.exec(
      message,
    );
  const retryAfterSeconds = delay === null ? NaN : Number(delay[1]);
  return {
    reason: "rate_limit",
    ...(Number.isFinite(retryAfterSeconds) &&
    retryAfterSeconds > 0 &&
    retryAfterSeconds <= 3_600
      ? { retryAfterSeconds }
      : {}),
  };
}

// A failed turn must fail the scan whatever its error payload looks like.
export function turnFailureMessage(error: unknown): string {
  if (isRecord(error) && typeof error["message"] === "string") {
    const message = error["message"].trim();
    if (message.length > 0) return error["message"];
  }
  return "The Codex Security scan turn failed without a readable error message.";
}

export function classifyConnectionFailure(
  error: unknown,
):
  | "rate_limited"
  | "unauthorized"
  | "forbidden"
  | "network_error"
  | "timeout"
  | "unknown" {
  const message = error instanceof Error ? error.message : String(error);
  if (/\b(?:sqlite3?|database|workbench)\b/iu.test(message)) {
    return "unknown";
  }
  if (
    /\brate[_ -]?limit(?:ed|[_ -]exceeded)?\b|\b429\b|\btoo many requests\b/iu.test(
      message,
    )
  ) {
    return "rate_limited";
  }
  if (
    /\b401\b|\bunauthori[sz]ed\b|\binvalid[_ -](?:api[_ -]?key|authentication|token|credentials?)\b|\b(?:expired|revoked)[_ -](?:api[_ -]?key|token|credentials?)\b|\b(?:api[_ -]?key|token|credentials?)(?: has)? (?:expired|been revoked)\b/iu.test(
      message,
    )
  ) {
    return "unauthorized";
  }
  if (
    /\b403\b|\bforbidden\b|\bpermission denied\b|\b(?:model|organization|project) access\b|\b(?:access denied|do not have access|not authorized|insufficient permissions)\b|\bmodel[_ -]?not[_ -]?found\b/iu.test(
      message,
    )
  ) {
    return "forbidden";
  }
  if (
    /\b(?:ENOTFOUND|ECONNRESET|ECONNREFUSED|EHOSTUNREACH|ETIMEDOUT)\b|\b(?:network|connection|TLS|DNS)\b|\berror sending request\b/iu.test(
      message,
    )
  ) {
    return "network_error";
  }
  if (/\b(?:timed? out|timeout)\b/iu.test(message)) return "timeout";
  return "unknown";
}

export function notifyObserver<Arguments extends unknown[]>(
  observerName: ScanObserverName,
  observer: ((...args: Arguments) => void) | undefined,
  onObserverError:
    ((observer: ScanObserverName, error: unknown) => void) | undefined,
  ...args: Arguments
): void {
  void Promise.resolve()
    .then(() => observer?.(...args))
    .catch((error: unknown) => onObserverError?.(observerName, error))
    .catch(() => {});
}

export function throwIfAborted(signal?: AbortSignal, scanDir = ""): void {
  if (!signal?.aborted) return;
  if (
    signal.reason instanceof ScanCostLimitExceededError ||
    signal.reason instanceof ScanCostTrackingError ||
    signal.reason instanceof ScanPermissionError ||
    signal.reason instanceof ScanTransportClosedError
  )
    throw signal.reason;
  const message = scanDir
    ? `Codex Security scan was interrupted; partial output remains at ${scanDir}.`
    : "Codex Security scan was interrupted during preparation.";
  throw new ScanInterruptedError(message, scanDir, { cause: signal.reason });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
