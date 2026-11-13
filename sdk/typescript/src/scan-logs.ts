import { createHash } from "node:crypto";
import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { firstNativeSessionLine, sessionLines } from "./session-lines.js";
import { parseJson } from "./value.js";
import { isRecord } from "./record.js";
import { sessionFiles, readWorkerReceipts } from "./cost.js";
import { CodexSecurityError } from "./errors.js";
import type { JsonObject } from "./config.js";
import {
  isScanArtifactDirectory,
  sessionOwnsTurn,
  sessionParentThreadId,
  sessionStartedAt,
} from "./scan-sessions.js";
import { compareTimestamps } from "./timestamps.js";
import { shortArchivePrefix } from "./scan-archive-path.js";

interface ScanLogOptions {
  scanId: string;
  threadId?: string;
  threadIds?: readonly string[];
  executionThreadIds?: readonly string[];
  codexHome: string | readonly string[];
  scanDirectory?: string;
  startedAt?: string;
  completedAt?: string | null;
  logCompletedAt?: string | null;
  allowMissingRoot?: boolean;
}

export type ScanLogSource = JsonObject & {
  scanId: string;
  continuationThreadId?: string;
  threadIds?: string[];
  executionThreadIds?: string[];
  mode?: string;
  scanDir?: string;
  logCompletedAt?: string | null;
  lifecycle?: { startedAt: string; finishedAt?: string | null };
  progress?: { status?: string; updatedAt?: string };
};

export function savedScanLogBoundaries(scan: ScanLogSource) {
  const status = scan.progress?.status;
  const terminal =
    status === "complete" || status === "failed" || status === "canceled";
  return {
    // Legacy completion still bounds inferred workers, but cannot identify the
    // final scan turn when sealed artifacts were completed before a resume.
    completedAt:
      status === "running"
        ? null
        : terminal
          ? (scan.lifecycle?.finishedAt ?? scan.progress?.updatedAt ?? "")
          : "",
    logCompletedAt: terminal ? (scan.logCompletedAt ?? null) : null,
  };
}

export function readSavedScanLogs(
  scan: ScanLogSource,
  codexHome: string | readonly string[],
  options: { allowMissingRoot?: boolean } = {},
) {
  const threadId = scan.continuationThreadId;
  if (!threadId && !options.allowMissingRoot) {
    throw new CodexSecurityError(
      `No session is associated with scan ${scan.scanId}.`,
    );
  }
  return readScanLogs({
    scanId: scan.scanId,
    threadId: threadId ?? scan.threadIds?.[0],
    threadIds: scan.threadIds,
    executionThreadIds: scan.executionThreadIds ?? [],
    codexHome,
    allowMissingRoot: options.allowMissingRoot,
    scanDirectory: scan.mode === "deep" ? scan.scanDir : undefined,
    startedAt: scan.lifecycle?.startedAt,
    ...savedScanLogBoundaries(scan),
  });
}

type SessionLog = NonNullable<Awaited<ReturnType<typeof findScanSession>>>;

async function* scanSessions(
  codexHome: string,
  directory = "sessions",
  workersOnly = false,
) {
  for await (const path of sessionFiles(join(codexHome, directory), true)) {
    const first = await firstSessionEvent(path);
    if (first?.["type"] !== "session_meta" || !isRecord(first["payload"]))
      continue;
    const metadata = first["payload"];
    const threadId = metadata["id"];
    if (typeof threadId !== "string") continue;
    yield {
      threadId,
      parentThreadId: sessionParentThreadId(
        workersOnly ? { source: metadata["source"] } : metadata,
      ),
      startedAt: sessionStartedAt(metadata["timestamp"]),
      timestamp:
        typeof metadata["timestamp"] === "string"
          ? metadata["timestamp"]
          : null,
      workingDirectory:
        typeof metadata["cwd"] === "string" ? metadata["cwd"] : null,
      path,
    };
  }
}

export async function findScanSession(codexHome: string, threadId: string) {
  for await (const session of scanSessions(codexHome)) {
    if (session.threadId === threadId) return session;
  }
  return null;
}

interface RolloutWindow {
  startedAt: string;
  completedAt: string;
}

function inRolloutWindow(
  timestamp: unknown,
  window: RolloutWindow,
): timestamp is string {
  return (
    typeof timestamp === "string" &&
    compareTimestamps(timestamp, window.startedAt) >= 0 &&
    compareTimestamps(timestamp, window.completedAt) < 0
  );
}

function startsAfterCompletion(
  timestamp: unknown,
  completedAt: unknown,
): boolean {
  return (
    typeof timestamp === "string" &&
    typeof completedAt === "string" &&
    compareTimestamps(timestamp, completedAt) >= 0
  );
}

async function selectSessionCopies(
  options: ScanLogOptions,
  window?: RolloutWindow,
) {
  const logs = new Map<string, [SessionLog, ...SessionLog[]]>();
  const homes = new Set(
    typeof options.codexHome === "string"
      ? [options.codexHome]
      : options.codexHome,
  );
  for (const directory of ["sessions", "archived_sessions"]) {
    for (const home of homes) {
      for await (const session of scanSessions(
        home,
        directory,
        window !== undefined,
      )) {
        const copies = logs.get(session.threadId);
        if (copies === undefined) logs.set(session.threadId, [session]);
        else copies.push(session);
      }
    }
  }

  const root = options.threadId ? logs.get(options.threadId)?.[0] : undefined;
  if (root === undefined && !options.allowMissingRoot) {
    throw new CodexSecurityError(
      `No saved session logs are available for scan ${options.scanId}.`,
    );
  }

  const included = new Set([
    ...(options.threadId ? [options.threadId] : []),
    ...(options.threadIds ?? []),
    ...(options.executionThreadIds ?? []),
  ]);
  // A Desktop owner can contain other work. Include its log without treating
  // the whole conversation tree as part of this scan.
  const traversed = new Set(options.executionThreadIds ?? included);
  const children = Map.groupBy(
    logs.values().map(([session]) => session),
    (session) => session.parentThreadId,
  );
  // Comparisons have no spawn edge. The saved scan window also works for a
  // shared Desktop owner, whose unrelated child threads must stay excluded.
  const startedAt =
    options.startedAt === undefined
      ? root && traversed.has(root.threadId)
        ? root.startedAt
        : null
      : sessionStartedAt(options.startedAt);
  if (options.scanDirectory && startedAt !== null) {
    const directories = [options.scanDirectory];
    const name = basename(options.scanDirectory);
    const parent = dirname(options.scanDirectory);
    const originals = new Set<string>();
    for (const marker of name.matchAll(/\.previous-/g)) {
      if (marker.index)
        originals.add(join(parent, name.slice(0, marker.index)));
    }
    if (name.startsWith(".previous-")) {
      // A short archive has no readable source name. Only already-bound
      // sessions can supply a sibling whose complete filename matches its hash.
      const boundCwds = [
        root?.workingDirectory,
        ...Array.from(traversed, (id) => logs.get(id)?.[0].workingDirectory),
      ];
      for (const cwd of boundCwds) {
        if (!cwd) continue;
        const path = relative(parent, cwd);
        const sibling = path.split(sep, 1)[0];
        if (
          sibling &&
          sibling !== ".." &&
          !isAbsolute(path) &&
          name.startsWith(shortArchivePrefix(sibling))
        ) {
          originals.add(join(parent, sibling));
        }
      }
    }
    for (const original of originals) {
      // A Desktop owner can work outside the scan directory. Its registered
      // workers provide the same binding after archiving the output.
      if (
        (root?.workingDirectory != null &&
          relative(original, root.workingDirectory) === "") ||
        Array.from(traversed).some((threadId) => {
          const cwd = logs.get(threadId)?.[0].workingDirectory;
          return cwd != null && isScanArtifactDirectory(original, cwd);
        })
      )
        directories.push(original);
    }
    for (const session of children.get(null) ?? []) {
      if (
        session !== root &&
        belongsToScan(session, directories, startedAt, options)
      ) {
        included.add(session.threadId);
        traversed.add(session.threadId);
      }
    }
  }
  for (const parentId of traversed) {
    for (const session of children.get(parentId) ?? []) {
      if (window && !inRolloutWindow(session.timestamp, window)) continue;
      if (startsAfterCompletion(session.timestamp, options.logCompletedAt))
        continue;
      included.add(session.threadId);
      traversed.add(session.threadId);
    }
  }
  return [...included].flatMap((id) => {
    const copies = logs.get(id);
    return copies ? [copies] : [];
  });
}

async function completeSession(copies: [SessionLog, ...SessionLog[]]) {
  let session = copies[0];
  for (const copy of copies.slice(1)) {
    if (await extendsSessionLog(session.path, copy.path)) session = copy;
  }
  return session;
}

async function* ownSessionEvents(session: SessionLog, verify = false) {
  let replaying = false;
  let first = true;
  for await (const event of sessionEvents(session.path, verify)) {
    const payload = event["payload"];
    const meta = event["type"] === "session_meta" && isRecord(payload);
    if (verify && first && (!meta || payload["id"] !== session.threadId)) {
      throw new CodexSecurityError(
        "The selected rollout changed before export.",
      );
    }
    first = false;
    if (meta) replaying = payload["id"] !== session.threadId;
    if (replaying) {
      if (
        event["type"] !== "event_msg" ||
        !isRecord(payload) ||
        payload["type"] !== "task_started" ||
        !sessionOwnsTurn(session, payload)
      )
        continue;
      replaying = false;
    }
    yield event;
  }
  if (verify && first)
    throw new CodexSecurityError("The selected rollout is unavailable.");
}

function rolloutInput(
  type: unknown,
  payload: Record<string, unknown>,
): unknown {
  if (type === "event_msg" && payload["type"] === "user_message")
    return payload["message"];
  if (
    type === "response_item" &&
    payload["type"] === "message" &&
    payload["role"] === "user"
  ) {
    const content = payload["content"];
    return Array.isArray(content) &&
      content.length === 1 &&
      isRecord(content[0]) &&
      content[0]["type"] === "input_text"
      ? content[0]["text"]
      : null;
  }
  return undefined;
}

function nativeUserText(item: Record<string, unknown>): string | undefined {
  const content = item["content"];
  if (
    !Array.isArray(content) ||
    content.length !== 1 ||
    !isRecord(content[0]) ||
    content[0]["type"] !== "text" ||
    typeof content[0]["text"] !== "string"
  )
    return;
  return content[0]["text"];
}

function taggedWorkerInput(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /\n\nWorker attempt ID: [0-9a-f-]{36}$/u.test(value)
  );
}

function workerInputProof(text: string | undefined, worker?: WorkerTurns) {
  if (text === undefined || !worker?.inputs.size) return;
  const proof = worker.inputs.get(
    createHash("sha256").update(text).digest("hex"),
  );
  return proof && text.endsWith(`\n\nWorker attempt ID: ${proof.attemptId}`)
    ? proof
    : undefined;
}

interface TurnMatch {
  count: number;
  windows: Map<string | undefined, RolloutWindow | undefined>;
  inputs: Map<string, string | null>;
}

interface WorkerInputReceipt extends RolloutWindow {
  attemptId: string;
  turnId?: string;
}

interface WorkerTurns {
  ids: Set<string>;
  inputs: Map<string, WorkerInputReceipt>;
  requiresProof: boolean;
}

// A root thread can be reused. Only its exact submitted input opens a retained
// turn. Workers without receipted turns need a fresh session and one in-window turn.
async function* retainedTurnEvents(
  session: SessionLog,
  window: RolloutWindow,
  prompt: string | undefined,
  match: TurnMatch,
  worker?: WorkerTurns,
) {
  let eligible = false;
  let active = false;
  let sawStart = false;
  let workerResponded = false;
  let turnStart: string | undefined;
  let turnId: string | undefined;
  let awaitingWorkerInput = false;
  let inputReceipt: WorkerInputReceipt | undefined;
  const begin = (timestamp: string) => {
    match.count++;
    match.windows.set(turnId, {
      startedAt: timestamp,
      completedAt:
        inputReceipt &&
        compareTimestamps(inputReceipt.completedAt, window.completedAt) < 0
          ? inputReceipt.completedAt
          : window.completedAt,
    });
    active = true;
  };
  const finish = (timestamp: unknown) => {
    const childWindow = active && match.windows.get(turnId);
    if (childWindow) {
      // An undated boundary cannot tell us when a child was spawned.
      if (
        typeof timestamp !== "string" ||
        !Number.isFinite(Date.parse(timestamp))
      )
        match.windows.set(turnId, undefined);
      else if (compareTimestamps(timestamp, childWindow.completedAt) < 0)
        childWindow.completedAt = timestamp;
    }
    eligible = active = awaitingWorkerInput = false;
    inputReceipt = undefined;
  };
  for await (const event of ownSessionEvents(session, true)) {
    const payload = event["payload"];
    if (!isRecord(payload)) continue;
    const type = event["type"];
    const timestamp = event["timestamp"];
    const task = type === "event_msg" ? payload["type"] : undefined;
    if (type === "session_meta") {
      finish(timestamp);
      continue;
    }
    if (task === "task_started") {
      finish(timestamp);
      sawStart = true;
      workerResponded = false;
      turnStart = typeof timestamp === "string" ? timestamp : undefined;
      turnId =
        worker && typeof payload["turn_id"] === "string" && payload["turn_id"]
          ? payload["turn_id"]
          : undefined;
      awaitingWorkerInput = !!turnId && !!worker?.inputs.size;
      eligible =
        typeof turnStart === "string" &&
        inRolloutWindow(turnStart, window) &&
        (!worker || (turnId !== undefined && worker.ids.has(turnId)));
      if (eligible && prompt === undefined) begin(turnStart!);
    }
    if (
      (awaitingWorkerInput || inputReceipt) &&
      (task === "thread_rolled_back" ||
        type === "compacted" ||
        ("turn_id" in payload && payload["turn_id"] !== turnId) ||
        ("thread_id" in payload && payload["thread_id"] !== session.threadId))
    )
      finish(timestamp);
    if (
      inputReceipt &&
      (!inRolloutWindow(timestamp, window) ||
        !inRolloutWindow(timestamp, inputReceipt))
    )
      finish(timestamp);
    const input = rolloutInput(type, payload);
    // This native record binds the submitted user input to both IDs, even when exec fails.
    const item =
      type === "event_msg" &&
      (task === "item_started" || task === "item_completed")
        ? payload["item"]
        : undefined;
    const userItem =
      isRecord(item) && item["type"] === "UserMessage" ? item : undefined;
    const text = userItem && nativeUserText(userItem);
    if (prompt === undefined && !worker && taggedWorkerInput(text ?? input)) {
      // An opted-in worker whose receipt could not be written cannot use the legacy fallback.
      match.count++;
      finish(timestamp);
    }
    if (prompt === undefined && userItem) {
      const proof = task === "item_completed" && workerInputProof(text, worker);
      if (proof) {
        // Reject a replay anywhere in this thread, even outside the receipt window.
        if (match.inputs.has(proof.attemptId)) match.count++;
        match.inputs.set(proof.attemptId, null);
        if (
          awaitingWorkerInput &&
          !active &&
          turnId &&
          (!proof.turnId || proof.turnId === turnId) &&
          payload["thread_id"] === session.threadId &&
          payload["turn_id"] === turnId &&
          inRolloutWindow(turnStart, proof) &&
          inRolloutWindow(timestamp, proof) &&
          inRolloutWindow(turnStart, window) &&
          inRolloutWindow(timestamp, window) &&
          compareTimestamps(timestamp, turnStart) >= 0
        ) {
          inputReceipt = { ...proof, startedAt: timestamp };
          match.inputs.set(proof.attemptId, turnId);
          begin(timestamp);
        }
      } else if (inputReceipt) finish(timestamp);
      if (task === "item_completed") awaitingWorkerInput = false;
      // Never export the event's copy of the submitted worker prompt.
      continue;
    }
    if (
      awaitingWorkerInput &&
      ((type === "response_item" &&
        input === undefined &&
        payload["role"] !== "developer" &&
        payload["role"] !== "system") ||
        task === "agent_message" ||
        task === "agent_reasoning")
    )
      awaitingWorkerInput = false;
    if (input !== undefined) {
      if (prompt === undefined) {
        // Backends can emit several user-role setup records before a worker's
        // first reply. Its input is unknown; omit it and stop at subsequent input.
        if (inputReceipt || workerResponded) finish(timestamp);
        continue;
      }
      if (active && input !== prompt) {
        finish(timestamp);
      } else if (!active && input === prompt) {
        if (eligible && turnStart !== undefined) {
          begin(
            typeof timestamp === "string" && inRolloutWindow(timestamp, window)
              ? timestamp
              : turnStart,
          );
        } else if (
          !sawStart &&
          typeof timestamp === "string" &&
          inRolloutWindow(timestamp, window)
        ) {
          // Direct Deep Scan injects one known user item without starting a model turn.
          match.count++;
          match.windows.set(undefined, undefined);
          yield event;
        }
      }
    }
    if (active) {
      if (
        (type === "response_item" &&
          payload["role"] !== "developer" &&
          payload["role"] !== "system") ||
        task === "agent_message" ||
        task === "agent_reasoning"
      )
        workerResponded = true;
      yield event;
    }
    if (task === "task_complete" || task === "turn_aborted") finish(timestamp);
  }
}

export interface ScanRolloutSession {
  attribution?: "recorded" | "inferred";
  threadId: string;
  parentThreadId: string | null;
  events(): AsyncIterable<Record<string, unknown>>;
}

/** Select only execution threads and their in-scan descendants for private export. */
export async function scanRolloutSessions(
  options: RolloutWindow & {
    codexHome: string | readonly string[];
    rootThreadId: string;
    rootPrompt?: string;
    executionThreadIds?: readonly string[];
    workerReceipts?: { directory: string; scanId: string };
  },
): Promise<ScanRolloutSession[]> {
  const execution = [
    options.rootThreadId,
    ...(options.executionThreadIds ?? []),
  ];
  const workerTurns = new Map<string, WorkerTurns>();
  if (options.workerReceipts) {
    await readWorkerReceipts(options.workerReceipts, new Map(), (receipt) => {
      const threadId = receipt["threadId"];
      if (
        typeof threadId !== "string" ||
        !inRolloutWindow(receipt["startedAt"], options)
      )
        return;
      // Comparisons start standalone SDK threads, while discovery retries can
      // resume one registered thread for several scan-owned turns.
      if (receipt["kind"] === "compare") execution.push(threadId);
      if (receipt["kind"] === "discovery") {
        const previous = workerTurns.get(threadId);
        const worker = previous ?? {
          ids: new Set<string>(),
          inputs: new Map<string, WorkerInputReceipt>(),
          requiresProof: false,
        };
        worker.requiresProof ||=
          previous !== undefined ||
          receipt["resumed"] === true ||
          "inputSha256" in receipt;
        const nativeId = receipt["turnId"];
        if (
          !("inputSha256" in receipt) &&
          typeof nativeId === "string" &&
          nativeId
        )
          worker.ids.add(nativeId);
        else if (
          typeof receipt["inputSha256"] === "string" &&
          /^[a-f0-9]{64}$/u.test(receipt["inputSha256"]) &&
          typeof receipt["attemptId"] === "string" &&
          typeof receipt["startedAt"] === "string" &&
          typeof receipt["observedAt"] === "string" &&
          ["failed", "succeeded", "canceled"].includes(
            String(receipt["outcome"]),
          )
        ) {
          worker.inputs.set(receipt["inputSha256"], {
            attemptId: receipt["attemptId"],
            ...(typeof nativeId === "string" &&
              nativeId && { turnId: nativeId }),
            startedAt: receipt["startedAt"],
            completedAt: receipt["observedAt"],
          });
        }
        workerTurns.set(threadId, worker);
      }
    });
  }
  const sessions = await selectSessionCopies(
    {
      scanId: options.rootThreadId,
      executionThreadIds: execution,
      codexHome: options.codexHome,
      allowMissingRoot: true,
    },
    options,
  );
  const byId = new Map(sessions.map((copies) => [copies[0].threadId, copies]));
  const registered = new Set(execution);
  type Capture = {
    session: SessionLog;
    prompt?: string;
    window: RolloutWindow;
    worker?: WorkerTurns;
    match: TurnMatch;
  };
  const captures = new Map<string, Promise<Capture | null>>();
  function capture(id: string): Promise<Capture | null> {
    const cached = captures.get(id);
    if (cached) return cached;
    const result = (async () => {
      const copies = byId.get(id);
      if (!copies) return null;
      const session = await completeSession(copies);
      const prompt =
        id === options.rootThreadId ? options.rootPrompt : undefined;
      const worker = prompt === undefined ? workerTurns.get(id) : undefined;
      // A retry receipt prevents the single-turn fallback even if only one
      // task survives in the rollout and no receipt has a native turn ID.
      const proofs =
        worker && (worker.requiresProof || worker.ids.size)
          ? worker
          : undefined;
      if (
        prompt === undefined &&
        !proofs &&
        !inRolloutWindow(session.timestamp, options)
      )
        return null;
      if (!registered.has(id)) {
        const parent = session.parentThreadId
          ? await capture(session.parentThreadId)
          : null;
        const { timestamp } = session;
        // Spawn metadata names a parent thread, not its turn. Creation at the
        // very same clock tick as either boundary cannot prove ownership.
        if (
          !timestamp ||
          !parent?.match.windows
            .values()
            .some(
              (window) =>
                window !== undefined &&
                compareTimestamps(timestamp, window.startedAt) > 0 &&
                inRolloutWindow(timestamp, window),
            )
        )
          return null;
      }
      const window =
        session.timestamp &&
        compareTimestamps(session.timestamp, options.startedAt) > 0
          ? { ...options, startedAt: session.timestamp }
          : options;
      const match: TurnMatch = {
        count: 0,
        windows: new Map(),
        inputs: new Map(),
      };
      // Establish uniqueness without keeping whole rollouts in memory.
      for await (const _ of retainedTurnEvents(
        session,
        window,
        prompt,
        match,
        proofs,
      )) {
        /* drain */
      }
      // Duplicate starts for one ID (including the legacy no-ID case) are ambiguous.
      return match.count > 0 && match.count === match.windows.size
        ? { session, prompt, window, match, worker: proofs }
        : null;
    })();
    captures.set(id, result);
    return result;
  }
  return sessions.map(([session]) => ({
    attribution:
      registered.has(session.threadId) || workerTurns.has(session.threadId)
        ? "recorded"
        : "inferred",
    threadId: session.threadId,
    parentThreadId:
      session.parentThreadId &&
      (registered.has(session.parentThreadId) ||
        byId.has(session.parentThreadId))
        ? session.parentThreadId
        : null,
    async *events() {
      const selected = await capture(session.threadId);
      if (!selected) return;
      const match: TurnMatch = {
        count: 0,
        windows: new Map(),
        inputs: new Map(),
      };
      yield* retainedTurnEvents(
        selected.session,
        selected.window,
        selected.prompt,
        match,
        selected.worker,
      );
      if (!isDeepStrictEqual(match, selected.match))
        throw new CodexSecurityError(
          "The selected rollout turn changed before export.",
        );
    },
  }));
}

export async function readScanLogs(options: ScanLogOptions) {
  const sessions: SessionLog[] = [];
  const events: Record<string, unknown>[] = [];
  for (const copies of await selectSessionCopies(options)) {
    const session = await completeSession(copies);
    sessions.push(session);
    for await (const event of ownSessionEvents(session)) {
      const payload = event["payload"];
      if (
        event["type"] === "event_msg" &&
        isRecord(payload) &&
        payload["type"] === "task_started" &&
        startsAfterCompletion(event["timestamp"], options.logCompletedAt)
      )
        break;
      events.push({ threadId: session.threadId, event });
    }
  }
  return {
    scanId: options.scanId,
    threadId: options.threadId ?? null,
    sessions: sessions.map(({ threadId, parentThreadId, path }) => ({
      threadId,
      parentThreadId,
      path,
    })),
    events,
  };
}

function belongsToScan(
  session: SessionLog,
  directories: string[],
  startedAt: number,
  options: ScanLogOptions,
): boolean {
  if (
    session.workingDirectory === null ||
    session.startedAt === null ||
    session.startedAt < startedAt
  ) {
    return false;
  }
  const beforeCompletion =
    typeof options.logCompletedAt === "string" && session.timestamp !== null
      ? compareTimestamps(session.timestamp, options.logCompletedAt) < 0
      : options.completedAt == null ||
        session.startedAt < Date.parse(options.completedAt);
  if (!beforeCompletion) return false;

  for (const directoryRoot of directories) {
    if (isScanArtifactDirectory(directoryRoot, session.workingDirectory)) {
      return true;
    }
  }
  return false;
}

// Prefer a longer copy only when it preserves every event in the earlier copy.
// Identical or divergent copies keep the existing home/archive precedence.
async function extendsSessionLog(
  previousPath: string,
  path: string,
): Promise<boolean> {
  const events = sessionEvents(path);
  try {
    for await (const previous of sessionEvents(previousPath)) {
      const next = await events.next();
      if (next.done || !isDeepStrictEqual(previous, next.value)) return false;
    }
    return !(await events.next()).done;
  } finally {
    await events.return(undefined);
  }
}

async function firstSessionEvent(path: string) {
  const line = await firstNativeSessionLine(path);
  if (line !== undefined) {
    const event = parseJson(() => line);
    if (isRecord(event)) return event;
  }
  // Also handles metadata split across frames and malformed prefix lines.
  for await (const event of sessionEvents(path)) return event;
}

async function* sessionEvents(
  path: string,
  strict = false,
): AsyncGenerator<Record<string, unknown>> {
  try {
    for await (const line of sessionLines(path)) {
      if (line.trim() === "") continue;
      try {
        const event: unknown = JSON.parse(line);
        if (isRecord(event)) yield event;
        else if (strict) throw new Error();
      } catch {
        if (strict)
          throw new CodexSecurityError(
            "The rollout contains an invalid event.",
          );
        continue;
      }
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}
