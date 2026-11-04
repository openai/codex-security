import { createReadStream } from "node:fs";
import { basename, dirname, join, relative } from "node:path";
import { createInterface } from "node:readline";
import { pipeline } from "node:stream";
import { isDeepStrictEqual } from "node:util";
import zlib from "node:zlib";
import { isRecord } from "./record.js";
import { sessionFiles } from "./cost.js";
import { CodexSecurityError } from "./errors.js";
import { compareTimestamps } from "./timestamps.js";
import type { JsonObject } from "./config.js";
import {
  isScanArtifactDirectory,
  sessionOwnsTurn,
  sessionParentThreadId,
  sessionStartedAt,
} from "./scan-sessions.js";

interface ScanLogOptions {
  scanId: string;
  threadId?: string;
  threadIds?: readonly string[];
  executionThreadIds?: readonly string[];
  codexHome: string | readonly string[];
  scanDirectory?: string;
  completedAt?: string | null;
  allowMissingRoot?: boolean;
}

export type ScanLogSource = JsonObject & {
  scanId: string;
  continuationThreadId?: string;
  threadIds?: string[];
  executionThreadIds?: string[];
  mode?: string;
  scanDir?: string;
  progress?: { status?: string; updatedAt?: string };
};

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
    completedAt:
      scan.progress?.status === "running"
        ? null
        : scan.progress?.status === "complete" ||
            scan.progress?.status === "failed" ||
            scan.progress?.status === "canceled"
          ? (scan.progress.updatedAt ?? "")
          : "",
  });
}

// Codex can compress cold rollouts to `.jsonl.zst`. Node 22.13 and 22.14 lack
// zstd, so they still read plain rollouts only.
const readsCompressedSessions = typeof zlib.createZstdDecompress === "function";

type SessionLog = NonNullable<Awaited<ReturnType<typeof findScanSession>>>;

async function* scanSessions(
  codexHome: string,
  directory = "sessions",
  workersOnly = false,
) {
  for await (const path of sessionFiles(
    join(codexHome, directory),
    readsCompressedSessions,
  )) {
    for await (const first of sessionEvents(path)) {
      if (first["type"] !== "session_meta" || !isRecord(first["payload"])) {
        break;
      }
      const metadata = first["payload"];
      const threadId = metadata["id"];
      if (typeof threadId !== "string") break;
      yield {
        threadId,
        parentThreadId: sessionParentThreadId(
          workersOnly ? { source: metadata["source"] } : metadata,
        ),
        timestamp:
          typeof metadata["timestamp"] === "string"
            ? metadata["timestamp"]
            : null,
        startedAt: sessionStartedAt(metadata["timestamp"]),
        workingDirectory:
          typeof metadata["cwd"] === "string" ? metadata["cwd"] : null,
        path,
      };
      break;
    }
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

function inRolloutWindow(timestamp: unknown, window: RolloutWindow): boolean {
  return (
    typeof timestamp === "string" &&
    compareTimestamps(timestamp, window.startedAt) >= 0 &&
    compareTimestamps(timestamp, window.completedAt) < 0
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
  let children: Map<string | undefined, SessionLog[]> | undefined;

  const included = new Set([
    ...(options.threadId ? [options.threadId] : []),
    ...(options.threadIds ?? []),
    ...(options.executionThreadIds ?? []),
  ]);
  // A Desktop owner can contain other work. Include its log without treating
  // the whole conversation tree as part of this scan.
  const traversed = new Set(options.executionThreadIds ?? included);
  for (const parentId of traversed) {
    const parent = logs.get(parentId)?.[0];
    // Parentless workers can only belong to the root, in discovery order.
    children ??= Map.groupBy(
      logs.values().map(([session]) => session),
      (session) => session.parentThreadId ?? root?.threadId,
    );
    for (const session of children.get(parentId) ?? []) {
      if (
        !traversed.has(session.threadId) &&
        (session.parentThreadId === parentId
          ? !window || inRolloutWindow(session.timestamp, window)
          : parent !== undefined && belongsToScan(session, parent, options))
      ) {
        included.add(session.threadId);
        traversed.add(session.threadId);
      }
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

interface TurnMatch {
  count: number;
  window?: RolloutWindow;
}

// A root thread can be reused. Only its exact submitted input opens a retained
// turn. Workers need a fresh session and a unique in-window turn.
async function* retainedTurnEvents(
  session: SessionLog,
  window: RolloutWindow,
  prompt: string | undefined,
  match: TurnMatch,
) {
  let eligible = false;
  let active = false;
  let sawStart = false;
  let workerResponded = false;
  let turnStart: string | undefined;
  const begin = (timestamp: string) => {
    match.count++;
    match.window = { startedAt: timestamp, completedAt: window.completedAt };
    active = true;
  };
  const finish = (timestamp: unknown) => {
    if (active && match.window) {
      // An undated boundary cannot tell us when a child was spawned.
      if (
        typeof timestamp !== "string" ||
        !Number.isFinite(Date.parse(timestamp))
      )
        delete match.window;
      else if (compareTimestamps(timestamp, match.window.completedAt) < 0)
        match.window.completedAt = timestamp;
    }
    eligible = active = false;
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
      eligible =
        typeof turnStart === "string" && inRolloutWindow(turnStart, window);
      if (eligible && prompt === undefined) begin(turnStart!);
    }
    const input = rolloutInput(type, payload);
    if (input !== undefined) {
      if (prompt === undefined) {
        // Backends can emit several user-role setup records before a worker's
        // first reply. Its input is unknown; omit it and stop at subsequent input.
        if (workerResponded) finish(timestamp);
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

export const MAX_SCAN_ROLLOUT_SESSIONS = 4096;

export interface ScanRolloutSession {
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
  },
): Promise<ScanRolloutSession[]> {
  const execution = [
    options.rootThreadId,
    ...(options.executionThreadIds ?? []),
  ];
  const sessions = await selectSessionCopies(
    {
      scanId: options.rootThreadId,
      executionThreadIds: execution,
      codexHome: options.codexHome,
      allowMissingRoot: true,
    },
    options,
  );
  if (sessions.length > MAX_SCAN_ROLLOUT_SESSIONS) {
    throw new CodexSecurityError(
      `Scan rollout index exceeds ${MAX_SCAN_ROLLOUT_SESSIONS} sessions.`,
    );
  }
  const byId = new Map(sessions.map((copies) => [copies[0].threadId, copies]));
  const registered = new Set(execution);
  type Capture = {
    session: SessionLog;
    prompt?: string;
    window: RolloutWindow;
    children?: RolloutWindow;
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
      if (prompt === undefined && !inRolloutWindow(session.timestamp, options))
        return null;
      if (!registered.has(id)) {
        const parent =
          session.parentThreadId && (await capture(session.parentThreadId));
        // Spawn metadata names a parent thread, not its turn. Creation at the
        // very same clock tick as either boundary cannot prove ownership.
        if (
          !parent ||
          !parent.children ||
          !session.timestamp ||
          compareTimestamps(session.timestamp, parent.children.startedAt) <=
            0 ||
          !inRolloutWindow(session.timestamp, parent.children)
        )
          return null;
      }
      const window =
        session.timestamp &&
        compareTimestamps(session.timestamp, options.startedAt) > 0
          ? { ...options, startedAt: session.timestamp }
          : options;
      const match: TurnMatch = { count: 0 };
      // Establish uniqueness without keeping whole rollouts in memory.
      for await (const _ of retainedTurnEvents(
        session,
        window,
        prompt,
        match,
      )) {
        /* drain */
      }
      return match.count === 1
        ? { session, prompt, window, children: match.window }
        : null;
    })();
    captures.set(id, result);
    return result;
  }
  return sessions.map(([session]) => ({
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
      const match: TurnMatch = { count: 0 };
      yield* retainedTurnEvents(
        selected.session,
        selected.window,
        selected.prompt,
        match,
      );
      if (
        match.count !== 1 ||
        !isDeepStrictEqual(match.window, selected.children)
      )
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
  root: SessionLog,
  options: ScanLogOptions,
): boolean {
  const { scanDirectory, completedAt } = options;
  if (
    scanDirectory === undefined ||
    session.workingDirectory === null ||
    root.startedAt === null ||
    session.startedAt === null ||
    session.startedAt < root.startedAt
  ) {
    return false;
  }
  if (completedAt !== undefined && completedAt !== null) {
    const completed = Date.parse(completedAt);
    if (!Number.isFinite(completed) || session.startedAt >= completed) {
      return false;
    }
  }

  const roots = [scanDirectory];
  const name = basename(scanDirectory);
  const marker = name.lastIndexOf(".previous-");
  if (
    marker > 0 &&
    root.workingDirectory !== null &&
    relative(
      join(dirname(scanDirectory), name.slice(0, marker)),
      root.workingDirectory,
    ) === ""
  ) {
    roots.push(root.workingDirectory);
  }

  for (const directoryRoot of roots) {
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

async function* sessionEvents(
  path: string,
  strict = false,
): AsyncGenerator<Record<string, unknown>> {
  const file = createReadStream(path);
  const stream = path.endsWith(".zst")
    ? pipeline(file, zlib.createZstdDecompress(), () => {})
    : file;
  const lines = createInterface({ input: stream, crlfDelay: Infinity });
  try {
    for await (const line of lines) {
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
  } finally {
    lines.close();
    stream.destroy();
  }
}
