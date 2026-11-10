import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { firstNativeSessionLine, sessionLines } from "./session-lines.js";
import { parseJson } from "./value.js";
import { isRecord } from "./record.js";
import { sessionFiles } from "./cost.js";
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

async function* scanSessions(codexHome: string, directory = "sessions") {
  for await (const path of sessionFiles(join(codexHome, directory), true)) {
    const first = await firstSessionEvent(path);
    if (first?.["type"] !== "session_meta" || !isRecord(first["payload"]))
      continue;
    const metadata = first["payload"];
    const threadId = metadata["id"];
    if (typeof threadId !== "string") continue;
    yield {
      threadId,
      parentThreadId: sessionParentThreadId(metadata),
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

export async function readScanLogs(options: ScanLogOptions) {
  const logs = new Map<string, [SessionLog, ...SessionLog[]]>();
  const homes = new Set(
    typeof options.codexHome === "string"
      ? [options.codexHome]
      : options.codexHome,
  );
  for (const directory of ["sessions", "archived_sessions"]) {
    for (const home of homes) {
      for await (const session of scanSessions(home, directory)) {
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

  const startsAfterCompletion = (timestamp: unknown) =>
    typeof options.logCompletedAt === "string" &&
    typeof timestamp === "string" &&
    compareTimestamps(timestamp, options.logCompletedAt) >= 0;

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
      if (startsAfterCompletion(session.timestamp)) continue;
      included.add(session.threadId);
      traversed.add(session.threadId);
    }
  }
  const sessions: SessionLog[] = [];
  for (const threadId of included) {
    const copies = logs.get(threadId);
    if (copies === undefined) continue;
    let session = copies[0];
    for (const copy of copies.slice(1)) {
      if (await extendsSessionLog(session.path, copy.path)) session = copy;
    }
    sessions.push(session);
  }
  const events: Record<string, unknown>[] = [];
  // Recorded completion can precede the scan turn's final response. Keep that
  // turn's remaining events, then stop before a post-completion turn starts.
  for (const session of sessions) {
    let replaying = false;
    for await (const event of sessionEvents(session.path)) {
      const payload = event["payload"];
      if (event["type"] === "session_meta" && isRecord(payload)) {
        replaying = payload["id"] !== session.threadId;
      }
      const taskStarted =
        event["type"] === "event_msg" &&
        isRecord(payload) &&
        payload["type"] === "task_started";
      if (replaying) {
        if (!taskStarted || !sessionOwnsTurn(session, payload)) continue;
        replaying = false;
      }
      if (taskStarted && startsAfterCompletion(event["timestamp"])) break;
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
): AsyncGenerator<Record<string, unknown>> {
  try {
    for await (const line of sessionLines(path)) {
      if (line.trim() === "") continue;
      try {
        const event: unknown = JSON.parse(line);
        if (isRecord(event)) yield event;
      } catch {
        continue;
      }
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}
