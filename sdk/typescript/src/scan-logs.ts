import { createReadStream } from "node:fs";
import { basename, dirname, join, relative } from "node:path";
import { createInterface } from "node:readline";
import { sessionFiles } from "./cost.js";
import { CodexSecurityError } from "./errors.js";
import type { JsonObject } from "./config.js";
import {
  attributedScanThreads,
  isAttributedScanEvent,
  isScanArtifactDirectory,
  sessionParentThreadId,
  sessionStartedAt,
  type ScanExecutionAttribution,
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
  executionAttribution?: ScanExecutionAttribution | null;
}

export type ScanLogSource = JsonObject & {
  scanId: string;
  continuationThreadId?: string;
  threadIds?: string[];
  executionThreadIds?: string[];
  executionAttribution?: ScanExecutionAttribution | null;
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
    executionAttribution: scan.executionAttribution,
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

interface SessionLog {
  threadId: string;
  parentThreadId: string | null;
  startedAt: number | null;
  workingDirectory: string | null;
  path: string;
}

async function* scanSessions(
  codexHome: string,
  directory = "sessions",
): AsyncGenerator<SessionLog> {
  for await (const path of sessionFiles(join(codexHome, directory))) {
    for await (const first of sessionEvents(path)) {
      if (first["type"] !== "session_meta" || !isRecord(first["payload"])) {
        break;
      }
      const metadata = first["payload"];
      const threadId = metadata["id"];
      if (typeof threadId !== "string") break;
      yield {
        threadId,
        parentThreadId: sessionParentThreadId(metadata),
        startedAt: sessionStartedAt(metadata["timestamp"]),
        workingDirectory:
          typeof metadata["cwd"] === "string" ? metadata["cwd"] : null,
        path,
      };
      break;
    }
  }
}

export async function findScanSession(
  codexHome: string,
  threadId: string,
): Promise<SessionLog | null> {
  for await (const session of scanSessions(codexHome)) {
    if (session.threadId === threadId) return session;
  }
  return null;
}

export async function readScanLogs(options: ScanLogOptions) {
  const logs = new Map<string, SessionLog>();
  const homes = new Set(
    typeof options.codexHome === "string"
      ? [options.codexHome]
      : options.codexHome,
  );
  for (const directory of ["sessions", "archived_sessions"]) {
    for (const home of homes) {
      for await (const session of scanSessions(home, directory)) {
        if (!logs.has(session.threadId)) logs.set(session.threadId, session);
      }
    }
  }

  const root = options.threadId ? logs.get(options.threadId) : undefined;
  if (root === undefined && !options.allowMissingRoot) {
    throw new CodexSecurityError(
      `No saved session logs are available for scan ${options.scanId}.`,
    );
  }

  const attribution = options.executionAttribution?.legacy
    ? null
    : options.executionAttribution;
  const included = attribution
    ? attributedScanThreads(logs.values(), attribution)
    : new Set([
        ...(options.threadId ? [options.threadId] : []),
        ...(options.threadIds ?? []),
        ...(options.executionThreadIds ?? []),
      ]);
  // A Desktop owner can contain other work. Include its log without treating
  // the whole conversation tree as part of this scan.
  const traversed = new Set(options.executionThreadIds ?? included);
  const pending = attribution ? [] : [...traversed];
  for (const parentId of pending) {
    const parent = logs.get(parentId);
    for (const session of logs.values()) {
      if (
        !traversed.has(session.threadId) &&
        (session.parentThreadId === parentId ||
          (root !== undefined &&
            parent === root &&
            session.parentThreadId === null &&
            belongsToScan(session, root, options)))
      ) {
        included.add(session.threadId);
        traversed.add(session.threadId);
        pending.push(session.threadId);
      }
    }
  }
  const sessions: SessionLog[] = [];
  for (const threadId of included) {
    const session = logs.get(threadId);
    if (session !== undefined) sessions.push(session);
  }
  const events: Record<string, unknown>[] = [];
  for (const session of sessions) {
    let replaying = false;
    let turnId: string | null = null;
    for await (const event of sessionEvents(session.path)) {
      const payload = event["payload"];
      if (
        isRecord(payload) &&
        (event["type"] === "turn_context" ||
          payload["type"] === "task_started") &&
        typeof payload["turn_id"] === "string"
      ) {
        turnId = payload["turn_id"];
      }
      if (event["type"] === "session_meta" && isRecord(payload)) {
        replaying = payload["id"] !== session.threadId;
      }
      if (replaying) {
        if (
          event["type"] !== "event_msg" ||
          !isRecord(payload) ||
          payload["type"] !== "task_started" ||
          typeof payload["started_at"] !== "number" ||
          session.startedAt === null ||
          payload["started_at"] < Math.floor(session.startedAt / 1_000)
        ) {
          continue;
        }
        replaying = false;
      }
      if (
        !attribution ||
        event["type"] === "session_meta" ||
        isAttributedScanEvent(
          attribution,
          session.threadId,
          event["type"] === "token_usage_record" &&
            isRecord(payload) &&
            typeof payload["turn_id"] === "string"
            ? payload["turn_id"]
            : turnId,
          event["timestamp"],
        )
      ) {
        events.push({ threadId: session.threadId, event });
      }
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

async function* sessionEvents(
  path: string,
): AsyncGenerator<Record<string, unknown>> {
  const stream = createReadStream(path, { encoding: "utf8" });
  const lines = createInterface({ input: stream, crlfDelay: Infinity });
  try {
    for await (const line of lines) {
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
  } finally {
    lines.close();
    stream.destroy();
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
