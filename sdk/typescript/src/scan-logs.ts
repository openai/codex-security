import { createReadStream } from "node:fs";
import { basename, dirname, join, relative } from "node:path";
import { createInterface } from "node:readline";
import { sessionFiles } from "./cost.js";
import { CodexSecurityError } from "./errors.js";
import type { JsonObject } from "./config.js";
import {
  isScanArtifactDirectory,
  sessionParentThreadId,
  sessionStartedAt,
} from "./scan-sessions.js";

interface ScanLogOptions {
  scanId: string;
  threadId?: string;
  threadIds?: readonly string[];
  codexHome: string | readonly string[];
  scanDirectory?: string;
  completedAt?: string | null;
  allowMissingRoot?: boolean;
}

export type ScanLogSource = JsonObject & {
  scanId: string;
  continuationThreadId?: string;
  threadIds?: string[];
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
    codexHome,
    allowMissingRoot: options.allowMissingRoot,
    scanDirectory: scan.mode === "deep" ? scan.scanDir : undefined,
    completedAt:
      scan.progress?.status === "running"
        ? null
        : scan.progress?.status === "complete" ||
            scan.progress?.status === "failed" ||
            scan.progress?.status === "canceled"
          ? scan.progress.updatedAt ?? ""
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

  const sessions: SessionLog[] = [];
  const included = new Set([
    ...(options.threadId ? [options.threadId] : []),
    ...(options.threadIds ?? []),
  ]);
  const pending = [...included];
  for (const parentId of pending) {
    const parent = logs.get(parentId);
    if (parent !== undefined) sessions.push(parent);
    for (const session of logs.values()) {
      if (
        !included.has(session.threadId) &&
        (session.parentThreadId === parentId ||
          (root !== undefined &&
            parent === root &&
            session.parentThreadId === null &&
            belongsToScan(session, root, options)))
      ) {
        included.add(session.threadId);
        pending.push(session.threadId);
      }
    }
  }
  const events: Record<string, unknown>[] = [];
  for (const session of sessions) {
    let replaying = false;
    for await (const event of sessionEvents(session.path)) {
      const payload = event["payload"];
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
