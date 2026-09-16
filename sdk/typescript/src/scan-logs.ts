import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { appendFile, mkdir } from "node:fs/promises";
import { basename, dirname, join, relative } from "node:path";
import { createInterface } from "node:readline";
import { isDeepStrictEqual } from "node:util";
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

// The SDK owns these calls even when a scan was sealed before they started.
// Record observed rollout task IDs separately from canonical scan artifacts.
export async function* recordScanLogTurn<T extends { readonly type: string }>(
  options: { scanId: string; threadId: string; codexHome: string },
  run: () => Promise<{ events: AsyncGenerator<T> }>,
  onError: (error: unknown) => void,
): AsyncGenerator<T> {
  const taskIds = async () => {
    const session = await findScanSession(options.codexHome, options.threadId);
    const ids = new Set<string>();
    if (session !== null) {
      for await (const event of sessionEvents(session.path)) {
        const payload = event["payload"];
        if (
          event["type"] === "event_msg" &&
          isRecord(payload) &&
          payload["type"] === "task_started" &&
          typeof payload["turn_id"] === "string"
        )
          ids.add(payload["turn_id"]);
      }
    }
    return ids;
  };
  let seen: Set<string> | undefined;
  try {
    seen = await taskIds();
  } catch (error) {
    onError(error);
  }
  const record = async () => {
    if (seen === undefined) return;
    try {
      const added = [...(await taskIds())].filter((id) => !seen!.has(id));
      if (added.length === 0) return;
      const path = scanLogTurnsPath(options.codexHome, options.scanId);
      await mkdir(dirname(path), { recursive: true, mode: 0o700 });
      await appendFile(
        path,
        added
          .map(
            (turnId) =>
              JSON.stringify({ threadId: options.threadId, turnId }) + "\n",
          )
          .join(""),
        { mode: 0o600 },
      );
      for (const id of added) seen.add(id);
    } catch (error) {
      onError(error);
    }
  };
  try {
    for await (const event of (await run()).events) {
      if (event.type === "turn.started") await record();
      yield event;
    }
  } finally {
    await record();
  }
}

function scanLogTurnsPath(codexHome: string, scanId: string): string {
  return join(
    codexHome,
    "scan-log-turns",
    createHash("sha256").update(scanId).digest("hex") + ".jsonl",
  );
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

  const included = new Set([
    ...(options.threadId ? [options.threadId] : []),
    ...(options.threadIds ?? []),
    ...(options.executionThreadIds ?? []),
  ]);
  // A Desktop owner can contain other work. Include its log without treating
  // the whole conversation tree as part of this scan.
  const traversed = new Set(options.executionThreadIds ?? included);
  const pending = [...traversed];
  for (const parentId of pending) {
    const parent = logs.get(parentId)?.[0];
    for (const [session] of logs.values()) {
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
    const copies = logs.get(threadId);
    if (copies === undefined) continue;
    let session = copies[0];
    for (const copy of copies.slice(1)) {
      if (await extendsSessionLog(session.path, copy.path)) session = copy;
    }
    sessions.push(session);
  }
  const ownedTurns = new Map<string, Set<string>>();
  for (const home of homes) {
    for await (const record of sessionEvents(
      scanLogTurnsPath(home, options.scanId),
    )) {
      if (
        typeof record["threadId"] !== "string" ||
        typeof record["turnId"] !== "string"
      )
        continue;
      const turns = ownedTurns.get(record["threadId"]) ?? new Set<string>();
      turns.add(record["turnId"]);
      ownedTurns.set(record["threadId"], turns);
    }
  }
  const completedAt = Date.parse(options.completedAt ?? "");
  const events: Record<string, unknown>[] = [];
  for (const session of sessions) {
    let replaying = false;
    let scanTurn = false;
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
      const timestamp =
        typeof event["timestamp"] === "string"
          ? Date.parse(event["timestamp"])
          : NaN;
      if (
        event["type"] === "event_msg" &&
        isRecord(payload) &&
        payload["type"] === "task_started"
      ) {
        // Completion is recorded before the terminal tool result and reply.
        scanTurn =
          timestamp <= completedAt ||
          (typeof payload["turn_id"] === "string" &&
            ownedTurns.get(session.threadId)?.has(payload["turn_id"]) === true);
      }
      if (!scanTurn && timestamp > completedAt) {
        continue;
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
