import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { CodexSecurityError, redactedErrorMessage } from "./errors.js";
import {
  scanActivityFromSessionEvent,
  type ScanActivity,
} from "./scan-activity.js";

interface ScanLogOptions {
  scanId: string;
  threadId: string;
  repository: string;
  codexHome: string;
  raw?: boolean;
}

interface SessionLog {
  threadId: string;
  parentThreadId: string | null;
  startedAt: number | null;
  path: string;
  events: Record<string, unknown>[];
}

export interface ScanLogs {
  scanId: string;
  threadId: string;
  sessions: Array<{
    threadId: string;
    parentThreadId: string | null;
    path: string;
  }>;
  events: Record<string, unknown>[];
}

export async function readScanLogs(options: ScanLogOptions): Promise<ScanLogs> {
  const logs = new Map<string, SessionLog>();
  for (const path of await sessionPaths(join(options.codexHome, "sessions"))) {
    const events = (await readFile(path, "utf8"))
      .split("\n")
      .filter((line) => line.trim() !== "")
      .flatMap((line) => {
        try {
          const event: unknown = JSON.parse(line);
          return isRecord(event) ? [event] : [];
        } catch {
          return [];
        }
      });
    const first = events[0];
    if (first?.["type"] !== "session_meta" || !isRecord(first["payload"])) {
      continue;
    }
    const metadata = first["payload"];
    const threadId = metadata["id"];
    if (typeof threadId !== "string") continue;
    const source = metadata["source"];
    const subagent = isRecord(source) ? source["subagent"] : undefined;
    const spawn = isRecord(subagent) ? subagent["thread_spawn"] : undefined;
    const parent =
      metadata["parent_thread_id"] ??
      (isRecord(spawn) ? spawn["parent_thread_id"] : undefined);
    logs.set(threadId, {
      threadId,
      parentThreadId: typeof parent === "string" ? parent : null,
      startedAt:
        typeof metadata["timestamp"] === "string"
          ? Math.floor(Date.parse(metadata["timestamp"]) / 1_000)
          : null,
      path,
      events,
    });
  }

  const root = logs.get(options.threadId);
  if (root === undefined) {
    throw new CodexSecurityError(
      `No saved session logs are available for scan ${options.scanId}.`,
    );
  }

  const included = new Set([root.threadId]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const session of logs.values()) {
      if (
        session.parentThreadId !== null &&
        included.has(session.parentThreadId) &&
        !included.has(session.threadId)
      ) {
        included.add(session.threadId);
        changed = true;
      }
    }
  }

  const sessions = [
    root,
    ...[...logs.values()].filter(
      (session) =>
        session.threadId !== root.threadId && included.has(session.threadId),
    ),
  ];
  const events: Record<string, unknown>[] = [];
  for (const session of sessions) {
    const calls = new Map<string, ScanActivity>();
    let replaying = false;
    for (const event of session.events) {
      const payload = event["payload"];
      if (event["type"] === "session_meta" && isRecord(payload)) {
        replaying = payload["id"] !== session.threadId;
      } else if (replaying) {
        if (
          event["type"] === "event_msg" &&
          isRecord(payload) &&
          payload["type"] === "task_started" &&
          typeof payload["started_at"] === "number" &&
          session.startedAt !== null &&
          payload["started_at"] >= session.startedAt
        ) {
          replaying = false;
        } else {
          continue;
        }
      }
      if (replaying) continue;
      if (options.raw) {
        events.push({ threadId: session.threadId, event });
        continue;
      }
      let activity = scanActivityFromSessionEvent(event, options.repository);
      if (
        activity === null &&
        event["type"] === "response_item" &&
        isRecord(payload) &&
        (payload["type"] === "function_call_output" ||
          payload["type"] === "custom_tool_call_output") &&
        typeof payload["call_id"] === "string"
      ) {
        const call = calls.get(payload["call_id"]);
        if (call !== undefined) {
          activity = {
            ...call,
            status: payload["status"] === "failed" ? "failed" : "completed",
          };
          calls.delete(call.id);
        }
      }
      if (activity === null) continue;
      if (activity.status === "running") calls.set(activity.id, activity);
      events.push({
        threadId: session.threadId,
        ...(typeof event["timestamp"] === "string"
          ? { timestamp: event["timestamp"] }
          : {}),
        kind: activity.kind,
        status: activity.status,
        description: redactedErrorMessage(activity.description),
        ...(activity.paths.length === 0
          ? {}
          : {
              paths: activity.paths.map((path) => redactedErrorMessage(path)),
            }),
      });
    }
  }

  return {
    scanId: options.scanId,
    threadId: root.threadId,
    sessions: sessions.map(({ threadId, parentThreadId, path }) => ({
      threadId,
      parentThreadId,
      path,
    })),
    events,
  };
}

async function sessionPaths(directory: string): Promise<string[]> {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
  const paths = await Promise.all(
    entries.map(async (entry) => {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) return await sessionPaths(path);
      return entry.isFile() && entry.name.endsWith(".jsonl") ? [path] : [];
    }),
  );
  return paths.flat();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
