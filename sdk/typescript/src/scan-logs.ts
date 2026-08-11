import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { sessionFiles } from "./cost.js";
import { CodexSecurityError } from "./errors.js";

interface ScanLogOptions {
  scanId: string;
  threadId: string;
  codexHome: string;
}

interface SessionLog {
  threadId: string;
  parentThreadId: string | null;
  startedAt: number | null;
  path: string;
  events: Record<string, unknown>[];
}

export async function readScanLogs(options: ScanLogOptions) {
  const logs = new Map<string, SessionLog>();
  for await (const path of sessionFiles(join(options.codexHome, "sessions"))) {
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

  const sessions = [root];
  for (const parent of sessions) {
    for (const session of logs.values()) {
      if (session.parentThreadId === parent.threadId) sessions.push(session);
    }
  }
  const events: Record<string, unknown>[] = [];
  for (const session of sessions) {
    let replaying = false;
    for (const event of session.events) {
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
          payload["started_at"] < session.startedAt
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
    threadId: root.threadId,
    sessions: sessions.map(({ threadId, parentThreadId, path }) => ({
      threadId,
      parentThreadId,
      path,
    })),
    events,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
