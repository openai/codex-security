import { createReadStream } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";
import { createInterface } from "node:readline";
import { sessionFiles } from "./cost.js";
import { CodexSecurityError } from "./errors.js";

interface ScanLogOptions {
  scanId: string;
  threadId: string;
  codexHome: string;
  scanDirectory?: string;
  completedAt?: string | null;
}

interface SessionLog {
  threadId: string;
  parentThreadId: string | null;
  startedAt: number | null;
  workingDirectory: string | null;
  path: string;
}

export async function readScanLogs(options: ScanLogOptions) {
  const logs = new Map<string, SessionLog>();
  for await (const path of sessionFiles(join(options.codexHome, "sessions"))) {
    for await (const first of sessionEvents(path)) {
      if (first["type"] !== "session_meta" || !isRecord(first["payload"])) {
        break;
      }
      const metadata = first["payload"];
      const threadId = metadata["id"];
      if (typeof threadId !== "string") break;
      const source = metadata["source"];
      const subagent = isRecord(source) ? source["subagent"] : undefined;
      const spawn = isRecord(subagent) ? subagent["thread_spawn"] : undefined;
      const parent =
        metadata["parent_thread_id"] ??
        (isRecord(spawn) ? spawn["parent_thread_id"] : undefined);
      const startedAt =
        typeof metadata["timestamp"] === "string"
          ? Date.parse(metadata["timestamp"])
          : Number.NaN;
      logs.set(threadId, {
        threadId,
        parentThreadId: typeof parent === "string" ? parent : null,
        startedAt: Number.isFinite(startedAt) ? startedAt : null,
        workingDirectory:
          typeof metadata["cwd"] === "string" ? metadata["cwd"] : null,
        path,
      });
      break;
    }
  }

  const root = logs.get(options.threadId);
  if (root === undefined) {
    throw new CodexSecurityError(
      `No saved session logs are available for scan ${options.scanId}.`,
    );
  }

  const sessions = [root];
  const included = new Set([root.threadId]);
  for (const parent of sessions) {
    for (const session of logs.values()) {
      if (
        !included.has(session.threadId) &&
        (session.parentThreadId === parent.threadId ||
          (parent === root &&
            session.parentThreadId === null &&
            belongsToScan(session, root, options)))
      ) {
        included.add(session.threadId);
        sessions.push(session);
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
    threadId: root.threadId,
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
    const artifacts = join(directoryRoot, "artifacts");
    if (relative(artifacts, session.workingDirectory) === "") return true;
    const workers = join(artifacts, "deep_discovery", "workers");
    const directory = relative(workers, session.workingDirectory);
    const components = directory.split(sep);
    if (
      !isAbsolute(directory) &&
      components.length === 2 &&
      components[0] !== ".." &&
      relative(
        join(workers, components[0]!, "output"),
        session.workingDirectory,
      ) === ""
    ) {
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
  } finally {
    lines.close();
    stream.destroy();
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
