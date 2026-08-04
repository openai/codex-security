import { open, readdir } from "node:fs/promises";
import { join } from "node:path";

export interface ScanTokenUsage {
  input_tokens: number;
  cached_input_tokens: number;
  cache_write_input_tokens: number;
  output_tokens: number;
  reasoning_output_tokens: number;
  total_tokens: number;
}

export interface CodexRolloutSession {
  readonly path: string;
  readonly threadId: string;
  readonly parentThreadId: string | null;
  readonly usage: Readonly<ScanTokenUsage> | null;
}

export interface CodexRolloutSnapshot {
  readonly rootThreadId: string;
  readonly complete: boolean;
  readonly sessions: readonly CodexRolloutSession[];
}

interface SessionState {
  offset: number;
  pendingLine: Buffer[];
  pendingLineBytes: number;
  unreadable: boolean;
  threadId: string | null;
  parentThreadId: string | null;
  usage: ScanTokenUsage | null;
}

const SESSION_READ_SIZE = 64 * 1_024;
const MAX_SESSION_EVENT_BYTES = 1 * 1_024 * 1_024;

export class CodexRolloutReader {
  readonly #sessionsRoot: string;
  readonly #sessions = new Map<string, SessionState>();
  #lastRootThreadId: string | null = null;
  #lastRefreshComplete = false;

  public constructor(codexHome: string) {
    this.#sessionsRoot = join(codexHome, "sessions");
  }

  public async refresh(
    rootThreadId: string,
  ): Promise<readonly CodexRolloutSession[]> {
    this.#lastRootThreadId = rootThreadId;
    this.#lastRefreshComplete = false;
    const unreadable: Array<{ session: SessionState; error: unknown }> = [];
    for await (const path of sessionFiles(this.#sessionsRoot)) {
      let session = this.#sessions.get(path);
      if (session === undefined) {
        session = {
          offset: 0,
          pendingLine: [],
          pendingLineBytes: 0,
          unreadable: false,
          threadId: null,
          parentThreadId: null,
          usage: null,
        };
        this.#sessions.set(path, session);
      }
      try {
        await readSession(path, session);
      } catch (error) {
        unreadable.push({ session, error });
      }
    }

    const included = this.#includedThreadIds(rootThreadId);
    for (const { session, error } of unreadable) {
      if (session.threadId === null || included.has(session.threadId)) {
        throw error;
      }
    }
    this.#lastRefreshComplete = true;
    return this.#relatedSessions(rootThreadId, included);
  }

  public snapshot(rootThreadId: string): CodexRolloutSnapshot {
    const included = this.#includedThreadIds(rootThreadId);
    const sessions = this.#relatedSessions(rootThreadId, included);
    return {
      rootThreadId,
      complete:
        this.#lastRefreshComplete &&
        this.#lastRootThreadId === rootThreadId &&
        sessions.some((session) => session.threadId === rootThreadId),
      sessions,
    };
  }

  #includedThreadIds(rootThreadId: string): Set<string> {
    const included = new Set([rootThreadId]);
    let changed = true;
    while (changed) {
      changed = false;
      for (const session of this.#sessions.values()) {
        if (
          session.threadId !== null &&
          session.parentThreadId !== null &&
          included.has(session.parentThreadId) &&
          !included.has(session.threadId)
        ) {
          included.add(session.threadId);
          changed = true;
        }
      }
    }
    return included;
  }

  #relatedSessions(
    rootThreadId: string,
    included = this.#includedThreadIds(rootThreadId),
  ): readonly CodexRolloutSession[] {
    return [...this.#sessions.entries()]
      .flatMap(([path, session]): CodexRolloutSession[] =>
        session.threadId !== null && included.has(session.threadId)
          ? [
              {
                path,
                threadId: session.threadId,
                parentThreadId: session.parentThreadId,
                usage: session.usage,
              },
            ]
          : [],
      )
      .sort((left, right) => {
        if (left.threadId === rootThreadId) return -1;
        if (right.threadId === rootThreadId) return 1;
        return left.path.localeCompare(right.path);
      });
  }
}

async function* sessionFiles(directory: string): AsyncGenerator<string> {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    if (isMissingFile(error)) return;
    throw error;
  }
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      yield* sessionFiles(path);
    } else if (entry.isFile() && entry.name.endsWith(".jsonl")) {
      yield path;
    }
  }
}

async function readSession(path: string, session: SessionState): Promise<void> {
  if (session.unreadable) return;
  let file;
  try {
    file = await open(path, "r");
  } catch (error) {
    if (isMissingFile(error)) return;
    throw error;
  }
  try {
    const buffer = Buffer.alloc(SESSION_READ_SIZE);
    while (true) {
      const { bytesRead } = await file.read(
        buffer,
        0,
        buffer.length,
        session.offset,
      );
      if (bytesRead === 0) return;
      session.offset += bytesRead;
      try {
        readSessionChunk(buffer.subarray(0, bytesRead), session);
      } catch (error) {
        session.unreadable = true;
        session.pendingLine = [];
        session.pendingLineBytes = 0;
        throw error;
      }
    }
  } finally {
    await file.close();
  }
}

function readSessionChunk(contents: Buffer, session: SessionState): void {
  let lineStart = 0;
  while (lineStart < contents.length) {
    const newline = contents.indexOf(0x0a, lineStart);
    const lineEnd = newline === -1 ? contents.length : newline;
    const fragment = contents.subarray(lineStart, lineEnd);
    const lineBytes = session.pendingLineBytes + fragment.length;
    if (lineBytes > MAX_SESSION_EVENT_BYTES) {
      throw new Error("Codex session event exceeds the 1 MiB safety limit.");
    }

    if (newline === -1) {
      if (fragment.length > 0) {
        session.pendingLine.push(Buffer.from(fragment));
        session.pendingLineBytes = lineBytes;
      }
      return;
    }

    if (session.pendingLineBytes === 0) {
      readSessionEvent(fragment.toString("utf8"), session);
    } else {
      if (fragment.length > 0) session.pendingLine.push(Buffer.from(fragment));
      readSessionEvent(
        Buffer.concat(session.pendingLine, lineBytes).toString("utf8"),
        session,
      );
      session.pendingLine = [];
      session.pendingLineBytes = 0;
    }
    lineStart = newline + 1;
  }
}

function readSessionEvent(line: string, session: SessionState): void {
  if (line.length === 0) return;
  let event: unknown;
  try {
    event = JSON.parse(line) as unknown;
  } catch {
    return;
  }
  if (!isRecord(event) || !isRecord(event["payload"])) return;
  const payload = event["payload"];
  if (event["type"] === "session_meta") {
    if (typeof payload["id"] === "string") {
      session.threadId = payload["id"];
    }
    const source = payload["source"];
    const subagent = isRecord(source) ? source["subagent"] : undefined;
    const spawn = isRecord(subagent) ? subagent["thread_spawn"] : undefined;
    const parent =
      payload["parent_thread_id"] ??
      (isRecord(spawn) ? spawn["parent_thread_id"] : undefined);
    if (typeof parent === "string") session.parentThreadId = parent;
    return;
  }
  if (
    event["type"] !== "event_msg" ||
    payload["type"] !== "token_count" ||
    !isRecord(payload["info"])
  ) {
    return;
  }
  const usage = normalizeTokenUsage(payload["info"]["total_token_usage"]);
  if (usage !== null) session.usage = usage;
}

export function normalizeTokenUsage(value: unknown): ScanTokenUsage | null {
  if (!isRecord(value)) return null;
  const input = value["input_tokens"];
  const cached = value["cached_input_tokens"] ?? 0;
  const cacheWrite =
    value["cache_write_input_tokens"] ?? value["cache_write_tokens"] ?? 0;
  const output = value["output_tokens"];
  const reasoning = value["reasoning_output_tokens"] ?? 0;
  if (
    !isTokenCount(input) ||
    !isTokenCount(cached) ||
    !isTokenCount(cacheWrite) ||
    !isTokenCount(output) ||
    !isTokenCount(reasoning) ||
    cached + cacheWrite > input ||
    reasoning > output
  ) {
    return null;
  }
  return {
    input_tokens: input,
    cached_input_tokens: cached,
    cache_write_input_tokens: cacheWrite,
    output_tokens: output,
    reasoning_output_tokens: reasoning,
    total_tokens: input + output,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isMissingFile(error: unknown): boolean {
  return isRecord(error) && error["code"] === "ENOENT";
}

function isTokenCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
