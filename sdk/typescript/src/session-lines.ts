/* Generated from plugin session-lines.ts. Run `pnpm generate:models`. */
import { createReadStream } from "node:fs";
import { readdir } from "node:fs/promises";
import { basename, join } from "node:path";
import { createInterface } from "node:readline";
import { pipeline } from "node:stream";
import { isDeepStrictEqual } from "node:util";
import zlib from "node:zlib";
import { isRecord } from "./record.js";
import { createZstdDecompress } from "./session-decompression.js";

export async function* sessionFiles(
  directory: string,
  compressed = false,
): AsyncGenerator<string> {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    if (isRecord(error) && error["code"] === "ENOENT") return;
    throw error;
  }
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      yield* sessionFiles(path, compressed);
    } else if (
      entry.isFile() &&
      (entry.name.endsWith(".jsonl") ||
        (compressed && entry.name.endsWith(".jsonl.zst")))
    ) {
      yield path;
    }
  }
}

export function compressedSessionThreadId(path: string): string | null {
  return (
    /^rollout-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-([\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12})(?:_[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12})?\.jsonl\.zst$/u.exec(
      basename(path),
    )?.[1] ?? null
  );
}

/** Plain and cold compressed rollouts have the same newline-delimited format. */
export async function* sessionLines(path: string): AsyncGenerator<string> {
  const decompressor = path.endsWith(".zst")
    ? await createZstdDecompress()
    : null;
  const file = createReadStream(path);
  const stream =
    decompressor !== null ? pipeline(file, decompressor, () => {}) : file;
  const lines = createInterface({ input: stream, crlfDelay: Infinity });
  try {
    yield* lines;
  } finally {
    lines.close();
    stream.destroy();
  }
}

/** Native zstd can stop at the first frame. Only a newline completes a header. */
export async function firstNativeSessionLine(
  path: string,
): Promise<string | undefined> {
  if (!path.endsWith(".zst") || typeof zlib.createZstdDecompress !== "function")
    return;
  const stream = pipeline(
    createReadStream(path),
    zlib.createZstdDecompress(),
    () => {},
  );
  try {
    stream.setEncoding("utf8");
    let line = "";
    for await (const chunk of stream as AsyncIterable<string>) {
      const newline = chunk.search(/[\r\n]/u);
      if (newline >= 0) return line + chunk.slice(0, newline);
      line += chunk;
    }
  } catch {
    // The complete portable reader handles unsupported or damaged frames.
  } finally {
    stream.destroy();
  }
}

function sessionEvent(line: string): Record<string, unknown> | undefined {
  try {
    const event: unknown = JSON.parse(line);
    if (isRecord(event)) return event;
  } catch {
    // Rollouts can include malformed or incomplete JSON lines.
  }
}

export async function firstSessionEvent(path: string) {
  const line = await firstNativeSessionLine(path);
  if (line !== undefined) {
    const event = sessionEvent(line);
    if (event !== undefined) return event;
  }
  // Also handles metadata split across frames and malformed prefix lines.
  for await (const event of sessionEvents(path)) return event;
}

export async function* sessionEvents(
  path: string,
): AsyncGenerator<Record<string, unknown>> {
  try {
    for await (const line of sessionLines(path)) {
      const event = sessionEvent(line);
      if (event !== undefined) yield event;
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

// Prefer a longer copy only when it preserves every event in the earlier copy.
// Identical or divergent copies keep the existing home/archive precedence.
export async function extendsSessionLog(
  previousPath: string,
  path: string,
  selectedEvents = sessionEvents,
): Promise<boolean> {
  const events = selectedEvents(path);
  try {
    for await (const previous of selectedEvents(previousPath)) {
      const next = await events.next();
      if (next.done || !isDeepStrictEqual(previous, next.value)) return false;
    }
    return !(await events.next()).done;
  } finally {
    await events.return(undefined);
  }
}

export function sessionStartedAt(timestamp: unknown): number | null {
  const startedAt =
    typeof timestamp === "string" ? Date.parse(timestamp) : Number.NaN;
  return Number.isFinite(startedAt) ? startedAt : null;
}

export function sessionOwnsTurn(
  session: { threadId: string | null; startedAt: number | null },
  payload: Readonly<Record<string, unknown>>,
): boolean {
  // Fresh Codex worker thread/turn IDs share a same-process monotonic UUIDv7 generator.
  const threadOrder = uuid7Order(session.threadId);
  const turnOrder = uuid7Order(payload["turn_id"]);
  return threadOrder === null
    ? typeof payload["started_at"] === "number" &&
        session.startedAt !== null &&
        payload["started_at"] >= Math.floor(session.startedAt / 1_000)
    : turnOrder !== null && turnOrder >= threadOrder;
}

function uuid7Order(value: unknown): bigint | null {
  if (
    typeof value !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(
      value,
    )
  ) {
    return null;
  }
  return BigInt(`0x${value.replaceAll("-", "")}`);
}

// A forked rollout can replay its parent until the next task owned by this session.
export function replayingSessionEvent(
  event: Record<string, unknown>,
  session: { threadId: string | null; startedAt: number | null },
  replaying: boolean,
): boolean {
  const payload = event["payload"];
  if (event["type"] === "session_meta" && isRecord(payload))
    return payload["id"] !== session.threadId;
  return (
    replaying &&
    !(
      event["type"] === "event_msg" &&
      isRecord(payload) &&
      payload["type"] === "task_started" &&
      sessionOwnsTurn(session, payload)
    )
  );
}
