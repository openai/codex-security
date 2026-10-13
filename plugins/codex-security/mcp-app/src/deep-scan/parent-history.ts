import { createReadStream } from "node:fs";
import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { isDeepStrictEqual } from "node:util";
import { isRecord } from "../record.js";

/** Read the original owner's canonical native rollout, including archived copies. */
export async function readOriginalParentEvents(
  home: string,
  threadId: string,
): Promise<Record<string, unknown>[]> {
  let selected: Record<string, unknown>[] | undefined;
  let startedAt = Number.NaN;
  for (const directory of ["sessions", "archived_sessions"]) {
    for await (const file of sessionFiles(join(home, directory))) {
      const records = await sessionEvents(file, threadId);
      const first = records[0];
      const metadata = first?.["payload"];
      if (
        first?.["type"] !== "session_meta" ||
        !isRecord(metadata) ||
        metadata["id"] !== threadId
      )
        continue;
      // A divergent copy cannot replace the original. Prefer a longer copy only
      // when every original event remains its prefix.
      if (
        selected === undefined ||
        (records.length > selected.length &&
          selected.every((event, index) =>
            isDeepStrictEqual(event, records[index]),
          ))
      ) {
        selected = records;
        startedAt =
          typeof metadata["timestamp"] === "string"
            ? Date.parse(metadata["timestamp"])
            : Number.NaN;
      }
    }
  }
  const events: Record<string, unknown>[] = [];
  let replaying = false;
  for (const event of selected ?? []) {
    const payload = event["payload"];
    if (event["type"] === "session_meta" && isRecord(payload))
      replaying = payload["id"] !== threadId;
    if (replaying) {
      if (
        event["type"] !== "event_msg" ||
        !isRecord(payload) ||
        payload["type"] !== "task_started" ||
        typeof payload["started_at"] !== "number" ||
        !Number.isFinite(startedAt) ||
        payload["started_at"] < Math.floor(startedAt / 1000)
      )
        continue;
      replaying = false;
    }
    events.push(event);
  }
  return events;
}

async function* sessionFiles(directory: string): AsyncGenerator<string> {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) yield* sessionFiles(path);
    else if (entry.isFile() && entry.name.endsWith(".jsonl")) yield path;
  }
}
async function sessionEvents(
  path: string,
  threadId: string,
): Promise<Record<string, unknown>[]> {
  const events: Record<string, unknown>[] = [];
  const stream = createReadStream(path, { encoding: "utf8" });
  const lines = createInterface({ input: stream, crlfDelay: Infinity });
  try {
    for await (const line of lines) {
      if (line.trim() === "") continue;
      try {
        const event: unknown = JSON.parse(line);
        if (!isRecord(event)) continue;
        if (events.length === 0) {
          const metadata = event["payload"];
          if (
            event["type"] !== "session_meta" ||
            !isRecord(metadata) ||
            metadata["id"] !== threadId
          )
            return [];
        }
        events.push(event);
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
  return events;
}
