import { stat } from "node:fs/promises";
import { isAbsolute, join, relative, sep } from "node:path";
import { isRecord } from "./record.js";

export async function recordedScanCodexHome(
  _scanDirectory: string,
  attribution?: ScanExecutionAttribution | null,
): Promise<string | undefined> {
  return attribution?.workerCodexHome ?? undefined;
}

export interface ScanExecutionAttribution {
  formatVersion: 1;
  legacy?: true;
  workerCodexHome?: string | null;
  executionThreadIds: string[];
  owner: {
    threadId: string | null;
    turnId: string | null;
    startedAt: string;
    dedicated?: boolean;
  };
  startedAt: string;
  completedAt: string | null;
}

/** Reuse attribution until SQLite changes; token-log polling remains independent. */
export function cachedScanAttributionReader(
  stateDirectory: string,
  read: () => Promise<ScanExecutionAttribution | null | undefined>,
): (force?: boolean) => Promise<ScanExecutionAttribution | null | undefined> {
  const database = join(stateDirectory, "workbench.sqlite3");
  let cachedKey: string | null = null;
  let cached: ScanExecutionAttribution | null | undefined;
  return async (force = false) => {
    const [main, wal] = await Promise.all([
      databaseSignature(database),
      databaseSignature(`${database}-wal`),
    ]);
    const key = main === null ? null : `${main};${wal}`;
    if (!force && key !== null && key === cachedKey) return cached;
    const value = await read();
    // Save the pre-read signature so a concurrent transaction is read next time.
    cachedKey = key;
    cached = value;
    return value;
  };
}

async function databaseSignature(path: string): Promise<string | null> {
  try {
    const metadata = await stat(path, { bigint: true });
    return `${metadata.dev}:${metadata.ino}:${metadata.size}:${metadata.mtimeNs}`;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

export function attributedScanThreads(
  sessions: Iterable<{
    threadId: string | null;
    parentThreadId: string | null;
  }>,
  attribution: ScanExecutionAttribution,
): Set<string> {
  const included = new Set(attribution.executionThreadIds);
  const pending = [...included];
  const all = [...sessions];
  for (const parent of pending) {
    for (const session of all) {
      if (
        session.threadId !== null &&
        session.parentThreadId === parent &&
        !included.has(session.threadId)
      ) {
        included.add(session.threadId);
        pending.push(session.threadId);
      }
    }
  }
  if (attribution.owner.threadId) included.add(attribution.owner.threadId);
  return included;
}

export function isAttributedScanEvent(
  attribution: ScanExecutionAttribution,
  threadId: string,
  turnId: string | null,
  timestamp: unknown,
): boolean {
  const time = sessionStartedAt(timestamp);
  if (
    time === null ||
    time < Date.parse(attribution.startedAt) ||
    (attribution.completedAt !== null &&
      time > Date.parse(attribution.completedAt))
  )
    return false;
  if (
    threadId !== attribution.owner.threadId ||
    attribution.executionThreadIds.includes(threadId)
  )
    return true;
  return (
    attribution.owner.turnId !== null && turnId === attribution.owner.turnId
  );
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

export function sessionParentThreadId(
  metadata: Readonly<Record<string, unknown>>,
): string | null {
  const source = metadata["source"];
  const subagent = isRecord(source) ? source["subagent"] : undefined;
  const spawn = isRecord(subagent) ? subagent["thread_spawn"] : undefined;
  for (const parent of [
    isRecord(spawn) ? spawn["parent_thread_id"] : undefined,
    metadata["parent_thread_id"],
    metadata["forked_from_id"],
  ]) {
    if (typeof parent === "string" && parent !== "") return parent;
  }
  return null;
}

export function isScanArtifactDirectory(
  scanDirectory: string,
  workingDirectory: string,
): boolean {
  const artifacts = join(scanDirectory, "artifacts");
  if (relative(artifacts, workingDirectory) === "") return true;

  const workers = join(artifacts, "deep_discovery", "workers");
  const directory = relative(workers, workingDirectory);
  const components = directory.split(sep);
  return (
    !isAbsolute(directory) &&
    components.length === 2 &&
    components[0] !== ".." &&
    relative(join(workers, components[0]!, "output"), workingDirectory) === ""
  );
}
