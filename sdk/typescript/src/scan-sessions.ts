import { isAbsolute, join, relative, sep } from "node:path";

export interface ScanExecutionAttribution {
  formatVersion: 1;
  legacy?: true;
  executionThreadIds: string[];
  owner: { threadId: string | null; turnId: string | null; startedAt: string };
  startedAt: string;
  completedAt: string | null;
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
