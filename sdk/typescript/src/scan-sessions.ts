import { isAbsolute, join, relative, sep } from "node:path";
import { isRecord } from "./record.js";

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
