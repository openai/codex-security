import { isAbsolute, join, relative, sep } from "node:path";

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
