import { isAbsolute, join, relative, sep } from "node:path";

export function sessionStartedAt(timestamp: unknown): number | null {
  const startedAt =
    typeof timestamp === "string" ? Date.parse(timestamp) : Number.NaN;
  return Number.isFinite(startedAt) ? startedAt : null;
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
