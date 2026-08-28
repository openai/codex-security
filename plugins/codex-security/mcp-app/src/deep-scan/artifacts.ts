import { randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
export interface DeepScanArtifacts {
  scanDir: string;
  deepRoot: string;
  workersRoot: string;
  dedupRoot: string;
}

export interface DiscoveryArtifacts {
  resultPath: string;
}

export function createDeepScanArtifacts(scanDir: string): DeepScanArtifacts {
  const deepRoot = join(scanDir, "artifacts", "deep_discovery");
  return {
    scanDir,
    deepRoot,
    workersRoot: join(deepRoot, "workers"),
    dedupRoot: join(deepRoot, "dedup")
  };
}

export function discoveryArtifacts(artifactDir: string): DiscoveryArtifacts {
  return {
    resultPath: join(artifactDir, "result.json")
  };
}

export async function ensureDeepScanDirectories(artifacts: DeepScanArtifacts): Promise<void> {
  for (const path of [
    artifacts.deepRoot,
    artifacts.workersRoot,
    artifacts.dedupRoot
  ]) {
    await fs.mkdir(path, { recursive: true });
  }
}

export async function writePrivateFile(path: string, content: string): Promise<void> {
  await fs.mkdir(dirname(path), { recursive: true });
  await fs.writeFile(path, content, { encoding: "utf8", mode: 0o600, flag: "wx" });
}

export async function writeJsonAtomic(path: string, payload: unknown): Promise<void> {
  await fs.mkdir(dirname(path), { recursive: true });
  const temporaryPath = `${path}.${randomUUID()}.tmp`;
  await fs.writeFile(temporaryPath, `${JSON.stringify(payload, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600
  });
  await fs.rename(temporaryPath, path);
}

export async function readJsonObject(path: string): Promise<Record<string, unknown>> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await fs.readFile(path, "utf8"));
  } catch (error) {
    throw new Error(`Invalid Deep Scan JSON artifact ${path}: ${errorMessage(error)}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`Deep Scan JSON artifact must contain an object: ${path}`);
  }
  return parsed as Record<string, unknown>;
}

export async function requireRegularFile(
  path: string,
  root: string,
  requireContent = true
): Promise<void> {
  const rootPath = await fs.realpath(root);
  const resolvedPath = await fs.realpath(path);
  assertInside(rootPath, resolvedPath, `Deep Scan artifact escaped its scan directory: ${path}`);
  assertCanonicalPath(path, resolvedPath);
  const [linkStat, fileStat] = await Promise.all([fs.lstat(path), fs.stat(path)]);
  if (linkStat.isSymbolicLink() || !fileStat.isFile() || (requireContent && fileStat.size === 0)) {
    throw new Error(`Deep Scan artifact is not a valid regular file: ${path}`);
  }
}

export async function archiveDirectory(source: string, destination: string): Promise<void> {
  await fs.mkdir(dirname(destination), { recursive: true });
  await fs.rm(destination, { recursive: true, force: true });
  try {
    await fs.rename(source, destination);
  } catch (error) {
    if (!isMissing(error)) throw error;
  }
  await fs.mkdir(source, { recursive: true });
}

function assertInside(root: string, path: string, message: string): void {
  const child = relative(root, path);
  if (child === "" || (!isAbsolute(child) && child !== ".." && !child.startsWith(`..${sep}`))) {
    return;
  }
  throw new Error(message);
}

function assertCanonicalPath(path: string, resolvedPath: string): void {
  if (relative(resolve(path), resolvedPath) === "") return;
  throw new Error(`Deep Scan artifact must use a canonical non-symlink path: ${path}`);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isMissing(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && error.code === "ENOENT");
}
