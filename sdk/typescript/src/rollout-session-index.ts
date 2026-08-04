import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, rm, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, sep } from "node:path";
import type { Stats } from "node:fs";
import type { CodexRolloutSnapshot } from "./codex-rollouts.js";

export const ROLLOUT_SESSION_INDEX_RELATIVE_PATH = [
  "artifacts",
  "rollout-sessions",
  "index.json",
] as const;
export const MAX_ROLLOUT_SESSION_INDEX_ENTRIES = 4_096;

export interface RolloutSessionIndexEntry {
  threadId: string;
  parentThreadId: string | null;
  role: "coordinator" | "worker";
  sourcePath: string;
  retainedPath?: string;
}

export interface RolloutSessionIndex {
  schemaVersion: 1;
  rootThreadId: string;
  complete: boolean;
  retained: boolean;
  sessions: RolloutSessionIndexEntry[];
}

interface WriteRolloutSessionIndexOptions {
  codexHome: string;
  scanDir: string;
  snapshot: CodexRolloutSnapshot;
  retain: boolean;
}

export async function writeRolloutSessionIndex(
  options: WriteRolloutSessionIndexOptions,
): Promise<string> {
  if (options.snapshot.sessions.length > MAX_ROLLOUT_SESSION_INDEX_ENTRIES) {
    throw new Error(
      `Rollout session index exceeds the ${MAX_ROLLOUT_SESSION_INDEX_ENTRIES}-session safety limit.`,
    );
  }
  const artifactsDir = join(options.scanDir, "artifacts");
  await mkdir(artifactsDir, { recursive: true, mode: 0o700 });
  const artifactsMetadata = await lstat(artifactsDir);
  if (artifactsMetadata.isSymbolicLink() || !artifactsMetadata.isDirectory()) {
    throw new Error("Scan artifacts path is not a regular directory.");
  }

  const rolloutDir = join(artifactsDir, "rollout-sessions");
  await mkdir(rolloutDir, { mode: 0o700 });
  try {
    await chmod(rolloutDir, 0o700);
    const sessions: RolloutSessionIndexEntry[] = [];
    for (const session of options.snapshot.sessions) {
      const entry: RolloutSessionIndexEntry = {
        threadId: session.threadId,
        parentThreadId: session.parentThreadId,
        role:
          session.threadId === options.snapshot.rootThreadId
            ? "coordinator"
            : "worker",
        sourcePath: session.path,
      };
      if (options.retain) {
        const sourceRelativePath = sessionRelativePath(
          options.codexHome,
          session.path,
        );
        const destination = join(
          rolloutDir,
          "sessions",
          ...sourceRelativePath.split("/"),
        );
        await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
        await copyPrivateFile(session.path, destination);
        entry.retainedPath = relative(options.scanDir, destination)
          .split(sep)
          .join("/");
      }
      sessions.push(entry);
    }
    const index: RolloutSessionIndex = {
      schemaVersion: 1,
      rootThreadId: options.snapshot.rootThreadId,
      complete: options.snapshot.complete,
      retained: options.retain,
      sessions,
    };
    const path = join(options.scanDir, ...ROLLOUT_SESSION_INDEX_RELATIVE_PATH);
    await writeFile(path, `${JSON.stringify(index, null, 2)}\n`, {
      flag: "wx",
      mode: 0o600,
    });
    await chmod(path, 0o600);
    return path;
  } catch (error) {
    await rm(rolloutDir, { recursive: true, force: true });
    throw error;
  }
}

function sessionRelativePath(codexHome: string, path: string): string {
  const relativePath = relative(join(codexHome, "sessions"), path);
  if (
    relativePath === "" ||
    relativePath === ".." ||
    relativePath.startsWith(`..${sep}`) ||
    isAbsolute(relativePath)
  ) {
    throw new Error("Codex rollout path is outside the session directory.");
  }
  return relativePath.split(sep).join("/");
}

async function copyPrivateFile(
  source: string,
  destination: string,
): Promise<void> {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      await copyPrivateFileOnce(source, destination);
      return;
    } catch (error) {
      await rm(destination, { force: true });
      if (attempt === 1) throw error;
    }
  }
}

async function copyPrivateFileOnce(
  source: string,
  destination: string,
): Promise<void> {
  const sourceMetadata = await lstat(source);
  if (sourceMetadata.isSymbolicLink() || !sourceMetadata.isFile()) {
    throw new Error(`Codex rollout is not a regular file: ${source}`);
  }
  const input = await open(
    source,
    constants.O_RDONLY |
      (process.platform === "win32" ? 0 : constants.O_NOFOLLOW),
  );
  let output: Awaited<ReturnType<typeof open>> | null = null;
  try {
    const openedMetadata = await input.stat();
    if (!sameFile(sourceMetadata, openedMetadata)) {
      throw new Error(
        `Codex rollout changed before it could be retained: ${source}`,
      );
    }
    output = await open(
      destination,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        (process.platform === "win32" ? 0 : constants.O_NOFOLLOW),
      0o600,
    );
    const buffer = Buffer.alloc(64 * 1_024);
    let offset = 0;
    while (offset < openedMetadata.size) {
      const length = Math.min(buffer.length, openedMetadata.size - offset);
      const { bytesRead } = await input.read(buffer, 0, length, offset);
      if (bytesRead === 0) {
        throw new Error(
          `Codex rollout changed while it was retained: ${source}`,
        );
      }
      let chunkOffset = 0;
      while (chunkOffset < bytesRead) {
        const { bytesWritten } = await output.write(
          buffer,
          chunkOffset,
          bytesRead - chunkOffset,
          offset + chunkOffset,
        );
        if (bytesWritten === 0) {
          throw new Error(`Could not retain Codex rollout: ${source}`);
        }
        chunkOffset += bytesWritten;
      }
      offset += bytesRead;
    }
    const retainedMetadata = await input.stat();
    if (
      retainedMetadata.size !== openedMetadata.size ||
      retainedMetadata.mtimeMs !== openedMetadata.mtimeMs ||
      retainedMetadata.ctimeMs !== openedMetadata.ctimeMs
    ) {
      throw new Error(`Codex rollout changed while it was retained: ${source}`);
    }
    await output.chmod(0o600);
  } finally {
    await output?.close();
    await input.close();
  }
}

function sameFile(left: Stats, right: Stats): boolean {
  return right.isFile() && left.dev === right.dev && left.ino === right.ino;
}
