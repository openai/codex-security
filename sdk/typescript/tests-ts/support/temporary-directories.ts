import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { chmod, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { copyCompletedScanFixture } from "../plugin-root.js";

export function createTemporaryDirectories({
  canonical = true,
}: { canonical?: boolean } = {}) {
  const directories: string[] = [];

  return {
    track(path: string): void {
      directories.push(path);
    },

    async create(prefix: string): Promise<string> {
      const directory = await mkdtemp(join(tmpdir(), prefix));
      const path = canonical ? await realpath(directory) : directory;
      directories.push(path);
      return path;
    },

    async cleanup(): Promise<void> {
      await Promise.all(
        directories
          .splice(0)
          .map((path) => rm(path, { recursive: true, force: true })),
      );
    },
  };
}

export function createApiTestFixtures(
  prefix = "codex-security-api-",
  canonicalize = true,
) {
  const temporaryDirectories = createTemporaryDirectories({
    canonical: canonicalize,
  });
  return {
    temporaryDirectories,
    cleanup: temporaryDirectories.cleanup,
    async copyCompletedScan(root: string): Promise<string> {
      const scanDir = join(root, "scan");
      await copyCompletedScanFixture(scanDir);
      await chmod(scanDir, 0o700);
      await writeFile(join(scanDir, "report.md"), "# Scan report\n");
      return scanDir;
    },
    temporaryDirectory(directoryPrefix = prefix): Promise<string> {
      return temporaryDirectories.create(directoryPrefix);
    },
  };
}

export function createSyncTestDirectories(
  prefix: string,
  canonicalize = false,
) {
  const temporaryDirectories: string[] = [];
  return {
    temporaryDirectories,
    cleanup(): void {
      for (const directory of temporaryDirectories.splice(0)) {
        rmSync(directory, { recursive: true, force: true });
      }
    },
    temporaryDirectory(directoryPrefix = prefix): string {
      const created = temporaryDirectorySync(directoryPrefix);
      const path = canonicalize ? realpathSync(created) : created;
      temporaryDirectories.push(path);
      return path;
    },
  };
}

export function temporaryDirectorySync(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

export async function temporaryDirectory(
  prefix: string,
  canonicalize = true,
): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), prefix));
  return canonicalize ? realpath(path) : path;
}
