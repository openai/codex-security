import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

export function createTemporaryDirectories(canonicalize = false) {
  const roots: string[] = [];
  return {
    track(root: string): void {
      roots.push(root);
    },
    async create(prefix: string) {
      const root = await temporaryDirectory(prefix, canonicalize);
      roots.push(root);
      return root;
    },
    async cleanup(): Promise<void> {
      await Promise.all(
        roots
          .splice(0)
          .map((root) => rm(root, { recursive: true, force: true })),
      );
    },
  };
}

export async function temporaryDirectory(prefix: string, canonicalize = false) {
  const directory = await mkdtemp(join(tmpdir(), prefix));
  return canonicalize ? realpath(directory) : directory;
}
