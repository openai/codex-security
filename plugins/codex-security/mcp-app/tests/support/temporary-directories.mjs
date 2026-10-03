import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

export function createTemporaryDirectories(canonicalize = false) {
  const roots = [];
  return {
    async create(prefix) {
      const root = await temporaryDirectory(prefix, canonicalize);
      roots.push(root);
      return root;
    },
    cleanup() {
      return Promise.all(
        roots.map((root) => rm(root, { recursive: true, force: true })),
      );
    },
  };
}

export async function temporaryDirectory(prefix, canonicalize = false) {
  const directory = await mkdtemp(join(tmpdir(), prefix));
  return canonicalize ? realpath(directory) : directory;
}
