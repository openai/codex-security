import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

export async function removeTemporaryDirectory(path: string): Promise<void> {
  // Bun 1.3.14 ignores fs.rm's retry options.
  for (let attempt = 0; ; attempt++) {
    try {
      await rm(path, { recursive: true, force: true });
      return;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EBUSY" || attempt === 10)
        throw error;
      await Bun.sleep(100 * (attempt + 1));
    }
  }
}

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
