import { rm } from "node:fs/promises";
import {
  createTemporaryDirectories,
  temporaryDirectory as createPluginTemporaryDirectory,
} from "../../../../plugins/codex-security/mcp-app/tests/support/temporary-directories.ts";

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

export { createTemporaryDirectories };

export function createApiTestFixtures(
  prefix = "codex-security-api-",
  canonicalize = true,
) {
  const temporaryDirectories = createTemporaryDirectories(canonicalize);
  return {
    temporaryDirectories,
    cleanup: temporaryDirectories.cleanup,
    temporaryDirectory(directoryPrefix = prefix): Promise<string> {
      return temporaryDirectories.create(directoryPrefix);
    },
  };
}

export function temporaryDirectory(
  prefix: string,
  canonicalize = true,
): Promise<string> {
  return createPluginTemporaryDirectory(prefix, canonicalize);
}
