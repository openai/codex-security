import { chmod, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { copyCompletedScanFixture } from "../plugin-root.js";
import {
  createTemporaryDirectories,
  temporaryDirectory as createPluginTemporaryDirectory,
} from "../../../../plugins/codex-security/mcp-app/tests/support/temporary-directories.ts";

export { createTemporaryDirectories };

export function createApiTestFixtures(
  prefix = "codex-security-api-",
  canonicalize = true,
) {
  const temporaryDirectories = createTemporaryDirectories(canonicalize);
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

export function temporaryDirectory(
  prefix: string,
  canonicalize = true,
): Promise<string> {
  return createPluginTemporaryDirectory(prefix, canonicalize);
}
