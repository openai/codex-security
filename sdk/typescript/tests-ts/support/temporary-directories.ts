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
