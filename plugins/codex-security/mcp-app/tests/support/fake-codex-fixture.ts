import { chmod, writeFile } from "node:fs/promises";
import path from "node:path";
import { fakeCodexSource } from "./fake-codex-source.ts";
import type { createTemporaryDirectories } from "./temporary-directories.ts";

export const emptyWorkerPermissionProfile = {
  extends: ":read-only",
  filesystem: { ":root": "read" },
  network: { enabled: false },
};

export async function createFakeCodexFixture(
  temporaryDirectories: ReturnType<typeof createTemporaryDirectories>,
  preflightProfile = emptyWorkerPermissionProfile,
  preflightAllowed = true,
  accountResult: {
    account: { type: string } | null;
    requiresOpenaiAuth: boolean;
  } = { account: { type: "apiKey" }, requiresOpenaiAuth: true },
) {
  const root = await temporaryDirectories.create(
    "codex-security-sdk-executor-",
  );
  const markerPath = path.join(root, "invocation.json");
  const preflightMarkerPath = path.join(root, "preflight.json");
  const scriptPath = path.join(root, "fake-codex.mjs");
  await writeFile(
    scriptPath,
    fakeCodexSource(
      preflightProfile,
      preflightAllowed,
      accountResult,
      preflightMarkerPath,
    ),
  );
  await chmod(scriptPath, 0o755);
  process.env.FAKE_CODEX_MARKER = markerPath;
  return { root, markerPath, preflightMarkerPath, executablePath: scriptPath };
}
