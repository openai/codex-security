import { chmod, writeFile } from "node:fs/promises";
import path from "node:path";
import { fakeCodexSource } from "./fake-codex-source.ts";
import type { createTemporaryDirectories } from "./temporary-directories.ts";
import { privateWindowsOutputRoot } from "./windows-output-fixture.ts";

export const trustedParentSandbox = Object.freeze({
  filesystemDenies: [],
});
export const trustedParentSandboxWithDenials = Object.freeze({
  filesystemDenies: [
    "/repo/.env",
    "/repo/**/.secret",
    "/repo/**/*.pem",
    "/repo/temp[1]",
    "/repo/secret[1]",
    "/repo/.env",
  ],
  literalFilesystemDenies: ["/repo/temp[1]", "/repo/secret[1]"],
  globScanMaxDepth: 3,
});
export const deniedWorkerPermissionProfile = {
  extends: ":read-only",
  filesystem: {
    ":root": "read",
    "/repo/.env": "deny",
    "/repo/**/.secret": "deny",
    "/repo/**/*.pem": "deny",
    "/repo/temp[1]": { ".": "deny" },
    "/repo/secret[1]": { ".": "deny" },
    "/": { "repo/temp[1]": "deny", "repo/secret[1]": "deny" },
    glob_scan_max_depth: 3,
  },
  network: { enabled: false },
};

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
  privateWindowsRoot = false,
) {
  let root = await temporaryDirectories.create("codex-security-sdk-executor-");
  if (privateWindowsRoot) root = await privateWindowsOutputRoot(root);
  const markerPath = path.join(root, "invocation.json");
  const preflightMarkerPath = path.join(root, "preflight.json");
  const scriptPath = path.join(root, "fake-codex.mjs");
  await writeFile(path.join(root, "config.toml"), "");
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
