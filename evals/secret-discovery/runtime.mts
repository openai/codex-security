import { link, mkdtemp, realpath, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { importModule } from "../../plugins/codex-security/mcp-app/tests/import-module.ts";

// Bundle production runtime helpers directly for the deterministic checks.
export const {
  DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID,
  preflightDeepScanWorkerPermissionProfile,
  deepScanPermissionProfileFallbackError,
  executablePathForSpawn,
  inlineToml,
  bundledCodexSdkEnvironment,
} = await importModule({
  stdin: {
    contents: `export { DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID, preflightDeepScanWorkerPermissionProfile, deepScanPermissionProfileFallbackError } from "../../plugins/codex-security/mcp-app/src/deep-scan/permission-profile-preflight.ts";
export { executablePathForSpawn } from "../../plugins/codex-security/mcp-app/src/deep-scan/executable-path.ts";
export { inlineToml } from "../../sdk/typescript/src/config.ts";
export { bundledCodexSdkEnvironment } from "../../sdk/typescript/src/codex-sdk-environment.ts";`,
    resolveDir: import.meta.dirname,
  },
});

/** Keep temporary source and the login link alive until cancelled work stops. */
export async function withEvalState(
  createHome: (parent?: string) => Promise<string>,
  ambientHome: string,
  run: (state: {
    home: string;
    root: string;
    signal: AbortSignal;
  }) => Promise<void>,
) {
  const controller = new AbortController();
  let interrupted: NodeJS.Signals | undefined;
  const signals = ["SIGINT", "SIGTERM"];
  const handler = (signal: NodeJS.Signals) => {
    interrupted = signal;
    controller.abort(
      new DOMException(`Eval interrupted by ${signal}`, "AbortError"),
    );
  };
  for (const signal of signals) process.on(signal, handler);
  let root;
  let home;
  try {
    root = await mkdtemp(join(tmpdir(), "source-audit-"));
    // Share saved login updates without importing the caller's configuration.
    let auth;
    try {
      const path = await realpath(join(ambientHome, "auth.json"));
      if ((await stat(path)).isFile()) auth = path;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    // A hard link must stay on the saved login's filesystem, including symlinks.
    const allocatedHome = await createHome(auth ? dirname(auth) : undefined);
    try {
      if (auth) await link(auth, join(allocatedHome, "auth.json"));
    } catch (error) {
      await rm(allocatedHome, { recursive: true, force: true });
      throw error;
    }
    home = allocatedHome;
    if (!interrupted) await run({ root, home, signal: controller.signal });
  } catch (error) {
    if (!interrupted) throw error;
  } finally {
    await Promise.all([
      root && rm(root, { recursive: true, force: true }),
      home && rm(home, { recursive: true, force: true }),
    ]).finally(() => {
      for (const signal of signals) process.off(signal, handler);
      if (interrupted) process.exitCode = interrupted === "SIGINT" ? 130 : 143;
    });
  }
}
