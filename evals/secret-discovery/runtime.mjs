import { link, mkdtemp, realpath, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "../../sdk/typescript/node_modules/esbuild/lib/main.js";

// Bundle production runtime helpers directly so deterministic checks need no SDK build.
const bundle = await build({
  stdin: {
    contents: [
      'export { DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID, preflightDeepScanWorkerPermissionProfile, deepScanPermissionProfileFallbackError } from "../../plugins/codex-security/mcp-app/src/deep-scan/permission-profile-preflight.ts";',
      'export { executablePathForSpawn } from "../../plugins/codex-security/mcp-app/src/deep-scan/executable-path.ts";',
      'export { inlineToml } from "../../sdk/typescript/src/config.ts";',
      'export { bundledCodexSdkEnvironment } from "../../sdk/typescript/src/codex-sdk-environment.ts";',
    ].join("\n"),
    resolveDir: fileURLToPath(new URL(".", import.meta.url)),
  },
  bundle: true,
  format: "esm",
  platform: "node",
  write: false,
});
export const {
  DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID,
  preflightDeepScanWorkerPermissionProfile,
  deepScanPermissionProfileFallbackError,
  executablePathForSpawn,
  inlineToml,
  bundledCodexSdkEnvironment,
} = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);

/** Share saved login updates without importing the caller's configuration. */
export async function createEvalHome(createHome, ambientHome) {
  let auth;
  try {
    const path = await realpath(join(ambientHome, "auth.json"));
    if ((await stat(path)).isFile()) auth = path;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  // A hard link must stay on the saved login's filesystem, including symlinks.
  const home = await createHome(auth ? dirname(auth) : undefined);
  try {
    if (auth) await link(auth, join(home, "auth.json"));
    return { home };
  } catch (error) {
    await rm(home, { recursive: true, force: true });
    throw error;
  }
}

/** Keep temporary source and the login link alive until cancelled work stops. */
export async function withEvalState(createHome, run) {
  const controller = new AbortController();
  let interrupted;
  const handlers = ["SIGINT", "SIGTERM"].map((signal) => {
    const handler = () => {
      interrupted = signal;
      process.exitCode = signal === "SIGINT" ? 130 : 143;
      controller.abort(
        new DOMException(`Eval interrupted by ${signal}`, "AbortError"),
      );
    };
    process.on(signal, handler);
    return [signal, handler];
  });
  let root;
  let state;
  try {
    root = await mkdtemp(join(tmpdir(), "source-audit-"));
    state = await createHome();
    controller.signal.throwIfAborted();
    const result = await run({ root, ...state, signal: controller.signal });
    controller.signal.throwIfAborted();
    return result;
  } catch (error) {
    if (!interrupted) throw error;
    process.exitCode = interrupted === "SIGINT" ? 130 : 143;
  } finally {
    try {
      await Promise.all(
        [root, state?.home]
          .filter(Boolean)
          .map((path) => rm(path, { recursive: true, force: true })),
      );
    } finally {
      for (const [signal, handler] of handlers) process.off(signal, handler);
    }
  }
}
