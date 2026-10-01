import { link, mkdtemp, realpath, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "../../sdk/typescript/node_modules/esbuild/lib/main.js";

// Reuse the native preflight and warning handling exercised by Deep Scan.
const bundle = await build({
  entryPoints: [
    fileURLToPath(
      new URL(
        "../../plugins/codex-security/mcp-app/src/deep-scan/permission-profile-preflight.ts",
        import.meta.url,
      ),
    ),
  ],
  bundle: true,
  format: "esm",
  platform: "node",
  write: false,
});
export const {
  preflightDeepScanWorkerPermissionProfile,
  deepScanPermissionProfileFallbackError,
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
    return { home, hasLogin: Boolean(auth) };
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
