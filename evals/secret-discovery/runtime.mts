import type { EvalSettings } from "./harness.mts";
import { link, mkdtemp, realpath, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { build } from "../../sdk/typescript/node_modules/esbuild/lib/main.js";

// Bundle production runtime helpers directly so deterministic checks need no SDK build.
const bundle = await build({
  stdin: {
    contents: [
      'export { createPermissionCheckedCodex } from "../../sdk/typescript/src/permission-profile.ts";',
      'export { executablePathForSpawn } from "../../sdk/typescript/src/runtime.ts";',
      'export { inlineToml } from "../../sdk/typescript/src/config.ts";',
      'export { bundledCodexSdkEnvironment } from "../../sdk/typescript/src/codex-sdk-environment.ts";',
    ].join("\n"),
    resolveDir: fileURLToPath(new URL(".", import.meta.url)),
  },
  bundle: true,
  define: {
    "import.meta.url": JSON.stringify(
      new URL("../../sdk/typescript/src/runtime.ts", import.meta.url).href,
    ),
  },
  format: "cjs",
  platform: "node",
  write: false,
});
const module = { exports: {} };
new Function("require", "module", "exports", bundle.outputFiles[0].text)(
  createRequire(new URL("../../sdk/typescript/package.json", import.meta.url)),
  module,
  module.exports,
);
// Keep the existing managed-policy profile name while using the shared checker.
export const EVAL_PERMISSION_PROFILE_ID = "codex_security_deep_scan_worker";
export const {
  createPermissionCheckedCodex,
  executablePathForSpawn,
  inlineToml,
  bundledCodexSdkEnvironment,
} = module.exports as {
  createPermissionCheckedCodex: typeof import("../../sdk/typescript/src/permission-profile.js").createPermissionCheckedCodex;
  executablePathForSpawn: typeof import("../../sdk/typescript/src/runtime.js").executablePathForSpawn;
  inlineToml: typeof import("../../sdk/typescript/src/config.js").inlineToml;
  bundledCodexSdkEnvironment: typeof import("../../sdk/typescript/src/codex-sdk-environment.js").bundledCodexSdkEnvironment;
};

/** Ask native Codex about saved login state before selecting an API-key fallback. */
export async function shouldUseOpenAiApiKey(
  settings: EvalSettings,
  cwd: string,
  signal?: AbortSignal,
) {
  signal?.throwIfAborted();
  const child = spawn(
    settings.codexPathOverride,
    [
      ...settings.configOverrides.flatMap((value) => ["--config", value]),
      "app-server",
      "--stdio",
    ],
    { cwd, env: settings.env, signal, stdio: "pipe" },
  );
  const closed = new Promise((resolve) => child.once("close", resolve));
  const failed = new Promise<never>((_, reject) => {
    child.on("error", reject);
    child.stdin.on("error", reject);
    child.once("exit", () =>
      reject(new Error("Codex account lookup ended before its response.")),
    );
  });
  child.stderr.resume();
  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  const iterator = lines[Symbol.asyncIterator]();
  let nextId = 0;
  const request = async (method: string, params: Record<string, unknown>) => {
    const id = ++nextId;
    child.stdin.write(`${JSON.stringify({ id, method, params })}\n`);
    while (true) {
      const line = await Promise.race([iterator.next(), failed]);
      if (line.done)
        throw new Error("Codex account lookup ended before its response.");
      if (!line.value.trim()) continue;
      const response = JSON.parse(line.value);
      if (response.id === undefined || response.method !== undefined) continue;
      if (response.id !== id || response.error || !response.result)
        throw new Error(`Codex account lookup failed for ${method}.`);
      return response.result;
    }
  };
  try {
    await request("initialize", {
      clientInfo: { name: "codex_security_eval", version: "1" },
      capabilities: { experimentalApi: true },
    });
    child.stdin.write(
      `${JSON.stringify({ method: "initialized", params: {} })}\n`,
    );
    const config = await request("config/read", { cwd, includeLayers: false });
    if (config.config?.forced_login_method === "chatgpt") return false;
    const result = await request("account/read", { refreshToken: false });
    return result.requiresOpenaiAuth === true && result.account === null;
  } catch (error) {
    signal?.throwIfAborted();
    throw error;
  } finally {
    lines.close();
    if (!child.stdin.destroyed) child.stdin.end();
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await closed;
  }
}

/** Share saved login updates without importing the caller's configuration. */
export async function createEvalHome(
  createHome: (root?: string) => Promise<string>,
  ambientHome: string,
) {
  let auth;
  try {
    const path = await realpath(join(ambientHome, "auth.json"));
    if ((await stat(path)).isFile()) auth = path;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
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
export async function withEvalState<T>(
  createHome: () => Promise<{ home: string }>,
  run: (state: {
    root: string;
    home: string;
    signal: AbortSignal;
  }) => Promise<T>,
) {
  const controller = new AbortController();
  let interrupted: "SIGINT" | "SIGTERM" | undefined;
  const handlers = (["SIGINT", "SIGTERM"] as const).map((signal) => {
    const handler = () => {
      interrupted = signal;
      process.exitCode = signal === "SIGINT" ? 130 : 143;
      controller.abort(
        new DOMException(`Eval interrupted by ${signal}`, "AbortError"),
      );
    };
    process.on(signal, handler);
    return [signal, handler] as const;
  });
  let root: string | undefined;
  let state: { home: string } | undefined;
  try {
    root = await realpath(await mkdtemp(join(tmpdir(), "source-audit-")));
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
          .filter((path): path is string => typeof path === "string")
          .map((path) => rm(path, { recursive: true, force: true })),
      );
    } finally {
      for (const [signal, handler] of handlers) process.off(signal, handler);
    }
  }
}
