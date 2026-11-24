import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { build, type BuildOptions } from "esbuild";

export const applicationRoot = resolve(import.meta.dirname, "..");

export function buildServer(outfile: string, options: BuildOptions = {}) {
  return build({
    bundle: true,
    define: { "import.meta.url": "__filename" },
    entryPoints: [join(applicationRoot, "main.ts")],
    external: ["fsevents"],
    format: "cjs",
    loader: { ".md": "text" },
    logLevel: "silent",
    outfile,
    platform: "node",
    ...options,
  });
}

export async function loadGraphSession(runtime: string) {
  const bundle = join(runtime, "session.cjs");
  await buildServer(bundle, {
    entryPoints: [join(applicationRoot, "src/dependency-trace/session.ts")],
  });
  return (
    (await import(pathToFileURL(bundle).href)) as {
      default: typeof import("../src/dependency-trace/session.ts");
    }
  ).default;
}
