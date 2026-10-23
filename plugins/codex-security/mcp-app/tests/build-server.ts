import path from "node:path";
import { build, type BuildOptions } from "esbuild";
import { mcpBundleOptions } from "../scripts/bundle_options.mjs";

export const applicationRoot = path.resolve(import.meta.dirname, "..");

export function buildServer(outfile: string, options: BuildOptions = {}) {
  return build({
    ...mcpBundleOptions,
    entryPoints: [path.join(applicationRoot, "main.ts")],
    external: ["fsevents"],
    format: "cjs",
    loader: { ".md": "text" },
    logLevel: "silent",
    outfile,
    platform: "node",
    ...options,
  });
}
