import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { mcpBundleOptions } from "../scripts/bundle_options.mjs";

export const applicationRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

export function buildServer(outfile, options = {}) {
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
