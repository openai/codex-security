import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

export const applicationRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

export function buildServer(outfile, options = {}) {
  return build({
    bundle: true,
    define: { "import.meta.url": "__filename" },
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
