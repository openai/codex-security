import { resolve } from "node:path";
import { build } from "esbuild";

export async function buildNativeWrappers() {
  const root = resolve(import.meta.dirname, "../../native");
  await build({
    absWorkingDir: root,
    entryPoints: ["*.mts"],
    outdir: root,
    outExtension: { ".js": ".mjs" },
    format: "esm",
    platform: "node",
    target: "node20",
  });
}
