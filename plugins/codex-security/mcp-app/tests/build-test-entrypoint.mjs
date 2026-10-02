import { build } from "esbuild";

export function buildTestEntrypoint(options) {
  return build({
    bundle: true,
    external: ["fsevents"],
    format: "cjs",
    loader: { ".md": "text" },
    logLevel: "silent",
    platform: "node",
    ...options,
  });
}
