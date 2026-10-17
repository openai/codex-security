import { build, type BuildOptions } from "esbuild";
import path from "node:path";

export async function importModule(options: BuildOptions) {
  const result = await build({
    bundle: true,
    format: "esm",
    platform: "node",
    nodePaths: [path.resolve(import.meta.dirname, "../node_modules")],
    write: false,
    ...options,
  });
  return import(
    `data:text/javascript;base64,${Buffer.from(result.outputFiles![0].contents).toString("base64")}`
  );
}

export function importSource(entryPoint: string, options: BuildOptions = {}) {
  return importModule({ entryPoints: [entryPoint], ...options });
}
