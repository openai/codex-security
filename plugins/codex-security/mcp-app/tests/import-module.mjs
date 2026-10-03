import { build } from "esbuild";

export async function importModule(options) {
  const result = await build({
    bundle: true,
    format: "esm",
    platform: "node",
    write: false,
    ...options,
  });
  return import(
    `data:text/javascript;base64,${Buffer.from(result.outputFiles[0].contents).toString("base64")}`
  );
}

export function importSource(entryPoint, options = {}) {
  return importModule({ entryPoints: [entryPoint], ...options });
}
