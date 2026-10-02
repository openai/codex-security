import { fileURLToPath } from "node:url";
import { build } from "esbuild";

export async function loadTestModule(entryPoint, options = {}) {
  const bundle = await build({
    bundle: true,
    entryPoints: [fileURLToPath(entryPoint)],
    format: "esm",
    platform: "node",
    write: false,
    ...options,
  });
  return import(
    `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
  );
}
