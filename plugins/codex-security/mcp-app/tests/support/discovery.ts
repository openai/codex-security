import path from "node:path";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";
import { importSource } from "../import-module.ts";

export const discoveryPluginRoot = path.resolve(
  process.env["CODEX_SECURITY_TEST_PLUGIN_ROOT"] ??
    path.join(
      import.meta.dirname,
      "../../../../../sdk/typescript/_bundled_plugin",
    ),
);

export async function importDiscoverySource(outputFile?: string) {
  const source = path.join(
    import.meta.dirname,
    "../../src/artifact-discovery.ts",
  );
  const options = {
    define: {
      "import.meta.url": JSON.stringify(
        pathToFileURL(path.join(discoveryPluginRoot, "mcp/server.mjs")).href,
      ),
    },
  };
  if (outputFile === undefined) return importSource(source, options);
  // Bun's module loader does not support the large data URL used by Node fixtures.
  await build({
    ...options,
    bundle: true,
    entryPoints: [source],
    format: "esm",
    platform: "node",
    outfile: outputFile,
  });
  return import(pathToFileURL(outputFile).href);
}
