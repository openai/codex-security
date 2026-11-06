import path from "node:path";
import { pathToFileURL } from "node:url";
import { importSource } from "../import-module.ts";

export const discoveryPluginRoot = path.resolve(
  process.env["CODEX_SECURITY_TEST_PLUGIN_ROOT"] ??
    path.join(
      import.meta.dirname,
      "../../../../../sdk/typescript/_bundled_plugin",
    ),
);

export function importDiscoverySource() {
  const source = path.join(
    import.meta.dirname,
    "../../src/artifact-discovery.ts",
  );
  return importSource(source, {
    define: {
      "import.meta.url": JSON.stringify(
        pathToFileURL(path.join(discoveryPluginRoot, "mcp/server.mjs")).href,
      ),
    },
  });
}
