import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { brotliDecompressSync } from "node:zlib";

const sourcePlugin = new URL(
  "../../../plugins/codex-security/",
  import.meta.url,
);
const bundledPlugin = new URL("../_bundled_plugin/", import.meta.url);
const hasSourcePlugin = existsSync(
  new URL(".codex-plugin/plugin.json", sourcePlugin),
);
const plugin = hasSourcePlugin ? sourcePlugin : bundledPlugin;

export const PLUGIN_ROOT = fileURLToPath(plugin);

export const INTEGRATION_TARGET = hasSourcePlugin
  ? "project/codex-security-sdk/src"
  : "sdk/typescript/src";

let bundledRuntime: Promise<string> | undefined;

export function loadBundledRuntime(): Promise<string> {
  return (bundledRuntime ??= Promise.all(
    ["000", "001"].map((part) =>
      readFile(new URL(`mcp/server.mjs.br.part-${part}`, plugin)),
    ),
  ).then((parts) =>
    brotliDecompressSync(Buffer.concat(parts)).toString("utf8"),
  ));
}
