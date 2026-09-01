import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { brotliDecompressSync } from "node:zlib";

const bundledPlugin = new URL("../_bundled_plugin/", import.meta.url);
const hasMonorepoSdk = existsSync(
  new URL("../../../project/codex-security-sdk/src/", import.meta.url),
);

export const PLUGIN_ROOT = fileURLToPath(bundledPlugin);

export const INTEGRATION_TARGET = hasMonorepoSdk
  ? "project/codex-security-sdk/src"
  : "sdk/typescript/src";

let bundledRuntime: Promise<string> | undefined;

export function loadBundledRuntime(): Promise<string> {
  return (bundledRuntime ??= Promise.all(
    ["000", "001"].map((part) =>
      readFile(new URL(`mcp/server.mjs.br.part-${part}`, bundledPlugin)),
    ),
  ).then((parts) =>
    brotliDecompressSync(Buffer.concat(parts)).toString("utf8"),
  ));
}
