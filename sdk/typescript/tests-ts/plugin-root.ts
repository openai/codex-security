import { existsSync } from "node:fs";
import { readFile, readdir } from "node:fs/promises";
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
  return (bundledRuntime ??= (async () => {
    const directory = new URL("mcp/", bundledPlugin);
    const chunks = (await readdir(directory))
      .filter((name) => name.startsWith("server.mjs.br.part-"))
      .sort();
    const parts = await Promise.all(
      chunks.map((name) => readFile(new URL(name, directory))),
    );
    return brotliDecompressSync(Buffer.concat(parts)).toString("utf8");
  })());
}
