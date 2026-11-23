import { lstat, realpath } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { PluginBootstrapError } from "./errors.js";

export function bundledPluginCandidates(moduleUrl: string): string[] {
  // The MCP build replaces import.meta.url with the loader's __filename.
  if (isAbsolute(moduleUrl)) {
    const directory = dirname(moduleUrl);
    return basename(moduleUrl) === "server.mjs" && basename(directory) === "mcp"
      ? [dirname(directory)]
      : [];
  }
  const moduleDirectory = dirname(fileURLToPath(moduleUrl));
  return [
    resolve(moduleDirectory, "_bundled_plugin"),
    resolve(moduleDirectory, "../_bundled_plugin"),
  ];
}

export async function hasPluginManifest(root: string): Promise<boolean> {
  return await lstat(join(root, ".codex-plugin", "plugin.json")).then(
    (metadata) => metadata.isFile(),
    () => false,
  );
}

export async function bundledPluginRoot(): Promise<string> {
  for (const candidate of bundledPluginCandidates(import.meta.url)) {
    if (await hasPluginManifest(candidate)) {
      return await realpath(candidate);
    }
  }
  throw new PluginBootstrapError(
    "The bundled Codex Security plugin is missing.",
  );
}
