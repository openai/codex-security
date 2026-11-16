import { lstat, realpath } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { PluginBootstrapError } from "./errors.js";

export function bundledPluginCandidates(moduleDirectory: string): string[] {
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
  const moduleDirectory = dirname(fileURLToPath(import.meta.url));
  for (const candidate of bundledPluginCandidates(moduleDirectory)) {
    if (await hasPluginManifest(candidate)) {
      return await realpath(candidate);
    }
  }
  throw new PluginBootstrapError(
    "The bundled Codex Security plugin is missing.",
  );
}
