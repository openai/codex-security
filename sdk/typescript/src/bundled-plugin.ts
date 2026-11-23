import { lstat, realpath } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { PluginBootstrapError } from "./errors.js";

export function bundledPluginCandidates(moduleDirectory: string): string[] {
  return [
    resolve(moduleDirectory, "_bundled_plugin"),
    resolve(moduleDirectory, "../_bundled_plugin"),
    resolve(moduleDirectory, ".."),
  ];
}

export async function hasPluginManifest(root: string): Promise<boolean> {
  return await lstat(join(root, ".codex-plugin", "plugin.json")).then(
    (metadata) => metadata.isFile(),
    () => false,
  );
}

export async function bundledPluginRoot(): Promise<string> {
  const modulePath = import.meta.url;
  const moduleDirectory = dirname(
    modulePath.startsWith("file:") ? fileURLToPath(modulePath) : modulePath,
  );
  for (const candidate of bundledPluginCandidates(moduleDirectory)) {
    if (await hasPluginManifest(candidate)) {
      return await realpath(candidate);
    }
  }
  throw new PluginBootstrapError(
    "The bundled Codex Security plugin is missing.",
  );
}
