import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { resolveCodexProfile, type JsonObject } from "./config.js";
import { isRecord } from "./record.js";
import { isWithin } from "./trusted-executable.js";

/** Keep native skill injection out of the denied credential home. The scan
 * prompt loads the same workflow from CODEX_SECURITY_PLUGIN_ROOT instead. */
export async function scanSkillConfig(
  config: JsonObject,
  plugin: { pluginRoot: string; installedRoot: string },
  credentialHome: string,
): Promise<JsonObject> {
  if (!isWithin(credentialHome, plugin.installedRoot)) return config;
  const skills = await readdir(join(plugin.pluginRoot, "skills"), {
    withFileTypes: true,
  }).catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return [];
    throw error;
  });
  const paths = new Set(
    skills
      .filter((entry) => entry.isDirectory())
      .map((entry) =>
        join(plugin.installedRoot, "skills", entry.name, "SKILL.md"),
      ),
  );
  if (paths.size === 0) return config;
  const configured = resolveCodexProfile(config)["skills"];
  // Leave malformed user settings intact so native configuration reports them.
  if (configured !== undefined && !isRecord(configured)) return config;
  const entries = configured?.["config"];
  if (entries !== undefined && !Array.isArray(entries)) return config;
  const selection = {
    ...configured,
    config: [
      ...(entries ?? []).filter(
        (entry) => !isRecord(entry) || !paths.has(String(entry["path"])),
      ),
      ...Array.from(paths, (path) => ({ path, enabled: false })),
    ],
  } as JsonObject;
  const updated = structuredClone(config);
  updated["skills"] = selection;
  const profiles = updated["profiles"];
  const profile =
    typeof updated["profile"] === "string" && isRecord(profiles)
      ? profiles[updated["profile"]]
      : undefined;
  if (isRecord(profile)) profile["skills"] = selection;
  return updated;
}
