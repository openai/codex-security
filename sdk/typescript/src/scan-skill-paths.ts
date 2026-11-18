import { realpath as callbackRealpath } from "node:fs";
import { readdir } from "node:fs/promises";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  parse,
  relative,
  resolve,
} from "node:path";
import { promisify } from "node:util";
import { deepMerge, type JsonObject } from "./config.js";
import { isRecord } from "./record.js";
import { isWithin } from "./trusted-executable.js";

const nativeRealpath = promisify(callbackRealpath.native);

function stripExtendedPrefix(path: string): string {
  if (process.platform !== "win32") return path;
  if (/^\\\\\?\\UNC\\/iu.test(path)) return `\\\\${path.slice(8)}`;
  if (path.startsWith("\\\\?\\") && /^[A-Za-z]:[\\/]/u.test(path.slice(4))) {
    return path.slice(4);
  }
  return path;
}

function hasCompleteRoot(path: string): boolean {
  const normalized = stripExtendedPrefix(path);
  return (
    isAbsolute(normalized) &&
    (process.platform !== "win32" || parse(normalized).root.length >= 3)
  );
}

async function canonicalizePath(path: string): Promise<string> {
  const resolved = resolve(stripExtendedPrefix(path));
  let current = resolved;
  const suffix: string[] = [];
  for (;;) {
    try {
      return join(await nativeRealpath(current), ...suffix);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") return resolved;
      const parent = dirname(current);
      if (parent === current) return resolved;
      suffix.unshift(basename(current));
      current = parent;
    }
  }
}

function selectedProfile(config: JsonObject): JsonObject | undefined {
  const name = config["profile"];
  const profiles = config["profiles"];
  const profile =
    typeof name === "string" &&
    isRecord(profiles) &&
    Object.hasOwn(profiles, name)
      ? profiles[name]
      : undefined;
  return isRecord(profile) ? profile : undefined;
}

function effectiveSkills(config: JsonObject): unknown {
  const base = config["skills"];
  const profile = selectedProfile(config);
  if (
    profile === undefined ||
    !Object.hasOwn(profile, "skills") ||
    profile["skills"] === undefined
  ) {
    return base;
  }
  const override = profile["skills"];
  return isRecord(base) && isRecord(override)
    ? deepMerge(structuredClone(base), override)
    : override;
}

/** Keep native skill injection out of the denied credential home. The scan
 * prompt loads the same workflow from CODEX_SECURITY_PLUGIN_ROOT instead. */
export async function scanSkillConfig(
  config: JsonObject,
  plugin: { pluginRoot: string; installedRoot: string },
  credentialHome: string,
): Promise<JsonObject> {
  const [canonicalHome, installedRoot] = await Promise.all([
    canonicalizePath(credentialHome),
    canonicalizePath(plugin.installedRoot),
  ]);
  if (!isWithin(canonicalHome, installedRoot)) return config;
  const skills = await readdir(join(plugin.pluginRoot, "skills"), {
    withFileTypes: true,
  }).catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return [];
    throw error;
  });
  const paths = [
    ...new Set(
      await Promise.all(
        skills
          .filter((entry) => entry.isDirectory())
          .map((entry) =>
            canonicalizePath(
              join(installedRoot, "skills", entry.name, "SKILL.md"),
            ),
          ),
      ),
    ),
  ];
  if (paths.length === 0) return config;
  const configured = effectiveSkills(config);
  // Leave malformed user settings intact so native configuration reports them.
  if (configured !== undefined && !isRecord(configured)) return config;
  const entries = configured?.["config"];
  if (entries !== undefined && !Array.isArray(entries)) return config;
  const retained: unknown[] = [];
  for (const entry of entries ?? []) {
    if (
      isRecord(entry) &&
      typeof entry["path"] === "string" &&
      hasCompleteRoot(entry["path"])
    ) {
      const candidate = await canonicalizePath(entry["path"]);
      if (paths.some((blocked) => relative(blocked, candidate) === "")) {
        continue;
      }
    }
    retained.push(entry);
  }
  const selection = {
    ...configured,
    config: [...retained, ...paths.map((path) => ({ path, enabled: false }))],
  } as JsonObject;
  const updated = structuredClone(config);
  updated["skills"] = selection;
  const profile = selectedProfile(updated);
  if (profile !== undefined) profile["skills"] = selection;
  return updated;
}
