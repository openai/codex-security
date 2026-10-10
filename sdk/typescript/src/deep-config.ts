import { readFile } from "node:fs/promises";
import { parse as parseToml, type TomlTable } from "smol-toml";
import { DEFAULT_DEEP_SCAN_SETTINGS } from "./deep-scan-defaults.js";
import { CodexSecurityError } from "./errors.js";
import {
  DEFAULT_SCAN_MODE,
  DEEP_SCAN_SETTINGS,
  DeepScanSettingsSchema,
  type DeepScanOptions,
} from "./scan-settings.js";
import type { ScanMode } from "./scan-modes.js";

export type DeepScanSources = Record<
  keyof DeepScanOptions,
  "default" | "legacy" | "override"
>;
export interface ResolvedDeepScanConfig {
  settings: Required<DeepScanOptions>;
  sources: DeepScanSources;
}

export function deepScanOptions(
  options: DeepScanOptions & { mode?: ScanMode },
): DeepScanOptions {
  const selected: DeepScanOptions = {};
  for (const [name] of DEEP_SCAN_SETTINGS) {
    const value = options[name];
    if (value === undefined) continue;
    if ((options.mode ?? DEFAULT_SCAN_MODE) !== "deep") {
      throw new CodexSecurityError("Deep scan settings require deep mode.");
    }
    selected[name] = requireDeepScanValue(name, value, name);
  }
  return selected;
}

function requireDeepScanValue(
  name: keyof DeepScanOptions,
  value: unknown,
  label: string,
): number {
  const parsed = DeepScanSettingsSchema.shape[name].unwrap().safeParse(value);
  if (!parsed.success) {
    throw new CodexSecurityError(
      `Deep scan ${label} ${parsed.error.issues[0]!.message}.`,
    );
  }
  return parsed.data;
}

export async function resolveDeepScanConfig(
  options: DeepScanOptions,
  source: string,
  signal?: AbortSignal,
): Promise<ResolvedDeepScanConfig> {
  const explicit = deepScanOptions({ ...options, mode: "deep" });
  let document: TomlTable = {};
  // Complete saved settings do not depend on today's ambient configuration.
  if (!DEEP_SCAN_SETTINGS.every(([name]) => explicit[name] !== undefined)) {
    document = await readDeepScanDocument(source, signal);
  }
  const existing = document["deep_scan"];
  if (
    existing !== undefined &&
    (typeof existing !== "object" ||
      existing === null ||
      Array.isArray(existing) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(existing)))
  ) {
    throw new CodexSecurityError(
      `Codex Security configuration [deep_scan] at ${source} must be a TOML table.`,
    );
  }
  const configured = (existing ?? {}) as TomlTable;
  const keys = new Set<string>(DEEP_SCAN_SETTINGS.map(([, key]) => key));
  const unknown = Object.keys(configured).filter((key) => !keys.has(key));
  if (unknown.length > 0) {
    throw new CodexSecurityError(
      `Unknown Codex Security Deep Scan configuration ${unknown.join(", ")} in ${source}.`,
    );
  }
  const settings = {
    ...DEFAULT_DEEP_SCAN_SETTINGS,
  } as Required<DeepScanOptions>;
  const sources = {} as DeepScanSources;
  for (const [name, key] of DEEP_SCAN_SETTINGS) {
    let value = Object.hasOwn(configured, key)
      ? configured[key]
      : DEFAULT_DEEP_SCAN_SETTINGS[name];
    if (name === "workers" && value === "auto")
      value = DEFAULT_DEEP_SCAN_SETTINGS.workers;
    if (explicit[name] !== undefined) value = explicit[name];
    sources[name] =
      explicit[name] !== undefined
        ? "override"
        : Object.hasOwn(configured, key)
          ? "legacy"
          : "default";
    settings[name] = requireDeepScanValue(
      name,
      value,
      sources[name] === "legacy" ? `${key} in ${source}` : name,
    );
  }
  return {
    settings,
    sources,
  };
}

async function readDeepScanDocument(
  source: string,
  signal?: AbortSignal,
): Promise<TomlTable> {
  try {
    return parseToml(await readFile(source, { encoding: "utf8", signal }));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw new CodexSecurityError(
        `Cannot read Codex Security configuration at ${source}.`,
        { cause: error },
      );
    }
    return {};
  }
}
