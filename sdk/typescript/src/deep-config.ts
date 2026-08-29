import { readFile, realpath } from "node:fs/promises";
import { parse as parseToml, type TomlTable } from "smol-toml";
import { writeCodexConfig, type JsonObject } from "./config.js";
import { DEFAULT_DEEP_SCAN_SETTINGS } from "./deep-scan-defaults.js";
import { CodexSecurityError } from "./errors.js";
import { DEEP_SCAN_SETTINGS, type DeepScanOptions } from "./scan-settings.js";
import type { ScanMode } from "./targets.js";

export type DeepScanSources = Record<
  keyof DeepScanOptions,
  "default" | "legacy" | "override"
>;
export interface ResolvedDeepScanConfig {
  settings: Required<DeepScanOptions>;
  sources: DeepScanSources;
  source: string;
  document: TomlTable;
  hasOverrides: boolean;
}

export function deepScanOptions(
  options: DeepScanOptions & { mode?: ScanMode },
): DeepScanOptions {
  const selected: DeepScanOptions = {};
  for (const [name, , minimum] of DEEP_SCAN_SETTINGS) {
    const value = options[name];
    if (value === undefined) continue;
    if ((options.mode ?? "standard") !== "deep") {
      throw new CodexSecurityError("Deep scan settings require deep mode.");
    }
    if (name === "maxTimeHours") {
      if (!Number.isFinite(value) || value <= 0 || value > 96) {
        throw new CodexSecurityError(
          "Deep scan maxTimeHours must be a positive number no greater than 96.",
        );
      }
    } else if (!Number.isSafeInteger(value) || value < minimum) {
      throw new CodexSecurityError(
        `Deep scan ${name} must be ${minimum === 0 ? "a non-negative" : "a positive"} integer.`,
      );
    }
    selected[name] = value;
  }
  return selected;
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
    try {
      document = parseToml(
        await readFile(source, { encoding: "utf8", signal }),
      );
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw new CodexSecurityError(
          `Cannot read Codex Security configuration at ${source}.`,
          { cause: error },
        );
      }
    }
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
  const values: Record<string, unknown> = { ...DEFAULT_DEEP_SCAN_SETTINGS };
  const sources = {} as DeepScanSources;
  for (const [name, key] of DEEP_SCAN_SETTINGS) {
    if (Object.hasOwn(configured, key)) values[name] = configured[key];
    if (name === "workers" && values[name] === "auto")
      values[name] = DEFAULT_DEEP_SCAN_SETTINGS.workers;
    if (explicit[name] !== undefined) values[name] = explicit[name];
    sources[name] =
      explicit[name] !== undefined
        ? "override"
        : Object.hasOwn(configured, key)
          ? "legacy"
          : "default";
  }
  const settings = deepScanOptions({
    ...values,
    mode: "deep",
  } as DeepScanOptions & { mode: ScanMode }) as Required<DeepScanOptions>;
  return {
    settings,
    sources,
    source,
    document,
    hasOverrides: Object.keys(explicit).length > 0,
  };
}

export async function writeDeepScanConfig(
  destination: string,
  resolved: ResolvedDeepScanConfig,
): Promise<void> {
  if (!resolved.hasOverrides) {
    const [source, target] = await Promise.all([
      realpath(resolved.source).catch(() => null),
      realpath(destination).catch(() => null),
    ]);
    if (source !== null && source === target) return;
  }
  await writeCodexConfig(destination, {
    ...resolved.document,
    deep_scan: Object.fromEntries(
      DEEP_SCAN_SETTINGS.map(([name, key]) => [key, resolved.settings[name]]),
    ),
  } as JsonObject);
}
