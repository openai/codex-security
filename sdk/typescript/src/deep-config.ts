import { isRecord } from "./record.js";
import { lstat, readFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { parse as parseToml, type TomlTable } from "smol-toml";
import { writeCodexConfig, type JsonObject } from "./config.js";
import { canonicalConfigPath } from "./runtime.js";
import {
  DEEP_SCAN_SETTINGS,
  DEFAULT_DEEP_SCAN_SETTINGS,
  hoursConflict,
} from "./deep-scan-defaults.js";
import { CodexSecurityError } from "./errors.js";
import {
  DEFAULT_SCAN_MODE,
  DeepScanSettingsSchema,
  ScanSettingsSchema,
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
  source: string;
  document: TomlTable;
}

export function deepScanOptions(
  options: DeepScanOptions & { mode?: ScanMode; maxTimeMinutes?: number },
): DeepScanOptions {
  const selected: DeepScanOptions = {};
  const minutes = ScanSettingsSchema.shape.maxTimeMinutes.safeParse(
    options.maxTimeMinutes,
  );
  if (!minutes.success) {
    throw new CodexSecurityError(
      "maxTimeMinutes / --max-time must be a finite positive number of minutes.",
    );
  }
  for (const [name] of DEEP_SCAN_SETTINGS) {
    const value = options[name];
    if (value === undefined) continue;
    if ((options.mode ?? DEFAULT_SCAN_MODE) !== "deep") {
      throw new CodexSecurityError("Deep scan settings require deep mode.");
    }
    selected[name] = requireDeepScanValue(name, value, name);
  }
  if (minutes.data !== undefined && options.mode === "deep") {
    if (minutes.data > 5760) {
      throw new CodexSecurityError(
        "Deep scan maxTimeMinutes / --max-time must be no greater than 5760 minutes.",
      );
    }
    const hours = minutes.data / 60;
    if (hoursConflict(hours, selected.maxTimeHours)) {
      throw new CodexSecurityError(
        "Conflicting maxTimeMinutes / --max-time and maxTimeHours / --max-time-hours settings.",
      );
    }
    selected.maxTimeHours = hours;
  }
  if (
    minutes.data !== undefined &&
    !Number.isFinite(new Date(Date.now() + minutes.data * 60_000).getTime())
  ) {
    throw new CodexSecurityError(
      "maxTimeMinutes / --max-time must produce a deadline within the supported date range.",
    );
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
  options: DeepScanOptions & { maxTimeMinutes?: number },
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
    (!isRecord(existing) ||
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
  const settings: Required<DeepScanOptions> = { ...DEFAULT_DEEP_SCAN_SETTINGS };
  const sources = {} as DeepScanSources;
  for (const [name, key] of DEEP_SCAN_SETTINGS) {
    const legacy = Object.hasOwn(configured, key) ? configured[key] : undefined;
    const override = explicit[name];
    sources[name] =
      override !== undefined
        ? "override"
        : legacy !== undefined
          ? "legacy"
          : "default";
    const value = override ?? legacy ?? settings[name];
    settings[name] = requireDeepScanValue(
      name,
      name === "workers" && value === "auto"
        ? DEFAULT_DEEP_SCAN_SETTINGS.workers
        : value,
      sources[name] === "legacy" ? `${key} in ${source}` : name,
    );
  }
  return {
    settings,
    sources,
    source,
    document,
  };
}

export async function writeDeepScanConfig(
  destination: string,
  resolved: ResolvedDeepScanConfig,
  workerRuntime?: JsonObject,
): Promise<void> {
  const [source, target] = await Promise.all([
    canonicalConfigPath(resolved.source),
    runtimeConfigPath(destination),
  ]);
  const ambient = source === target;
  const fields = DEEP_SCAN_SETTINGS.filter(
    ([name]) => !ambient || resolved.sources[name] === "override",
  );
  if (fields.length === 0) return;
  const document = ambient
    ? await readDeepScanDocument(destination)
    : resolved.document;
  // A complete snapshot replaces the Deep table. Partial ambient writes preserve other keys.
  await writeCodexConfig(destination, {
    ...document,
    ...(workerRuntime === undefined ? {} : { worker_runtime: workerRuntime }),
    deep_scan: {
      ...(fields.length < DEEP_SCAN_SETTINGS.length
        ? (document["deep_scan"] as TomlTable | undefined)
        : {}),
      ...Object.fromEntries(
        fields.map(([name, key]) => [key, resolved.settings[name]]),
      ),
    },
  } as JsonObject);
}

async function runtimeConfigPath(path: string): Promise<string> {
  try {
    return await canonicalConfigPath(path);
  } catch (error) {
    if (
      (error as NodeJS.ErrnoException).code !== "ELOOP" ||
      !(await lstat(path)).isSymbolicLink()
    )
      throw error;
    // A stale cyclic file link is replaced by writeCodexConfig's atomic rename.
    // Errors resolving its parent (or the ambient source) still fail the write.
    return join(await canonicalConfigPath(dirname(path)), basename(path));
  }
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
