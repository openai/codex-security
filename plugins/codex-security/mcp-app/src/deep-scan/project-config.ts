import { readFile, realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { extname, isAbsolute, resolve } from "node:path";
import Ajv, { type ValidateFunction } from "ajv";
import { parseDocument } from "yaml";
import { DEEP_SCAN_SETTINGS, hoursConflict } from "../deep-scan-settings.js";
import schema from "./project-config.schema.json";

let validate: ValidateFunction | undefined;
export interface DeepScanProjectConfig {
  path: string;
  selectedPath?: string;
  settings: Partial<Record<(typeof DEEP_SCAN_SETTINGS)[number][0], number>>;
}

/** Keep POSIX symlink traversal before a subsequent "..". */
export function selectedProjectConfigPath(
  file: string,
  target: string,
): string {
  const spelling =
    process.platform !== "win32" && file.startsWith("~\\")
      ? file.replaceAll("\\", "/")
      : file;
  const selected = spelling.replace(/^~(?=$|[/\\])/, () => homedir());
  if (process.platform === "win32") return resolve(target, selected);
  return isAbsolute(selected) ? selected : `${target}/${selected}`;
}

/** Read only an explicitly selected file; repository configuration is never discovered. */
export async function readDeepScanProjectConfig(
  file: string | undefined,
  canonicalTarget: string,
): Promise<DeepScanProjectConfig | undefined> {
  if (file === undefined) return undefined;
  const requested = selectedProjectConfigPath(file, canonicalTarget);
  const extension = extname(requested).toLowerCase();
  if (![".json", ".yaml", ".yml"].includes(extension)) {
    throw new Error(
      "Project configuration must be a .yaml, .yml, or .json file.",
    );
  }
  const path = await realpath(requested);
  const text = await readFile(path, "utf8");
  let value: unknown;
  try {
    if (extension === ".json") value = JSON.parse(text.replace(/^\uFEFF/u, ""));
    else {
      const document = parseDocument(text, { prettyErrors: false });
      if (document.errors.length > 0) throw document.errors[0];
      value = document.toJS({ maxAliasCount: 10_000 });
    }
  } catch (error) {
    throw new Error(
      `Cannot parse project configuration at ${path}: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  }
  validate ??= new Ajv({ allErrors: true }).compile(schema);
  if (!validate(value)) {
    throw new Error(
      `Invalid project configuration at ${path}: ${validate.errors!.map((issue) => `${issue.instancePath || "configuration"}: ${issue.keyword === "additionalProperties" ? `Unknown key ${issue.params["additionalProperty"]}.` : issue.message}`).join("; ")}`,
    );
  }
  const input = value as {
    scan?: {
      mode?: string;
      max_time_minutes?: number;
      deep?: Record<(typeof DEEP_SCAN_SETTINGS)[number][2], number>;
    };
    [key: string]: unknown;
  };
  const unsupported = [
    ...Object.keys(input).filter((key) => !["$schema", "scan"].includes(key)),
    ...Object.keys(input.scan ?? {})
      .filter((key) => !["mode", "max_time_minutes", "deep"].includes(key))
      .map((key) => `scan.${key}`),
  ];
  if (unsupported.length > 0) {
    throw new Error(
      `Unsupported native Deep Scan project settings: ${unsupported.join(", ")}. Only scan.mode, scan.max_time_minutes, and scan.deep are supported.`,
    );
  }
  if (input.scan?.mode !== undefined && input.scan.mode !== "deep") {
    throw new Error(
      "The selected project configuration must use scan.mode: deep or omit scan.mode.",
    );
  }
  const settings: DeepScanProjectConfig["settings"] = {};
  for (const [name, , field] of DEEP_SCAN_SETTINGS) {
    const value = input.scan?.deep?.[field];
    if (value !== undefined) settings[name] = value;
  }
  const minutes = input.scan?.max_time_minutes;
  if (minutes !== undefined) {
    if (minutes > 5760)
      throw new Error(
        "Deep Scan scan.max_time_minutes must be no greater than 5760 minutes.",
      );
    const hours = minutes / 60;
    if (hoursConflict(hours, settings.maxTimeHours)) {
      throw new Error(
        "Conflicting scan.max_time_minutes and scan.deep.max_time_hours settings.",
      );
    }
    settings.maxTimeHours = hours;
  }
  return {
    path,
    ...(requested === path ? {} : { selectedPath: requested }),
    settings,
  };
}
