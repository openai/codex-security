import { readFile, realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { extname, isAbsolute, resolve } from "node:path";
import Ajv from "ajv";
import { parseDocument } from "yaml";
import schema from "./project-config.schema.json";

const validate = new Ajv({ allErrors: true }).compile(schema);
const fields = {
  workers: "workers",
  subagents_per_worker: "subagents",
  stop_after_no_new: "stopAfterNoNew",
  stop_after_consecutive_errors: "stopAfterConsecutiveErrors",
  max_discovery_runs: "maxDiscoveryRuns",
  max_time_hours: "maxTimeHours",
} as const;

export interface DeepScanProjectConfig {
  path: string;
  settings: Partial<Record<(typeof fields)[keyof typeof fields], number>>;
}

/** Read only an explicitly selected file; repository configuration is never discovered. */
export async function readDeepScanProjectConfig(
  file: string | undefined,
  canonicalTarget: string,
): Promise<DeepScanProjectConfig | undefined> {
  if (file === undefined) return undefined;
  const selected = file.replace(/^~(?=$|[/\\])/, () => homedir());
  const extension = extname(selected).toLowerCase();
  if (![".json", ".yaml", ".yml"].includes(extension)) {
    throw new Error(
      "Project configuration must be a .yaml, .yml, or .json file.",
    );
  }
  let requested = selected;
  if (process.platform === "win32")
    requested = resolve(canonicalTarget, selected);
  // Preserve POSIX symlink traversal before a subsequent "..".
  else if (!isAbsolute(selected)) requested = `${canonicalTarget}/${selected}`;
  const path = await realpath(requested);
  const text = await readFile(path, "utf8");
  let value: unknown;
  try {
    if (extension === ".json") value = JSON.parse(text);
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
  if (!validate(value)) {
    throw new Error(
      `Invalid project configuration at ${path}: ${validate.errors!.map((issue) => `${issue.instancePath || "configuration"}: ${issue.keyword === "additionalProperties" ? `Unknown key ${issue.params["additionalProperty"]}.` : issue.message}`).join("; ")}`,
    );
  }
  const input = value as {
    scan?: {
      mode?: string;
      max_time_minutes?: number;
      deep?: Record<keyof typeof fields, number>;
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
  for (const [field, name] of Object.entries(fields)) {
    const value = input.scan?.deep?.[field as keyof typeof fields];
    if (value !== undefined) settings[name] = value;
  }
  const minutes = input.scan?.max_time_minutes;
  if (minutes !== undefined) {
    if (minutes > 5760)
      throw new Error(
        "Deep Scan scan.max_time_minutes must be no greater than 5760 minutes.",
      );
    const hours = minutes / 60;
    if (
      settings.maxTimeHours !== undefined &&
      Math.abs(settings.maxTimeHours - hours) >
        Number.EPSILON * Math.max(settings.maxTimeHours, hours)
    ) {
      throw new Error(
        "Conflicting scan.max_time_minutes and scan.deep.max_time_hours settings.",
      );
    }
    settings.maxTimeHours = hours;
  }
  return { path, settings };
}
