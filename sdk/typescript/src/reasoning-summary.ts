import {
  inlineToml,
  resolveCodexProfile,
  scanModelConfiguration,
  type JsonObject,
} from "./config.js";
import { scanPreflightCodexConfig } from "./preflight-config.js";
import {
  runCodexCommand,
  type CodexCommand,
  type ProcessEnvironment,
} from "./runtime.js";

/** Capture a future owner's selected model default; never infer historical settings. */
export async function captureOriginalReasoningSummary(options: {
  config: JsonObject;
  command: CodexCommand;
  cwd: string;
  environment: ProcessEnvironment;
  signal: AbortSignal;
}): Promise<string | undefined> {
  // Keep explicit selections and invalid values with their existing native validator.
  if (
    scanPreflightCodexConfig(options.config)["model_reasoning_summary"] !==
      undefined ||
    resolveCodexProfile(options.config)["model_reasoning_summary"] !== undefined
  )
    return undefined;
  const { model } = scanModelConfiguration(options.config);
  // The same per-session overrides protect the lookup from concurrent home edits.
  const config = JSON.parse(JSON.stringify(options.config)) as JsonObject;
  const args = [
    "debug",
    "models",
    ...Object.entries(config).flatMap(([key, value]) => [
      "--config",
      `${key}=${inlineToml(value)}`,
    ]),
  ];
  const result = await runCodexCommand(
    options.command,
    args,
    options.environment,
    undefined,
    options.signal,
    options.cwd,
  );
  // Older native executables and models absent from their catalog provide no
  // recoverable value. Preserve omission instead of choosing another default.
  if (!result.success) return undefined;
  let catalog: unknown;
  try {
    catalog = JSON.parse(result.stdout);
  } catch {
    return undefined;
  }
  if (!isRecord(catalog) || !Array.isArray(catalog["models"])) return undefined;
  const selected = catalog["models"].find(
    (entry: unknown) => isRecord(entry) && entry["slug"] === model,
  );
  return isRecord(selected) &&
    typeof selected["default_reasoning_summary"] === "string"
    ? selected["default_reasoning_summary"]
    : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
