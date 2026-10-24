import type { CodexSecuritySurface } from "./api.js";
import { inlineToml, resolveCodexProfile, type JsonObject } from "./config.js";
import { isRecord } from "./record.js";
import type { ScanMode } from "./scan-modes.js";
import { VERSION } from "./version.js";

interface RequestContextOptions {
  surface: CodexSecuritySurface;
  command: string;
  pluginVersion?: string;
  mode?: ScanMode;
  /** False when this caller leaves provider selection to native config layers. */
  providerResolved?: boolean;
}

/** Per-operation attribution, independent of native analytics and OTel settings.
 * Provider family reflects wrapper configuration; native managed settings can override it. */
export function codexSecurityRequestContext(
  config: Readonly<JsonObject>,
  context: RequestContextOptions,
) {
  const resolved = resolveCodexProfile(config);
  const configured = resolved["responses_api_metadata"];
  const metadata = Object.freeze({
    ...(isRecord(configured) ? configured : {}),
    codex_security_surface: context.surface,
    codex_security_command: context.command,
    codex_security_package_version: VERSION,
    ...(context.pluginVersion === undefined
      ? {}
      : { codex_security_plugin_version: context.pluginVersion }),
    ...(context.providerResolved === false
      ? {}
      : {
          codex_security_provider: providerFamily(resolved["model_provider"]),
        }),
    ...(context.mode === undefined
      ? {}
      : { codex_security_scan_mode: context.mode }),
  }) as Readonly<Record<string, string>>;
  return Object.freeze({
    metadata,
    // The SDK's structured config flattens literal dotted keys into nested tables.
    configOverride: `responses_api_metadata=${inlineToml(metadata)}`,
  });
}

function providerFamily(provider: unknown): string {
  if (typeof provider !== "string")
    return provider === undefined ? "openai" : "custom";
  switch (provider) {
    case "openai":
    case "amazon-bedrock":
    case "cheaperinference":
    case "openrouter":
    case "fireworks":
    case "opper":
    case "ollama":
    case "lmstudio":
      return provider;
    default:
      return "custom";
  }
}
