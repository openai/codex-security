import type { CodexSecuritySurface } from "./api.js";
import { VERSION } from "./version.js";

/** Attribution for model requests, independent of native analytics events. */
export function codexSecurityRequestMetadata(
  surface: CodexSecuritySurface,
  command: string,
  pluginVersion?: string,
) {
  return {
    codex_security_surface: surface,
    codex_security_command: command,
    codex_security_package_version: VERSION,
    ...(pluginVersion === undefined
      ? {}
      : { codex_security_plugin_version: pluginVersion }),
  };
}
