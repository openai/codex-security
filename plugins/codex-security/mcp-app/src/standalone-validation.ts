// Source-only builds resolve this module. Full builds bundle the SDK
// implementation through build_mcp_app.mjs.
import { homedir } from "node:os";
import { join, resolve } from "node:path";

export function codexSecurityStateDirectory() {
  const expand = (value: string) => {
    if (value === "~") return homedir();
    if (value.startsWith("~/")) return join(homedir(), value.slice(2));
    if (value.startsWith("~\\"))
      return join(homedir(), ...value.slice(2).split("\\"));
    return value;
  };
  const override = process.env.CODEX_SECURITY_STATE_DIR;
  if (override?.trim())
    return resolve(
      expand(process.platform === "win32" ? override.trim() : override),
    );
  const home = process.env.CODEX_HOME;
  return resolve(
    expand(home?.trim() ? home : "~/.codex"),
    "state",
    "plugins",
    "codex-security",
  );
}

export type ValidationProviderConfiguration = {
  provider: string;
  [key: string]: unknown;
};

function unavailable(): never {
  throw new Error(
    "For host-side validation, install the packaged plugin or build it from a checkout including sdk/typescript.",
  );
}

export const validationProviderFromConfiguration: (
  configuration: ValidationProviderConfiguration,
) => unknown = unavailable;
export const assessPluginFindings: (...args: unknown[]) => never = unavailable;
// Source-only builds can read the protected cache written by the packaged SDK.
export const continuumAssessmentVersion = 4;

// Only the SDK can run the provider or update the saved assessment.
export function withPublicationLock<T>(
  _state: string,
  _key: string,
  _signal: AbortSignal | undefined,
  operation: () => Promise<T>,
) {
  return operation();
}
