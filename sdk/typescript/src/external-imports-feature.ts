import { environmentEntry } from "./auth.js";
import { CodexSecurityError } from "./errors.js";

export function externalImportsEnabled(
  environment: NodeJS.ProcessEnv = process.env,
): boolean {
  return (
    environmentEntry(environment, "CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS") ===
    "1"
  );
}

export function requireExternalImports(
  environment: NodeJS.ProcessEnv = process.env,
): void {
  if (!externalImportsEnabled(environment)) {
    throw new CodexSecurityError(
      "External findings imports are disabled. Set CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1 to enable them.",
    );
  }
}
