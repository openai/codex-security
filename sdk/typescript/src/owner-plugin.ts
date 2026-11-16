import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { bundledPluginRoot } from "./runtime.js";
import { CodexSecurityError, InvalidTargetError } from "./errors.js";
import type { OwnerResolver } from "#plugin-shared/owners/types";

export async function ownerPlugin(): Promise<OwnerResolver> {
  const url = pathToFileURL(
    join(await bundledPluginRoot(), "mcp", "scan-owners.mjs"),
  );
  return (await import(url.href)).ownerResolver;
}
// Preserve SDK error types when an independently bundled plugin rejects a checkout.
export async function withOwnerErrors<T>(
  operation: () => Promise<T>,
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof Error && error.name === "InvalidTargetError")
      throw new InvalidTargetError(error.message, { cause: error });
    if (error instanceof Error && error.name === "CodexSecurityError")
      throw new CodexSecurityError(error.message, { cause: error });
    throw error;
  }
}
