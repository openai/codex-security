import { CodexSecurityError } from "./errors.js";

export const DEFAULT_CLOUD_BASE_URL =
  "https://chatgpt.com/backend-api/aardvark";

/** Resolve the deployment once so discovery, writes, and retries share a host. */
export function cloudBaseUrl(environment: NodeJS.ProcessEnv): string {
  const configured = environment["CODEX_SECURITY_CLOUD_BASE_URL"];
  if (configured === undefined) return DEFAULT_CLOUD_BASE_URL;
  let url: URL;
  try {
    url = new URL(configured.trim());
  } catch {
    throw new CodexSecurityError(
      "CODEX_SECURITY_CLOUD_BASE_URL must be an absolute HTTP(S) Cloud API base URL.",
    );
  }
  if (
    !["https:", "http:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  )
    throw new CodexSecurityError(
      "CODEX_SECURITY_CLOUD_BASE_URL must be an HTTP(S) Cloud API base URL without credentials, a query, or a fragment.",
    );
  return url.href.replace(/\/+$/u, "");
}
