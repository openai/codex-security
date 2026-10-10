import { CodexSecurityError } from "./errors.js";

export const DEFAULT_CLOUD_BASE_URL =
  "https://chatgpt.com/backend-api/aardvark";

const CLOUD_APP_PATH =
  "/mcp-app/connector_openai_defense_factory/open_defense_factory";

/** Custom deployments can serve their UI separately from the authenticated API. */
export function cloudFindingsUrl(
  environment: NodeJS.ProcessEnv,
  repositoryId: string,
): string | undefined {
  const configured = environment["CODEX_SECURITY_CLOUD_WEB_URL"];
  const api = new URL(cloudBaseUrl(environment));
  const hosted = api.href === DEFAULT_CLOUD_BASE_URL;
  if (configured === undefined && !hosted) return undefined;
  let url: URL;
  try {
    url = new URL(configured?.trim() ?? `${api.origin}${CLOUD_APP_PATH}`);
  } catch {
    throw new CodexSecurityError(
      "CODEX_SECURITY_CLOUD_WEB_URL must be an absolute HTTP(S) Cloud app URL.",
    );
  }
  if (
    !["https:", "http:"].includes(url.protocol) ||
    url.username ||
    url.password
  )
    throw new CodexSecurityError(
      "CODEX_SECURITY_CLOUD_WEB_URL must be an HTTP(S) Cloud app URL without credentials.",
    );
  url.hash = `/repositories/${encodeURIComponent(repositoryId)}/findings`;
  return url.href;
}

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
