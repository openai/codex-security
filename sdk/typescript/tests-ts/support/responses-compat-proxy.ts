import type { JsonObject } from "../../src/config.js";

/** Base URLs of providers routed through the Responses compatibility proxy. */
export const COMPAT_PROXY_BASE_URL_PATTERN =
  /^http:\/\/127\.0\.0\.1:\d+\/[0-9a-f-]+\/v1$/;

/**
 * Providers routed through the Responses compatibility proxy keep every field
 * except `base_url`, which points at the per-scan loopback proxy. Normalize a
 * live `model_providers` object against the configured providers so equality
 * assertions compare everything else. Only base URLs that match the proxy
 * pattern are replaced, so an unexpected endpoint still fails the comparison;
 * the replaced URLs are returned for a pattern assertion.
 */
export function normalizeCompatProxyProviders(
  actual: JsonObject,
  expected: JsonObject,
): { providers: JsonObject; proxyUrls: string[] } {
  const providers: JsonObject = {};
  const proxyUrls: string[] = [];
  for (const [id, definition] of Object.entries(actual)) {
    if (
      typeof definition === "object" &&
      definition !== null &&
      !Array.isArray(definition) &&
      typeof (definition as JsonObject)["base_url"] === "string" &&
      COMPAT_PROXY_BASE_URL_PATTERN.test(
        (definition as JsonObject)["base_url"] as string,
      )
    ) {
      proxyUrls.push((definition as JsonObject)["base_url"] as string);
      const expectedDefinition = expected[id];
      const expectedBaseUrl =
        typeof expectedDefinition === "object" &&
        expectedDefinition !== null &&
        !Array.isArray(expectedDefinition)
          ? (expectedDefinition as JsonObject)["base_url"]
          : undefined;
      providers[id] =
        typeof expectedBaseUrl === "string"
          ? { ...(definition as JsonObject), base_url: expectedBaseUrl }
          : definition;
    } else {
      providers[id] = definition;
    }
  }
  return { providers, proxyUrls };
}
