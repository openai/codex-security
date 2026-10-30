import { importEnvironmentSetting } from "./external-imports-feature.js";
import { isRecord } from "./record.js";

function endpointSetting(environment: NodeJS.ProcessEnv, name: string) {
  if (name === "SNYK_API_V3_URL" || name === "SNYK_API_REST_URL") {
    // snyk-config preserves key case and converts boolean literals before interpolation.
    for (const key in environment) {
      if (key !== name) continue;
      const raw = environment[key];
      if (raw === "false" || raw === "FALSE") return undefined;
      return raw?.replace(
        /\$\{([^}\r\n\u2028\u2029]*)\}?/gu,
        (match, reference: string) => {
          // Consume an unterminated reference once, leaving it literal.
          if (!match.endsWith("}")) return match;
          const requested =
            process.platform === "win32" ? reference.toUpperCase() : reference;
          const value = importEnvironmentSetting(environment, requested)?.value;
          if (value === undefined)
            throw new Error(
              `${name} references missing environment variable ${reference}.`,
            );
          return value;
        },
      );
    }
    return undefined;
  }
  return importEnvironmentSetting(environment, name)?.value;
}

function endpointOrigin(value: string, snykBase: boolean): string | undefined {
  const url = URL.parse(value);
  if (url?.protocol !== "https:") return undefined;
  // Snyk derives its REST host from the general endpoint (e.g. app.eu.snyk.io).
  if (snykBase && !url.hostname.startsWith("api."))
    url.hostname = `api.${url.hostname.replace(/^app\./u, "")}`;
  return url.origin;
}

export function checkSnykTokenOrigin(token: string, origin: string): void {
  // Snyk user and service access tokens carry their API hostname in the h claim.
  const payload =
    /^snyk_(?:uat|sat)\.[a-z0-9]{8}\.([A-Za-z0-9_-]+)\.[A-Za-z0-9_-]+$/u.exec(
      token.trim(),
    )?.[1];
  if (!payload) return;
  let claims: unknown;
  try {
    claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    return;
  }
  const host = isRecord(claims) ? claims["h"] : undefined;
  if (typeof host !== "string" || !host) return;
  const base = host.startsWith("http") ? host : `https://${host}`;
  if (endpointOrigin(base, true) !== origin)
    throw new Error(
      `The Snyk access token's API host does not match ${origin}. Select its API origin before collecting findings.`,
    );
}

/** Use a vendor environment token only at the origin configured for it. */
export function snykEnvironmentToken(
  environment: NodeJS.ProcessEnv,
  origin: string,
): string | undefined {
  const tokenName = "SNYK_TOKEN";
  const originNames = [
    "API_V3_URL",
    "SNYK_API_V3_URL",
    "API_REST_URL",
    "SNYK_API_REST_URL",
    "SNYK_API",
    "SNYK_CFG_ENDPOINT",
  ];
  const token = importEnvironmentSetting(environment, tokenName)?.value;
  if (token) {
    for (const name of originNames) {
      const configured = endpointSetting(environment, name);
      if (!configured) continue;
      const snykBase = name === "SNYK_API" || name === "SNYK_CFG_ENDPOINT";
      if (endpointOrigin(configured, snykBase) !== origin)
        throw new Error(
          `${name} does not match ${origin}. Select a matching API origin and ${tokenName} before collecting findings.`,
        );
      break;
    }
  }
  return token;
}
