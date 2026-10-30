import { waitForRetry } from "./deduplication/retry.js";
import { CodexSecurityError } from "./errors.js";
import { ambiguousHostedHttpPath } from "./external-import-contract.js";
import { importEnvironmentSetting } from "./external-imports-feature.js";
import { isRecord } from "./record.js";
import {
  decodeScannerJson,
  parseHostedScannerJson,
  requiredText,
} from "./scanner-import.js";

export interface HostedScannerHttpOptions {
  environment?: NodeJS.ProcessEnv;
  fetch?: (url: URL, init: RequestInit) => Promise<Response>;
  signal?: AbortSignal;
}

export function validateHostedRepositoryUrl(value: string): void {
  if (
    /[\x00-\x20\x7f]/u.test(value) &&
    (/^https?:\/\//iu.test(value) ||
      /^https?:$/u.test(URL.parse(value)?.protocol ?? ""))
  )
    throw new CodexSecurityError(
      "HTTP(S) repository URLs must percent-encode spaces and control characters.",
    );
  if (ambiguousHostedHttpPath(value))
    throw new CodexSecurityError(
      "The repository URL has an HTTP path that does not match its Git path.",
    );
}

export function hostedRepositoryUrl(value: unknown, label: string): string {
  const raw = requiredText(value, label);
  validateHostedRepositoryUrl(raw);
  const url = URL.parse(raw);
  if (
    !url ||
    url.pathname === "/" ||
    !/^https?:\/\/[^@/?#\\\s]+\/[^?#\\]+$/iu.test(raw)
  )
    throw new Error(
      "Select an HTTP(S) source repository URL with a path and without credentials, query or fragment.",
    );
  return raw;
}

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
export function hostedEnvironmentToken(
  environment: NodeJS.ProcessEnv,
  tokenName: string,
  origin: string,
  ...originNames: string[]
): string | undefined {
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

function httpDate(hint: string, now: number): number {
  const normalized = hint.replace("23:59:60", "23:59:59");
  const leapSecond = normalized === hint ? 0 : 1000;
  let canonical = normalized;
  const asctime =
    /^(\w{3}) (\w{3}) ( \d|\d{2}) (\d{2}:\d{2}:\d{2}) (\d{4})$/u.exec(
      normalized,
    );
  const rfc850 =
    /^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (\d{2})-(\w{3})-(\d{2}) (\d{2}:\d{2}:\d{2}) GMT$/u.exec(
      normalized,
    );
  if (asctime) {
    const [, weekday, month, day, time, year] = asctime;
    canonical = `${weekday}, ${day!.replace(" ", "0")} ${month} ${year} ${time} GMT`;
  } else if (rfc850) {
    const [, weekday, day, month, year, time] = rfc850;
    const cutoff = new Date(now);
    cutoff.setUTCFullYear(cutoff.getUTCFullYear() + 50);
    const century = Math.floor(cutoff.getUTCFullYear() / 100) * 100;
    const dateIn = (century: number) =>
      `${weekday!.slice(0, 3)}, ${day} ${month} ${century + Number(year)} ${time} GMT`;
    canonical = dateIn(century);
    if (Date.parse(canonical) + leapSecond > cutoff.getTime())
      canonical = dateIn(century - 100);
  }
  const date = new Date(canonical);
  if (leapSecond && new Date(date.getTime() + leapSecond).getUTCDate() !== 1)
    return NaN;
  return canonical.length === 29 && date.toUTCString() === canonical
    ? date.getTime() + leapSecond
    : NaN;
}

function retryAfterMs(response: Response): number | undefined {
  if (response.status !== 429) return;
  const hint = response.headers.get("retry-after");
  if (!hint) return;
  let delay: number;
  if (/^\d+$/u.test(hint)) {
    delay = Number(hint) * 1000;
  } else {
    const now = Date.now();
    const serverDate = httpDate(response.headers.get("date") ?? "", now);
    const reference = Number.isNaN(serverDate) ? now : serverDate;
    delay = Math.max(0, httpDate(hint, reference) - reference);
  }
  return delay <= 10_000 ? delay : undefined;
}

export function hostedScannerHttp(
  dependencies: HostedScannerHttpOptions,
  callerSignal?: AbortSignal,
) {
  const { signal: transportSignal } = dependencies;
  const signal =
    callerSignal && transportSignal
      ? AbortSignal.any([callerSignal, transportSignal])
      : (callerSignal ?? transportSignal);
  signal?.throwIfAborted();
  const request = dependencies.fetch?.bind(dependencies) ?? fetch;
  async function getJson(url: URL, authorization: string): Promise<unknown> {
    signal?.throwIfAborted();
    if (/[\0\r\n]/u.test(authorization))
      throw new Error("Scanner API token cannot contain a NUL or line break.");
    const get = () =>
      request(new URL(url), {
        method: "GET",
        headers: {
          accept: "application/vnd.api+json, application/json",
          authorization,
        },
        redirect: "error",
        signal,
      });
    let response = await get();
    const delay = retryAfterMs(response);
    if (delay !== undefined) {
      void response.body?.cancel().catch(() => undefined);
      if (delay > 0) await waitForRetry(delay, signal);
      signal?.throwIfAborted();
      response = await get();
    }
    if (!response.ok) {
      const retry = response.headers.get("retry-after");
      const detail = await response.text();
      throw new CodexSecurityError(
        `GET ${url.origin}${url.pathname} failed (HTTP ${response.status})${retry ? `; Retry-After: ${retry}` : ""}${detail ? `: ${detail}` : "."}`,
      );
    }
    return parseHostedScannerJson(
      decodeScannerJson(await response.arrayBuffer()),
    );
  }
  return { signal, getJson };
}
