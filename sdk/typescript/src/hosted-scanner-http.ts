import { waitForRetry } from "./deduplication/retry.js";
import { canonicalNumber } from "./external-import-contract.js";
import { CodexSecurityError, errorMessage } from "./errors.js";
import { normalizeHostedGitRepositoryUrl } from "./hosted-git-repository.js";
import { isRecord } from "./record.js";
import { declaredScannerRepositoryUrl } from "./scanner-repository-url.js";

export interface HostedScannerHttpOptions {
  environment?: NodeJS.ProcessEnv;
  fetch?: (url: URL, init: RequestInit) => Promise<Response>;
  signal?: AbortSignal;
}

// Our minimum Node runtime provides source-aware JSON parsing. Our SDK targets ES2022 types.
const wireJson = JSON as JSON & {
  rawJSON(source: string): { rawJSON: string };
  isRawJSON(value: unknown): value is { rawJSON: string };
};
export function hostedNumberToken(value: unknown): string | undefined {
  return wireJson.isRawJSON(value) ? value.rawJSON : undefined;
}

/** Store native evidence by exact numeric value, independently of its wire spelling. */
export function stringifyHostedEvidence(value: unknown): string {
  return JSON.stringify(value, (_key, field: unknown) =>
    wireJson.isRawJSON(field)
      ? wireJson.rawJSON(canonicalNumber(field.rawJSON))
      : field,
  );
}

/** Keep vendor numeric IDs and evidence exact when a response is saved as JSON. */
export function parseHostedScannerJson(source: string): unknown {
  return JSON.parse(
    source,
    (_key: string, value: unknown, context?: { source?: string }) => {
      if (typeof value === "number") return wireJson.rawJSON(context!.source!);
      // Identical vendor evidence can arrive with a different member order on replay.
      return isRecord(value)
        ? Object.fromEntries(
            Object.keys(value)
              .sort()
              .map((key) => [key, value[key]]),
          )
        : value;
    },
  );
}

export function hostedRepositoryUrl(value: unknown, label: string): string {
  // Hosted Git URLs retain %23 and %3F as path bytes; a literal query or fragment is rejected.
  return declaredScannerRepositoryUrl(value, label, "local", {
    allowEncodedQueryAndFragment: true,
  });
}

/** Normalize the provider's HTTP or independently identified SSH repository address. */
export function hostedNativeRepositoryUrl(
  value: unknown,
  label: string,
  additionalGitHost?: string,
): string {
  const source = additionalGitHost ? `https://${additionalGitHost}` : undefined;
  const normalized =
    typeof value === "string" && value.trim() === value
      ? normalizeHostedGitRepositoryUrl(value, source, source !== undefined)
      : value;
  return hostedRepositoryUrl(normalized, label);
}

export function scannerEnvironmentValue(
  environment: NodeJS.ProcessEnv,
  requested: string,
) {
  const exact = environment[requested];
  if (process.platform !== "win32") return exact;
  // A scan can override a case-insensitive process.env with its own spelling.
  function callerDeclares(key: string): boolean {
    for (
      let owner: object | null = environment;
      owner && owner !== process.env;
      owner = Object.getPrototypeOf(owner)
    ) {
      if (Object.hasOwn(owner, key)) return true;
    }
    return false;
  }
  if (exact !== undefined && callerDeclares(requested)) return exact;
  // Node includes enumerable prototype keys and sorts competing spellings.
  const keys: string[] = [];
  for (const name in environment) {
    if (name.toUpperCase() === requested) keys.push(name);
  }
  keys.sort();
  const key = keys.find(callerDeclares) ?? keys[0];
  if (key !== undefined) return key === requested ? exact : environment[key];
}

/** Use the selected vendor credential only with its configured service origin. */
export function hostedScannerToken(
  environment: NodeJS.ProcessEnv,
  tokenName: string,
  explicitToken: string | undefined,
  origin: string,
  ...originNames: string[]
): string | undefined {
  const token =
    explicitToken ?? scannerEnvironmentValue(environment, tokenName);
  if (token) {
    for (const name of originNames) {
      const configured = scannerEnvironmentValue(environment, name);
      if (!configured) continue;
      if (URL.parse(configured)?.origin !== origin)
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

// A proxy's failure page can be arbitrarily large, including when chunked or compressed.
// Bound only the remote diagnostic; successful vendor findings use the normal parser.
const HTTP_ERROR_DETAIL_BYTES = 64 * 1024;

async function scannerHttpError(
  url: URL,
  response: Response,
  signal?: AbortSignal,
) {
  const retry = response.headers.get("retry-after");
  const status = `GET ${url.origin}${url.pathname} failed (HTTP ${response.status})${retry ? `; Retry-After: ${retry}` : ""}`;
  const reader = response.body?.getReader();
  if (!reader) return new CodexSecurityError(`${status}.`);
  const decoder = new TextDecoder();
  let remaining = HTTP_ERROR_DETAIL_BYTES;
  let detail = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        detail += decoder.decode();
        break;
      }
      const prefix = value.subarray(0, remaining);
      detail += decoder.decode(prefix, { stream: true });
      remaining -= prefix.byteLength;
      if (prefix.byteLength < value.byteLength) {
        void reader.cancel().catch(() => undefined);
        detail += `\nShowing the first ${HTTP_ERROR_DETAIL_BYTES} bytes of the error response.`;
        break;
      }
    }
  } catch (cause) {
    signal?.throwIfAborted();
    const received = detail ? `: ${detail}` : "";
    return new CodexSecurityError(
      `${status}${received}\nReading the error response failed: ${errorMessage(cause)}`,
      { cause },
    );
  } finally {
    reader.releaseLock();
  }
  return new CodexSecurityError(`${status}${detail ? `: ${detail}` : "."}`);
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
    if (!response.ok) throw await scannerHttpError(url, response, signal);
    return parseHostedScannerJson(
      new TextDecoder("utf-8", { fatal: true }).decode(
        await response.arrayBuffer(),
      ),
    );
  }
  return { signal, getJson };
}
