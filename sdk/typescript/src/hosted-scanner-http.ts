import { CodexSecurityError } from "./errors.js";
import { normalizeHostedGitRepositoryUrl } from "./hosted-git-repository.js";
import { importEnvironmentSetting } from "./external-imports-feature.js";
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

/** Use the selected vendor credential only with its configured service origin. */
export function hostedScannerToken(
  environment: NodeJS.ProcessEnv,
  tokenName: string,
  explicitToken: string | undefined,
  origin: string,
  ...originNames: string[]
): string | undefined {
  const token =
    explicitToken ?? importEnvironmentSetting(environment, tokenName)?.value;
  if (token) {
    for (const name of originNames) {
      const configured = importEnvironmentSetting(environment, name)?.value;
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
    const response = await request(url, {
      method: "GET",
      headers: {
        accept: "application/vnd.api+json, application/json",
        authorization,
      },
      redirect: "error",
      signal,
    });
    if (!response.ok) {
      const retry = response.headers.get("retry-after");
      const detail = await response.text();
      throw new CodexSecurityError(
        `GET ${url.origin}${url.pathname} failed (HTTP ${response.status})${retry ? `; Retry-After: ${retry}` : ""}${detail ? `: ${detail}` : "."}`,
      );
    }
    return parseHostedScannerJson(
      new TextDecoder("utf-8", { fatal: true }).decode(
        await response.arrayBuffer(),
      ),
    );
  }
  return { signal, getJson };
}
