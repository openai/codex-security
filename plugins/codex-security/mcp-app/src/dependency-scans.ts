import { readFile } from "node:fs/promises";
import { join } from "node:path";

const DEFAULT_AARDVARK_BASE_URL = "https://chatgpt.com/backend-api/aardvark";
const TRUSTED_AARDVARK_DOMAINS = [
  "chatgpt.com",
  "chatgpt-staging.com",
  "openai.com",
  "openai-staging.com",
  "openai.org",
] as const;
const AARDVARK_BASE_URL_ERROR =
  "Dependency scanning must use a trusted OpenAI HTTPS origin or local loopback endpoint.";
const CHATGPT_LOGIN_ERROR =
  'Dependency scanning requires an existing ChatGPT login; use auth: "chatgpt" or --auth chatgpt.';

type JsonObject = Record<string, unknown>;

export interface DependencyScanDependency {
  ecosystem: string;
  registry: string;
  package: string;
  oldVersion: string | null;
  newVersion: string;
}

export interface DependencyScanRoleModelSettings {
  model?: string;
  reasoningEffort?: string;
}

export interface DependencyScanModelSettings {
  acquisition?: DependencyScanRoleModelSettings;
  scan?: DependencyScanRoleModelSettings;
  verification?: DependencyScanRoleModelSettings;
  history?: DependencyScanRoleModelSettings;
}

export interface DependencyScanRequest {
  dependencies: DependencyScanDependency[];
  dependencyScanTarget?: "malware" | "malware-and-vulnerabilities";
  modelSettings?: DependencyScanModelSettings;
}

export interface DependencyScanClientOptions {
  baseUrl?: string;
  codexHome?: string;
  fetchImplementation?: typeof fetch;
}

interface ChatGptCredentials {
  accessToken: string;
  accountId: string;
}

export function resolveAardvarkBaseUrl(
  configuredBaseUrl = process.env.CODEX_SECURITY_AARDVARK_BASE_URL,
): string {
  const candidate = configuredBaseUrl?.trim() || DEFAULT_AARDVARK_BASE_URL;
  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error(AARDVARK_BASE_URL_ERROR);
  }

  const hostname = parsed.hostname.toLowerCase();
  const loopback =
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "[::1]";
  const trustedDomain = TRUSTED_AARDVARK_DOMAINS.some(
    (domain) => hostname === domain || hostname.endsWith(`.${domain}`),
  );

  if (
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    (parsed.protocol !== "https:" &&
      (!loopback || parsed.protocol !== "http:")) ||
    (!loopback && !trustedDomain)
  ) {
    throw new Error(AARDVARK_BASE_URL_ERROR);
  }

  const configuredPath = parsed.pathname.replace(/\/+$/, "");
  parsed.pathname =
    configuredPath || (loopback ? "/api/aardvark" : "/backend-api/aardvark");
  return parsed.toString().replace(/\/+$/, "");
}

export async function submitDependencyScan(
  request: DependencyScanRequest,
  options: DependencyScanClientOptions = {},
): Promise<JsonObject> {
  const sendRequest = await prepareDependencyScanSubmission(request, options);
  return await sendRequest();
}

export async function prepareDependencyScanSubmission(
  request: DependencyScanRequest,
  options: DependencyScanClientOptions = {},
): Promise<() => Promise<JsonObject>> {
  const dependencies = request.dependencies.map((dependency) => ({
    ecosystem: dependency.ecosystem,
    registry: dependency.registry,
    package: dependency.package,
    old_version: dependency.oldVersion,
    new_version: dependency.newVersion,
  }));
  const modelSettings = request.modelSettings;
  const body = {
    dependencies,
    ...(request.dependencyScanTarget === undefined
      ? {}
      : { dependency_scan_target: request.dependencyScanTarget }),
    ...(modelSettings === undefined
      ? {}
      : {
          model_settings: Object.fromEntries(
            (
              ["acquisition", "scan", "verification", "history"] as const
            ).flatMap((role) => {
              const settings = modelSettings[role];
              return settings === undefined
                ? []
                : [
                    [
                      role,
                      {
                        ...(settings.model === undefined
                          ? {}
                          : { model: settings.model }),
                        ...(settings.reasoningEffort === undefined
                          ? {}
                          : { reasoning_effort: settings.reasoningEffort }),
                      },
                    ],
                  ];
            }),
          ),
        }),
  };

  return await prepareDependencyScanRequest(
    "/dependency-scans",
    {
      method: "POST",
      body: JSON.stringify(body),
    },
    options,
  );
}

export async function getDependencyScan(
  jobId: string,
  options: DependencyScanClientOptions = {},
): Promise<JsonObject> {
  if (!/^dps_[A-Za-z0-9_-]+$/.test(jobId)) {
    throw new Error("Invalid dependency scan job identifier.");
  }

  const sendRequest = await prepareDependencyScanRequest(
    `/dependency-scans/${encodeURIComponent(jobId)}`,
    { method: "GET" },
    options,
  );
  return await sendRequest();
}

async function prepareDependencyScanRequest(
  path: string,
  request: Pick<RequestInit, "body" | "method">,
  options: DependencyScanClientOptions,
): Promise<() => Promise<JsonObject>> {
  const baseUrl = resolveAardvarkBaseUrl(options.baseUrl);
  const credentials = await readChatGptCredentials(options.codexHome);
  const headers: Record<string, string> = {
    Accept: "application/json",
    Authorization: `Bearer ${credentials.accessToken}`,
    "ChatGPT-Account-ID": credentials.accountId,
  };
  if (request.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  return async () => {
    let response: Response;
    try {
      response = await (options.fetchImplementation ?? fetch)(
        `${baseUrl}${path}`,
        {
          ...request,
          headers,
          redirect: "error",
        },
      );
    } catch (error) {
      throw new Error("Dependency scan request failed.", { cause: error });
    }

    if (!response.ok) {
      const authenticationHint =
        response.status === 401 || response.status === 403
          ? " Verify the active ChatGPT login and account access."
          : "";
      throw new Error(
        `Dependency scan request failed with HTTP ${response.status}.${authenticationHint}`,
      );
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch (error) {
      throw new Error(
        "Dependency scanning returned an invalid dependency scan response.",
        { cause: error },
      );
    }
    if (!isJsonObject(body)) {
      throw new Error(
        "Dependency scanning returned an invalid dependency scan response.",
      );
    }

    return toCamelCase(body) as JsonObject;
  };
}

async function readChatGptCredentials(
  configuredCodexHome = process.env.CODEX_HOME,
): Promise<ChatGptCredentials> {
  const codexHome = configuredCodexHome?.trim();
  if (!codexHome) throw new Error(CHATGPT_LOGIN_ERROR);

  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(join(codexHome, "auth.json"), "utf8"));
  } catch (error) {
    throw new Error(CHATGPT_LOGIN_ERROR, { cause: error });
  }

  const tokens =
    isJsonObject(parsed) && isJsonObject(parsed.tokens)
      ? parsed.tokens
      : undefined;
  const accessToken =
    typeof tokens?.access_token === "string" ? tokens.access_token.trim() : "";
  const accountId =
    typeof tokens?.account_id === "string" ? tokens.account_id.trim() : "";

  if (!accessToken || !accountId) throw new Error(CHATGPT_LOGIN_ERROR);
  return { accessToken, accountId };
}

function toCamelCase(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(toCamelCase);
  if (!isJsonObject(value)) return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, nested]) => [
      key.replace(/_([a-z])/g, (_, letter: string) => letter.toUpperCase()),
      toCamelCase(nested),
    ]),
  );
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
