import { rawEnvironmentValue as environmentValue } from "./codex-home.js";
export { rawEnvironmentValue as environmentValue } from "./codex-home.js";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { forwardExternalImportSetting } from "./external-imports-feature.js";
import { EXTERNAL_CODEX_PROVIDERS, isExternalModelProvider } from "./config.js";
import { AuthenticationRequiredError } from "./errors.js";
import {
  DEFAULT_SCAN_AUTH,
  SCAN_AUTH_MODES,
  type ScanAuthMode,
} from "./scan-settings.js";
import type { ProcessEnvironment } from "./runtime.js";

export type ScanAuthentication =
  | { method: "host"; verified: false }
  | { method: "command"; verified: false }
  | {
      method: "api_key";
      source: string;
      verified: false;
    }
  | {
      method: "stored_credentials";
      credentialType?: "api_key" | "chatgpt";
      verified: false;
    }
  | {
      method: "aws_credentials";
      source:
        | "AWS_BEARER_TOKEN_BEDROCK"
        | "AWS_ACCESS_KEY_ID"
        | "AWS_PROFILE"
        | "AWS_WEB_IDENTITY_TOKEN_FILE"
        | "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
        | "AWS_CONTAINER_CREDENTIALS_FULL_URI"
        | "default_credential_chain";
      verified: false;
    };

export function scanAuthentication(
  environment: ProcessEnvironment,
  auth: ScanAuthMode = DEFAULT_SCAN_AUTH,
  modelProvider?: unknown,
  commandAuth = false,
  options:
    | boolean
    | {
        preflight?: boolean;
        preserveProviderEnvironment?: boolean;
        providerEnvKey?: string;
      } = false,
  providerEnvKey?: string,
): ScanAuthentication {
  const preflight = typeof options === "boolean" ? options : options.preflight;
  if (typeof options !== "boolean") providerEnvKey ??= options.providerEnvKey;
  if (!SCAN_AUTH_MODES.includes(auth)) {
    throw new TypeError(
      "Scan authentication mode must be auto, chatgpt, or api-key.",
    );
  }
  if (commandAuth) return { method: "command", verified: false };
  if (modelProvider === "amazon-bedrock") {
    const sources = [
      "AWS_BEARER_TOKEN_BEDROCK",
      "AWS_ACCESS_KEY_ID",
      "AWS_PROFILE",
      "AWS_WEB_IDENTITY_TOKEN_FILE",
      "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
      "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    ] as const;
    const source = sources.find((name) => environmentValue(environment, name));
    return {
      method: "aws_credentials",
      source: source ?? "default_credential_chain",
      verified: false,
    };
  }
  if (auth === "chatgpt" && !isExternalModelProvider(modelProvider)) {
    return { method: "stored_credentials", verified: false };
  }
  const key = environmentApiKeyEntry(
    environment,
    modelProvider,
    providerEnvKey,
  );
  if (
    key === null &&
    isExternalModelProvider(modelProvider) &&
    !(typeof options !== "boolean" && options.preserveProviderEnvironment)
  ) {
    const provider = EXTERNAL_CODEX_PROVIDERS[modelProvider];
    if (preflight && auth === "auto") {
      return {
        method: "api_key",
        source: providerEnvKey ?? provider.env_key,
        verified: false,
      };
    }
    throw new AuthenticationRequiredError(
      `Set ${providerEnvKey ?? provider.env_key} to run a scan through ${provider.name}.`,
    );
  }
  if (
    auth === "api-key" &&
    key === null &&
    !isExternalModelProvider(modelProvider)
  ) {
    throw new AuthenticationRequiredError(
      "API-key authentication requires OPENAI_API_KEY or CODEX_API_KEY. " +
        "Set a valid API key or use '--auth chatgpt'.",
    );
  }
  return key === null
    ? { method: "stored_credentials", verified: false }
    : { method: "api_key", source: key.source, verified: false };
}

/** @internal */
export async function runtimeScanAuthentication(
  environment: ProcessEnvironment,
  codexHome: string,
  auth: ScanAuthMode = "auto",
  modelProvider?: unknown,
  options?:
    string | { preserveProviderEnvironment?: boolean; providerEnvKey?: string },
): Promise<ScanAuthentication> {
  const authentication = scanAuthentication(
    environment,
    auth,
    modelProvider,
    false,
    typeof options === "string" ? false : options,
    typeof options === "string" ? options : options?.providerEnvKey,
  );
  if (authentication.method !== "stored_credentials") return authentication;

  try {
    const stored = JSON.parse(
      await readFile(join(codexHome, "auth.json"), "utf8"),
    ) as unknown;
    if (!isRecord(stored)) return authentication;

    const mode = stored["auth_mode"];
    if (mode === "apikey" || mode === "api_key") {
      return { ...authentication, credentialType: "api_key" };
    }
    if (mode === "chatgpt") {
      return { ...authentication, credentialType: "chatgpt" };
    }
  } catch {
    return authentication;
  }

  return authentication;
}

/** @internal */
export function selectedScanEnvironment(
  environment: ProcessEnvironment,
  auth: ScanAuthMode = "auto",
  modelProvider?: unknown,
  providerEnvKey?: string,
): ProcessEnvironment {
  const standardProviderKey = isExternalModelProvider(modelProvider)
    ? EXTERNAL_CODEX_PROVIDERS[modelProvider].env_key
    : null;
  const selectedProviderKey =
    standardProviderKey === null
      ? null
      : (providerEnvKey ?? standardProviderKey);
  const bedrockProvider = modelProvider === "amazon-bedrock";
  if (auth !== "chatgpt" && selectedProviderKey === null && !bedrockProvider) {
    return environment;
  }
  const selected = Object.fromEntries(
    Object.entries(environment).filter(([name]) => {
      const key = name.toUpperCase();
      if (key === "OPENAI_API_KEY" || key === "CODEX_API_KEY") {
        return (
          selectedProviderKey !== null &&
          key === selectedProviderKey.toUpperCase()
        );
      }
      if (
        key === "OPENROUTER_API_KEY" ||
        key === "FIREWORKS_API_KEY" ||
        key === "CHEAPER_INFERENCE_API_KEY"
      ) {
        return (
          !bedrockProvider &&
          (selectedProviderKey === null ||
            key === standardProviderKey ||
            key === selectedProviderKey.toUpperCase())
        );
      }
      return true;
    }),
  );
  forwardExternalImportSetting(environment, selected);
  return selected;
}

export function environmentApiKey(
  environment: ProcessEnvironment,
  modelProvider?: unknown,
  providerEnvKey?: string,
): string | null {
  return (
    environmentApiKeyEntry(environment, modelProvider, providerEnvKey)?.value ??
    null
  );
}

function environmentApiKeyEntry(
  environment: ProcessEnvironment,
  modelProvider?: unknown,
  providerEnvKey?: string,
): { source: string; value: string } | null {
  const keys = isExternalModelProvider(modelProvider)
    ? [providerEnvKey ?? EXTERNAL_CODEX_PROVIDERS[modelProvider].env_key]
    : (["OPENAI_API_KEY", "CODEX_API_KEY"] as const);
  for (const requested of keys) {
    const value = environmentValue(environment, requested)?.trim();
    if (value) return { source: requested, value };
  }
  return null;
}

export function definedEnvironment(
  environment: ProcessEnvironment,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(environment).filter(
      (entry): entry is [string, string] => entry[1] !== undefined,
    ),
  );
}

export function withoutCodexHome(
  environment: ProcessEnvironment,
): Record<string, string> {
  const child = Object.fromEntries(
    Object.entries(definedEnvironment(environment)).filter(
      ([name]) => name.toUpperCase() !== "CODEX_HOME",
    ),
  );
  forwardExternalImportSetting(environment, child);
  return child;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
