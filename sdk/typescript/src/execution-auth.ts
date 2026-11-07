/** @internal */
import {
  environmentEntry,
  rawEnvironmentValue as environmentValue,
} from "./codex-home.js";
export { rawEnvironmentValue as environmentValue } from "./codex-home.js";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { configuredAuthEnvironment } from "./auth.js";
import {
  EXTERNAL_CODEX_PROVIDERS,
  hasCommandAuth,
  isExternalModelProvider,
  resolveCodexProfile,
  type JsonObject,
} from "./config.js";
import { AuthenticationRequiredError, ConfigurationError } from "./errors.js";
import { isRecord } from "./record.js";
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
  options: {
    preflight?: boolean;
    providerEnvKey?: string;
    preserveProviderEnvironment?: boolean;
  } = {},
): ScanAuthentication {
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
  const provider = isExternalModelProvider(modelProvider)
    ? EXTERNAL_CODEX_PROVIDERS[modelProvider]
    : undefined;
  const selectedKey = options.providerEnvKey ?? provider?.env_key;
  if (auth === "chatgpt" && provider === undefined) {
    if (selectedKey !== undefined)
      throw new ConfigurationError(
        `ChatGPT authentication cannot use the ${modelProvider} provider's required ${selectedKey} environment key. Use '--auth api-key' or choose a provider configured for ChatGPT.`,
      );
    return { method: "stored_credentials", verified: false };
  }
  const key = environmentApiKeyEntry(environment, modelProvider, selectedKey);
  if (
    key === null &&
    selectedKey !== undefined &&
    !options.preserveProviderEnvironment
  ) {
    if (options.preflight && auth === "auto") {
      return {
        method: "api_key",
        source: selectedKey,
        verified: false,
      };
    }
    throw new AuthenticationRequiredError(
      `Set ${selectedKey} to run a scan through ${provider?.name ?? modelProvider}.`,
    );
  }
  if (auth === "api-key" && key === null) {
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
  options: {
    preserveProviderEnvironment?: boolean;
    providerEnvKey?: string;
  } = {},
): Promise<ScanAuthentication> {
  const authentication = scanAuthentication(
    environment,
    auth,
    modelProvider,
    false,
    options,
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
  config?: JsonObject,
): ProcessEnvironment {
  const standardProviderKey = isExternalModelProvider(modelProvider)
    ? EXTERNAL_CODEX_PROVIDERS[modelProvider].env_key
    : null;
  const selectedProviderKey = providerEnvKey ?? standardProviderKey;
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
  if (
    config !== undefined &&
    providerEnvKey !== undefined &&
    standardProviderKey === null &&
    !hasCommandAuth(config)
  ) {
    Object.assign(
      selected,
      declaredProviderEnvironment(
        resolveCodexProfile(config)["model_providers"],
        auth === "chatgpt"
          ? configuredAuthEnvironment(environment)
          : environment,
      ),
    );
  }
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
  if (providerEnvKey !== undefined && !isExternalModelProvider(modelProvider)) {
    const value = environmentEntry(environment, providerEnvKey);
    return value?.trim() ? { source: providerEnvKey, value } : null;
  }
  const selected =
    providerEnvKey ??
    (isExternalModelProvider(modelProvider)
      ? EXTERNAL_CODEX_PROVIDERS[modelProvider].env_key
      : undefined);
  const keys =
    selected === undefined ? ["OPENAI_API_KEY", "CODEX_API_KEY"] : [selected];
  for (const requested of keys) {
    const value = environmentValue(environment, requested)?.trim();
    if (value) return { source: requested, value };
  }
  return null;
}

export function declaredProviderEnvironment(
  providers: unknown,
  environment: ProcessEnvironment,
): Record<string, string> {
  const names = isRecord(providers)
    ? Object.values(providers)
        .flatMap((providerConfig) =>
          isRecord(providerConfig)
            ? [
                providerConfig["env_key"],
                ...(isRecord(providerConfig["env_http_headers"])
                  ? Object.values(providerConfig["env_http_headers"])
                  : []),
              ]
            : [],
        )
        .filter((name): name is string => typeof name === "string")
    : [];
  return Object.fromEntries(
    names.flatMap((name) => {
      const key =
        process.platform === "win32"
          ? Object.keys(environment)
              .sort()
              .find((key) => key.toUpperCase() === name.toUpperCase())
          : name;
      const value = key === undefined ? undefined : environment[key];
      return value === undefined ? [] : [[name, value]];
    }),
  );
}

/** Keep model credentials out of local helper processes. */
export function withoutProviderEnvironment(
  environment: ProcessEnvironment,
  modelEnvironment?: Record<string, string>,
): ProcessEnvironment {
  if (modelEnvironment === undefined) return environment;
  const keys = new Set(
    Object.keys(modelEnvironment).map((key) => key.toUpperCase()),
  );
  const child = Object.fromEntries(
    Object.entries(environment).filter(([key]) => !keys.has(key.toUpperCase())),
  );
  return child;
}

export function definedEnvironment(
  environment: ProcessEnvironment,
): Record<string, string> {
  const child = Object.fromEntries(
    Object.entries(environment).filter(
      (entry): entry is [string, string] => entry[1] !== undefined,
    ),
  );
  return child;
}

export function withoutCodexHome(
  environment: ProcessEnvironment,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(definedEnvironment(environment)).filter(
      ([name]) => name.toUpperCase() !== "CODEX_HOME",
    ),
  );
}
