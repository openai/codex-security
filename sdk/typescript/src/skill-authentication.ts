import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import {
  scanAuthentication,
  selectedScanEnvironment,
  type ScanAuthMode,
  type ScanAuthentication,
} from "./api.js";
import { environmentEntry } from "./auth.js";
import {
  deepMerge,
  EXTERNAL_CODEX_PROVIDERS,
  isExternalModelProvider,
  modelProviderConfigOverride,
  scanModelProvider,
  type JsonObject,
} from "./config.js";
import { AuthenticationRequiredError } from "./errors.js";

/** Resolve a skill's authentication before preparing homes or launching Codex. */
export function resolveSkillAuthentication(
  options: {
    auth: ScanAuthMode;
    modelProvider?: string;
    codexOverrides?: JsonObject;
    command: "validate" | "patch" | "verify-fix";
  },
  processEnvironment: NodeJS.ProcessEnv,
  ambientConfig: JsonObject,
) {
  const overrides = parseToml(
    stringifyToml(options.codexOverrides ?? {}),
  ) as JsonObject;
  const config = deepMerge(structuredClone(ambientConfig), overrides);
  const provider = options.modelProvider ?? scanModelProvider(config);
  // Native Codex ignores configured tables for these built-in providers.
  const providerConfiguration =
    typeof provider === "string" &&
    !["openai", "ollama", "lmstudio"].includes(provider)
      ? (config["model_providers"] as Record<string, JsonObject> | undefined)?.[
          provider
        ]
      : undefined;
  const providerEnvKey =
    typeof providerConfiguration?.["env_key"] === "string"
      ? providerConfiguration["env_key"]
      : undefined;
  const commandAuth = providerConfiguration?.["auth"] != null;
  const explicitChatgpt =
    options.auth === "chatgpt" && !isExternalModelProvider(provider);
  const providerBearer =
    typeof providerConfiguration?.["experimental_bearer_token"] === "string";
  const providerKeyConfigured = providerEnvKey !== undefined || providerBearer;
  const requiresOpenAiAuth =
    !commandAuth &&
    (explicitChatgpt || !providerKeyConfigured) &&
    (provider === undefined ||
      provider === "openai" ||
      providerConfiguration?.["requires_openai_auth"] === true ||
      (explicitChatgpt && providerKeyConfigured));
  let authentication: ScanAuthentication;
  let configOverrides: string[] = [];
  if (providerEnvKey !== undefined && !commandAuth && !explicitChatgpt) {
    const key = environmentEntry(processEnvironment, providerEnvKey)?.trim();
    if (!key && options.auth === "api-key") {
      throw new AuthenticationRequiredError(
        `API-key authentication requires ${providerEnvKey}. Set a valid API key for the selected provider.`,
      );
    }
    authentication = key
      ? { method: "api_key", source: providerEnvKey, verified: false }
      : { method: "stored_credentials", verified: false };
  } else {
    authentication = scanAuthentication(
      processEnvironment,
      options.auth,
      provider,
      commandAuth,
    );
  }
  if (
    authentication.method === "stored_credentials" &&
    isExternalModelProvider(provider)
  ) {
    const externalProvider = EXTERNAL_CODEX_PROVIDERS[provider];
    throw new AuthenticationRequiredError(
      `Set ${providerEnvKey ?? externalProvider.env_key} to run ${options.command} through ${externalProvider.name}.`,
    );
  }
  let selected = selectedScanEnvironment(
    processEnvironment,
    authentication.method === "command" ? "chatgpt" : options.auth,
    provider,
  );
  if (
    explicitChatgpt &&
    !commandAuth &&
    providerConfiguration !== undefined &&
    providerKeyConfigured
  ) {
    if (providerEnvKey !== undefined) {
      selected = Object.fromEntries(
        Object.entries(selected).filter(([name]) =>
          process.platform === "win32"
            ? name.toUpperCase() !== providerEnvKey.toUpperCase()
            : name !== providerEnvKey,
        ),
      );
    }
    // Native provider keys take precedence over stored authentication.
    // Apply explicit ChatGPT selection to the home and CLI configuration.
    const providerOverrides =
      typeof provider === "string"
        ? (
            overrides["model_providers"] as
              Record<string, JsonObject> | undefined
          )?.[provider]
        : undefined;
    for (const selectedConfig of [providerConfiguration, providerOverrides]) {
      if (selectedConfig === undefined) continue;
      delete selectedConfig["env_key"];
      delete selectedConfig["experimental_bearer_token"];
      selectedConfig["requires_openai_auth"] = true;
    }
    configOverrides = modelProviderConfigOverride(overrides);
  }
  return {
    authentication,
    provider,
    providerConfiguration,
    providerEnvKey,
    requiresOpenAiAuth,
    environment: selected,
    configOverrides,
  };
}
