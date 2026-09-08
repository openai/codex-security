import { randomUUID } from "node:crypto";
import { mkdir, open, rename, unlink } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { stringify } from "smol-toml";
import { ConfigurationError } from "./errors.js";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | JsonObject;
export interface JsonObject {
  [key: string]: JsonValue;
}

export interface CodexSecurityConfig {
  pluginPath?: string;
  codexOverrides?: JsonObject;
  pythonPath?: string;
}

export interface ScanModelConfiguration {
  model: string;
  reasoningEffort: string;
}

export const OPENROUTER_CODEX_PROVIDER = {
  name: "OpenRouter",
  base_url: "https://openrouter.ai/api/v1",
  env_key: "OPENROUTER_API_KEY",
  wire_api: "responses",
} as const satisfies JsonObject;

export const FIREWORKS_CODEX_PROVIDER = {
  name: "Fireworks AI",
  base_url: "https://api.fireworks.ai/inference/v1",
  env_key: "FIREWORKS_API_KEY",
  wire_api: "responses",
} as const satisfies JsonObject;

export const EXTERNAL_CODEX_PROVIDERS = {
  openrouter: OPENROUTER_CODEX_PROVIDER,
  fireworks: FIREWORKS_CODEX_PROVIDER,
} as const;

export type ExternalModelProvider = keyof typeof EXTERNAL_CODEX_PROVIDERS;

export function isExternalModelProvider(
  provider: unknown,
): provider is ExternalModelProvider {
  return (
    typeof provider === "string" &&
    Object.hasOwn(EXTERNAL_CODEX_PROVIDERS, provider)
  );
}

export const DEFAULT_CODEX_CONFIG: Readonly<JsonObject> = {
  approval_policy: "on-request",
  approvals_reviewer: "auto_review",
  cli_auth_credentials_store: "auto",
  model: "gpt-5.6-sol",
  model_reasoning_effort: "xhigh",
  model_reasoning_summary: "detailed",
  show_raw_agent_reasoning: true,
  features: {
    plugins: true,
    goals: true,
    multi_agent_v2: {
      enabled: true,
      max_concurrent_threads_per_session: 9,
    },
  },
  // Named filesystem profiles need an active Windows sandbox backend.
  windows: {
    sandbox: "unelevated",
  },
};

deepFreezeJson(DEFAULT_CODEX_CONFIG);

export function scanModelConfiguration(
  config: Readonly<JsonObject>,
): ScanModelConfiguration {
  const selectedProfile = selectedScanProfile(config);
  const model =
    selectedProfile !== undefined && Object.hasOwn(selectedProfile, "model")
      ? selectedProfile["model"]
      : config["model"];
  if (typeof model !== "string" || model.trim().length === 0) {
    throw new ConfigurationError(
      "The configured Codex model must be a nonempty string.",
    );
  }
  const reasoningEffort =
    selectedProfile !== undefined &&
    Object.hasOwn(selectedProfile, "model_reasoning_effort")
      ? selectedProfile["model_reasoning_effort"]
      : config["model_reasoning_effort"];
  if (
    typeof reasoningEffort !== "string" ||
    reasoningEffort.trim().length === 0
  ) {
    throw new ConfigurationError(
      "The configured Codex reasoning effort must be a nonempty string.",
    );
  }
  return { model, reasoningEffort };
}

export function scanModelProvider(config: Readonly<JsonObject>): unknown {
  const selectedProfile = selectedScanProfile(config);
  return selectedProfile !== undefined &&
    Object.hasOwn(selectedProfile, "model_provider")
    ? selectedProfile["model_provider"]
    : config["model_provider"];
}

/** @internal Native Codex validates the auth table, including invalid selections. */
export function hasCommandAuth(config: Readonly<JsonObject>): boolean {
  const selected = scanModelProvider(config);
  const providers = config["model_providers"];
  const provider =
    typeof selected === "string" && isObject(providers)
      ? providers[selected]
      : undefined;
  return isObject(provider) && provider["auth"] !== undefined;
}

/** @internal Keep host-side helpers independent of the source checkout. */
export function resolveCommandAuthConfig(
  config: JsonObject,
  home: string,
): JsonObject {
  const resolved = cloneJson(config);
  const providers = resolved["model_providers"];
  if (isObject(providers)) {
    for (const provider of Object.values(providers)) {
      if (!isObject(provider) || !isObject(provider["auth"])) continue;
      const auth = provider["auth"];
      const cwd = auth["cwd"];
      if (
        cwd === undefined ||
        (typeof cwd === "string" && !/^~(?:[/\\]|$)/u.test(cwd))
      ) {
        auth["cwd"] = resolve(home, cwd ?? ".");
      }
    }
  }
  return resolved;
}

/** @internal CLI dotted keys cannot represent provider IDs containing dots. */
export function modelProviderConfigOverride(config: JsonObject): string[] {
  return config["model_providers"] === undefined
    ? []
    : [`model_providers=${inlineToml(config["model_providers"])}`];
}

function inlineToml(value: JsonValue): string {
  if (Array.isArray(value)) return `[${value.map(inlineToml).join(",")}]`;
  if (isObject(value)) {
    return `{${Object.entries(value)
      .map(([key, item]) => `${JSON.stringify(key)}=${inlineToml(item)}`)
      .join(",")}}`;
  }
  return stringify({ value }).slice("value = ".length).trim();
}

export function scanApprovalPolicy(
  config: Readonly<JsonObject>,
): "never" | "on-request" {
  return config["approval_policy"] === "never" ||
    selectedScanProfile(config)?.["approval_policy"] === "never"
    ? "never"
    : "on-request";
}

function selectedScanProfile(
  config: Readonly<JsonObject>,
): Record<string, JsonValue> | undefined {
  const profileName = config["profile"];
  const profiles = config["profiles"];
  const configuredProfile =
    typeof profileName === "string" &&
    isObject(profiles) &&
    Object.hasOwn(profiles, profileName)
      ? profiles[profileName]
      : undefined;
  return isObject(configuredProfile) ? configuredProfile : undefined;
}

export async function mergedCodexConfig(
  config: CodexSecurityConfig,
): Promise<JsonObject> {
  if (config.codexOverrides !== undefined && !isObject(config.codexOverrides)) {
    throw new ConfigurationError("codexOverrides must be an object.");
  }
  validateOverrideKeys(config.codexOverrides ?? {});
  const overrides = cloneJson(config.codexOverrides ?? {});
  validateOverrides(overrides);
  validateNativeMultiAgentV2Overrides(overrides);
  normalizeLegacyWindowsSandboxOverride(overrides);
  const profiles = overrides["profiles"];
  if (isObject(profiles)) {
    for (const profile of Object.values(profiles)) {
      if (isObject(profile)) {
        normalizeLegacyWindowsSandboxOverride(profile);
      }
    }
  }
  return deepMerge(cloneJson(DEFAULT_CODEX_CONFIG), overrides);
}

function normalizeLegacyWindowsSandboxOverride(overrides: JsonObject): void {
  const features = overrides["features"];
  if (!isObject(features)) {
    return;
  }
  const elevated = features["elevated_windows_sandbox"];
  if (typeof elevated !== "boolean") {
    return;
  }
  const windows = overrides["windows"];
  if (
    windows !== undefined &&
    (!isObject(windows) || Object.hasOwn(windows, "sandbox"))
  ) {
    return;
  }
  overrides["windows"] = {
    ...(isObject(windows) ? windows : {}),
    sandbox: elevated ? "elevated" : "unelevated",
  };
}

export async function writeCodexConfig(
  path: string,
  config: JsonObject,
): Promise<void> {
  const parent = dirname(path);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  let contents: string;
  try {
    contents = stringify(config);
  } catch (error) {
    throw new ConfigurationError("Invalid Codex configuration.", {
      cause: error,
    });
  }
  const temporary = join(parent, `.${randomUUID()}.config.toml.tmp`);
  let created = false;
  try {
    const handle = await open(temporary, "wx", 0o600);
    created = true;
    try {
      await handle.chmod(0o600);
      await handle.writeFile(contents, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, path);
    created = false;
  } finally {
    if (created) {
      await unlink(temporary).catch(() => undefined);
    }
  }
}

function validateOverrideKeys(value: JsonValue): void {
  if (Array.isArray(value)) {
    for (const item of value) validateOverrideKeys(item);
    return;
  }
  if (!isObject(value)) return;
  for (const [key, item] of Object.entries(value)) {
    if (["__proto__", "constructor", "prototype"].includes(key)) {
      throw new ConfigurationError(`Invalid Codex override key: ${key}.`);
    }
    validateOverrideKeys(item);
  }
}

function validateOverrides(overrides: JsonObject): void {
  if ("plugins" in overrides || "marketplaces" in overrides) {
    throw new ConfigurationError(
      "Codex Security owns plugin loading configuration.",
    );
  }
  const features = overrides["features"];
  if ("features" in overrides && !isObject(features)) {
    throw new ConfigurationError(
      "Codex override features must be a TOML table.",
    );
  }
  if (isObject(features) && "plugins" in features) {
    throw new ConfigurationError(
      "Codex Security owns plugin loading configuration.",
    );
  }
  const profiles = overrides["profiles"];
  if (profiles === undefined) {
    return;
  }
  if (!isObject(profiles)) {
    throw new ConfigurationError(
      "Codex override profiles must be TOML tables.",
    );
  }
  for (const [name, profile] of Object.entries(profiles)) {
    if (!isObject(profile)) {
      throw new ConfigurationError(
        `Codex override profile ${name} must be a TOML table.`,
      );
    }
    const profileFeatures = profile["features"];
    if (profileFeatures !== undefined && !isObject(profileFeatures)) {
      throw new ConfigurationError(
        `Codex override profile ${name} features must be a TOML table.`,
      );
    }
    if (isObject(profileFeatures) && "plugins" in profileFeatures) {
      throw new ConfigurationError(
        `Codex Security owns plugin loading configuration in profile ${name}.`,
      );
    }
  }
}

function validateNativeMultiAgentV2Overrides(overrides: JsonObject): void {
  const agents = overrides["agents"];
  if (isObject(agents) && "max_threads" in agents) {
    throw new ConfigurationError(
      "The selected Codex Security plugin requires native multi-agent v2; " +
        "agents.max_threads is a legacy v1 setting. Use " +
        "features.multi_agent_v2.max_concurrent_threads_per_session instead.",
    );
  }
  if ("features" in overrides) {
    const features = overrides["features"];
    if (!isObject(features)) {
      throw new ConfigurationError(
        "The selected Codex Security plugin requires native multi-agent v2; " +
          "features must remain a table containing features.multi_agent_v2.",
      );
    }
    if ("multi_agent_v2" in features) {
      const multiAgentV2 = features["multi_agent_v2"];
      if (!isObject(multiAgentV2)) {
        throw new ConfigurationError(
          "The selected Codex Security plugin requires native multi-agent v2; " +
            "features.multi_agent_v2 must remain a table with enabled = true.",
        );
      }
      if ("enabled" in multiAgentV2 && multiAgentV2["enabled"] !== true) {
        throw new ConfigurationError(
          "The selected Codex Security plugin requires native multi-agent v2; " +
            "features.multi_agent_v2.enabled cannot be disabled.",
        );
      }
    }
  }

  const profiles = overrides["profiles"];
  if (!isObject(profiles)) {
    return;
  }
  for (const [name, profile] of Object.entries(profiles)) {
    if (!isObject(profile)) {
      continue;
    }
    const profileAgents = profile["agents"];
    if (isObject(profileAgents) && "max_threads" in profileAgents) {
      throw new ConfigurationError(
        `The selected Codex Security plugin requires native multi-agent v2; profile ${name} agents.max_threads is a legacy v1 setting.`,
      );
    }
    const profileFeatures = profile["features"];
    if (!isObject(profileFeatures) || !("multi_agent_v2" in profileFeatures)) {
      continue;
    }
    const profileV2 = profileFeatures["multi_agent_v2"];
    if (
      !isObject(profileV2) ||
      ("enabled" in profileV2 && profileV2["enabled"] !== true)
    ) {
      throw new ConfigurationError(
        `The selected Codex Security plugin requires native multi-agent v2; profile ${name} features.multi_agent_v2 cannot be disabled.`,
      );
    }
  }
}

/** @internal */
export function deepMerge(base: JsonObject, overrides: JsonObject): JsonObject {
  for (const [key, value] of Object.entries(overrides)) {
    const existing = Object.hasOwn(base, key) ? base[key] : undefined;
    base[key] =
      isObject(value) && isObject(existing)
        ? deepMerge({ ...existing }, value)
        : cloneJson(value);
  }
  return base;
}

function cloneJson<T extends JsonValue>(value: T): T {
  return structuredClone(value);
}

function deepFreezeJson(value: JsonValue): void {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) {
    return;
  }
  for (const item of Array.isArray(value) ? value : Object.values(value)) {
    deepFreezeJson(item);
  }
  Object.freeze(value);
}

function isObject(value: unknown): value is Record<string, JsonValue> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
