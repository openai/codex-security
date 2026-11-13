import type { ScanPricingContext } from "./cost-model.js";
import { randomUUID } from "node:crypto";
import { mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { isIP } from "node:net";
import { dirname, join, resolve } from "node:path";
import type { CyberAccessProgram } from "@openai/codex-sdk";
import { parse, stringify } from "smol-toml";
import { ConfigurationError } from "./errors.js";
import { childEnvironmentEntry, environmentEntry } from "./value.js";

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

export const CHEAPERINFERENCE_CODEX_PROVIDER = {
  name: "Cheaper Inference",
  base_url: "https://api.cheaperinference.com/v1",
  env_key: "CHEAPER_INFERENCE_API_KEY",
  wire_api: "responses",
} as const satisfies JsonObject;

export const AZURE_CODEX_PROVIDER = {
  name: "Azure OpenAI",
  env_key: "AZURE_OPENAI_API_KEY",
  wire_api: "responses",
} as const satisfies JsonObject;

export const EXTERNAL_CODEX_PROVIDERS = {
  openrouter: OPENROUTER_CODEX_PROVIDER,
  fireworks: FIREWORKS_CODEX_PROVIDER,
  cheaperinference: CHEAPERINFERENCE_CODEX_PROVIDER,
  azure: AZURE_CODEX_PROVIDER,
} as const;

export type ExternalModelProvider = keyof typeof EXTERNAL_CODEX_PROVIDERS;

export const EXTERNAL_PROVIDER_KEYS: ReadonlySet<string> = new Set(
  Object.values(EXTERNAL_CODEX_PROVIDERS).map(({ env_key }) => env_key),
);

type ProviderEnvironment = Readonly<Record<string, string | undefined>>;

function azureTableCredential(
  native: JsonObject,
  environment?: ProviderEnvironment,
): string | undefined {
  if (typeof native["experimental_bearer_token"] === "string")
    return "experimental_bearer_token";
  const defaultKey =
    environment &&
    environmentEntry(environment, AZURE_CODEX_PROVIDER.env_key)?.trim();
  for (const field of ["http_headers", "env_http_headers"] as const) {
    const headers = native[field];
    if (!isObject(headers)) continue;
    const names = Object.keys(headers);
    if (names.some((name) => /^(?:authorization|api-key)$/iu.test(name)))
      return field;
    // A gateway can authenticate with its own header name. Ancillary headers
    // still allow an explicitly supplied Azure resource key to use the preset.
    if (names.length && !defaultKey) return field;
  }
  return undefined;
}

/** Only declared header variables belong in the selected Azure model process. */
export function azureHeaderEnvironment(
  environment: ProviderEnvironment,
  config: Readonly<JsonObject>,
): Record<string, string> {
  if (scanModelProvider(config) !== "azure") return {};
  const providers = resolveCodexProfile(config)["model_providers"];
  const azure = isObject(providers) ? providers["azure"] : undefined;
  const headers = isObject(azure) ? azure["env_http_headers"] : undefined;
  if (!isObject(headers)) return {};
  return Object.fromEntries(
    Object.values(headers).flatMap((name) => {
      if (typeof name !== "string") return [];
      const value = childEnvironmentEntry(environment, name);
      return value === undefined ? [] : [[name, value]];
    }),
  );
}

/** Keep the Azure key only for a model configuration that names it. */
export function azureProviderEnvironment(
  environment: ProviderEnvironment,
  config: JsonObject,
): Record<string, string | undefined> {
  const isAzureKey = (name: unknown) =>
    typeof name === "string" &&
    name.toUpperCase() === AZURE_CODEX_PROVIDER.env_key;
  if (!Object.keys(environment).some(isAzureKey)) return environment;
  const selected = scanModelProvider(config);
  const providers = resolveCodexProfile(config)["model_providers"];
  const provider =
    typeof selected === "string" && isObject(providers)
      ? providers[selected]
      : undefined;
  const native = isObject(provider) ? provider : {};
  if (
    (selected === "azure" &&
      native["env_key"] === undefined &&
      native["auth"] == null &&
      azureTableCredential(native, environment) === undefined) ||
    isAzureKey(native["env_key"]) ||
    (isObject(native["env_http_headers"]) &&
      Object.values(native["env_http_headers"]).some(isAzureKey))
  )
    return environment;
  return Object.fromEntries(
    Object.entries(environment).filter(([name]) => !isAzureKey(name)),
  );
}

export function azureBaseUrl(
  environment: ProviderEnvironment,
  baseUrl?: unknown,
): string {
  const configured =
    baseUrl === undefined
      ? environmentEntry(environment, "AZURE_OPENAI_BASE_URL")?.trim() ||
        environmentEntry(environment, "AZURE_OPENAI_ENDPOINT")?.trim()
      : baseUrl;
  if (configured === undefined || configured === "") {
    throw new ConfigurationError(
      "Set AZURE_OPENAI_BASE_URL or AZURE_OPENAI_ENDPOINT to the Azure OpenAI resource endpoint.",
    );
  }
  if (
    typeof configured !== "string" ||
    !/^https?:\/\//iu.test(configured.trim()) ||
    !URL.canParse(configured)
  ) {
    throw new ConfigurationError(
      "The Azure OpenAI endpoint must be an absolute HTTP(S) URL.",
    );
  }
  const url = new URL(configured);
  const path = url.pathname.replace(/\/+$/u, "");
  if (
    url.username ||
    url.password ||
    /[?#]/u.test(url.href) ||
    (path !== "" && path !== "/openai/v1")
  ) {
    throw new ConfigurationError(
      "Use the Azure resource origin or /openai/v1 without credentials, a query, or a fragment.",
    );
  }
  if (
    url.protocol === "http:" &&
    url.hostname !== "localhost" &&
    url.hostname !== "[::1]" &&
    !(isIP(url.hostname) === 4 && url.hostname.startsWith("127."))
  ) {
    throw new ConfigurationError(
      "The Azure OpenAI endpoint requires HTTPS except on loopback.",
    );
  }
  return `${url.origin}/openai/v1`;
}

export function externalProviderTable(
  provider: ExternalModelProvider,
  environment: ProviderEnvironment,
  configured?: unknown,
): JsonObject {
  const table = EXTERNAL_CODEX_PROVIDERS[provider];
  if (provider !== "azure") return { ...table };
  const native = isObject(configured) ? configured : {};
  const preset: JsonObject = { ...table };
  if (
    native["auth"] != null ||
    azureTableCredential(native, environment) !== undefined
  )
    delete preset["env_key"];
  return {
    ...preset,
    ...native,
    base_url: azureBaseUrl(environment, native["base_url"]),
  };
}

export function isExternalModelProvider(
  provider: unknown,
): provider is ExternalModelProvider {
  return (
    typeof provider === "string" &&
    Object.hasOwn(EXTERNAL_CODEX_PROVIDERS, provider)
  );
}

export const MODEL_FILE_SETTINGS = [
  "model_instructions_file",
  "model_catalog_json",
  "experimental_compact_prompt_file",
] as const;

export const DEFAULT_CODEX_CONFIG: Readonly<JsonObject> = Object.freeze({
  approval_policy: "on-request",
  approvals_reviewer: "auto_review",
  cli_auth_credentials_store: "auto",
  model: "gpt-5.6-sol",
  model_reasoning_effort: "xhigh",
  model_reasoning_summary: "detailed",
  show_raw_agent_reasoning: true,
  features: Object.freeze({
    plugins: true,
    goals: true,
    multi_agent_v2: Object.freeze({
      enabled: true,
      max_concurrent_threads_per_session: 9,
    }),
  }),
  // Credential read denials require the elevated Windows sandbox backend.
  windows: Object.freeze({
    sandbox: "elevated",
  }),
});

/** @internal Authentication settings shared by login and model commands. */
export const CODEX_AUTH_CONFIG_KEYS = [
  "cli_auth_credentials_store",
  "forced_login_method",
  "forced_chatgpt_workspace_id",
] as const;

/**
 * @internal Read only the native sign-in preferences. Scans with independently
 * supplied credentials may not have access to the ambient home.
 */
export async function readCodexAuthConfig(
  home: string,
  required = false,
): Promise<JsonObject> {
  let config: JsonObject;
  try {
    config = parse(await readFile(join(home, "config.toml"), "utf8"), {
      integersAsBigInt: "asNeeded",
    }) as JsonObject;
  } catch (error) {
    if (!required || (error as NodeJS.ErrnoException).code === "ENOENT")
      return {};
    throw new ConfigurationError(
      `Could not read Codex sign-in settings from ${join(home, "config.toml")}: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  }
  return Object.fromEntries(
    CODEX_AUTH_CONFIG_KEYS.flatMap((key) =>
      config[key] === undefined ? [] : [[key, config[key]]],
    ),
  );
}

export function scanModelConfiguration(
  config: Readonly<JsonObject>,
): ScanModelConfiguration {
  const selectedProfile = selectedScanProfile(config);
  const model = scanModel(config);
  if (typeof model !== "string" || model.trim().length === 0) {
    throw new ConfigurationError(
      "The configured Codex model must be a nonempty string.",
    );
  }
  const reasoningEffort =
    selectedProfile?.["model_reasoning_effort"] ??
    config["model_reasoning_effort"];
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

export function scanModel(config: Readonly<JsonObject>): unknown {
  const selectedProfile = selectedScanProfile(config);
  return selectedProfile?.["model"] ?? config["model"];
}

export function scanModelProvider(config: Readonly<JsonObject>): unknown {
  const selectedProfile = selectedScanProfile(config);
  return selectedProfile?.["model_provider"] ?? config["model_provider"];
}

function bedrockPricingRegion(
  provider: JsonValue | undefined,
  environment: Readonly<Record<string, string | undefined>>,
): string | null {
  const baseUrl = isObject(provider) ? provider["base_url"] : undefined;
  if (typeof baseUrl === "string") {
    // Codex sends inference to an explicit endpoint even when aws.region differs.
    const host = URL.parse(baseUrl)?.hostname ?? "";
    return (
      /^bedrock-(?:mantle|runtime)(?:-fips)?\.([a-z0-9-]+)\.(?:api\.aws|amazonaws\.com(?:\.cn)?)$/.exec(
        host,
      )?.[1] ?? null
    );
  }
  const aws = isObject(provider) ? provider["aws"] : undefined;
  const region = isObject(aws) ? aws["region"] : undefined;
  return (
    (typeof region === "string" && region.trim()) ||
    environment["AWS_REGION"]?.trim() ||
    environment["AWS_DEFAULT_REGION"]?.trim() ||
    null
  );
}

/** @internal Keep billing selection separate from model names shared by providers. */
export function scanPricingContext(
  config: Readonly<JsonObject>,
  environment: Readonly<Record<string, string | undefined>>,
): ScanPricingContext | undefined {
  const selected = scanModelProvider(config) ?? "openai";
  if (selected === "azure") return { provider: "azure" };
  if (typeof selected !== "string") return undefined;
  const resolved = selectedScanProfile(config)
    ? resolveCodexProfile(config)
    : config;
  const providers = resolved["model_providers"];
  const provider = isObject(providers) ? providers[selected] : undefined;
  if (selected === "amazon-bedrock" || selected === "amazon-bedrock-runtime") {
    return {
      provider: "amazon-bedrock",
      region: bedrockPricingRegion(provider, environment),
    };
  }
  // Native Codex only accepts inference routing for the built-in OpenAI
  // provider through the top-level openai_base_url setting.
  const baseUrl =
    selected === "openai"
      ? resolved["openai_base_url"]
      : isObject(provider)
        ? provider["base_url"]
        : undefined;
  if (baseUrl == null)
    return selected === "gcp" ? { provider: "gcp" } : undefined;

  const url = typeof baseUrl === "string" ? URL.parse(baseUrl) : null;
  const host = url?.hostname.replace(/\.$/, "") ?? "";
  if (host.endsWith(".prediction.vertexai.goog")) {
    return { provider: "gcp", managedEndpoint: false };
  }
  const vertexHost =
    url &&
    /^(?:[a-z0-9-]+-)?aiplatform(?:\.mtls)?\.googleapis\.com$/.test(host);
  if (selected !== "gcp" && !vertexHost) return undefined;
  // A dedicated endpoint bills the serving infrastructure. Only publisher and
  // shared OpenAPI endpoints identify the managed token-based service.
  const managedEndpoint =
    !!vertexHost &&
    /^\/v1(?:beta1)?\/projects\/[^/]+\/locations\/[^/]+\/(?:publishers\/openai\/v1|endpoints\/openapi)\/?$/.test(
      url.pathname,
    );
  return { provider: "gcp", managedEndpoint };
}

/** Codex reads header and bearer credentials from the private provider table. */
export function azureCredentialSource(
  config: Readonly<JsonObject>,
): string | undefined {
  if (scanModelProvider(config) !== "azure") return undefined;
  const providers = resolveCodexProfile(config)["model_providers"];
  const azure = isObject(providers) ? providers["azure"] : undefined;
  return isObject(azure) && azure["auth"] == null && azure["env_key"] == null
    ? azureTableCredential(azure)
    : undefined;
}

/** @internal Use the selected native provider's configured credential key. */
export function scanProviderEnvKey(
  config: Readonly<JsonObject>,
): string | undefined {
  const selected = scanModelProvider(config);
  if (
    typeof selected !== "string" ||
    azureCredentialSource(config) !== undefined ||
    ["openai", "ollama", "lmstudio", "amazon-bedrock"].includes(selected)
  )
    return undefined;
  const providers = resolveCodexProfile(config)["model_providers"];
  const provider = isObject(providers) ? providers[selected] : undefined;
  return isObject(provider) && typeof provider["env_key"] === "string"
    ? provider["env_key"]
    : isExternalModelProvider(selected)
      ? EXTERNAL_CODEX_PROVIDERS[selected].env_key
      : undefined;
}

/** @internal Native Codex validates the auth table, including invalid selections. */
export function hasCommandAuth(config: Readonly<JsonObject>): boolean {
  const selected = scanModelProvider(config);
  const providers = resolveCodexProfile(config)["model_providers"];
  const provider =
    typeof selected === "string" && isObject(providers)
      ? providers[selected]
      : undefined;
  return isObject(provider) && provider["auth"] != null;
}

/** @internal Keep host-side helpers independent of the source checkout. */
export function resolveCommandAuthConfig(
  config: JsonObject,
  home: string,
): JsonObject {
  const resolved = structuredClone(config);
  const providers = resolveCodexProfile(resolved)["model_providers"];
  if (isObject(providers)) {
    (selectedScanProfile(resolved) ?? resolved)["model_providers"] = providers;
    for (const provider of Object.values(providers)) {
      if (!isObject(provider) || !isObject(provider["auth"])) continue;
      const auth = provider["auth"];
      const cwd = auth["cwd"];
      if (
        cwd == null ||
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
  return config["model_providers"] == null
    ? []
    : [`model_providers=${inlineToml(config["model_providers"])}`];
}

/** @internal Resolve settings; literal-key tables use native file layers. */
export function structuredCodexConfig(config: JsonObject = {}): JsonObject {
  const structured = resolveCodexProfile(config);
  delete structured["projects"];
  delete structured["permissions"];
  delete structured["model_providers"];
  return structured;
}

/** @internal Quote a TOML string without changing its contents. */
export function quoteTomlString(value: string): string {
  return JSON.stringify(value).replaceAll("\u007f", "\\u007f");
}

/** @internal Serialize one Codex CLI override value without flattening its keys. */
export function inlineToml(value: JsonValue): string {
  if (value === null)
    throw new ConfigurationError(
      "Codex TOML overrides cannot contain null values.",
    );
  // Match the Codex SDK's numeric spelling, including integers above 2**53 - 1.
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(inlineToml).join(",")}]`;
  if (isObject(value)) {
    return `{${Object.entries(value)
      .filter(([, item]) => item !== null)
      .map(([key, item]) => `${quoteTomlString(key)}=${inlineToml(item)}`)
      .join(",")}}`;
  }
  return stringify({ value }).slice("value = ".length).trim();
}

export function scanApprovalPolicy(
  config: Readonly<JsonObject>,
): "never" | "on-request" {
  const configured =
    selectedScanProfile(config)?.["approval_policy"] ??
    config["approval_policy"];
  return configured === "never" ? "never" : "on-request";
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

/** @internal A named profile reloads from disk unless an inline table supplies it. */
export function codexFileProfileName(config: JsonObject): string | undefined {
  const name = config["profile"];
  return typeof name === "string" && selectedScanProfile(config) === undefined
    ? name
    : undefined;
}

export function resolveCodexProfile(config: JsonObject): JsonObject {
  const normalized = parse(stringify(config)) as JsonObject;
  const resolved = deepMerge(normalized, selectedScanProfile(normalized) ?? {});
  delete resolved["profile"];
  delete resolved["profiles"];
  return resolved;
}

/** @internal */
export function scanCyberAccessConfig(
  config: JsonObject,
  program: CyberAccessProgram | undefined,
): JsonObject {
  if (program === undefined) return config;
  const features = isObject(config["features"]) ? config["features"] : {};
  return {
    ...config,
    features: {
      ...features,
      // Set a root default. Normal profile resolution preserves explicit overrides.
      api_key_cyber_access_programs:
        features["api_key_cyber_access_programs"] ?? true,
    },
  };
}

/** @internal Read file-profile settings before wrapper defaults or CLI model validation. */
export async function readCodexFileProfile(
  overrides: JsonObject,
  profileHome?: string,
): Promise<JsonObject> {
  let nativeProfile: JsonObject = {};
  if (
    overrides["profile"] != null &&
    typeof overrides["profile"] !== "string"
  ) {
    throw new ConfigurationError("Codex profile must be a name.");
  }
  const profileName = codexFileProfileName(overrides);
  if (profileHome !== undefined && profileName !== undefined) {
    if (!/^[A-Za-z0-9_-]+$/u.test(profileName)) {
      throw new ConfigurationError("Codex profile must be a plain name.");
    }
    try {
      nativeProfile = parse(
        await readFile(join(profileHome, `${profileName}.config.toml`), "utf8"),
      ) as JsonObject;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw new ConfigurationError(
          `Could not read Codex profile ${profileName}.`,
          {
            cause: error,
          },
        );
      }
    }
    if ("profile" in nativeProfile || "profiles" in nativeProfile) {
      throw new ConfigurationError(
        `Codex profile ${profileName} contains legacy profile settings.`,
      );
    }
    validateOverrideKeys(nativeProfile);
    validateOverrides(nativeProfile);
    // CLI overrides otherwise resolve this file against the scan directory.
    for (const key of [...MODEL_FILE_SETTINGS, "sqlite_home", "log_dir"]) {
      resolveConfigPath(nativeProfile, key, profileHome);
    }
    resolveNestedConfigPaths(nativeProfile, profileHome);
    normalizeLegacyWindowsSandboxOverride(nativeProfile);
  }
  return nativeProfile;
}

function resolveConfigPath(
  config: JsonObject,
  key: string,
  directory: string,
): void {
  const path = config[key];
  if (typeof path === "string" && !/^~(?:[/\\]|$)/u.test(path)) {
    config[key] = resolve(directory, path);
  }
}

/** @internal Keep agent, skill, and TLS file paths anchored to their config directory. */
export function resolveNestedConfigPaths(
  config: JsonObject,
  directory: string,
): void {
  const agents = config["agents"];
  if (isObject(agents)) {
    for (const agent of Object.values(agents)) {
      if (isObject(agent)) resolveConfigPath(agent, "config_file", directory);
    }
  }
  const skills = config["skills"];
  if (isObject(skills) && Array.isArray(skills["config"])) {
    for (const skill of skills["config"]) {
      if (!isObject(skill)) continue;
      resolveConfigPath(skill, "path", directory);
    }
  }

  const otel = config["otel"];
  if (!isObject(otel)) return;
  for (const key of ["exporter", "trace_exporter", "metrics_exporter"]) {
    const exporter = otel[key];
    if (!isObject(exporter)) continue;
    for (const configuration of Object.values(exporter)) {
      if (!isObject(configuration) || !isObject(configuration["tls"])) continue;
      const tls = configuration["tls"];
      for (const field of [
        "ca-certificate",
        "client-certificate",
        "client-private-key",
      ]) {
        resolveConfigPath(tls, field, directory);
      }
    }
  }
}

export async function mergedCodexConfig(
  config: CodexSecurityConfig,
  profileHome?: string,
  environment: ProviderEnvironment = process.env,
  purpose: "scan" | "login" | "read-only" = "scan",
): Promise<JsonObject> {
  if (config.codexOverrides !== undefined && !isObject(config.codexOverrides)) {
    throw new ConfigurationError("codexOverrides must be an object.");
  }
  validateOverrideKeys(config.codexOverrides ?? {});
  const overrides = structuredClone(config.codexOverrides ?? {});
  validateOverrides(overrides);
  normalizeLegacyWindowsSandboxOverride(overrides);
  const nativeProfile = await readCodexFileProfile(overrides, profileHome);
  const profiles = overrides["profiles"];
  if (isObject(profiles)) {
    for (const profile of Object.values(profiles)) {
      if (isObject(profile)) {
        normalizeLegacyWindowsSandboxOverride(profile);
      }
    }
  }
  const defaults: JsonObject = structuredClone(DEFAULT_CODEX_CONFIG);
  // Native login keeps the credential home's existing store unless one was requested.
  if (purpose === "login") delete defaults["cli_auth_credentials_store"];
  if (profileHome !== undefined)
    Object.assign(
      defaults,
      await readCodexAuthConfig(profileHome, purpose === "login"),
    );
  const effectiveOverrides = deepMerge(nativeProfile, overrides);
  validateNativeMultiAgentV2Overrides(effectiveOverrides);
  const provider = scanModelProvider(effectiveOverrides);
  if (provider === "azure" && purpose !== "read-only") {
    const tables = resolveCodexProfile(effectiveOverrides)["model_providers"];
    const providers = isObject(tables) ? tables : {};
    (selectedScanProfile(effectiveOverrides) ?? effectiveOverrides)[
      "model_providers"
    ] = {
      ...providers,
      azure: externalProviderTable(provider, environment, providers["azure"]),
    };
  } else if (provider === "amazon-bedrock") {
    // Bedrock models can reject reasoning.summary before the scan starts.
    defaults["model_reasoning_summary"] = "none";
  }
  return deepMerge(defaults, effectiveOverrides);
}

/** @internal Preserve existing native Windows backend selections. */
export function normalizeLegacyWindowsSandboxOverride(
  overrides: JsonObject,
): void {
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
  let contents: string;
  try {
    contents = stringify(config);
  } catch (error) {
    throw new ConfigurationError("Invalid Codex configuration.", {
      cause: error,
    });
  }
  await writePrivateConfig(path, contents);
}

/** @internal Write private configuration without changing its serialized contents. */
export async function writePrivateConfig(
  path: string,
  contents: string,
): Promise<void> {
  const parent = dirname(path);
  await mkdir(parent, { recursive: true, mode: 0o700 });
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

// Validate the root before visiting profiles in configuration order.
function* overrideTables(
  overrides: JsonObject,
): Generator<[JsonObject, string?]> {
  yield [overrides];
  const profiles = overrides["profiles"];
  if (profiles === undefined) return;
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
    yield [profile, name];
  }
}

function validateOverrides(overrides: JsonObject): void {
  for (const [table, name] of overrideTables(overrides)) {
    const features = table["features"];
    if (
      "plugins" in table ||
      "marketplaces" in table ||
      (isObject(features) && "plugins" in features)
    ) {
      const location = name === undefined ? "" : ` in profile ${name}`;
      throw new ConfigurationError(
        `Codex Security owns plugin loading configuration${location}.`,
      );
    }
    if (
      !isObject(features) &&
      (features !== undefined || (name === undefined && "features" in table))
    ) {
      const location = name === undefined ? "" : ` profile ${name}`;
      throw new ConfigurationError(
        `Codex override${location} features must be a TOML table.`,
      );
    }
  }
}

function validateNativeMultiAgentV2Overrides(overrides: JsonObject): void {
  const required =
    "The selected Codex Security plugin requires native multi-agent v2; ";
  for (const [table, name] of overrideTables(overrides)) {
    const agents = table["agents"];
    if (isObject(agents) && "max_threads" in agents) {
      const message =
        name === undefined
          ? "agents.max_threads is a legacy v1 setting. Use features.multi_agent_v2.max_concurrent_threads_per_session instead."
          : `profile ${name} agents.max_threads is a legacy v1 setting.`;
      throw new ConfigurationError(required + message);
    }
    const features = table["features"];
    if (!isObject(features) || !("multi_agent_v2" in features)) continue;
    const setting = features["multi_agent_v2"];
    if (
      isObject(setting) &&
      (!("enabled" in setting) || setting["enabled"] === true)
    )
      continue;
    const message =
      name !== undefined
        ? `profile ${name} features.multi_agent_v2 cannot be disabled.`
        : isObject(setting)
          ? "features.multi_agent_v2.enabled cannot be disabled."
          : "features.multi_agent_v2 must remain a table with enabled = true.";
    throw new ConfigurationError(required + message);
  }
}

export function mergeCodexOverrides(
  base: JsonObject,
  overrides: JsonObject,
): JsonObject {
  validateOverrideKeys(base);
  validateOverrideKeys(overrides);
  return deepMerge(structuredClone(base), overrides);
}

/** @internal */
export function deepMerge(base: JsonObject, overrides: JsonObject): JsonObject {
  for (const [key, value] of Object.entries(overrides)) {
    const existing = Object.hasOwn(base, key) ? base[key] : undefined;
    base[key] =
      isObject(value) && isObject(existing)
        ? deepMerge({ ...existing }, value)
        : structuredClone(value);
  }
  return base;
}

function isObject(value: unknown): value is Record<string, JsonValue> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
