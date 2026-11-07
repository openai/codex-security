import { constants } from "node:fs";
import { access, realpath, rm, stat, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import type { CyberAccessProgram } from "@openai/codex-sdk";
import {
  CODEX_AUTH_CONFIG_KEYS,
  configuredCodexHome,
  environmentEntry,
  readCodexHomeConfig,
  readStoredFileCredentialType,
  withoutOpenAiApiKeys,
} from "./auth.js";
import {
  daybreakFeatures,
  modelCyberAccessPrograms,
  type AppServerRequest,
} from "./cli-daybreak.js";
import {
  bundledCodexSdkEnvironment,
  resolveBundledCodexExecutable,
} from "./codex-sdk-environment.js";
import {
  hasCommandAuth,
  inlineToml,
  projectTrustKey,
  resolveCodexProfile,
  writeCodexConfig,
  type JsonObject,
} from "./config.js";
import {
  isBundledExecutable,
  nativeAppServerSupportsCd,
  sdkConfigFlags,
} from "./deep-scan.js";
import { ConfigurationError, PluginBootstrapError } from "./errors.js";
import {
  nativePermissionPreflight,
  nativeProfileClient,
  providerPreflightCommand,
} from "./provider-profile.js";
import { isRecord } from "./record.js";
import {
  expandHome,
  prepareOutputDir,
  runCodexCommand,
  type CodexCommand,
} from "./runtime.js";

interface ScanCyberAccessOptions {
  command: CodexCommand;
  cwd: string;
  launcherCwd?: string;
  getKeyCatalogHome?: (parent: string) => Promise<string>;
  environment: Record<string, string>;
  config: JsonObject;
  model: string;
  credentialType?: "chatgpt" | "api_key";
  nativeProfile?: boolean;
  program?: CyberAccessProgram;
  signal: AbortSignal;
}

const catalogFeatures = [
  "cli_daybreak",
  "api_key_model_discovery",
  "api_key_cyber_access_programs",
  "psp",
  "respect_system_proxy",
  "system_proxy_fallback",
  "secret_auth_storage",
];
const catalogSettings = new Set([
  ...CODEX_AUTH_CONFIG_KEYS,
  "auth_keyring_backend",
  "model",
  "daybreak",
  "model_catalog_json",
  "project_root_markers",
  "chatgpt_base_url",
  "openai_base_url",
]);

// Preserve the SDK's ordering of a nested table relative to literal dotted keys.
function catalogConfig(source: JsonObject, nativeProfile = false): JsonObject {
  const result: JsonObject = {};
  for (const [key, value] of Object.entries(source)) {
    if (value == null) continue;
    if (key === "features" && isRecord(value)) {
      const entries = Object.entries(value);
      const selected = entries.filter(
        ([feature, enabled]) =>
          enabled != null && catalogFeatures.includes(feature),
      );
      // A native profile sends the entire table as one CLI override.
      if (nativeProfile || selected.length || !entries.length)
        result[key] = Object.fromEntries(selected) as JsonObject;
    } else if (
      catalogSettings.has(key) ||
      (key.startsWith("features.") &&
        catalogFeatures.includes(key.slice("features.".length)))
    ) {
      result[key] = value;
    }
  }
  return result;
}

function openAiProvider(providers: unknown) {
  return isRecord(providers) && isRecord(providers["openai"])
    ? providers["openai"]
    : undefined;
}

function privateCatalogUrl(config: JsonObject, nativeProfile = false) {
  // The full provider table belongs to the private profile. Literal dotted
  // keys are CLI overrides and retain their order above that profile.
  let url = openAiProvider(config["model_providers"])?.["model_catalog_url"];
  let pinned = false;
  for (const [key, value] of Object.entries(config)) {
    if (
      key === "model_providers.openai.model_catalog_url" &&
      typeof value === "string"
    ) {
      url = value;
      pinned = true;
    } else if (key === "model_providers.openai" && isRecord(value)) {
      const next = value["model_catalog_url"];
      // Stock SDK nonempty objects set each leaf independently. A native
      // profile or explicit empty table replaces the entire provider.
      if (
        typeof next === "string" ||
        nativeProfile ||
        !Object.keys(value).length
      ) {
        url = next;
        pinned = true;
      }
    }
  }
  return { url: typeof url === "string" ? url : undefined, pinned };
}

async function prepareLauncherKeyPolicyHome(
  originalConfig: JsonObject,
  resolved: JsonObject,
  originalEnv: Record<string, string>,
  scratch: string,
): Promise<boolean> {
  const home = configuredCodexHome(originalEnv);
  const config = catalogConfig(originalConfig);
  delete config["sqlite_home"];
  config["cli_auth_credentials_store"] = "ephemeral";
  const file = config["model_catalog_json"];
  if (typeof file === "string")
    config["model_catalog_json"] = resolve(home, expandHome(file, originalEnv));
  for (const key of ["model_provider", "analytics", "responses_api_metadata"]) {
    if (originalConfig[key] != null) config[key] = originalConfig[key]!;
  }
  const projects = originalConfig["projects"];
  if (isRecord(projects)) {
    config["projects"] = Object.fromEntries(
      Object.entries(projects).flatMap(([path, entry]) =>
        isRecord(entry) && typeof entry["trust_level"] === "string"
          ? [[path, { trust_level: entry["trust_level"] }]]
          : [],
      ),
    );
  }
  const definitions = originalConfig["model_providers"];
  if (isRecord(definitions)) {
    const shells: JsonObject = {};
    for (const [id, definition] of Object.entries(definitions)) {
      // Custom providers require a name. Their ID is sufficient for lookup.
      if (id !== "openai" && isRecord(definition) && definition["name"])
        shells[id] = { name: id };
    }
    const url = openAiProvider(definitions)?.["model_catalog_url"];
    if (typeof url === "string") shells["openai"] = { model_catalog_url: url };
    if (Object.keys(shells).length) config["model_providers"] = shells;
  }
  await writeCodexConfig(join(scratch, "config.toml"), config);

  if (environmentEntry(originalEnv, "CODEX_ACCESS_TOKEN")) return true;
  const store =
    resolved["cli_auth_credentials_store"] ??
    originalConfig["cli_auth_credentials_store"] ??
    "file";
  if (store === "ephemeral") return false;
  if (store !== "file") return true;
  const account = await readStoredFileCredentialType(home);
  return account !== "missing" && account !== "api_key";
}

// config/read returns layers in descending order of precedence.
function hasSettingAboveUserConfig(
  layers: unknown,
  read: (settings: Record<string, unknown>) => unknown,
): boolean {
  if (!Array.isArray(layers)) return false;
  for (const layer of layers) {
    if (!isRecord(layer) || layer["disabledReason"] || !isRecord(layer["name"]))
      continue;
    if (layer["name"]["type"] === "user") break;
    if (isRecord(layer["config"]) && read(layer["config"]) != null) return true;
  }
  return false;
}

// Scoped config/read resolves a launcher's relative CLI paths against the scan
// directory, even when an older app-server must start in the caller's directory.
async function readLauncherSessionConfig({
  command,
  cwd,
  useCd,
  environment,
  home,
  originalHomeConfig,
  provider,
  providerNames = [],
  maskedCatalog,
  configOverrides,
  checkRoute,
  signal,
}: {
  command: CodexCommand & { cwd: string };
  cwd: string;
  useCd: boolean;
  environment: Record<string, string>;
  home: string;
  originalHomeConfig: JsonObject;
  provider?: string;
  providerNames?: readonly string[];
  maskedCatalog?: string;
  configOverrides: string[];
  checkRoute: (session: JsonObject) => boolean;
  signal: AbortSignal;
}): Promise<{
  session: JsonObject;
  fallback?: {
    enabled: boolean;
    model?: string;
    catalogFile?: string;
    requiredCatalog?: boolean;
  };
}> {
  const env = credentialFreeEnvironment(environment, home);
  const native = await nativePermissionPreflight();
  const options = {
    codexPath: command.command,
    commandArgs: command.args,
    cwd: command.cwd,
    ...(useCd && { configCwd: cwd }),
    env,
    signal,
    context: "scan-catalog",
  };
  const offline = [
    'cli_auth_credentials_store="ephemeral"',
    "features.api_key_model_discovery=false",
  ];
  const session: JsonObject | undefined = await native.withPreflightClient(
    {
      ...options,
      configOverrides: [
        ...configOverrides,
        'model_provider="openai"',
        ...offline,
      ],
    },
    async (client: { request: AppServerRequest }) => {
      const { layers } = await client.request("config/read", {
        cwd,
        includeLayers: true,
      });
      if (!Array.isArray(layers)) return undefined;
      const layer = layers.find(
        (layer) =>
          isRecord(layer) &&
          !layer["disabledReason"] &&
          isRecord(layer["name"]) &&
          layer["name"]["type"] === "sessionFlags",
      );
      if (!isRecord(layer) || !isRecord(layer["config"])) return undefined;
      const settings = layer["config"] as JsonObject;
      const path = settings["model_catalog_json"];
      if (typeof path === "string")
        settings["model_catalog_json"] = resolve(cwd, expandHome(path, env));
      return settings;
    },
  );
  if (!session || !checkRoute(session)) return { session: session ?? {} };

  // The first read forces OpenAI to isolate launcher inspection. A static
  // catalog lets native resolve the actual provider without requesting models
  // or running its authentication command.
  let catalog = session["model_catalog_json"];
  if (typeof catalog !== "string") {
    catalog = join(home, "launcher-models.json");
    const raw = await nativeCatalog(
      command,
      command.cwd,
      env,
      ["debug", "models", "--bundled"],
      signal,
    );
    await writeFile(catalog, raw, { mode: 0o600 });
  }
  const result = native.withPreflightClient(
    {
      ...options,
      configOverrides: [
        ...configOverrides,
        ...(provider === undefined
          ? []
          : [`model_provider=${inlineToml(provider)}`]),
        ...offline,
        `model_catalog_json=${inlineToml(catalog)}`,
      ],
    },
    async (client: { request: AppServerRequest }) => {
      const { config, layers } = await client.request("config/read", {
        cwd,
        includeLayers: true,
      });
      if (!isRecord(config)) return { session, fallback: { enabled: false } };
      const setting = (key: string, feature?: string) => {
        const read = (settings: Record<string, unknown>) => {
          const value = settings[key];
          if (feature === undefined) return value;
          return isRecord(value) ? value[feature] : undefined;
        };
        return hasSettingAboveUserConfig(layers, read)
          ? read(config)
          : (read(originalHomeConfig) ?? read(config));
      };
      if (setting("daybreak") != null)
        return { session, fallback: { enabled: false } };
      const { flags, policy, requirementsUnavailable } =
        await readFeaturePolicy(client.request.bind(client), config, true);
      const selectedProvider =
        policy["modelProvider"] ??
        (provider === undefined
          ? setting("model_provider")
          : config["model_provider"]);
      const required = isRecord(policy["featureRequirements"])
        ? policy["featureRequirements"]
        : {};
      const enabled = (name: string) =>
        (required[name] ?? setting("features", name) ?? flags.get(name)) ===
        true;
      const forcedLogin = setting("forced_login_method");
      const supported =
        (selectedProvider ?? "openai") === "openai" &&
        enabled("cli_daybreak") &&
        enabled("api_key_cyber_access_programs") &&
        (forcedLogin == null || forcedLogin === "api") &&
        (!Array.isArray(policy["allowedLoginMethods"]) ||
          policy["allowedLoginMethods"].includes("api"));
      if (requirementsUnavailable)
        return { session, fallback: { enabled: supported } };
      const effectiveFile = config["model_catalog_json"];
      const sessionFile = session["model_catalog_json"];
      let file = configuredCatalogLayer(layers)?.path;
      if (typeof sessionFile === "string" && sessionFile !== maskedCatalog)
        file = sessionFile;
      if (typeof effectiveFile === "string" && effectiveFile !== catalog)
        file = effectiveFile;
      if (typeof policy["modelCatalogJson"] === "string")
        file = fileURLToPath(policy["modelCatalogJson"]);
      return {
        session,
        fallback: {
          enabled: supported,
          requiredCatalog: typeof policy["modelCatalogJson"] === "string",
          ...(typeof config["model"] === "string" && {
            model: config["model"],
          }),
          ...(file !== undefined && {
            catalogFile: resolve(cwd, expandHome(file, env)),
          }),
        },
      };
    },
  );
  return result.catch((error: unknown) => {
    signal.throwIfAborted();
    if (provider === undefined && error instanceof Error) {
      // Native selected a custom provider whose private definition the real
      // scan has. Only the isolated metadata client is missing that definition.
      const definitions = originalHomeConfig["model_providers"];
      const names = [
        ...providerNames,
        ...(isRecord(definitions) ? Object.keys(definitions) : []),
      ];
      if (missingPrivateProvider(error, names))
        return { session, fallback: { enabled: false } };
    }
    throw error;
  });
}

function missingPrivateProvider(
  error: unknown,
  names: readonly string[],
): boolean {
  if (!(error instanceof Error)) return false;
  const rpc = isRecord(error.cause) ? error.cause["message"] : undefined;
  return names.some((name) => {
    if (name === "openai") return false;
    const missing = "Model provider `" + name + "` not found";
    return typeof rpc === "string"
      ? rpc === missing ||
          rpc === `failed to resolve feature override precedence: ${missing}`
      : error.message.trimEnd().endsWith(`\nError: ${missing}`);
  });
}

// Native workspace bootstrap selects stored credentials and the HTTP client
// before loading cloud requirements. Keep unrelated scan settings out of this comparison.
function workspacePolicyInputs(
  settings: JsonObject,
  layers: unknown[],
  ignoreLoginMethod = false,
) {
  const selectors = (config: Record<string, unknown>) => {
    const features = isRecord(config["features"]) ? config["features"] : {};
    return [
      ...CODEX_AUTH_CONFIG_KEYS.map((key) =>
        ignoreLoginMethod && key === "forced_login_method"
          ? null
          : (config[key] ?? null),
      ),
      config["chatgpt_base_url"] ?? null,
      ...[
        "secret_auth_storage",
        "respect_system_proxy",
        "system_proxy_fallback",
      ].map((key) => features[key] ?? null),
    ];
  };
  // config/read applies exact workspace requirements to its effective values.
  // Include project selectors below those requirements to catch a masked change.
  const projectSelectors = layers.flatMap((layer) => {
    if (
      !isRecord(layer) ||
      layer["disabledReason"] ||
      !isRecord(layer["name"]) ||
      layer["name"]["type"] !== "project" ||
      !isRecord(layer["config"])
    )
      return [];
    const values = selectors(layer["config"]);
    return values.some((value) => value !== null) ? [values] : [];
  });
  return [selectors(settings), projectSelectors];
}

function storedCatalogScope(config: JsonObject, layers: unknown[]) {
  const features = isRecord(config["features"]) ? config["features"] : {};
  return [
    workspacePolicyInputs(config, layers),
    config["model_provider"] ?? "openai",
    openAiProvider(config["model_providers"]),
    config["openai_base_url"],
    config["daybreak"],
    catalogFeatures.map((key) => features[key] ?? null),
  ];
}

// Project selectors have to be restored when removing the launcher's project.
// Session flags already supplied by the launcher or scan take precedence.
function targetProjectSettings(layers: unknown): JsonObject {
  if (!Array.isArray(layers)) return {};
  const local = layers.filter(
    (layer) =>
      isRecord(layer) &&
      !layer["disabledReason"] &&
      isRecord(layer["name"]) &&
      ["project", "sessionFlags"].includes(String(layer["name"]["type"])) &&
      isRecord(layer["config"]),
  );
  const settings: JsonObject = {};
  for (const key of [
    ...CODEX_AUTH_CONFIG_KEYS,
    "auth_keyring_backend",
    "daybreak",
  ]) {
    const source = local.find((layer) => layer.config[key] != null);
    if (source?.name.type === "project") settings[key] = source.config[key];
  }
  const features: JsonObject = {};
  for (const key of catalogFeatures) {
    const source = local.find((layer) => layer.config.features?.[key] != null);
    if (source?.name.type === "project")
      features[key] = source.config.features[key];
  }
  if (Object.keys(features).length) settings["features"] = features;
  return settings;
}

function isUnsupportedRpcMethod(error: unknown): boolean {
  return (
    error instanceof Error &&
    isRecord(error.cause) &&
    error.cause["code"] === -32601
  );
}

async function appServerCatalogProgram(
  model: string,
  request: AppServerRequest,
  signal: AbortSignal,
) {
  const programs = await modelCyberAccessPrograms(model, request).catch(
    (error: unknown) => {
      signal.throwIfAborted();
      if (isUnsupportedRpcMethod(error)) return undefined;
      throw error;
    },
  );
  signal.throwIfAborted();
  return selectedProgram(model, programs);
}

async function readCatalogRequirements(request: AppServerRequest) {
  try {
    const { requirements } = await request("configRequirements/read", {});
    return isRecord(requirements) ? requirements : {};
  } catch (error) {
    if (isUnsupportedRpcMethod(error)) return undefined;
    throw error;
  }
}

function disabledDaybreakGate(
  config: JsonObject,
  policy: Record<string, unknown> | undefined,
) {
  if (policy === undefined) return false;
  const required = policy["featureRequirements"];
  const scoped = config["features"];
  return (
    ((isRecord(required) ? required["cli_daybreak"] : undefined) ??
      (isRecord(scoped) ? scoped["cli_daybreak"] : undefined)) === false
  );
}

async function readFeaturePolicy(
  request: AppServerRequest,
  config: JsonObject,
  includeRequirements: boolean,
  deferFeaturesToKey = false,
) {
  const requirements = includeRequirements
    ? await readCatalogRequirements(request)
    : {};
  // A launcher may set Daybreak differently when it receives the key.
  // Without the policy or feature API, keep the explicit native preference.
  const explicitPreference = config["daybreak"] != null;
  const flags =
    deferFeaturesToKey ||
    (includeRequirements && disabledDaybreakGate(config, requirements))
      ? new Map<string, unknown>()
      : explicitPreference && requirements === undefined
        ? undefined
        : await daybreakFeatures(request).catch((error: unknown) => {
            if (explicitPreference && isUnsupportedRpcMethod(error))
              return undefined;
            throw error;
          });
  return {
    config,
    flags: flags ?? new Map<string, unknown>(),
    policy: requirements ?? {},
    requirementsUnavailable: requirements === undefined || flags === undefined,
  };
}

// The temporary catalog is a session flag. config/read returns lower layers
// in priority order so the original file can still be found.
function configuredCatalogLayer(
  layers: unknown,
): { path: string; source: unknown } | undefined {
  if (!Array.isArray(layers)) return undefined;
  for (const layer of layers) {
    if (
      isRecord(layer) &&
      !layer["disabledReason"] &&
      isRecord(layer["name"]) &&
      layer["name"]["type"] !== "sessionFlags" &&
      isRecord(layer["config"]) &&
      typeof layer["config"]["model_catalog_json"] === "string"
    )
      return {
        path: layer["config"]["model_catalog_json"],
        source: layer["name"]["type"],
      };
  }
  return undefined;
}

function catalogFile(settings: JsonObject, layers: unknown, masked: boolean) {
  return masked
    ? configuredCatalogLayer(layers)?.path
    : settings["model_catalog_json"];
}

function hasManagedCatalogSettings(layer: unknown): boolean {
  if (!isRecord(layer) || !isRecord(layer["name"])) return false;
  const source = layer["name"]["type"];
  if (
    source !== "enterpriseManaged" &&
    source !== "legacyManagedConfigTomlFromMdm" &&
    source !== "legacyManagedConfigTomlFromFile"
  )
    return false;
  const config = layer["config"];
  if (!isRecord(config)) return false;
  const features = config["features"];
  return (
    [
      "chatgpt_base_url",
      "openai_base_url",
      "model_catalog_json",
      "cli_auth_credentials_store",
      "application",
      "network",
    ].some((key) => config[key] != null) ||
    (isRecord(features) &&
      (features["respect_system_proxy"] != null ||
        features["system_proxy_fallback"] != null ||
        features["psp"] != null))
  );
}

function selectedProgram(model: string, programs: unknown): CyberAccessProgram {
  if (Array.isArray(programs)) {
    if (programs.includes("daybreakBlue") || programs.includes("daybreak_blue"))
      return "daybreak_blue";
    if (
      (programs.includes("daybreakRed") || programs.includes("daybreak_red")) &&
      !programs.includes("standard")
    ) {
      throw new ConfigurationError(
        `Model ${model} requires Daybreak Red. Choose a model that supports Standard or Daybreak Blue, or explicitly select --cyber-access-program daybreak_red.`,
      );
    }
  }
  // Omitting the program can select Red when catalog metadata is missing.
  return "standard";
}

class DebugModelsUnavailable extends ConfigurationError {}
class BundledCatalogUnavailable extends DebugModelsUnavailable {}

function rawCatalogProgram(raw: string, model: string) {
  const catalog = JSON.parse(raw).models;
  const row = Array.isArray(catalog)
    ? catalog.find((entry) => isRecord(entry) && entry["slug"] === model)
    : undefined;
  return selectedProgram(model, row?.available_access_programs?.cyber);
}

async function untrustedLauncherProject(cwd: string): Promise<string[]> {
  const projectKey = projectTrustKey(await realpath(cwd));
  return [
    "project_root_markers=[]",
    `projects=${inlineToml({ [projectKey]: { trust_level: "untrusted" } })}`,
  ];
}

// The launcher can pick a different local catalog when it sees the scan key.
// Keep a static file below its CLI flags so this lookup never needs model HTTP.
async function keyedLauncherProgram({
  command,
  cwd,
  useCd,
  environment,
  home,
  apiKey,
  model,
  configOverrides,
  providerNames = [],
  bootstrapCatalog,
  telemetry,
  signal,
}: {
  command: CodexCommand & { cwd: string };
  cwd: string;
  useCd: boolean;
  environment: Record<string, string>;
  home: string;
  apiKey: string;
  model: string;
  configOverrides: string[];
  providerNames?: readonly string[];
  bootstrapCatalog?: string;
  telemetry: JsonObject;
  signal: AbortSignal;
}): Promise<CyberAccessProgram | undefined | { remoteModel: string }> {
  const localEnv = credentialFreeEnvironment(environment, home);
  const env = { ...localEnv, CODEX_API_KEY: apiKey };
  const config = await readCodexHomeConfig(localEnv, signal);
  let fallback: string | undefined;
  const explicitCatalog = configOverrides.some((flag) =>
    flag.startsWith("model_catalog_json="),
  );
  if (typeof config["model_catalog_json"] !== "string" && !explicitCatalog) {
    fallback = bootstrapCatalog ?? join(home, "key-bundled-models.json");
    if (!bootstrapCatalog) {
      const raw = await nativeCatalog(
        command,
        command.cwd,
        localEnv,
        ["debug", "models", "--bundled"],
        signal,
      );
      await writeFile(fallback, raw, { mode: 0o600 });
    }
    config["model_catalog_json"] = fallback;
  }
  await writeCodexConfig(join(home, "config.toml"), {
    ...config,
    ...telemetry,
  });
  const overrides = [
    ...configOverrides,
    'cli_auth_credentials_store="ephemeral"',
  ];
  const native = await nativePermissionPreflight();
  const options = {
    codexPath: command.command,
    commandArgs: command.args,
    cwd: command.cwd,
    ...(useCd && { configCwd: cwd }),
    env,
    signal,
    context: "scan-catalog",
  };
  let initialized = false;
  type Selection =
    | CyberAccessProgram
    | undefined
    | { remoteModel: string }
    | { catalog: string; model: string };
  const inspect = async (
    client: { request: AppServerRequest },
    masked = false,
  ): Promise<Selection> => {
    initialized = true;
    const request = client.request.bind(client);
    const { config: target } = await request("config/read", {
      cwd,
      includeLayers: true,
    });
    if (!isRecord(target) || target["daybreak"] != null) return undefined;
    const policy = await readCatalogRequirements(request);
    if (
      (policy?.["modelProvider"] ?? target["model_provider"] ?? "openai") !==
        "openai" ||
      target["forced_login_method"] === "chatgpt" ||
      (Array.isArray(policy?.["allowedLoginMethods"]) &&
        !policy["allowedLoginMethods"].includes("api"))
    )
      return undefined;
    const file =
      typeof policy?.["modelCatalogJson"] === "string"
        ? fileURLToPath(policy["modelCatalogJson"])
        : target["model_catalog_json"];
    const catalog =
      typeof file === "string"
        ? resolve(cwd, expandHome(file, env))
        : undefined;
    const required = isRecord(policy?.["featureRequirements"])
      ? policy["featureRequirements"]
      : {};
    const scoped = isRecord(target["features"]) ? target["features"] : {};
    if (disabledDaybreakGate(target, policy)) return undefined;
    let flags: Map<string, unknown>;
    try {
      flags = await daybreakFeatures(request);
    } catch (error) {
      if (isUnsupportedRpcMethod(error)) return undefined;
      // Older servers reload feature defaults relative to their home. A catalog
      // resolved by config/read for the actual target can be pinned for that RPC.
      if (
        !catalog ||
        catalog === fallback ||
        !/failed to reload config: (?:no such file or directory|.*cannot find the file specified)/i.test(
          String(error),
        )
      )
        throw error;
      flags = await native.withPreflightClient(
        {
          ...options,
          configOverrides: [
            ...overrides,
            `model_catalog_json=${inlineToml(catalog)}`,
          ],
        },
        (other: { request: AppServerRequest }) =>
          daybreakFeatures(other.request.bind(other)),
      );
    }
    const enabled = (name: string) =>
      (required[name] ?? scoped[name] ?? flags.get(name)) === true;
    if (!enabled("cli_daybreak") || !enabled("api_key_cyber_access_programs"))
      return undefined;
    if (policy === undefined || masked) return "standard";
    const actualModel =
      typeof target["model"] === "string" ? target["model"] : model;
    if (catalog && catalog !== fallback) return { catalog, model: actualModel };
    return enabled("api_key_model_discovery")
      ? { remoteModel: actualModel }
      : "standard";
  };
  let selection: Selection;
  try {
    selection = await native.withPreflightClient(
      { ...options, configOverrides: overrides },
      inspect,
    );
  } catch (error) {
    signal.throwIfAborted();
    if (missingPrivateProvider(error, providerNames)) return undefined;
    if (
      !initialized &&
      !useCd &&
      resolve(command.cwd) !== resolve(cwd) &&
      !explicitCatalog &&
      /no such file or directory|cannot find the file specified/i.test(
        String(error),
      )
    ) {
      try {
        selection = await native.withPreflightClient(
          {
            ...options,
            configOverrides: [
              ...overrides,
              `model_catalog_json=${inlineToml(config["model_catalog_json"]!)}`,
            ],
          },
          (client: { request: AppServerRequest }) => inspect(client, true),
        );
      } catch {
        signal.throwIfAborted();
        throw error;
      }
    } else {
      throw error;
    }
  }
  if (typeof selection !== "object" || "remoteModel" in selection)
    return selection;
  const offline = [
    ...overrides,
    "features.api_key_model_discovery=false",
    'model_provider="openai"',
    ...(await untrustedLauncherProject(command.cwd)),
    `model_catalog_json=${inlineToml(selection.catalog)}`,
  ];
  return nativeCatalogProgram(
    command,
    command.cwd,
    env,
    offline,
    selection.model,
    signal,
  );
}

function credentialFreeEnvironment(
  environment: Record<string, string>,
  home: string,
) {
  return {
    ...Object.fromEntries(
      Object.entries(withoutOpenAiApiKeys(environment)).filter(
        ([name]) =>
          !["CODEX_ACCESS_TOKEN", "CODEX_HOME"].includes(name.toUpperCase()),
      ),
    ),
    CODEX_HOME: home,
  };
}

async function nativeCatalog(
  command: CodexCommand,
  cwd: string,
  environment: Record<string, string>,
  args: string[],
  signal: AbortSignal,
) {
  const result = await runCodexCommand(
    { ...command, cwd },
    args,
    environment,
    undefined,
    signal,
  );
  if (result.success) return result.stdout;
  const diagnostic = result.stderr || result.stdout;
  const unsupported =
    /^(?:error:\s*)?(?:unsupported launcher command:\s*debug models(?: --bundled)?|(?:sandboxed )?launcher does not expose debug models|(?:unknown|unrecognized) subcommand ['`"](?:debug|models)['`"])\.?\s*$/im;
  const bundled = args.at(-1) === "--bundled";
  const missingBundledOption =
    bundled &&
    /^error: unexpected argument '--bundled' found\s*$/im.test(diagnostic);
  if (
    result.exitCode === null ||
    (!unsupported.test(diagnostic) && !missingBundledOption)
  )
    throw new ConfigurationError(diagnostic);
  if (!bundled) throw new DebugModelsUnavailable(diagnostic);

  // The static catalog only masks model discovery during native policy reads.
  // A launcher's lack of debug tooling need not prevent those reads.
  let binary: string;
  try {
    binary = resolveBundledCodexExecutable();
  } catch (error) {
    if (error instanceof PluginBootstrapError)
      throw new BundledCatalogUnavailable(diagnostic);
    throw error;
  }
  const home = await prepareOutputDir(
    undefined,
    "catalog",
    configuredCodexHome(environment),
  );
  try {
    const local = await runCodexCommand(
      { command: binary, cwd: home },
      ["-c", "analytics.enabled=false", "debug", "models", "--bundled"],
      {
        HOME: home,
        USERPROFILE: home,
        CODEX_HOME: home,
        SystemRoot: environmentEntry(environment, "SystemRoot"),
      },
      undefined,
      signal,
    );
    if (!local.success)
      throw new ConfigurationError(local.stderr || local.stdout);
    return local.stdout;
  } finally {
    await rm(home, { recursive: true, force: true });
  }
}

async function nativeCatalogProgram(
  command: CodexCommand,
  cwd: string,
  environment: Record<string, string>,
  overrides: string[],
  model: string,
  signal: AbortSignal,
): Promise<CyberAccessProgram> {
  try {
    const args = [
      ...overrides.flatMap((value) => ["-c", value]),
      "debug",
      "models",
    ];
    return rawCatalogProgram(
      await nativeCatalog(command, cwd, environment, args, signal),
      model,
    );
  } catch (error) {
    if (!(error instanceof DebugModelsUnavailable)) throw error;
  }
  // An online lookup can't be redirected to another executable. An explicitly
  // scoped static catalog can still be read through this launcher's app-server.
  if (!overrides.some((value) => value.startsWith("model_catalog_json=")))
    return "standard";
  const native = await nativePermissionPreflight();
  return native.withPreflightClient(
    {
      codexPath: command.command,
      commandArgs: command.args,
      cwd,
      env: environment,
      configOverrides: overrides,
      signal,
      context: "scan-catalog",
    },
    async (client: { request: AppServerRequest }) => {
      await client.request("config/read", { cwd });
      return appServerCatalogProgram(
        model,
        client.request.bind(client),
        signal,
      );
    },
  );
}

/** Discover programs with the scan's credentials, before its first model turn. */
export async function resolveScanCyberAccessProgram({
  command,
  cwd,
  launcherCwd = process.cwd(),
  getKeyCatalogHome,
  environment,
  config,
  model,
  credentialType,
  nativeProfile,
  program,
  signal,
}: ScanCyberAccessOptions): Promise<CyberAccessProgram | undefined> {
  if (program !== undefined) return program;
  const resolved = resolveCodexProfile(config);
  if (
    resolved["daybreak"] != null ||
    (resolved["model_provider"] ?? "openai") !== "openai" ||
    hasCommandAuth(resolved)
  )
    return undefined;
  // Native workload identity takes precedence over an environment API key.
  if (
    environmentEntry(environment, "OPENAI_FEDERATION_RULE_ID") !== undefined ||
    environmentEntry(environment, "OPENAI_IDENTITY_TOKEN_FILE") !== undefined
  )
    return undefined;
  const apiKey = environmentEntry(environment, "CODEX_API_KEY");
  const bundled = isBundledExecutable(command.command);
  const externalLauncher = !bundled || Boolean(command.args?.length);
  const isolatedKey = Boolean(apiKey && externalLauncher);
  const policyEnvironment = withoutOpenAiApiKeys(environment);
  // A custom launcher's neighboring directories can belong to the scan target.
  const env = bundled
    ? bundledCodexSdkEnvironment(command.command, policyEnvironment)
    : policyEnvironment;
  if (!environmentEntry(env, "CODEX_INTERNAL_ORIGINATOR_OVERRIDE"))
    env["CODEX_INTERNAL_ORIGINATOR_OVERRIDE"] = "codex_sdk_ts";
  const { url: privateUrl, pinned: callerPinsCatalog } = privateCatalogUrl(
    resolved,
    nativeProfile,
  );
  const projected = catalogConfig({ ...resolved, model }, nativeProfile);
  const modelCatalog = projected["model_catalog_json"];
  if (typeof modelCatalog === "string")
    projected["model_catalog_json"] = resolve(
      cwd,
      expandHome(modelCatalog, env),
    );
  const policyConfig = { ...projected };
  if (apiKey) {
    // These endpoints belong to the project key. Workspace bootstrap may use
    // the user's saved login solely with its own configured identity service.
    delete policyConfig["openai_base_url"];
    delete policyConfig["chatgpt_base_url"];
  }
  const serialize = nativeProfile
    ? (await nativeProfileClient()).profileConfigOverrides
    : sdkConfigFlags;
  const policyOverrides: string[] = serialize(policyConfig);
  const providers = isRecord(resolved["model_providers"])
    ? { ...resolved["model_providers"] }
    : {};
  delete providers["openai"]; // The private catalog URL stays out of argv.
  const consent = Object.fromEntries(
    Object.entries(resolved).filter(
      ([key, value]) =>
        value != null && (key === "analytics" || key === "analytics.enabled"),
    ),
  );
  // Each metadata reader, policy lookup and catalog command in this call uses
  // the same private SQLite directory. Other scans can initialize independently.
  const scratch = await prepareOutputDir(
    undefined,
    "catalog",
    configuredCodexHome(env),
  );
  let readForwarding:
    ((error: Error) => Promise<CyberAccessProgram | undefined>) | undefined;
  try {
    const sqliteHome = join(scratch, "sqlite");
    for (const name of Object.keys(env)) {
      if (name.toUpperCase() === "CODEX_SQLITE_HOME") delete env[name];
    }
    env["CODEX_SQLITE_HOME"] = sqliteHome;
    // A launcher may choose a different account endpoint only when given the
    // real home. Never give it that home or a saved access token to discover
    // programs for a different (project-key) identity.
    const discoveryEnv = isolatedKey
      ? credentialFreeEnvironment(env, scratch)
      : env;
    const catalogCommand = await providerPreflightCommand(
      {
        ...command,
        args: [
          ...(command.args ?? []),
          "-c",
          `sqlite_home=${inlineToml(sqliteHome)}`,
          ...serialize(consent).flatMap((override: string) => ["-c", override]),
        ],
      },
      resolved["responses_api_metadata"] == null
        ? {}
        : { responses_api_metadata: resolved["responses_api_metadata"] },
    );
    const policyCommand = await providerPreflightCommand(catalogCommand, {
      ...(resolved["model_provider"] != null && {
        model_provider: resolved["model_provider"],
      }),
      model_providers: providers,
    });
    // A custom launcher can execute ./helper or take relative script arguments.
    // Only change process cwd when launching our own native binary directly.
    const nativeCwd = bundled ? cwd : launcherCwd;
    const differentCwd = resolve(nativeCwd) !== resolve(cwd);
    const useCd =
      differentCwd &&
      (await nativeAppServerSupportsCd(
        { ...catalogCommand, cwd: nativeCwd },
        cwd,
        discoveryEnv,
        signal,
      ));
    const legacyLauncher = differentCwd && !useCd;
    const native = await nativePermissionPreflight();
    const probe = <T>(
      overrides: string[],
      operation: (request: AppServerRequest) => Promise<T>,
      probeEnv = discoveryEnv,
    ): Promise<T> =>
      native.withPreflightClient(
        {
          codexPath: policyCommand.command,
          commandArgs: policyCommand.args,
          cwd: nativeCwd,
          ...(useCd && { configCwd: cwd }),
          env: probeEnv,
          configOverrides: isolatedKey
            ? [...overrides, 'cli_auth_credentials_store="ephemeral"']
            : overrides,
          signal,
          context: "scan-catalog",
        },
        (client: { request: AppServerRequest }) =>
          operation(client.request.bind(client)),
      );

    readForwarding = async (error) => {
      const diagnostic = new ConfigurationError(
        `${error.message}\nCould not establish native access-program forwarding. Pass --cyber-access-program <program> or configure Daybreak directly with --codex daybreak=false.`,
        { cause: error },
      );
      const original = resolveCodexProfile(
        await readCodexHomeConfig(env, signal),
      );
      await prepareLauncherKeyPolicyHome(original, resolved, env, scratch);
      return probe(
        [
          ...policyOverrides,
          'model_provider="openai"',
          'cli_auth_credentials_store="ephemeral"',
          "features.api_key_model_discovery=false",
        ],
        async (request) => {
          const { config, layers } = await request("config/read", {
            cwd,
            includeLayers: true,
          });
          if (!isRecord(config) || !Array.isArray(layers)) throw diagnostic;
          if (
            config["daybreak"] != null ||
            (config["model_provider"] ?? "openai") !== "openai"
          )
            return undefined;
          // The offline bootstrap uses OpenAI so that reading a different provider's
          // config cannot run its authentication command. Its forwarding rules are unknown.
          if (
            resolved["model_provider"] == null &&
            layers.some(
              (layer) =>
                isRecord(layer) &&
                !layer["disabledReason"] &&
                isRecord(layer["config"]) &&
                layer["config"]["model_provider"] != null &&
                layer["config"]["model_provider"] !== "openai",
            )
          )
            throw diagnostic;
          const flags = await daybreakFeatures(request);
          const features = isRecord(config["features"])
            ? config["features"]
            : {};
          const daybreak = flags.get("cli_daybreak");
          if (daybreak === false || features["cli_daybreak"] === false)
            return undefined;
          if (daybreak !== true) throw diagnostic;
          const method = apiKey ? "api_key" : credentialType;
          const forced = config["forced_login_method"];
          if (
            (method === "api_key" && forced === "chatgpt") ||
            (method === "chatgpt" && forced === "api")
          )
            return undefined;
          if (method === "chatgpt" || forced === "chatgpt") return "standard";
          const apiPrograms = flags.get("api_key_cyber_access_programs");
          if (
            apiPrograms === true &&
            features["api_key_cyber_access_programs"] !== false
          )
            return "standard";
          if (
            (method === "api_key" || forced === "api") &&
            (apiPrograms === false ||
              features["api_key_cyber_access_programs"] === false)
          )
            return undefined;
          throw diagnostic;
        },
        credentialFreeEnvironment(env, scratch),
      ).catch((failure: unknown) => {
        signal.throwIfAborted();
        if (isUnsupportedRpcMethod(failure)) throw diagnostic;
        throw failure;
      });
    };

    let launcherUrl: string | undefined;
    let launcherSelectsFile = false;
    let launcherDaybreakDisabled = false;
    let conflictingBaseUrl = false;
    if (isolatedKey) {
      const homeConfig = resolveCodexProfile(
        await readCodexHomeConfig(env, signal),
      );
      const workspaceUnknown = await prepareLauncherKeyPolicyHome(
        homeConfig,
        resolved,
        env,
        scratch,
      );
      const launcherOptions = {
        command: { ...catalogCommand, cwd: nativeCwd },
        cwd,
        useCd,
        environment: env,
        home: scratch,
        originalHomeConfig: homeConfig,
        providerNames: Object.keys(providers),
        provider:
          typeof resolved["model_provider"] === "string"
            ? resolved["model_provider"]
            : undefined,
        signal,
        configOverrides: policyOverrides.filter(
          (flag) =>
            flag.startsWith("features.") ||
            flag.startsWith("features=") ||
            flag.startsWith("project_root_markers=") ||
            flag.startsWith("forced_login_method=") ||
            flag.startsWith("model_catalog_json=") ||
            flag.startsWith("model="),
        ),
        checkRoute: (session: JsonObject) =>
          workspaceUnknown || typeof session["chatgpt_base_url"] === "string",
      };
      const unavailableLauncherProgram = (): CyberAccessProgram | undefined => {
        // Some launchers require files in their original Codex home even
        // before running a no-turn subcommand. Actual exec validates that
        // home. Keep its known native preferences without exposing its login.
        const feature = (name: string) => {
          let value = isRecord(homeConfig["features"])
            ? homeConfig["features"][name]
            : undefined;
          for (const [key, setting] of Object.entries(resolved)) {
            if (
              key === "features" &&
              isRecord(setting) &&
              setting[name] != null
            )
              value = setting[name];
            if (key === `features.${name}`) value = setting;
          }
          return value;
        };
        const forcedLogin =
          resolved["forced_login_method"] ?? homeConfig["forced_login_method"];
        if (
          (resolved["daybreak"] ?? homeConfig["daybreak"]) != null ||
          (resolved["model_provider"] ??
            homeConfig["model_provider"] ??
            "openai") !== "openai" ||
          feature("cli_daybreak") === false ||
          forcedLogin === "chatgpt" ||
          feature("api_key_cyber_access_programs") === false
        )
          return undefined;
        return "standard";
      };
      const missingFile = (failure: unknown) =>
        /no such file or directory|cannot find the file specified/i.test(
          String(failure),
        );
      // Native app-server appends stderr to this diagnostic whenever there is any.
      const silentStartup = (failure: unknown) =>
        failure instanceof Error &&
        failure.message ===
          `Could not read the scan model catalog. Codex executable ${JSON.stringify(catalogCommand.command)} exited before the configuration read completed with code 1.`;
      let metadata;
      try {
        metadata = await readLauncherSessionConfig(launcherOptions);
      } catch (error) {
        signal.throwIfAborted();
        // A launcher can resolve its catalog under the real Codex home or
        // exec's target cwd. Neither is the credential-free probe's home.
        const silent = silentStartup(error);
        if (!missingFile(error) && !silent) throw error;
        const explicitCatalog = projected["model_catalog_json"];
        if (explicitCatalog != null) {
          if (typeof explicitCatalog !== "string") throw error;
          const readable = await Promise.all([
            stat(explicitCatalog),
            access(explicitCatalog, constants.R_OK),
          ]).then(
            ([catalog]) => catalog.isFile(),
            () => false,
          );
          signal.throwIfAborted();
          if (!readable) throw error;
        }
        try {
          const mask = join(scratch, "launcher-fallback-models.json");
          const raw = await nativeCatalog(
            catalogCommand,
            nativeCwd,
            credentialFreeEnvironment(env, scratch),
            ["debug", "models", "--bundled"],
            signal,
          );
          await writeFile(mask, raw, { mode: 0o600 });
          const masked = await readLauncherSessionConfig({
            ...launcherOptions,
            maskedCatalog: mask,
            configOverrides: [
              ...launcherOptions.configOverrides,
              `model_catalog_json=${inlineToml(mask)}`,
            ],
            checkRoute: () => true,
          });
          if (!masked.fallback) throw error;
          return masked.fallback.enabled ? "standard" : undefined;
        } catch (maskedError) {
          signal.throwIfAborted();
          const silentRetry =
            silentStartup(maskedError) ||
            (maskedError instanceof ConfigurationError &&
              maskedError.message === "");
          if (
            (silent && maskedError !== error && silentRetry) ||
            (!silent && missingFile(maskedError))
          )
            return unavailableLauncherProgram();
          throw silentRetry ? error : maskedError;
        }
      }
      const { session, fallback } = metadata;
      launcherDaybreakDisabled = session["daybreak"] === false;
      // Missing session layers cannot establish the workspace's catalog policy.
      if (workspaceUnknown && !fallback) return unavailableLauncherProgram();
      const file = session["model_catalog_json"];
      launcherSelectsFile =
        typeof file === "string" && file !== projected["model_catalog_json"];
      if (fallback) {
        // An opaque launcher's workspace policy or private route is unknown.
        // Keep the lookup local; the real scan applies its own credentials.
        if (!fallback.enabled) return undefined;
        const localFile = fallback.catalogFile;
        if (
          typeof localFile === "string" &&
          (fallback.requiredCatalog ||
            localFile === projected["model_catalog_json"])
        ) {
          await nativeCatalogProgram(
            catalogCommand,
            nativeCwd,
            credentialFreeEnvironment(env, scratch),
            [
              'model_provider="openai"',
              'cli_auth_credentials_store="ephemeral"',
              "features.api_key_model_discovery=false",
              `model_catalog_json=${inlineToml(localFile)}`,
            ],
            fallback.model ?? model,
            signal,
          );
        }
        return "standard";
      }
      const catalog = openAiProvider(session["model_providers"])?.[
        "model_catalog_url"
      ];
      launcherUrl = typeof catalog === "string" ? catalog : undefined;
      conflictingBaseUrl =
        typeof session["openai_base_url"] === "string" &&
        typeof projected["openai_base_url"] === "string" &&
        session["openai_base_url"] !== projected["openai_base_url"];
    }
    const separateCatalog =
      Boolean(apiKey || callerPinsCatalog || privateUrl || externalLauncher) &&
      !projected["model_catalog_json"];
    const bootstrapOverrides = [...policyOverrides];
    let bootstrapCatalog: string | undefined;
    if (separateCatalog) {
      // Read the stored workspace's effective settings without warming the
      // wrong remote catalog. The pinned runtime supplies its own static model file.
      const bundled = await nativeCatalog(
        catalogCommand,
        launcherCwd,
        discoveryEnv,
        ["debug", "models", "--bundled"],
        signal,
      );
      bootstrapCatalog = join(scratch, "bootstrap-models.json");
      await writeFile(bootstrapCatalog, bundled, { mode: 0o600 });
      bootstrapOverrides.push(
        `model_catalog_json=${inlineToml(bootstrapCatalog)}`,
      );
    }
    const result = await probe<
      | CyberAccessProgram
      | undefined
      | {
          config: JsonObject;
          model: string;
          cliOverrides?: string[];
        }
    >(bootstrapOverrides, async (request) => {
      const initial = await request("config/read", {
        cwd,
        includeLayers: Boolean(apiKey || legacyLauncher || separateCatalog),
      });
      if (!isRecord(initial["config"])) return undefined;
      const originalSettings = initial["config"];
      const checkOptOutWithKey =
        launcherDaybreakDisabled && originalSettings["daybreak"] === false;
      if (
        originalSettings["daybreak"] != null &&
        (!isolatedKey ||
          (Array.isArray(initial["layers"]) &&
            initial["layers"].some(
              (layer) =>
                isRecord(layer) &&
                !layer["disabledReason"] &&
                isRecord(layer["name"]) &&
                layer["name"]["type"] !== "sessionFlags" &&
                isRecord(layer["config"]) &&
                layer["config"]["daybreak"] != null,
            )))
      )
        return undefined;
      const startup =
        legacyLauncher && !isolatedKey
          ? await request("config/read", {
              cwd: nativeCwd,
              includeLayers: true,
            })
          : undefined;
      const differentWorkspace = Boolean(
        startup &&
        (!isRecord(startup["config"]) ||
          !Array.isArray(startup["layers"]) ||
          !Array.isArray(initial["layers"]) ||
          !isDeepStrictEqual(
            workspacePolicyInputs(originalSettings, initial["layers"]),
            workspacePolicyInputs(startup["config"], startup["layers"]),
          )),
      );
      let scopedOverrides = policyOverrides;
      let rebound:
        | {
            config: JsonObject;
            layers: unknown;
            flags: Map<string, unknown>;
            policy: Record<string, unknown>;
            requirementsUnavailable: boolean;
            account?: unknown;
          }
        | undefined;
      if (differentWorkspace && Array.isArray(initial["layers"])) {
        // Old servers use their launch directory to choose the saved login
        // and download workspace policy. Disable its project for this process
        // and restore the scan project's active selectors at their own priority.
        const restore = serialize(targetProjectSettings(initial["layers"]));
        const scope = await untrustedLauncherProject(nativeCwd);
        scopedOverrides = [...restore, ...policyOverrides, ...scope];
        rebound = await probe(
          [...restore, ...bootstrapOverrides, ...scope],
          async (rpc) => {
            const target = await rpc("config/read", {
              cwd,
              includeLayers: true,
            });
            const launch = await rpc("config/read", { cwd: nativeCwd });
            if (
              !isRecord(target["config"]) ||
              !isRecord(launch["config"]) ||
              !isDeepStrictEqual(
                workspacePolicyInputs(target["config"], []),
                workspacePolicyInputs(launch["config"], []),
              )
            )
              return undefined;
            const state = await readFeaturePolicy(rpc, target["config"], true);
            return {
              ...state,
              layers: target["layers"],
              account: (await rpc("account/read", { refreshToken: false }))[
                "account"
              ],
            };
          },
        );
      }
      const {
        config: gateConfig,
        flags,
        policy,
        requirementsUnavailable,
      } = rebound ??
      (await readFeaturePolicy(
        request,
        originalSettings,
        !differentWorkspace,
        checkOptOutWithKey,
      ));
      const settings = gateConfig;
      const layers = rebound?.layers ?? initial["layers"];
      const requiredProvider = openAiProvider(policy["modelProviders"]);
      const homeUrl = openAiProvider(settings["model_providers"])?.[
        "model_catalog_url"
      ];
      // A required provider replaces the whole definition, including an absent URL.
      const nativeUrl = requiredProvider
        ? requiredProvider["model_catalog_url"]
        : homeUrl;
      const catalogUrl = requiredProvider
        ? nativeUrl
        : callerPinsCatalog
          ? privateUrl
          : (privateUrl ?? homeUrl);
      const effectiveModel =
        typeof settings["model"] === "string" ? settings["model"] : model;
      // Without a thread ID, experimentalFeature/list can omit the project's
      // overrides. Native requirements have precedence over scoped settings.
      const scopedFeatures = isRecord(gateConfig["features"])
        ? gateConfig["features"]
        : {};
      const requiredFeatures = isRecord(policy["featureRequirements"])
        ? policy["featureRequirements"]
        : {};
      // A project key cannot reload controls supplied by a ChatGPT workspace.
      // Only the scan itself may access the model through unreplayable controls.
      // A launcher can add a different -c route only when it receives a key.
      // A private config file cannot enforce a caller CLI flag or workspace
      // requirement at its original priority. The actual scan still can.
      const keyCatalogUrl =
        launcherUrl === undefined ? catalogUrl : (homeUrl ?? launcherUrl);
      const application = policy["application"];
      const protectedKeyRoute =
        (externalLauncher &&
          (requiredProvider !== undefined || callerPinsCatalog)) ||
        conflictingBaseUrl ||
        (launcherUrl !== undefined && launcherUrl !== keyCatalogUrl) ||
        policy["chatgptBaseUrl"] != null ||
        policy["enforceResidency"] != null ||
        requiredFeatures["respect_system_proxy"] != null ||
        requiredFeatures["system_proxy_fallback"] != null ||
        requiredFeatures["psp"] != null ||
        (isRecord(application) &&
          isRecord(application["network"]) &&
          application["network"]["enabled"] === true) ||
        (Array.isArray(layers) && layers.some(hasManagedCatalogSettings));
      // An opaque launcher can choose preferences from the selected key. Check
      // them in its actual key context only after the private route is usable.
      const inspectLauncherKey =
        isolatedKey && !requirementsUnavailable && !protectedKeyRoute;
      if (
        (!inspectLauncherKey &&
          (gateConfig["daybreak"] != null ||
            (gateConfig["model_provider"] ?? "openai") !== "openai")) ||
        (policy["modelProvider"] ?? "openai") !== "openai"
      )
        return undefined;
      const enabled = (name: string) =>
        requiredFeatures[name] ?? scopedFeatures[name] ?? flags.get(name);
      const mayForward = (name: string) =>
        inspectLauncherKey && requiredFeatures[name] !== false
          ? checkOptOutWithKey ||
            disabledDaybreakGate(gateConfig, policy) ||
            typeof enabled(name) === "boolean"
          : enabled(name) === true;
      if (!mayForward("cli_daybreak")) return undefined;
      const originalCatalog =
        rebound && separateCatalog
          ? configuredCatalogLayer(initial["layers"])
          : undefined;
      // Neutralizing the launcher can also hide a project shared with the target.
      const scopedFile =
        (originalCatalog?.source === "project"
          ? originalCatalog.path
          : undefined) ??
        catalogFile(settings, layers, separateCatalog) ??
        projected["model_catalog_json"];
      const staticCatalog =
        typeof policy["modelCatalogJson"] === "string"
          ? fileURLToPath(policy["modelCatalogJson"])
          : typeof scopedFile === "string"
            ? resolve(cwd, expandHome(scopedFile, env))
            : undefined;
      let accountType: unknown = "apiKey";
      if (!apiKey) {
        if (differentWorkspace && !rebound) {
          if (
            settings["forced_login_method"] === "api" &&
            scopedFeatures["api_key_cyber_access_programs"] === false
          )
            return undefined;
          const launch = startup?.["config"];
          if (
            !isRecord(launch) ||
            !Array.isArray(startup?.["layers"]) ||
            !Array.isArray(layers) ||
            credentialType === "chatgpt" ||
            settings["forced_login_method"] != null ||
            scopedFeatures["api_key_cyber_access_programs"] !== false
          )
            return "standard";

          const targetStore = settings["cli_auth_credentials_store"];
          const externalToken = environmentEntry(env, "CODEX_ACCESS_TOKEN");
          const knownKey = credentialType === "api_key" && !externalToken;
          const canReadSelectedKey =
            knownKey || (targetStore === "auto" && !externalToken);
          const sameFile =
            knownKey &&
            targetStore === "file" &&
            launch["cli_auth_credentials_store"] === "file";
          const readsApiKey = async (rpc: AppServerRequest) => {
            const account = (
              await rpc("account/read", { refreshToken: false })
            )["account"];
            return isRecord(account) && account["type"] === "apiKey";
          };
          if (
            isDeepStrictEqual(
              workspacePolicyInputs(settings, sameFile ? [] : layers, true),
              workspacePolicyInputs(
                launch,
                sameFile ? [] : startup["layers"],
                true,
              ),
            )
          ) {
            if (sameFile) return undefined;
            if (
              (canReadSelectedKey ||
                (isRecord(launch["features"]) &&
                  launch["features"]["api_key_cyber_access_programs"] ===
                    false)) &&
              (await readsApiKey(request))
            )
              return undefined;
            return "standard";
          }

          // An API-only launcher can hide the target's credential store. Native
          // auto storage selects the keyring or file grant before filtering its
          // login method, so only a positive native account/read proves a key.
          const targetInputs = workspacePolicyInputs(settings, [], true);
          if (
            canReadSelectedKey &&
            launch["forced_login_method"] === "api" &&
            (targetStore === "auto" || targetStore === "file") &&
            isDeepStrictEqual(
              targetInputs,
              workspacePolicyInputs(
                { ...launch, cli_auth_credentials_store: targetStore },
                [],
                true,
              ),
            )
          ) {
            if (launch["cli_auth_credentials_store"] === targetStore)
              return (await readsApiKey(request)) ? undefined : "standard";
            const confirmed = await probe(
              [
                ...bootstrapOverrides,
                `cli_auth_credentials_store=${inlineToml(targetStore)}`,
                'forced_login_method="api"',
              ],
              async (rpc) => {
                const scoped = (await rpc("config/read", { cwd: nativeCwd }))[
                  "config"
                ];
                return (
                  isRecord(scoped) &&
                  scoped["forced_login_method"] === "api" &&
                  isDeepStrictEqual(
                    targetInputs,
                    workspacePolicyInputs(scoped, [], true),
                  ) &&
                  (await readsApiKey(rpc))
                );
              },
            );
            if (confirmed) return undefined;
          }
          return "standard";
        }
        const account = rebound
          ? rebound.account
          : (await request("account/read", { refreshToken: false }))["account"];
        accountType = isRecord(account) ? account["type"] : undefined;
      }
      if (accountType === "apiKey") {
        if (
          !mayForward("api_key_cyber_access_programs") ||
          (differentWorkspace &&
            gateConfig["forced_login_method"] === "chatgpt") ||
          (Array.isArray(policy["allowedLoginMethods"]) &&
            !policy["allowedLoginMethods"].includes("api"))
        )
          return undefined;
      } else if (accountType !== "chatgpt") return undefined;
      if (requirementsUnavailable) return "standard";
      if (
        !apiKey &&
        !rebound &&
        startup &&
        (!isRecord(startup["config"]) ||
          !Array.isArray(startup["layers"]) ||
          !Array.isArray(layers) ||
          !isDeepStrictEqual(
            storedCatalogScope(settings, layers),
            storedCatalogScope(startup["config"], startup["layers"]),
          ) ||
          (staticCatalog === undefined &&
            scopedFile !==
              catalogFile(
                startup["config"],
                startup["layers"],
                separateCatalog,
              )))
      )
        return "standard";
      const telemetry: JsonObject = {};
      for (const key of ["analytics", "responses_api_metadata"]) {
        const value = settings[key] ?? resolved[key];
        if (value != null) telemetry[key] = value;
      }
      const select = (rpc: AppServerRequest) =>
        appServerCatalogProgram(effectiveModel, rpc, signal);
      if (!apiKey) {
        if (!separateCatalog)
          return rebound ? probe(scopedOverrides, select) : select(request);
        if (
          staticCatalog &&
          (!externalLauncher || policy["modelCatalogJson"])
        ) {
          return probe(
            [
              ...scopedOverrides,
              `model_catalog_json=${inlineToml(staticCatalog)}`,
            ],
            select,
          );
        }
        if (nativeUrl !== catalogUrl) return "standard";
        // A launcher may select its catalog from the active saved login. Only
        // the authenticated process can report that selection.
        let initialized = false;
        return probe<CyberAccessProgram>(scopedOverrides, async (rpc) => {
          initialized = true;
          if (!legacyLauncher) return select(rpc);
          const target = await rpc("config/read", { cwd });
          const launch = await rpc("config/read", { cwd: nativeCwd });
          if (!isRecord(target["config"]) || !isRecord(launch["config"]))
            return "standard";
          const file = target["config"]["model_catalog_json"];
          if (file === launch["config"]["model_catalog_json"])
            return select(rpc);
          if (typeof file !== "string") return "standard";
          return probe(
            [
              ...scopedOverrides,
              `model_catalog_json=${inlineToml(resolve(cwd, expandHome(file, env)))}`,
            ],
            select,
          );
        }).catch((error: unknown): CyberAccessProgram => {
          signal.throwIfAborted();
          // Old app-servers cannot start with a relative catalog that exists
          // only under exec's --cd. The actual scan validates its own file.
          if (
            !initialized &&
            legacyLauncher &&
            /no such file or directory|cannot find the file specified/i.test(
              String(error),
            )
          )
            return "standard";
          throw error;
        });
      }
      // A bound catalog can be read offline when the key cannot be used. When
      // it can, the launcher's native preferences still belong to the scan key.
      const boundFile =
        typeof policy["modelCatalogJson"] === "string" ||
        (typeof projected["model_catalog_json"] === "string" &&
          !launcherSelectsFile);
      if (
        staticCatalog !== undefined &&
        (!isolatedKey || (boundFile && protectedKeyRoute))
      ) {
        if (separateCatalog)
          return probe(
            [
              ...scopedOverrides,
              `model_catalog_json=${inlineToml(staticCatalog)}`,
            ],
            select,
          );
        return select(request);
      }
      const discoveryDisabled = enabled("api_key_model_discovery") === false;
      if (!isolatedKey && discoveryDisabled) return "standard";
      if (protectedKeyRoute) return "standard";
      let remoteModel = effectiveModel;
      if (inspectLauncherKey) {
        const selected = await keyedLauncherProgram({
          command: { ...catalogCommand, cwd: nativeCwd },
          cwd,
          useCd,
          environment: discoveryEnv,
          home: scratch,
          apiKey,
          model: effectiveModel,
          configOverrides:
            resolved["model_provider"] === "openai"
              ? [...policyOverrides, 'model_provider="openai"']
              : policyOverrides,
          bootstrapCatalog,
          telemetry,
          providerNames: Object.keys(providers),
          signal,
        });
        if (typeof selected !== "object") return selected;
        remoteModel = selected.remoteModel;
      }
      const keyConfig = { ...catalogConfig(settings), ...telemetry };
      keyConfig["model_provider"] = "openai";
      delete keyConfig["model_catalog_json"];
      // Restore caller-specific endpoints only in the isolated key process.
      for (const key of ["openai_base_url", "chatgpt_base_url"]) {
        if (projected[key] != null) keyConfig[key] = projected[key]!;
      }
      if (typeof keyCatalogUrl === "string")
        keyConfig["model_providers"] = {
          openai: { model_catalog_url: keyCatalogUrl },
        };
      // A launcher can prepend its own -c flags. Preserve the scan's CLI
      // precedence for catalog features. Private endpoints stay in keyConfig.
      const cliOverrides = policyOverrides.filter(
        (override) =>
          override.startsWith("features.") || override.startsWith("features="),
      );
      cliOverrides.push('model_provider="openai"');
      for (const name of catalogFeatures) {
        const required = requiredFeatures[name];
        if (typeof required === "boolean")
          cliOverrides.push(`features.${name}=${required}`);
      }
      return { config: keyConfig, model: remoteModel, cliOverrides };
    });
    if (typeof result !== "object") return result;
    // Serial component comparisons reuse the native identity-scoped model cache.
    const keyHome = getKeyCatalogHome
      ? await getKeyCatalogHome(configuredCodexHome(env))
      : scratch;
    const overrides = result.cliOverrides ?? [];
    if (differentCwd) {
      // The launcher can prepend trust flags for its own working directory.
      // Apply the scan's resolved config without loading that project's layers.
      overrides.push(...(await untrustedLauncherProject(nativeCwd)));
    }
    await writeCodexConfig(join(keyHome, "config.toml"), result.config);
    return await nativeCatalogProgram(
      catalogCommand,
      nativeCwd,
      {
        ...credentialFreeEnvironment(env, keyHome),
        CODEX_API_KEY: apiKey!,
      },
      overrides,
      result.model,
      signal,
    );
  } catch (error) {
    signal.throwIfAborted();
    if (error instanceof BundledCatalogUnavailable && readForwarding)
      return await readForwarding(error);
    throw error;
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}
