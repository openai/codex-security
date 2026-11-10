import { rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { CyberAccessProgram } from "@openai/codex-sdk";
import {
  configuredCodexHome,
  environmentEntry,
  withoutOpenAiApiKeys,
} from "./auth.js";
import {
  daybreakAccountType,
  daybreakFeatures,
  modelCyberAccessPrograms,
  type AppServerRequest,
} from "./cli-daybreak.js";
import { bundledCodexSdkEnvironment } from "./codex-sdk-environment.js";
import {
  CODEX_AUTH_CONFIG_KEYS,
  hasCommandAuth,
  inlineToml,
  resolveCodexProfile,
  writeCodexConfig,
  type JsonObject,
} from "./config.js";
import { isBundledExecutable, sdkConfigFlags } from "./deep-scan.js";
import { ConfigurationError } from "./errors.js";
import {
  nativePermissionPreflight,
  nativeProfileClient,
  providerPreflightCommand,
} from "./provider-profile.js";
import { asRecord, isRecord } from "./record.js";
import {
  expandHome,
  prepareOutputDir,
  runCodexCommand,
  type CodexCommand,
  type ProcessEnvironment,
} from "./runtime.js";

interface ScanCyberAccessOptions {
  command: CodexCommand;
  cwd: string;
  environment: Record<string, string>;
  config: JsonObject;
  model: string;
  nativeProfile?: boolean;
  signal: AbortSignal;
}

const networkFeatures = [
  "respect_system_proxy",
  "system_proxy_fallback",
  "psp",
];
const catalogFeatures = [
  "cli_daybreak",
  "api_key_model_discovery",
  "api_key_cyber_access_programs",
  "secret_auth_storage",
  ...networkFeatures,
];
const endpoints = ["chatgpt_base_url", "openai_base_url"];
const catalogSettings = [
  ...CODEX_AUTH_CONFIG_KEYS,
  ...endpoints,
  "auth_keyring_backend",
  "model",
  "daybreak",
  "model_catalog_json",
  "project_root_markers",
  "features",
  ...catalogFeatures.map((key) => `features.${key}`),
];

function pickSettings(source: JsonObject, keys: string[]): JsonObject {
  return Object.fromEntries(
    Object.entries(source).filter(
      ([key, value]) => value != null && keys.includes(key),
    ),
  );
}

// Keep the original order of literal dotted flags and tables. A native profile
// replaces the entire feature table, whereas the SDK emits individual leaves.
function catalogConfig(source: JsonObject, nativeProfile = false): JsonObject {
  const config = pickSettings(source, catalogSettings);
  const features = config["features"];
  if (isRecord(features)) {
    const selected = pickSettings(features, catalogFeatures);
    if (
      nativeProfile ||
      Object.keys(selected).length ||
      !Object.keys(features).length
    )
      config["features"] = selected;
    else delete config["features"];
  }
  return config;
}

function openAiProvider(providers: unknown) {
  return asRecord(asRecord(providers)?.["openai"]);
}

// File settings are below the SDK's literal dotted flags. TOML normalization
// places scalars before tables; a whole-table flag can also clear an inherited URL.
function catalogRoute(
  config: JsonObject,
  nativeProfile = false,
): { url?: string } | undefined {
  const table = asRecord(config["model_providers.openai"]);
  const override = table?.["model_catalog_url"];
  if (typeof override === "string") return { url: override };
  if (table && (nativeProfile || !Object.keys(table).length)) return {};
  const leaf = config["model_providers.openai.model_catalog_url"];
  const url =
    typeof leaf === "string"
      ? leaf
      : openAiProvider(config["model_providers"])?.["model_catalog_url"];
  return typeof url === "string" ? { url } : undefined;
}

const managedLayers = new Set([
  "enterpriseManaged",
  "legacyManagedConfigTomlFromMdm",
  "legacyManagedConfigTomlFromFile",
]);

/** These workspace routing controls cannot be reproduced by a separate API-key identity. */
function hasManagedRoute(policy: JsonObject, layers: unknown[]) {
  const required = asRecord(policy["featureRequirements"]);
  const network = asRecord(asRecord(policy["application"])?.["network"]);
  if (
    policy["chatgptBaseUrl"] != null ||
    policy["enforceResidency"] != null ||
    network?.["enabled"] === true ||
    networkFeatures.some((name) => required?.[name] != null)
  )
    return true;
  return layers.some((layer) => {
    const entry = asRecord(layer);
    if (!managedLayers.has(String(asRecord(entry?.["name"])?.["type"])))
      return false;
    const settings = asRecord(entry?.["config"]);
    const features = asRecord(settings?.["features"]);
    return (
      [
        "chatgpt_base_url",
        "openai_base_url",
        "model_catalog_json",
        "cli_auth_credentials_store",
        "application",
        "network",
      ].some((key) => settings?.[key] != null) ||
      networkFeatures.some((key) => features?.[key] != null)
    );
  });
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

/** The policy probe masks remote discovery with a bundled catalog. Recover a
 * workspace's actual catalog file from the first active layer below that flag. */
function configuredCatalogFile(layers: unknown[]) {
  for (const value of layers) {
    const layer = asRecord(value);
    const path = asRecord(layer?.["config"])?.["model_catalog_json"];
    if (
      !layer?.["disabledReason"] &&
      asRecord(layer?.["name"])?.["type"] !== "sessionFlags" &&
      typeof path === "string"
    )
      return path;
  }
}

/** Discover the selected model's programs using the scan's identity before its first turn. */
export async function resolveScanCyberAccessProgram({
  command,
  cwd,
  environment,
  config,
  model,
  nativeProfile,
  signal,
}: ScanCyberAccessOptions): Promise<CyberAccessProgram | undefined> {
  if (command.args?.length || !isBundledExecutable(command.command))
    return undefined;
  const resolved = resolveCodexProfile(config);
  if (
    resolved["daybreak"] != null ||
    (resolved["model_provider"] ?? "openai") !== "openai" ||
    hasCommandAuth(resolved) ||
    environmentEntry(environment, "OPENAI_FEDERATION_RULE_ID") !== undefined ||
    environmentEntry(environment, "OPENAI_IDENTITY_TOKEN_FILE") !== undefined
  )
    return undefined;

  const apiKey = environmentEntry(environment, "CODEX_API_KEY");
  const env = bundledCodexSdkEnvironment(
    command.command,
    withoutOpenAiApiKeys(environment),
  );
  if (!environmentEntry(env, "CODEX_INTERNAL_ORIGINATOR_OVERRIDE"))
    env["CODEX_INTERNAL_ORIGINATOR_OVERRIDE"] = "codex_sdk_ts";
  const serialize: (source: JsonObject) => string[] = nativeProfile
    ? (await nativeProfileClient()).profileConfigOverrides
    : sdkConfigFlags;
  const projected = catalogConfig({ ...resolved, model }, nativeProfile);
  if (typeof projected["model_catalog_json"] === "string")
    projected["model_catalog_json"] = resolve(
      cwd,
      expandHome(projected["model_catalog_json"], env),
    );
  const policyConfig = { ...projected };
  if (apiKey) {
    // Workspace policy uses the saved login. Never point it at a project key's endpoints.
    delete policyConfig["openai_base_url"];
    delete policyConfig["chatgpt_base_url"];
  }
  const policyOverrides = serialize(policyConfig);
  const route = catalogRoute(resolved, nativeProfile);
  const maskCatalog =
    Boolean(apiKey || route) && !projected["model_catalog_json"];
  const scratch = await prepareOutputDir(
    undefined,
    "catalog",
    configuredCodexHome(env),
  );
  try {
    const sqliteHome = join(scratch, "sqlite");
    for (const name of Object.keys(env)) {
      if (name.toUpperCase() === "CODEX_SQLITE_HOME") delete env[name];
    }
    env["CODEX_SQLITE_HOME"] = sqliteHome;
    // The policy preflight receives provider names only. Its saved login must never see a project key's route.
    const providers = { ...asRecord(resolved["model_providers"]) };
    delete providers["openai"];
    const policyCommand = await providerPreflightCommand(command, {
      ...pickSettings(resolved, ["model_provider", "responses_api_metadata"]),
      model_providers: providers as JsonObject,
    });
    policyOverrides.push(
      ...serialize(pickSettings(resolved, ["analytics", "analytics.enabled"])),
      `sqlite_home=${inlineToml(sqliteHome)}`,
    );
    // The project key uses a private home with no ambient login.
    const isolated = Object.fromEntries(
      Object.entries(env).filter(
        ([name]) =>
          !["CODEX_ACCESS_TOKEN", "CODEX_HOME"].includes(name.toUpperCase()),
      ),
    );
    isolated["CODEX_HOME"] = scratch;
    const debugModels = async (
      identity: ProcessEnvironment,
      bundled = false,
    ) => {
      const args = bundled
        ? ["-c", "analytics.enabled=false", "debug", "models", "--bundled"]
        : ["debug", "models"];
      const result = await runCodexCommand(
        command,
        args,
        identity,
        undefined,
        signal,
        { cwd: scratch },
      );
      if (!result.success)
        throw new ConfigurationError(result.stderr || result.stdout);
      return result.stdout;
    };
    const native = await nativePermissionPreflight();
    const probe = <T>(
      overrides: string[],
      operation: (request: AppServerRequest) => Promise<T>,
    ): Promise<T> =>
      native.withPreflightClient(
        {
          codexPath: command.command,
          commandArgs: policyCommand.args,
          cwd,
          env,
          configOverrides: overrides,
          signal,
          context: "scan-catalog",
        },
        (client: { request: AppServerRequest }) =>
          operation(client.request.bind(client)),
      );

    const bootstrap = [...policyOverrides];
    if (maskCatalog) {
      // Ask the saved workspace for policy without loading a catalog under the wrong identity or route.
      const path = join(scratch, "bootstrap-models.json");
      const bootstrapEnv = {
        HOME: scratch,
        USERPROFILE: scratch,
        CODEX_HOME: scratch,
        SystemRoot: environmentEntry(env, "SystemRoot"),
      };
      await writeFile(path, await debugModels(bootstrapEnv, true), {
        mode: 0o600,
      });
      bootstrap.push(`model_catalog_json=${inlineToml(path)}`);
    }

    return await probe(bootstrap, async (request) => {
      const { config: settings, layers: nativeLayers } = await request(
        "config/read",
        {
          cwd,
          includeLayers: Boolean(apiKey || maskCatalog),
        },
      );
      if (
        !isRecord(settings) ||
        settings["daybreak"] != null ||
        (settings["model_provider"] ?? "openai") !== "openai"
      )
        return undefined;
      const { requirements } = await request("configRequirements/read", {});
      const policy = isRecord(requirements) ? requirements : {};
      if ((policy["modelProvider"] ?? "openai") !== "openai") return undefined;
      const layers: unknown[] = Array.isArray(nativeLayers) ? nativeLayers : [];
      const requiredFeatures = asRecord(policy["featureRequirements"]) ?? {};
      const scopedFeatures = asRecord(settings["features"]) ?? {};
      if (
        (requiredFeatures["cli_daybreak"] ?? scopedFeatures["cli_daybreak"]) ===
        false
      )
        return undefined;
      const flags = await daybreakFeatures(request);
      const enabled = (name: string) =>
        requiredFeatures[name] ?? scopedFeatures[name] ?? flags.get(name);
      if (enabled("cli_daybreak") !== true) return undefined;
      const accountType = apiKey
        ? "apiKey"
        : await daybreakAccountType(request);
      if (accountType === "apiKey") {
        if (
          enabled("api_key_cyber_access_programs") !== true ||
          (Array.isArray(policy["allowedLoginMethods"]) &&
            !policy["allowedLoginMethods"].includes("api"))
        )
          return undefined;
      } else if (accountType !== "chatgpt") return undefined;

      const selectedModel =
        typeof settings["model"] === "string" ? settings["model"] : model;
      const select = async (rpc: AppServerRequest) =>
        selectedProgram(
          selectedModel,
          await modelCyberAccessPrograms(selectedModel, rpc),
        );
      if (!maskCatalog) return select(request);
      const file = configuredCatalogFile(layers);
      const staticCatalog =
        typeof policy["modelCatalogJson"] === "string"
          ? fileURLToPath(policy["modelCatalogJson"])
          : file;
      if (staticCatalog !== undefined) {
        const path = resolve(cwd, expandHome(staticCatalog, env));
        return probe(
          [...policyOverrides, `model_catalog_json=${inlineToml(path)}`],
          select,
        );
      }
      const requiredProvider = openAiProvider(policy["modelProviders"]);
      const nativeUrl = (requiredProvider ??
        openAiProvider(settings["model_providers"]))?.["model_catalog_url"];
      const catalogUrl = requiredProvider || !route ? nativeUrl : route.url;
      if (!apiKey)
        return nativeUrl === catalogUrl
          ? probe(policyOverrides, select)
          : "standard";

      // The isolated key cannot reload a saved workspace's managed network controls.
      if (
        enabled("api_key_model_discovery") === false ||
        hasManagedRoute(policy, layers)
      )
        return "standard";

      // Replay the effective native policy exactly once, in a private home without the saved login
      // or a second set of project layers. Keep the scan key in the environment and its route in the file.
      const keyConfig: JsonObject = {
        ...catalogConfig(settings),
        ...pickSettings(settings, ["analytics", "responses_api_metadata"]),
        ...pickSettings(projected, endpoints),
        features: {
          ...pickSettings(scopedFeatures as JsonObject, catalogFeatures),
          ...pickSettings(requiredFeatures as JsonObject, catalogFeatures),
        },
        model_provider: "openai",
        ...(typeof catalogUrl === "string" && {
          model_providers: { openai: { model_catalog_url: catalogUrl } },
        }),
        project_root_markers: [],
      };
      delete keyConfig["model_catalog_json"];
      await writeCodexConfig(join(scratch, "config.toml"), keyConfig);
      const raw = await debugModels({ ...isolated, CODEX_API_KEY: apiKey });
      const catalog = JSON.parse(raw).models;
      const row = Array.isArray(catalog)
        ? catalog.find(
            (entry) => isRecord(entry) && entry["slug"] === selectedModel,
          )
        : undefined;
      return selectedProgram(
        selectedModel,
        row?.available_access_programs?.cyber,
      );
    });
  } catch (error) {
    signal.throwIfAborted();
    throw error;
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}
