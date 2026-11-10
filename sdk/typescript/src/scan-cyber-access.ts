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
import {
  bundledCodexSdkEnvironment,
  isBundledExecutable,
} from "./codex-sdk-environment.js";
import {
  CODEX_AUTH_CONFIG_KEYS,
  hasCommandAuth,
  inlineToml,
  resolveCodexProfile,
  writeCodexConfig,
  type JsonObject,
  type JsonValue,
} from "./config.js";
import { ConfigurationError } from "./errors.js";
import {
  nativePermissionPreflight,
  preflightConfigOverrides,
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

function pickSettings(
  source: JsonValue | undefined,
  keys: string[],
): JsonObject {
  if (!isRecord(source)) return {};
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

type ConfigLayer = {
  name: { type: string };
  config: JsonObject;
  disabledReason?: string | null;
};

const managedLayers = new Set([
  "enterpriseManaged",
  "legacyManagedConfigTomlFromMdm",
  "legacyManagedConfigTomlFromFile",
]);

/** These workspace routing controls cannot be reproduced by a separate API-key identity. */
function hasManagedRoute(policy: JsonObject, layers: ConfigLayer[]) {
  const required = asRecord(policy["featureRequirements"]);
  const network = asRecord(asRecord(policy["application"])?.["network"]);
  if (
    policy["chatgptBaseUrl"] != null ||
    policy["enforceResidency"] != null ||
    network?.["enabled"] === true ||
    networkFeatures.some((name) => required?.[name] != null)
  )
    return true;
  return layers.some(({ name, config }) => {
    if (!managedLayers.has(name.type)) return false;
    const features = asRecord(config["features"]);
    return (
      [
        ...endpoints,
        "model_catalog_json",
        "cli_auth_credentials_store",
        "application",
        "network",
      ].some((key) => config[key] != null) ||
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

type CatalogModel = {
  slug: string;
  priority: number;
  supported_in_api: boolean;
  available_access_programs?: { cyber: string[] };
};

// Native debug models validates the catalog but returns raw rows. Native
// model/list filters for API support and chooses the lowest priority number first.
function apiKeyCatalogProgram(raw: string, model: string) {
  const models: CatalogModel[] = JSON.parse(raw).models;
  const [selected] = models
    .filter((entry) => entry.slug === model && entry.supported_in_api)
    .sort((a, b) => a.priority - b.priority);
  return selectedProgram(model, selected?.available_access_programs?.cyber);
}

/** Read workspace policy using its configured identity before choosing a catalog. */
async function readCatalogPolicy(
  request: AppServerRequest,
  cwd: string,
  projectKey: boolean,
  masked: boolean,
) {
  const response = await request("config/read", { cwd, includeLayers: masked });
  const settings = response["config"];
  if (
    !isRecord(settings) ||
    settings["daybreak"] != null ||
    (settings["model_provider"] ?? "openai") !== "openai"
  )
    return undefined;
  const { requirements } = await request("configRequirements/read", {});
  const policy = isRecord(requirements) ? requirements : {};
  if ((policy["modelProvider"] ?? "openai") !== "openai") return undefined;
  const features = {
    ...pickSettings(settings["features"], catalogFeatures),
    ...pickSettings(policy["featureRequirements"], catalogFeatures),
  };
  if (features["cli_daybreak"] === false) return undefined;
  const flags = await daybreakFeatures(request);
  const enabled = (name: string) => features[name] ?? flags.get(name);
  if (enabled("cli_daybreak") !== true) return undefined;
  const accountType = projectKey
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

  const layers = ((response["layers"] ?? []) as ConfigLayer[]).filter(
    ({ config }) => isRecord(config),
  );
  const file =
    typeof policy["modelCatalogJson"] === "string"
      ? fileURLToPath(policy["modelCatalogJson"])
      : masked
        ? layers.find(
            ({ name, config, disabledReason }) =>
              !disabledReason &&
              name.type !== "sessionFlags" &&
              typeof config["model_catalog_json"] === "string",
          )?.config["model_catalog_json"]
        : settings["model_catalog_json"];
  return {
    settings,
    features,
    file,
    requiredProvider: openAiProvider(policy["modelProviders"]),
    canDiscover:
      enabled("api_key_model_discovery") !== false &&
      !hasManagedRoute(policy, layers),
  };
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
    const policyOverrides = await preflightConfigOverrides(
      {
        ...policyConfig,
        ...pickSettings(resolved, ["analytics", "analytics.enabled"]),
        sqlite_home: sqliteHome,
      },
      nativeProfile,
    );
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
      const access = await readCatalogPolicy(
        request,
        cwd,
        Boolean(apiKey),
        maskCatalog,
      );
      if (!access) return undefined;
      const { settings, features, file, requiredProvider } = access;
      const selectedModel =
        typeof settings["model"] === "string" ? settings["model"] : model;
      const select = async (rpc: AppServerRequest) =>
        selectedProgram(
          selectedModel,
          await modelCyberAccessPrograms(selectedModel, rpc),
        );
      if (!apiKey && !maskCatalog) return select(request);
      const catalogFile =
        typeof file === "string"
          ? resolve(cwd, expandHome(file, env))
          : undefined;
      const nativeUrl = (requiredProvider ??
        openAiProvider(settings["model_providers"]))?.["model_catalog_url"];
      const catalogUrl = requiredProvider || !route ? nativeUrl : route.url;
      if (!apiKey) {
        if (catalogFile)
          policyOverrides.push(`model_catalog_json=${inlineToml(catalogFile)}`);
        else if (catalogUrl !== nativeUrl) return "standard";
        return probe(policyOverrides, select);
      }
      if (!catalogFile && !access.canDiscover) return "standard";

      // Replay the effective native policy exactly once, in a private home without the saved login
      // or a second set of project layers. Keep the scan key in the environment and its route in the file.
      const keyConfig: JsonObject = {
        ...catalogConfig(settings),
        ...pickSettings(settings, ["analytics", "responses_api_metadata"]),
        ...pickSettings(projected, endpoints),
        features,
        model_provider: "openai",
        model_catalog_json: catalogFile ?? null,
        ...(catalogFile === undefined &&
          typeof catalogUrl === "string" && {
            model_providers: { openai: { model_catalog_url: catalogUrl } },
          }),
        project_root_markers: [],
      };
      await writeCodexConfig(join(scratch, "config.toml"), keyConfig);
      // The project key uses a private home with no ambient login.
      const isolated = Object.fromEntries(
        Object.entries(env).filter(
          ([name]) =>
            !["CODEX_ACCESS_TOKEN", "CODEX_HOME"].includes(name.toUpperCase()),
        ),
      );
      const raw = await debugModels({
        ...isolated,
        CODEX_HOME: scratch,
        CODEX_API_KEY: apiKey,
      });
      return apiKeyCatalogProgram(raw, selectedModel);
    });
  } catch (error) {
    signal.throwIfAborted();
    throw error;
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}
