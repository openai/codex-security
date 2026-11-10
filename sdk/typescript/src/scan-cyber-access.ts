import { rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { CyberAccessProgram } from "@openai/codex-sdk";
import {
  CODEX_AUTH_CONFIG_KEYS,
  configuredCodexHome,
  environmentEntry,
  withoutOpenAiApiKeys,
} from "./auth.js";
import {
  daybreakFeatures,
  modelCyberAccessPrograms,
  type AppServerRequest,
} from "./cli-daybreak.js";
import { bundledCodexSdkEnvironment } from "./codex-sdk-environment.js";
import {
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
  environment: Record<string, string>;
  config: JsonObject;
  model: string;
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

/** The policy probe masks remote discovery with a bundled catalog. Recover a
 * workspace's actual catalog file from the first active layer below that flag. */
function configuredCatalogFile(layers: unknown) {
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
      return layer["config"]["model_catalog_json"];
  }
  return undefined;
}

async function nativeModels(
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
  signal.throwIfAborted();
  if (!result.success)
    throw new ConfigurationError(result.stderr || result.stdout);
  return result.stdout;
}

/** Discover the selected model's programs using the scan's identity before its first turn. */
export async function resolveScanCyberAccessProgram({
  command,
  cwd,
  environment,
  config,
  model,
  nativeProfile,
  program,
  signal,
}: ScanCyberAccessOptions): Promise<CyberAccessProgram | undefined> {
  if (program !== undefined) return program;
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
  const providers = isRecord(resolved["model_providers"])
    ? { ...resolved["model_providers"] }
    : {};
  delete providers["openai"]; // Its private catalog URL must stay out of argv.
  const { url, pinned } = privateCatalogUrl(resolved, nativeProfile);
  const maskCatalog =
    Boolean(apiKey || url || pinned) && !projected["model_catalog_json"];
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
    const consent = Object.fromEntries(
      Object.entries(resolved).filter(
        ([key, value]) =>
          value != null && (key === "analytics" || key === "analytics.enabled"),
      ),
    );
    const catalogCommand = await providerPreflightCommand(
      {
        ...command,
        args: [
          "-c",
          `sqlite_home=${inlineToml(sqliteHome)}`,
          ...serialize(consent).flatMap((flag) => ["-c", flag]),
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
      const bundled = await nativeModels(
        command,
        scratch,
        {
          HOME: scratch,
          USERPROFILE: scratch,
          CODEX_HOME: scratch,
          ...(environmentEntry(env, "SystemRoot") && {
            SystemRoot: environmentEntry(env, "SystemRoot")!,
          }),
        },
        ["-c", "analytics.enabled=false", "debug", "models", "--bundled"],
        signal,
      );
      await writeFile(path, bundled, { mode: 0o600 });
      bootstrap.push(`model_catalog_json=${inlineToml(path)}`);
    }

    return await probe(bootstrap, async (request) => {
      const { config: settings, layers } = await request("config/read", {
        cwd,
        includeLayers: Boolean(apiKey || maskCatalog),
      });
      if (
        !isRecord(settings) ||
        settings["daybreak"] != null ||
        (settings["model_provider"] ?? "openai") !== "openai"
      )
        return undefined;
      const { requirements } = await request("configRequirements/read", {});
      const policy = isRecord(requirements) ? requirements : {};
      if ((policy["modelProvider"] ?? "openai") !== "openai") return undefined;
      const requiredFeatures = isRecord(policy["featureRequirements"])
        ? policy["featureRequirements"]
        : {};
      const scopedFeatures = isRecord(settings["features"])
        ? settings["features"]
        : {};
      if (
        (requiredFeatures["cli_daybreak"] ?? scopedFeatures["cli_daybreak"]) ===
        false
      )
        return undefined;
      const flags = await daybreakFeatures(request);
      const enabled = (name: string) =>
        requiredFeatures[name] ?? scopedFeatures[name] ?? flags.get(name);
      if (enabled("cli_daybreak") !== true) return undefined;
      let accountType: unknown = "apiKey";
      if (!apiKey) {
        const { account } = await request("account/read", {
          refreshToken: false,
        });
        accountType = isRecord(account) ? account["type"] : undefined;
      }
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
      const catalogUrl = requiredProvider
        ? nativeUrl
        : pinned
          ? url
          : (url ?? nativeUrl);
      if (!apiKey)
        return nativeUrl === catalogUrl
          ? probe(policyOverrides, select)
          : "standard";

      // The isolated key cannot reload a saved workspace's managed network controls.
      const application = policy["application"];
      if (
        enabled("api_key_model_discovery") === false ||
        policy["chatgptBaseUrl"] != null ||
        policy["enforceResidency"] != null ||
        ["respect_system_proxy", "system_proxy_fallback", "psp"].some(
          (name) => requiredFeatures[name] != null,
        ) ||
        (isRecord(application) &&
          isRecord(application["network"]) &&
          application["network"]["enabled"] === true) ||
        (Array.isArray(layers) && layers.some(hasManagedCatalogSettings))
      )
        return "standard";

      // Native debug models uses CODEX_API_KEY. Its credential home contains only this call's private configuration.
      const keyConfig = catalogConfig(settings);
      keyConfig["model_provider"] = "openai";
      delete keyConfig["model_catalog_json"];
      for (const key of ["analytics", "responses_api_metadata"]) {
        const value = settings[key] ?? resolved[key];
        if (value != null) keyConfig[key] = value;
      }
      for (const key of ["openai_base_url", "chatgpt_base_url"]) {
        if (projected[key] != null) keyConfig[key] = projected[key]!;
      }
      if (typeof catalogUrl === "string")
        keyConfig["model_providers"] = {
          openai: { model_catalog_url: catalogUrl },
        };
      await writeCodexConfig(join(scratch, "config.toml"), keyConfig);
      const keyEnv = Object.fromEntries(
        Object.entries(env).filter(
          ([name]) =>
            !["CODEX_ACCESS_TOKEN", "CODEX_HOME"].includes(name.toUpperCase()),
        ),
      );
      const overrides = policyOverrides.filter(
        (flag) => flag.startsWith("features.") || flag.startsWith("features="),
      );
      overrides.push('model_provider="openai"');
      for (const name of catalogFeatures) {
        if (typeof requiredFeatures[name] === "boolean")
          overrides.push(`features.${name}=${requiredFeatures[name]}`);
      }
      const raw = await nativeModels(
        catalogCommand,
        cwd,
        { ...keyEnv, CODEX_HOME: scratch, CODEX_API_KEY: apiKey },
        [...overrides.flatMap((flag) => ["-c", flag]), "debug", "models"],
        signal,
      );
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
