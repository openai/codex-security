import { codexSecurityRequestMetadata } from "./request-metadata.js";
import { lstat, mkdir, readFile, realpath, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { parse as parseToml } from "smol-toml";
import {
  accountStatus,
  configuredCodexHome,
  readCodexHomeConfig,
} from "./auth.js";
import { bundledCodexSdkEnvironment } from "./codex-sdk-environment.js";
import { resolveConfigPath } from "./config-path.js";
import { isRecord } from "./record.js";
import {
  Codex,
  type CodexOptions,
  type ThreadOptions,
  type TurnOptions,
} from "@openai/codex-sdk";
import {
  EXTERNAL_CODEX_PROVIDERS,
  deepMerge,
  providerProcessConfiguration,
  mcpProcessConfiguration,
  codexConfigOverrides,
  writeCodexConfig,
  writeCodexConfigContents,
  hasCommandAuth,
  inlineToml,
  isExternalModelProvider,
  scanModelProvider,
  resolveCodexProfile,
  scanCompositionOverrides,
  type JsonObject,
} from "./config.js";
import { AuthenticationRequiredError, CodexSecurityError } from "./errors.js";
import {
  scanAuthentication,
  environmentApiKey,
  environmentValue,
  selectedScanEnvironment,
  withoutCodexHome,
  withoutOpenAiApiKeys,
  definedEnvironment,
  type ScanAuthentication,
} from "./execution-auth.js";
import {
  codexSecurityStateDirectory,
  acquireCodexSecurityCredentialHomeLock,
  environmentWithGit,
  executablePathForSpawn,
  pluginExecutionEnvironment,
  cleanupSdkDirectory,
  createIsolatedHome,
  requirePrivateCredentialHome,
  createMarketplace,
  MARKETPLACE_NAME,
  PLUGIN_NAME,
  pluginMetadata,
  type CodexCommand,
  type PluginInstall,
  type ProcessEnvironment,
} from "./runtime.js";
import { createExecutionProfileCodex } from "./execution-profile.js";
import { createPermissionCheckedCodex } from "./permission-profile.js";
import type { ScanAuthMode } from "./scan-settings.js";
import type { InspectedExecutable } from "./trusted-executable.js";

export const SCAN_PERMISSION_PROFILE = "codex_security_scan";
const SAFETY_IDENTIFIER_ENV = "CODEX_SAFETY_IDENTIFIER";

export type ExecutionPolicy = "ordinary" | "discovery" | "merge";
interface ExecutionClient {
  surface: "cli" | "sdk";
  command?: string;
  createCodex?: (options: CodexOptions) => CodexClientLike;
}

/** One per-scan snapshot; worker construction never consults a mutable parent environment. */
export interface ExecutionSource {
  readonly command: CodexCommand;
  readonly configuration: JsonObject;
  readonly environment: ProcessEnvironment;
  readonly authentication: ScanAuthentication;
  readonly modelProvider: unknown;
  readonly externalProvider:
    | (typeof EXTERNAL_CODEX_PROVIDERS)[keyof typeof EXTERNAL_CODEX_PROVIDERS]
    | null;
  readonly apiKey: string | null;
  readonly preserveProviderEnvironment: boolean;
}

export function prepareExecutionSource(input: {
  command: CodexCommand;
  configuration: JsonObject;
  environment: ProcessEnvironment;
  auth?: ScanAuthMode;
  preserveProviderEnvironment?: boolean;
}): ExecutionSource {
  const configuration = structuredClone(input.configuration);
  const environment = { ...input.environment };
  const commandAuth = hasCommandAuth(configuration);
  const modelProvider = scanModelProvider(configuration);
  const preserveProviderEnvironment =
    input.preserveProviderEnvironment === true;
  const externalProvider =
    !preserveProviderEnvironment &&
    !commandAuth &&
    isExternalModelProvider(modelProvider)
      ? EXTERNAL_CODEX_PROVIDERS[modelProvider]
      : null;
  const authentication = scanAuthentication(
    environment,
    preserveProviderEnvironment ? "auto" : input.auth,
    modelProvider,
    commandAuth,
  );
  const apiKey =
    !preserveProviderEnvironment && authentication.method === "api_key"
      ? environmentApiKey(environment, modelProvider)
      : null;
  if (externalProvider !== null && apiKey === null)
    throw new AuthenticationRequiredError(
      `Set ${externalProvider.env_key} to run a scan through ${externalProvider.name}.`,
    );
  return {
    command: { ...input.command },
    configuration,
    modelProvider,
    externalProvider,
    authentication,
    apiKey,
    preserveProviderEnvironment,
    environment: preserveProviderEnvironment
      ? environment
      : selectedScanEnvironment(
          commandAuth ? withoutOpenAiApiKeys(environment) : environment,
          input.auth,
          modelProvider,
        ),
  };
}

export interface CodexThreadLike {
  readonly id: string | null;
  runStreamed(
    input: string,
    options: TurnOptions,
  ): Promise<{ events: AsyncGenerator<ScanEvent> }>;
}

export interface ScanEvent {
  readonly type: string;
  readonly [key: string]: unknown;
}

export interface CodexClientLike {
  startThread(options: ThreadOptions): CodexThreadLike;
  resumeThread?(threadId: string, options: ThreadOptions): CodexThreadLike;
}

export interface PreparedRuntime {
  codexHome: string;
  /** Native runs use the invoking account without rewriting its home config. */
  preserveCodexHomeConfig?: boolean;
  bootstrapWorkspace?: string;
  configPath?: string;
  plugin: PluginInstall;
  environment: Record<string, string>;
  credentialsAvailable: boolean;
}

export type ScanPermissions = { filesystem: JsonObject; network: JsonObject };

export interface PreparedExecution {
  readonly auth?: ScanAuthMode;
  readonly policy: ExecutionPolicy;
  readonly source: ExecutionSource;
  inheritedPermissions?: ScanPermissions;
  safetyIdentifier?: string;
  readonly runtime: PreparedRuntime;
  runtimeHome: string;
  effectiveConfig: JsonObject;
  preflightConfig: JsonObject;
  sessionConfig: JsonObject;
  runtimeConfig?: JsonObject;
  authentication: ScanAuthentication;
  approvalPolicy: "never" | "on-request";
  python: string;
  releaseCredentialHome: (() => Promise<void>) | null;
}

/** Coordinate the managed credential home during its existing startup preflight. */
export async function lockExecutionConfiguration(
  codexHome: string,
  config: JsonObject,
  signal?: AbortSignal,
): Promise<() => Promise<void>> {
  const release = await acquireCodexSecurityCredentialHomeLock(
    codexHome,
    signal,
  );
  const path = join(codexHome, "config.toml");
  try {
    const previous = await readFile(path).catch(
      (error: NodeJS.ErrnoException) => {
        if (error.code === "ENOENT") return null;
        throw error;
      },
    );
    await writeCodexConfig(path, config);
    let restoration: Promise<void> | undefined;
    return () =>
      (restoration ??= (async () => {
        try {
          if (previous === null) await rm(path, { force: true });
          else await writeCodexConfigContents(path, previous);
        } finally {
          await release();
        }
      })());
  } catch (error) {
    await release();
    throw error;
  }
}

export function createExecutionCodex(
  client: ExecutionClient,
  session: PreparedExecution,
  runtimePaths: Record<string, string>,
  config?: JsonObject,
  configOverrides: string[] = [],
  git?: InspectedExecutable,
): { codex: CodexClientLike; environment: ProcessEnvironment } {
  const { runtime, python, sessionConfig } = session;
  const {
    environment: scanEnvironment,
    externalProvider,
    apiKey,
    preserveProviderEnvironment,
  } = session.source;
  const environment: ProcessEnvironment = {
    ...environmentWithGit(
      pluginExecutionEnvironment(python, {
        ...withoutCodexHome(scanEnvironment),
        CODEX_CLI_PATH: session.source.command.command,
      }),
      git,
    ),
    ...(externalProvider === null
      ? {}
      : { [externalProvider.env_key]: apiKey! }),
    CODEX_HOME: runtime.codexHome,
    CODEX_SECURITY_STATE_DIR: codexSecurityStateDirectory(scanEnvironment),
    ...runtimePaths,
  };
  for (const name of Object.keys(environment)) {
    if (name.toUpperCase() === SAFETY_IDENTIFIER_ENV) delete environment[name];
  }
  if (session.safetyIdentifier !== undefined) {
    environment[SAFETY_IDENTIFIER_ENV] = session.safetyIdentifier;
  }
  const launchConfig = deepMerge(
    { ...session.runtimeConfig },
    config ?? sessionConfig,
  );
  if (
    hasCommandAuth(sessionConfig) &&
    launchConfig["model_providers"] === undefined
  ) {
    launchConfig["model_providers"] = sessionConfig["model_providers"]!;
  }
  const nativeTransport =
    client.createCodex === undefined || runtime.preserveCodexHomeConfig;
  const sdkCodexConfig = { ...launchConfig };
  const mcpLaunch = nativeTransport
    ? mcpProcessConfiguration(sdkCodexConfig)
    : { config: sdkCodexConfig, requiresConfigFile: false };
  const providerLaunch = nativeTransport
    ? providerProcessConfiguration(mcpLaunch.config)
    : { config: mcpLaunch.config, requiresConfigFile: false };
  const processConfig = { ...providerLaunch.config };
  const requiresConfigFile =
    session.runtimeConfig !== undefined ||
    mcpLaunch.requiresConfigFile ||
    providerLaunch.requiresConfigFile;
  // Native launches read project trust from config.toml, not a large argv override.
  if (client.createCodex === undefined) delete processConfig["projects"];
  const checkPermissions =
    (session.policy !== "ordinary" ||
      session.inheritedPermissions !== undefined) &&
    client.createCodex === undefined;
  if (
    (session.inheritedPermissions !== undefined || checkPermissions) &&
    sdkCodexConfig["default_permissions"] === SCAN_PERMISSION_PROFILE
  ) {
    const permissions = sessionConfig["permissions"] as JsonObject;
    // A stable argv-only profile supports managed allowlists without merging
    // the runtime home's persisted scan defaults into inherited permissions.
    const profileId =
      session.policy === "ordinary"
        ? `${SCAN_PERMISSION_PROFILE}_execution`
        : "codex_security_deep_scan_worker";
    processConfig["default_permissions"] = profileId;
    configOverrides = [
      ...configOverrides,
      `permissions.${profileId}=${inlineToml(permissions[SCAN_PERMISSION_PROFILE]!)}`,
    ];
  }
  const configuredResponsesMetadata = isRecord(
    sdkCodexConfig["responses_api_metadata"],
  )
    ? sdkCodexConfig["responses_api_metadata"]
    : {};
  const requestMetadata = {
    ...configuredResponsesMetadata,
    ...codexSecurityRequestMetadata(
      client.surface,
      client.command ?? "scan",
      runtime.plugin.version,
    ),
  };
  delete processConfig["responses_api_metadata"];
  configOverrides = [
    ...configOverrides,
    `responses_api_metadata=${inlineToml(requestMetadata)}`,
  ];
  let codexPathOverride =
    !checkPermissions &&
    environmentValue(session.source.environment, "CODEX_CLI_PATH") === undefined
      ? undefined
      : session.source.command.command;
  let sdkEnvironment = definedEnvironment(
    preserveProviderEnvironment
      ? environment
      : withoutOpenAiApiKeys(environment),
  );
  if (checkPermissions || process.platform === "win32") {
    codexPathOverride ??= environment["CODEX_CLI_PATH"]!;
    sdkEnvironment = bundledCodexSdkEnvironment(
      codexPathOverride,
      sdkEnvironment,
    );
  }
  const createCodex =
    client.createCodex ??
    ((options: CodexOptions) => {
      if (requiresConfigFile && runtime.preserveCodexHomeConfig)
        return createExecutionProfileCodex(
          options,
          runtime.codexHome,
          sdkCodexConfig,
          checkPermissions,
        );
      if (checkPermissions) return createPermissionCheckedCodex(options);
      const { config, configOverrides, ...settings } = options;
      return new Codex({
        ...settings,
        configOverrides: [
          ...codexConfigOverrides((config ?? {}) as JsonObject),
          ...(configOverrides ?? []),
        ],
      });
    });
  const codex = createCodex({
    ...(codexPathOverride === undefined
      ? {}
      : { codexPathOverride: executablePathForSpawn(codexPathOverride) }),
    ...(externalProvider !== null || apiKey === null ? {} : { apiKey }),
    ...(configOverrides.length > 0
      ? {
          configOverrides: [...configOverrides],
        }
      : {}),
    env: sdkEnvironment,
    config: {
      ...(processConfig as NonNullable<CodexOptions["config"]>),
    },
  });
  const deepWorker = session.policy !== "ordinary";
  if (!requiresConfigFile && !deepWorker) return { codex, environment };
  const wrap = (thread: CodexThreadLike): CodexThreadLike => ({
    get id() {
      return thread.id;
    },
    async runStreamed(input, options) {
      return {
        events: (async function* () {
          let release =
            requiresConfigFile && !runtime.preserveCodexHomeConfig
              ? await lockExecutionConfiguration(
                  runtime.codexHome,
                  sdkCodexConfig,
                  options.signal,
                )
              : undefined;
          const controller = deepWorker ? new AbortController() : undefined;
          const forwardAbort = () => controller?.abort(options.signal?.reason);
          const detach = () =>
            options.signal?.removeEventListener("abort", forwardAbort);
          if (controller) {
            if (options.signal?.aborted) forwardAbort();
            else
              options.signal?.addEventListener("abort", forwardAbort, {
                once: true,
              });
          }
          try {
            const { events } = await thread.runStreamed(
              input,
              controller ? { ...options, signal: controller.signal } : options,
            );
            for await (const event of events) {
              await release?.();
              release = undefined;
              // Deep workers finish at turn.completed; ordinary scans retain late exit errors.
              const completed = deepWorker && event.type === "turn.completed";
              if (completed) detach();
              yield event;
              if (completed) return;
            }
          } finally {
            detach();
            await release?.();
          }
        })(),
      };
    },
  });
  return {
    environment,
    codex: {
      startThread: (options) => wrap(codex.startThread(options)),
      ...(codex.resumeThread === undefined
        ? {}
        : {
            resumeThread: (id: string, options: ThreadOptions) =>
              wrap(codex.resumeThread!(id, options)),
          }),
    },
  };
}

export interface AmbientExecution {
  readonly command: CodexCommand;
  readonly configuration: JsonObject;
  readonly environment: ProcessEnvironment;
  readonly preserveProviderEnvironment: boolean;
  readonly auth?: ScanAuthMode;
  readonly pluginRoot: string;
}

/** Native execution keeps the invoking account and applies the same provider selection as SDK workers. */
export async function prepareAmbientExecution(
  input: {
    command: CodexCommand;
    configuration: JsonObject;
    environment: ProcessEnvironment;
    pluginRoot: string;
    auth?: ScanAuthMode;
  },
  signal?: AbortSignal,
): Promise<AmbientExecution> {
  const config = structuredClone(input.configuration);
  const environment = { ...input.environment };
  let auth = input.auth;
  config["approval_policy"] = "never";
  let modelProvider = scanModelProvider(config);
  const providers = config["model_providers"] as JsonObject | undefined;
  if (modelProvider === undefined && providers?.["openai"] !== undefined) {
    config["model_provider"] = "openai";
    modelProvider = "openai";
  }
  const provider =
    typeof modelProvider === "string" &&
    !["openai", "ollama", "lmstudio"].includes(modelProvider)
      ? (providers?.[modelProvider] as JsonObject | undefined)
      : undefined;
  const configuredProvider =
    hasCommandAuth(config) ||
    provider?.["env_key"] !== undefined ||
    typeof provider?.["experimental_bearer_token"] === "string" ||
    (provider?.["requires_openai_auth"] !== true &&
      ((modelProvider !== undefined && modelProvider !== "openai") ||
        provider !== undefined));
  if (!configuredProvider && (auth ?? "auto") === "auto") {
    if (config["forced_login_method"] === "chatgpt") {
      auth = "chatgpt";
    } else if (config["forced_login_method"] === "api") {
      if (
        environment["CODEX_API_KEY"]?.trim() ||
        environment["OPENAI_API_KEY"]?.trim()
      )
        auth = "api-key";
    } else if (
      !environment["CODEX_API_KEY"]?.trim() &&
      environment["OPENAI_API_KEY"]?.trim()
    ) {
      const status = await accountStatus(
        { command: input.command.command },
        selectedScanEnvironment(environment, "chatgpt"),
        signal,
        config,
      );
      if (status.authenticated) auth = "chatgpt";
      else if (!/not logged in|unauthenticated/i.test(status.details))
        throw new CodexSecurityError(
          status.details || "Could not determine Codex account status.",
        );
    }
  }
  const selectedEnvironment = {
    ...(configuredProvider
      ? environment
      : selectedScanEnvironment(environment, auth, modelProvider)),
  };
  if (!configuredProvider && selectedEnvironment["CODEX_API_KEY"]?.trim())
    delete selectedEnvironment["OPENAI_API_KEY"];

  return {
    command: { ...input.command },
    configuration: config,
    environment: selectedEnvironment,
    preserveProviderEnvironment: configuredProvider,
    auth,
    pluginRoot: input.pluginRoot,
  };
}

export async function prepareAmbientRuntime(
  execution: AmbientExecution,
  signal?: AbortSignal,
): Promise<PreparedRuntime> {
  const requestedHome =
    execution.environment["CODEX_HOME"] ||
    configuredCodexHome(execution.environment);
  await mkdir(requestedHome, { recursive: true, mode: 0o700 });
  const codexHome = await realpath(requestedHome);
  const bootstrapWorkspace = await createIsolatedHome();
  try {
    await requirePrivateCredentialHome(
      await lstat(bootstrapWorkspace),
      bootstrapWorkspace,
    );
    const marketplaceRoot = await createMarketplace(
      bootstrapWorkspace,
      execution.pluginRoot,
      signal,
    );
    const pluginRoot = join(marketplaceRoot, "plugins", PLUGIN_NAME);
    return {
      codexHome,
      preserveCodexHomeConfig: true,
      bootstrapWorkspace,
      configPath: join(bootstrapWorkspace, "config-preflight.toml"),
      environment: {
        ...definedEnvironment(execution.environment),
        CODEX_HOME: codexHome,
      },
      credentialsAvailable: false,
      plugin: {
        pluginRoot,
        installedRoot: pluginRoot,
        marketplaceRoot,
        marketplaceName: MARKETPLACE_NAME,
        ...(await pluginMetadata(pluginRoot)),
      },
    };
  } catch (error) {
    await cleanupSdkDirectory(bootstrapWorkspace);
    throw error;
  }
}

export async function nativeScanConfiguration(
  environment: NodeJS.ProcessEnv,
  input: {
    recipe?: { config?: JsonObject };
    model?: string;
    reasoningEffort?: string;
  },
  subagents: number,
): Promise<JsonObject> {
  const ambient = await readCodexHomeConfig(environment);
  preserveConfigFileOrigin(ambient, configuredCodexHome(environment));
  const selectedPath = environment["CODEX_SECURITY_CONFIG_PATH"];
  const selected = selectedPath
    ? parseToml(await readFile(selectedPath, "utf8"))
    : {};
  if (selectedPath)
    preserveConfigFileOrigin(
      selected as JsonObject,
      dirname(resolveConfigPath(".", selectedPath)),
    );
  const config = scanCompositionOverrides(
    deepMerge(
      resolveCodexProfile(deepMerge(ambient, selected as JsonObject)),
      (input.recipe?.["config"] as JsonObject | undefined) ?? {},
    ),
    subagents,
  );
  if (input.recipe?.["config"] === undefined) {
    if (input.model) config["model"] = input.model;
    if (input.reasoningEffort)
      config["model_reasoning_effort"] = input.reasoningEffort;
  }
  return config;
}

function preserveConfigFileOrigin(config: JsonObject, directory: string): void {
  for (const layer of [
    config,
    ...(isRecord(config["profiles"]) ? Object.values(config["profiles"]) : []),
  ]) {
    if (!isRecord(layer)) continue;
    for (const key of ["model_catalog_json", "model_instructions_file"]) {
      if (typeof layer[key] === "string")
        layer[key] = resolveConfigPath(directory, layer[key]);
    }
  }
}

function deepWorkerConfig(sessionConfig: JsonObject): JsonObject {
  const config = structuredClone(sessionConfig);
  config["mcp_servers"] = {
    ...(isRecord(config["mcp_servers"]) ? config["mcp_servers"] : {}),
    // The SDK owns scan artifacts and lifecycle; workers use canonical files.
    // A disabled server still needs a transport during plugin resolution.
    "codex-security": { command: "node", enabled: false },
  };
  return config;
}

/** A Standard pass preserves the caller's write and network policy. */
export function prepareDiscoveryExecution(
  session: PreparedExecution,
): PreparedExecution {
  return {
    ...session,
    policy: "discovery",
    sessionConfig: deepWorkerConfig(session.sessionConfig),
  };
}

/** The merge uses the same inherited policy while applying its subagent budget. */
export function prepareMergeExecution(
  session: PreparedExecution,
  subagents: number,
): PreparedExecution {
  return {
    ...session,
    policy: "merge",
    sessionConfig: deepWorkerConfig(
      scanCompositionOverrides(session.sessionConfig, subagents),
    ),
  };
}

/** Read-only helpers retain denied paths while intentionally removing write access. */
export function prepareReadOnlyExecution(
  config: JsonObject,
  permissions?: ScanPermissions,
): {
  config: JsonObject;
  overrides: string[];
} {
  const prepared = structuredClone(config);
  if (permissions === undefined) {
    delete prepared["default_permissions"];
    return { config: prepared, overrides: [] };
  }
  delete prepared["permissions"];
  delete prepared["projects"];
  delete prepared["sandbox_mode"];
  prepared["default_permissions"] = "codex_security_comparison";
  return {
    config: prepared,
    overrides: [
      `permissions.codex_security_comparison=${inlineToml({
        extends: ":read-only",
        filesystem: readOnlyFilesystem(permissions.filesystem),
        network: { enabled: false },
      })}`,
    ],
  };
}

export function readOnlyFilesystem(filesystem: JsonObject): JsonObject {
  return Object.fromEntries(
    Object.entries(filesystem).map(([path, access]) => [
      path,
      access === "write"
        ? "read"
        : isRecord(access)
          ? readOnlyFilesystem(access as JsonObject)
          : access,
    ]),
  );
}
