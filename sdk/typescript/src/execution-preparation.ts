import { readFile, realpath } from "node:fs/promises";
import { parse as parseToml } from "smol-toml";
import { accountStatus, configuredCodexHome } from "./auth.js";
import { join } from "node:path";
import { bundledCodexSdkEnvironment } from "./codex-sdk-environment.js";
import {
  Codex,
  type CodexOptions,
  type ThreadOptions,
  type TurnOptions,
} from "@openai/codex-sdk";
import {
  EXTERNAL_CODEX_PROVIDERS,
  deepMerge,
  hasCommandAuth,
  inlineToml,
  isExternalModelProvider,
  resolveCodexProfile,
  scanModelProvider,
  structuredCodexConfig,
  scanCompositionOverrides,
  setScanSubagentBudget,
  writeCodexConfig,
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
  acquireCodexSecurityCredentialHomeLock,
  codexSecurityStateDirectory,
  environmentWithGit,
  executablePathForSpawn,
  pluginExecutionEnvironment,
  cleanupSdkDirectory,
  createIsolatedHome,
  createMarketplace,
  MARKETPLACE_NAME,
  PLUGIN_NAME,
  pluginMetadata,
  type CodexCommand,
  type PluginInstall,
  type ProcessEnvironment,
} from "./runtime.js";
import { codexSecurityRequestMetadata } from "./request-metadata.js";
import {
  createProfileCodex,
  providerPreflightCommand,
  type ProviderProfile,
} from "./provider-profile.js";
import { createPermissionCheckedCodex } from "./permission-profile.js";
import type { ScanAuthMode } from "./scan-settings.js";
import type { InspectedExecutable } from "./trusted-executable.js";

export const SCAN_PERMISSION_PROFILE = "codex_security_scan";
const SAFETY_IDENTIFIER_ENV = "CODEX_SAFETY_IDENTIFIER";

export type ExecutionPolicy = "ordinary" | "discovery" | "merge";
interface ExecutionClient {
  surface: "cli" | "sdk";
  command: string;
  createCodex?: (
    options: CodexOptions & { nativeProfile?: string },
  ) => CodexClientLike | Promise<CodexClientLike>;
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
    input.auth,
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
  providerProfile?: ProviderProfile;
  codexHome: string;
  persistentCredentialHome?: boolean;
  /** Native runs use the invoking account without rewriting its home config. */
  preserveCodexHomeConfig?: boolean;
  bootstrapWorkspace?: string;
  configPath?: string;
  plugin: PluginInstall;
  environment: Record<string, string>;
  credentialsAvailable: boolean;
  effectiveConfig?: JsonObject;
}

export type ScanPermissions = { filesystem: JsonObject; network: JsonObject };

export interface PreparedExecution {
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

export async function lockExecutionConfiguration(
  session: PreparedExecution,
  config: JsonObject,
  signal?: AbortSignal,
): Promise<(() => Promise<void>) | undefined> {
  if (session.runtimeConfig === undefined) return undefined;
  const release = await acquireCodexSecurityCredentialHomeLock(
    session.runtime.codexHome,
    signal,
  );
  try {
    await writeCodexConfig(
      join(session.runtime.codexHome, "config.toml"),
      deepMerge({ ...session.runtimeConfig }, config),
    );
    return release;
  } catch (error) {
    await release();
    throw error;
  }
}

export async function createExecutionCodex(
  client: ExecutionClient,
  session: PreparedExecution,
  runtimePaths: Record<string, string>,
  config?: JsonObject,
  configOverrides: string[] = [],
  git?: InspectedExecutable,
): Promise<{ codex: CodexClientLike; environment: ProcessEnvironment }> {
  const { runtime, python, sessionConfig } = session;
  const {
    environment: scanEnvironment,
    externalProvider,
    apiKey,
    preserveProviderEnvironment,
  } = session.source;
  const environment: ProcessEnvironment = {
    ...environmentWithGit(
      pluginExecutionEnvironment(python, withoutCodexHome(scanEnvironment)),
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
  const sdkCodexConfig = structuredCodexConfig(config ?? sessionConfig);
  // Projects and permissions already live in generated TOML files; the SDK
  // cannot safely encode their path and selector keys as dotted overrides.
  delete sdkCodexConfig["projects"];
  delete sdkCodexConfig["permissions"];
  const checkPermissions =
    (session.policy !== "ordinary" ||
      session.inheritedPermissions !== undefined) &&
    client.createCodex === undefined;
  if (session.inheritedPermissions !== undefined || checkPermissions) {
    const permissions = sessionConfig["permissions"] as JsonObject;
    configOverrides = [
      ...configOverrides,
      `permissions.${SCAN_PERMISSION_PROFILE}=${inlineToml(permissions[SCAN_PERMISSION_PROFILE]!)}`,
    ];
  }
  const configuredResponsesMetadata = isRecord(
    sdkCodexConfig["responses_api_metadata"],
  )
    ? sdkCodexConfig["responses_api_metadata"]
    : {};
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
  if (
    checkPermissions ||
    (process.platform === "win32" && codexPathOverride === undefined)
  ) {
    codexPathOverride ??= environment["CODEX_CLI_PATH"]!;
    sdkEnvironment = bundledCodexSdkEnvironment(
      codexPathOverride,
      sdkEnvironment,
    );
  }
  const metadata = {
    ...configuredResponsesMetadata,
    ...codexSecurityRequestMetadata(
      client.surface,
      client.command,
      runtime.plugin.version,
    ),
  };
  delete sdkCodexConfig["responses_api_metadata"];
  const codexOptions: CodexOptions = {
    ...(codexPathOverride === undefined
      ? {}
      : { codexPathOverride: executablePathForSpawn(codexPathOverride) }),
    ...(externalProvider !== null || apiKey === null ? {} : { apiKey }),
    configOverrides: [
      ...configOverrides,
      `responses_api_metadata=${inlineToml(metadata)}`,
    ],
    env: sdkEnvironment,
    config: sdkCodexConfig as NonNullable<CodexOptions["config"]>,
  };
  let codex: CodexClientLike;
  if (client.createCodex !== undefined) {
    codex = await client.createCodex({
      ...codexOptions,
      ...(runtime.providerProfile === undefined
        ? {}
        : { nativeProfile: runtime.providerProfile.name }),
    });
  } else {
    const profileCodex =
      runtime.providerProfile === undefined
        ? undefined
        : await createProfileCodex(
            codexOptions,
            runtime.providerProfile.name,
            checkPermissions ? SCAN_PERMISSION_PROFILE : undefined,
          );
    if (checkPermissions) {
      const preflightCommand = await providerPreflightCommand(
        { command: session.source.command.command },
        config ?? sessionConfig,
      );
      const providerOverrides = (preflightCommand.args ?? []).filter(
        (_, index) => index % 2 === 1,
      );
      codex = createPermissionCheckedCodex(codexOptions, {
        codex: profileCodex,
        preflightConfigOverrides: providerOverrides,
      });
    } else {
      codex = profileCodex ?? new Codex(codexOptions);
    }
  }
  const deepWorker = session.policy !== "ordinary";
  if (session.runtimeConfig === undefined && !deepWorker)
    return { codex, environment };
  const lockConfiguration = (signal?: AbortSignal) =>
    lockExecutionConfiguration(session, config ?? sessionConfig, signal);
  const wrapThread = (thread: CodexThreadLike): CodexThreadLike => ({
    get id() {
      return thread.id;
    },
    async runStreamed(input, options) {
      return {
        events: (async function* () {
          let release: (() => Promise<void>) | undefined =
            await lockConfiguration(options.signal);
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
              // Native startup has loaded its config before emitting SDK events.
              await release?.();
              release = undefined;
              // The Deep coordinator treats completion as the worker boundary.
              // Ordinary scans drain the process to retain late exit errors.
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
    codex: {
      startThread: (options) => wrapThread(codex.startThread(options)),
      ...(codex.resumeThread === undefined
        ? {}
        : {
            resumeThread: (id: string, options: ThreadOptions) =>
              wrapThread(codex.resumeThread!(id, options)),
          }),
    },
    environment,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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
  const provider = providers?.[
    typeof modelProvider === "string" ? modelProvider : "openai"
  ] as JsonObject | undefined;
  const configuredProvider =
    hasCommandAuth(config) ||
    provider?.["env_key"] !== undefined ||
    (provider?.["requires_openai_auth"] !== true &&
      ((modelProvider !== undefined && modelProvider !== "openai") ||
        provider !== undefined));
  if (!configuredProvider && (auth ?? "auto") === "auto") {
    if (config["forced_login_method"] === "chatgpt") {
      auth = "chatgpt";
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
  const selectedEnvironment = configuredProvider
    ? environment
    : selectedScanEnvironment(environment, auth, modelProvider);
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
  preparedPlugin?: PluginInstall,
): Promise<PreparedRuntime> {
  const codexHome = await realpath(
    execution.environment["CODEX_HOME"] ||
      configuredCodexHome(execution.environment),
  );
  const bootstrapWorkspace = await createIsolatedHome();
  try {
    const marketplaceRoot =
      preparedPlugin?.marketplaceRoot ??
      (await createMarketplace(
        bootstrapWorkspace,
        execution.pluginRoot,
        signal,
      ));
    const pluginRoot = join(marketplaceRoot, "plugins", PLUGIN_NAME);
    return {
      codexHome,
      persistentCredentialHome: true,
      preserveCodexHomeConfig: true,
      bootstrapWorkspace,
      configPath: join(bootstrapWorkspace, "config-preflight.toml"),
      environment: {
        ...definedEnvironment(execution.environment),
        CODEX_HOME: codexHome,
      },
      credentialsAvailable: false,
      plugin: preparedPlugin ?? {
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
  input: { recipe?: JsonObject; model?: string; reasoningEffort?: string },
  subagents: number,
): Promise<JsonObject> {
  if (input.recipe?.["config"] !== undefined)
    return scanCompositionOverrides(
      input.recipe["config"] as JsonObject,
      subagents,
    );
  const ambientPath = join(
    environment["CODEX_HOME"] || configuredCodexHome(environment),
    "config.toml",
  );
  const ambient = await readFile(ambientPath, "utf8").catch(
    (error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return "";
      throw error;
    },
  );
  const selected = environment["CODEX_SECURITY_CONFIG_PATH"]
    ? parseToml(
        await readFile(environment["CODEX_SECURITY_CONFIG_PATH"], "utf8"),
      )
    : {};
  const config = scanCompositionOverrides(
    {
      ...parseToml(ambient),
      ...selected,
    } as JsonObject,
    subagents,
  );
  if (input.model) config["model"] = input.model;
  if (input.reasoningEffort)
    config["model_reasoning_effort"] = input.reasoningEffort;
  return config;
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

/** Standard passes retain inherited permissions while isolating workbench tools. */
export function prepareDiscoveryExecution(
  session: PreparedExecution,
): PreparedExecution {
  return {
    ...session,
    policy: "discovery",
    sessionConfig: deepWorkerConfig(session.sessionConfig),
  };
}

/** The merge retains inherited permissions and applies its own subagent budget. */
export function prepareMergeExecution(
  session: PreparedExecution,
  subagents: number,
): PreparedExecution {
  const config = deepWorkerConfig(resolveCodexProfile(session.sessionConfig));
  setScanSubagentBudget(config, subagents);
  return { ...session, policy: "merge", sessionConfig: config };
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
  if (permissions === undefined) return { config: prepared, overrides: [] };
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

function readOnlyFilesystem(filesystem: JsonObject): JsonObject {
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
