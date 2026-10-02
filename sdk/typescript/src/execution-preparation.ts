import { join } from "node:path";
import { bundledCodexSdkEnvironment } from "./codex-sdk-environment.js";
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
  hasCommandAuth,
  inlineToml,
  isExternalModelProvider,
  modelProviderConfigOverride,
  resolveCodexProfile,
  scanModelProvider,
  setScanSubagentBudget,
  writeCodexConfig,
  type JsonObject,
} from "./config.js";
import { AuthenticationRequiredError } from "./errors.js";
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
  type CodexCommand,
  type PluginInstall,
  type ProcessEnvironment,
} from "./runtime.js";
import { createPermissionCheckedCodex } from "./permission-profile.js";
import type { ScanAuthMode } from "./scan-settings.js";
import type { InspectedExecutable } from "./trusted-executable.js";

export const SCAN_PERMISSION_PROFILE = "codex_security_scan";
const SAFETY_IDENTIFIER_ENV = "CODEX_SAFETY_IDENTIFIER";

export type ExecutionPolicy = "ordinary" | "discovery" | "merge";
interface ExecutionClient {
  surface: "cli" | "sdk";
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
  codexHome: string;
  persistentCredentialHome?: boolean;
  /** Native runs use the invoking account without rewriting its home config. */
  preserveCodexHomeConfig?: boolean;
  bootstrapWorkspace?: string;
  configPath?: string;
  /** Legacy coordinator configuration, retained until joint activation. */
  deepScanConfigPath?: string;
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
  const commandAuth = hasCommandAuth(sessionConfig);
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
  const sdkCodexConfig = { ...(config ?? sessionConfig) };
  // Projects and permissions already live in generated TOML files; the SDK
  // cannot safely encode their path and selector keys as dotted overrides.
  delete sdkCodexConfig["projects"];
  delete sdkCodexConfig["permissions"];
  if (commandAuth) delete sdkCodexConfig["model_providers"];
  const checkPermissions =
    (session.policy !== "ordinary" ||
      session.inheritedPermissions !== undefined) &&
    client.createCodex === undefined;
  if (session.inheritedPermissions !== undefined || checkPermissions) {
    const permissions = sessionConfig["permissions"] as JsonObject;
    // A stable argv-only profile supports managed allowlists without merging
    // the runtime home's persisted scan defaults into inherited permissions.
    const profileId = `${SCAN_PERMISSION_PROFILE}_execution`;
    sdkCodexConfig["default_permissions"] = profileId;
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
  const createCodex =
    client.createCodex ??
    (checkPermissions
      ? createPermissionCheckedCodex
      : (options: CodexOptions) => new Codex(options));
  const codex = createCodex({
    ...(codexPathOverride === undefined
      ? {}
      : { codexPathOverride: executablePathForSpawn(codexPathOverride) }),
    ...(externalProvider !== null || apiKey === null ? {} : { apiKey }),
    ...(commandAuth || configOverrides.length > 0
      ? {
          configOverrides: [
            ...(commandAuth ? modelProviderConfigOverride(sessionConfig) : []),
            ...configOverrides,
          ],
        }
      : {}),
    env: sdkEnvironment,
    config: {
      ...(sdkCodexConfig as NonNullable<CodexOptions["config"]>),
      responses_api_metadata: {
        ...configuredResponsesMetadata,
        codex_security_surface: client.surface,
      },
    },
  });
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
