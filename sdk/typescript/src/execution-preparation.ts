import type { ThreadOptions, TurnOptions } from "@openai/codex-sdk";
import {
  EXTERNAL_CODEX_PROVIDERS,
  hasCommandAuth,
  isExternalModelProvider,
  scanModelProvider,
  type JsonObject,
} from "./config.js";
import { AuthenticationRequiredError } from "./errors.js";
import {
  scanAuthentication,
  environmentApiKey,
  selectedScanEnvironment,
  withoutOpenAiApiKeys,
  type ScanAuthentication,
} from "./execution-auth.js";
import type {
  CodexCommand,
  PluginInstall,
  ProcessEnvironment,
} from "./runtime.js";
import type { ScanAuthMode } from "./scan-settings.js";

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
  bootstrapWorkspace?: string;
  configPath?: string;
  deepScanConfigPath?: string;
  plugin: PluginInstall;
  environment: Record<string, string>;
  credentialsAvailable: boolean;
  effectiveConfig?: JsonObject;
}

export interface PreparedSession {
  readonly source: ExecutionSource;
  safetyIdentifier?: string;
  runtime: PreparedRuntime;
  runtimeHome: string;
  effectiveConfig: JsonObject;
  preflightConfig: JsonObject;
  sessionConfig: JsonObject;
  modelProvider: unknown;
  externalProvider:
    | (typeof EXTERNAL_CODEX_PROVIDERS)[keyof typeof EXTERNAL_CODEX_PROVIDERS]
    | null;
  apiKey: string | null;
  scanEnvironment: ProcessEnvironment;
  authentication: ScanAuthentication;
  approvalPolicy: "never" | "on-request";
  python: string;
  releaseCredentialHome: (() => Promise<void>) | null;
}
