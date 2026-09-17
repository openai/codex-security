import { readFile, realpath } from "node:fs/promises";
import { join } from "node:path";
import { parse as parseToml } from "smol-toml";
import {
  CodexSecurity,
  selectedScanEnvironment,
  type ScanOptions,
} from "../../../../sdk/typescript/src/api.js";
import {
  hasCommandAuth,
  scanCompositionOverrides,
  scanModelProvider,
  type JsonObject,
} from "../../../../sdk/typescript/src/config.js";
import {
  ScanSettingsSchema,
  type DeepScanOptions,
} from "../../../../sdk/typescript/src/scan-settings.js";
import {
  accountStatus,
  configuredCodexHome,
} from "../../../../sdk/typescript/src/auth.js";
import { CodexSecurityError } from "../../../../sdk/typescript/src/errors.js";
import { resolveDeepScanConfig } from "../../../../sdk/typescript/src/deep-config.js";
import { ScanTransportClosedError } from "../../../../sdk/typescript/src/scan-execution.js";
import type { ScanResult } from "../../../../sdk/typescript/src/result.js";
import {
  cleanupSdkDirectory,
  createIsolatedHome,
  createMarketplace,
  MARKETPLACE_NAME,
  PLUGIN_NAME,
  pluginMetadata,
} from "../../../../sdk/typescript/src/runtime.js";
import {
  resolveCodexPath,
  snapshotNativeEnvironment,
} from "./native-executable.js";
import type { NativeParentSandbox } from "./native-permissions.js";
import { createPermissionCheckedCodex } from "../../../../sdk/typescript/src/permission-profile.js";
import type { ScanResults } from "./types.js";

export interface NativeScanInput {
  scan: ScanResults;
  recipe?: JsonObject;
  savedDeepScanSettings?: DeepScanOptions;
  threadId: string;
  pluginRoot: string;
  pythonPath: string;
  model?: string;
  reasoningEffort?: string;
  parentSandbox: NativeParentSandbox;
  stateDirectory?: string;
}

type NativeClient = Pick<CodexSecurity, "run" | "close">;
type PreparedNativeScan = { client: NativeClient; options: ScanOptions };

/** Native tools join the same ordinary scan operation until it finishes. */
export class NativeScanHost {
  private readonly active = new Map<
    string,
    {
      controller: AbortController;
      promise: Promise<ScanResult>;
    }
  >();

  constructor(private readonly prepare = prepareNativeScan) {}

  run(input: NativeScanInput, waiterSignal?: AbortSignal): Promise<ScanResult> {
    let active = this.active.get(input.scan.scanId);
    if (!active) {
      const controller = new AbortController();
      const promise = Promise.resolve()
        .then(async () => {
          const { client, options } = await this.prepare(
            input,
            controller.signal,
          );
          try {
            return await client.run(input.scan.targetPath, {
              ...options,
              signal: controller.signal,
            });
          } finally {
            try {
              await client.close();
            } catch (error) {
              try {
                console.warn("Could not clean up the native scan:", error);
              } catch {}
            }
          }
        })
        .finally(() => this.active.delete(input.scan.scanId));
      active = { controller, promise };
      this.active.set(input.scan.scanId, active);
      void promise.catch(() => undefined);
    }
    return waitForScan(active.promise, waiterSignal);
  }

  async cancel(scanId: string, reason = "user_canceled_scan"): Promise<void> {
    const active = this.active.get(scanId);
    if (!active) return;
    active.controller.abort(new Error(reason));
    await active.promise.catch(() => undefined);
  }

  async close(): Promise<void> {
    const active = [...this.active.values()];
    for (const run of active)
      run.controller.abort(
        new ScanTransportClosedError("mcp_transport_closed"),
      );
    await Promise.allSettled(active.map((run) => run.promise));
  }
}

export async function prepareNativeScan(
  input: NativeScanInput,
  signal?: AbortSignal,
): Promise<PreparedNativeScan> {
  const environment = await snapshotNativeEnvironment();
  environment.CODEX_CLI_PATH = resolveCodexPath(environment);
  if (input.stateDirectory)
    environment.CODEX_SECURITY_STATE_DIR = input.stateDirectory;
  const recipe = input.recipe ?? {};
  const savedPermissions =
    recipe.inheritedPermissions as ScanOptions["inheritedPermissions"];
  const savedGlobDepth = savedPermissions?.filesystem.glob_scan_max_depth;
  const inheritedPermissions = {
    filesystem: Object.fromEntries([
      ...Object.entries(savedPermissions?.filesystem ?? {}),
      ...input.parentSandbox.filesystemDenies.map((path) => [path, "deny"]),
      ...(input.parentSandbox.globScanMaxDepth === undefined
        ? []
        : [
            [
              "glob_scan_max_depth",
              typeof savedGlobDepth === "number"
                ? Math.min(savedGlobDepth, input.parentSandbox.globScanMaxDepth)
                : input.parentSandbox.globScanMaxDepth,
            ],
          ]),
    ]) as JsonObject,
    network: { enabled: false },
  };
  const options = ScanSettingsSchema.parse({
    ...input.savedDeepScanSettings,
    ...(recipe.deepScan as JsonObject | undefined),
    auth: recipe.auth,
    knowledgeBasePaths:
      recipe.knowledgeBasePaths ??
      (environment.CODEX_SECURITY_KNOWLEDGE_BASE
        ? [environment.CODEX_SECURITY_KNOWLEDGE_BASE]
        : undefined),
    maxCostUsd: recipe.maxCostUsd,
    postScanPrompt: recipe.postScanPrompt,
    failureSeverity: recipe.failOnSeverity,
    mode: "deep",
    scanPrompt: input.scan.userContext ?? undefined,
    outputDir: input.scan.scanDir,
  });
  const deep = await resolveDeepScanConfig(
    options,
    environment.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH ??
      join(
        environment.CODEX_HOME || configuredCodexHome(environment),
        "codex-security",
        "config.toml",
      ),
  );
  const config = await nativeScanConfiguration(
    environment,
    input,
    deep.settings.subagents,
  );
  config.approval_policy = "never";
  let modelProvider = scanModelProvider(config);
  const providers = config.model_providers as JsonObject | undefined;
  if (modelProvider === undefined && providers?.openai !== undefined) {
    config.model_provider = "openai";
    modelProvider = "openai";
  }
  const provider = providers?.[
    typeof modelProvider === "string" ? modelProvider : "openai"
  ] as JsonObject | undefined;
  const configuredProvider =
    hasCommandAuth(config) ||
    provider?.env_key !== undefined ||
    (provider?.requires_openai_auth !== true &&
      ((modelProvider !== undefined && modelProvider !== "openai") ||
        provider !== undefined));
  if (!configuredProvider && (options.auth ?? "auto") === "auto") {
    if (config.forced_login_method === "chatgpt") {
      options.auth = "chatgpt";
    } else if (
      !environment.CODEX_API_KEY?.trim() &&
      environment.OPENAI_API_KEY?.trim()
    ) {
      const status = await accountStatus(
        { command: environment.CODEX_CLI_PATH },
        selectedScanEnvironment(environment, "chatgpt"),
        signal,
        config,
      );
      if (status.authenticated) options.auth = "chatgpt";
      else if (!/not logged in|unauthenticated/i.test(status.details))
        throw new CodexSecurityError(
          status.details || "Could not determine Codex account status.",
        );
    }
  }
  const selectedEnvironment = configuredProvider
    ? environment
    : selectedScanEnvironment(environment, options.auth, modelProvider);
  if (!configuredProvider && selectedEnvironment.CODEX_API_KEY?.trim())
    delete selectedEnvironment.OPENAI_API_KEY;
  const client = new CodexSecurity(
    {
      pluginPath: input.pluginRoot,
      pythonPath: input.pythonPath,
      codexOverrides: config,
    },
    {
      createCodex: createPermissionCheckedCodex,
      environment: selectedEnvironment,
      inheritedPermissions,
      prepareRuntime: async (_config, runtimeSignal) => {
        const codexHome = await realpath(
          environment.CODEX_HOME || configuredCodexHome(environment),
        );
        const bootstrapWorkspace = await createIsolatedHome();
        try {
          const marketplaceRoot = await createMarketplace(
            bootstrapWorkspace,
            input.pluginRoot,
            runtimeSignal,
          );
          const pluginRoot = join(marketplaceRoot, "plugins", PLUGIN_NAME);
          return {
            codexHome,
            persistentCredentialHome: true,
            preserveCodexHomeConfig: true,
            bootstrapWorkspace,
            configPath: join(bootstrapWorkspace, "config-preflight.toml"),
            environment: { ...selectedEnvironment, CODEX_HOME: codexHome },
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
      },
    },
    { surface: "sdk" },
  );
  return {
    client,
    options: {
      ...options,
      ...deep.settings,
      inheritedPermissions,
      ...(configuredProvider ? { preserveProviderEnvironment: true } : {}),
      target:
        (recipe.target as JsonObject | undefined)?.kind === "paths"
          ? ((recipe.target as JsonObject).paths as string[])
          : input.scan.scope && input.scan.scope !== "."
            ? [input.scan.scope]
            : "repository",
      safetyIdentifier:
        typeof recipe.safetyIdentifier === "string"
          ? recipe.safetyIdentifier
          : environment.CODEX_SAFETY_IDENTIFIER,
      registeredScan: {
        scanId: input.scan.scanId,
        scanDir: input.scan.scanDir,
        threadId: input.threadId,
        handoffClaimToken: input.scan.handoffClaimToken,
      },
    },
  };
}

export async function nativeScanConfiguration(
  environment: NodeJS.ProcessEnv,
  input: Pick<NativeScanInput, "recipe" | "model" | "reasoningEffort">,
  subagents: number,
): Promise<JsonObject> {
  if (input.recipe?.config !== undefined)
    return scanCompositionOverrides(
      input.recipe.config as JsonObject,
      subagents,
    );
  const ambientPath = join(
    environment.CODEX_HOME || configuredCodexHome(environment),
    "config.toml",
  );
  const ambient = await readFile(ambientPath, "utf8").catch(
    (error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return "";
      throw error;
    },
  );
  const selected = environment.CODEX_SECURITY_CONFIG_PATH
    ? parseToml(await readFile(environment.CODEX_SECURITY_CONFIG_PATH, "utf8"))
    : {};
  const config = scanCompositionOverrides(
    {
      ...parseToml(ambient),
      ...selected,
    } as JsonObject,
    subagents,
  );
  if (input.model) config.model = input.model;
  if (input.reasoningEffort)
    config.model_reasoning_effort = input.reasoningEffort;
  return config;
}

function waitForScan(
  promise: Promise<ScanResult>,
  signal?: AbortSignal,
): Promise<ScanResult> {
  if (!signal) return promise;
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const abort = () =>
      reject(signal.reason ?? new Error("Deep Scan waiter detached."));
    signal.addEventListener("abort", abort, { once: true });
    promise
      .then(resolve, reject)
      .finally(() => signal.removeEventListener("abort", abort));
  });
}
