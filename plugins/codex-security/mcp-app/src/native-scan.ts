import {
  readKnowledgeBaseSnapshot,
  type KnowledgeBaseSnapshot,
} from "../../../../sdk/typescript/src/knowledge-base.js";
import { canonicalizeModelSafePath } from "../../../../sdk/typescript/src/runtime.js";
import {
  environmentValue,
  expandHomePath,
} from "../../../../sdk/typescript/src/codex-home.js";
import { hasSealedScanArtifacts } from "../../../../sdk/typescript/src/scan-publication.js";
import { join } from "node:path";
import {
  modelInstructionsFileDigest,
  restoreScanKnowledge,
} from "../../../../sdk/typescript/src/scan-inputs.js";
import {
  CodexSecurity,
  type ScanOptions,
} from "../../../../sdk/typescript/src/api.js";
import {
  inlineToml,
  mergedCodexConfig,
  scanModelConfiguration,
  type JsonObject,
  type ScanModelConfiguration,
} from "../../../../sdk/typescript/src/config.js";
import {
  readDeepScanParentCyberAccessProgram,
  type DeepScanParentTurn,
} from "./deep-scan/permission-profile-preflight.js";
import {
  ScanSettingsSchema,
  type DeepScanOptions,
} from "../../../../sdk/typescript/src/scan-settings.js";
import { configuredCodexHome } from "../../../../sdk/typescript/src/auth.js";
import {
  gitMarkerRoot,
  gitProtectionRoots,
} from "../../../../sdk/typescript/src/targets.js";
import { CodexSecurityError } from "../../../../sdk/typescript/src/errors.js";
import { resolveDeepScanConfig } from "../../../../sdk/typescript/src/deep-config.js";
import {
  ScanTransportClosedError,
  waitForScanExecution,
} from "../../../../sdk/typescript/src/scan-execution.js";
import type { ScanResult } from "../../../../sdk/typescript/src/result.js";
import {
  resolveCodexPath,
  resolveTrustedCodex,
  explicitCodexPath,
  snapshotNativeEnvironment,
} from "./native-executable.js";
import type { NativeParentSandbox } from "./native-permissions.js";
import {
  prepareAmbientExecution,
  nativeScanConfiguration,
  resolveExecutionPaths,
  readOnlyFilesystem,
} from "../../../../sdk/typescript/src/execution-preparation.js";
export { nativeScanConfiguration } from "../../../../sdk/typescript/src/execution-preparation.js";
import type { ScanResults } from "./types.js";
import { isRecord } from "./record.js";

export interface NativeScanSemanticInputs {
  knowledgeBasePaths?: string[];
  knowledgeBaseSnapshot?: KnowledgeBaseSnapshot;
  deepScanSettings: Required<DeepScanOptions>;
  config: JsonObject;
  modelSettings: ScanModelConfiguration;
  modelInstructionsFileSha256?: string | null;
}

export interface NativeScanInput {
  scan: ScanResults;
  recipe?: JsonObject;
  savedDeepScanSettings?: DeepScanOptions;
  semanticInputs?: NativeScanSemanticInputs;
  threadId: string;
  pluginRoot: string;
  pythonPath: string;
  model?: string;
  reasoningEffort?: string;
  parentSandbox: NativeParentSandbox | (() => NativeParentSandbox);
  parentTurn?: DeepScanParentTurn;
  stateDirectory?: string;
}

type NativeClient = Pick<CodexSecurity, "run" | "close">;
type PreparedNativeScan = { client: NativeClient; options: ScanOptions };

/** Native tools join the same ordinary scan operation until it finishes. */
export class NativeScanHost {
  private closed = false;
  private readonly active = new Map<
    string,
    {
      controller: AbortController;
      promise: Promise<ScanResult>;
    }
  >();

  constructor(private readonly prepare = prepareNativeScan) {}

  run(input: NativeScanInput, waiterSignal?: AbortSignal): Promise<ScanResult> {
    if (this.closed)
      return Promise.reject(
        new ScanTransportClosedError("mcp_transport_closed"),
      );
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
    this.closed = true;
    const active = [...this.active.values()];
    for (const run of active)
      run.controller.abort(
        new ScanTransportClosedError("mcp_transport_closed"),
      );
    await Promise.allSettled(active.map((run) => run.promise));
  }
}

function nativeDeepScanConfigPath(environment: NodeJS.ProcessEnv): string {
  return expandHomePath(
    environment.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH?.trim() ||
      join(
        environment.CODEX_HOME || configuredCodexHome(environment),
        "codex-security",
        "config.toml",
      ),
    environment,
  );
}

/** Read once for completed-result comparison and any new execution it requires. */
export async function readNativeScanSemanticInputs(
  signal?: AbortSignal,
  modelSettings: Pick<NativeScanInput, "model" | "reasoningEffort"> = {},
  completedScanDir?: string,
): Promise<NativeScanSemanticInputs> {
  const environment = await snapshotNativeEnvironment();
  const knowledgeBasePath = environmentValue(
    environment,
    "CODEX_SECURITY_KNOWLEDGE_BASE",
  );
  const knowledgeBasePaths = knowledgeBasePath
    ? [knowledgeBasePath]
    : undefined;
  const deepScanSettings = (
    await resolveDeepScanConfig(
      {},
      nativeDeepScanConfigPath(environment),
      signal,
    )
  ).settings;
  const config = await nativeScanConfiguration(
    environment,
    modelSettings,
    deepScanSettings.subagents,
  );
  const completedConfig =
    completedScanDir === undefined
      ? undefined
      : resolveExecutionPaths(config, completedScanDir, environment);
  return {
    config,
    modelInstructionsFileSha256:
      completedConfig === undefined
        ? undefined
        : await modelInstructionsFileDigest(
            typeof completedConfig["model_instructions_file"] === "string"
              ? completedConfig["model_instructions_file"]
              : undefined,
            signal,
          ),
    modelSettings: scanModelConfiguration(
      await mergedCodexConfig({ codexOverrides: config }),
    ),
    knowledgeBasePaths,
    knowledgeBaseSnapshot: knowledgeBasePaths
      ? await readKnowledgeBaseSnapshot(knowledgeBasePaths, signal)
      : undefined,
    deepScanSettings,
  };
}

export async function prepareNativeScan(
  input: NativeScanInput,
  signal?: AbortSignal,
): Promise<PreparedNativeScan> {
  const scanEnvironment = { ...process.env };
  const originalCwd = process.cwd();
  const recipe = input.recipe ?? {};
  const semanticInputs =
    input.recipe === undefined ? input.semanticInputs : undefined;
  const postScanPrompt = ScanSettingsSchema.shape.postScanPrompt.parse(
    recipe.postScanPrompt,
  );
  const publicationOnly =
    input.recipe !== undefined &&
    !postScanPrompt?.trim() &&
    (await hasSealedScanArtifacts(input.scan.scanDir, signal));
  const environment: NodeJS.ProcessEnv = await snapshotNativeEnvironment(
    publicationOnly ? canonicalizeModelSafePath : undefined,
    scanEnvironment,
    originalCwd,
  );
  const knowledgeBasePath = environmentValue(
    environment,
    "CODEX_SECURITY_KNOWLEDGE_BASE",
  );
  if (
    input.recipe !== undefined ||
    semanticInputs !== undefined ||
    knowledgeBasePath === undefined
  )
    delete environment.CODEX_SECURITY_KNOWLEDGE_BASE;
  const resolveCommand = async () => {
    if (publicationOnly)
      throw new CodexSecurityError(
        "The native scan was prepared for sealed-result publication only. Rejoin the scan to resume execution.",
      );
    const explicit = input.scan.targetProtectionRoots?.length
      ? undefined
      : explicitCodexPath(environment, process.platform, originalCwd);
    if (!input.scan.targetProtectionRoots?.length && explicit === undefined)
      throw new CodexSecurityError(
        "This saved scan does not record its original target paths. Rejoin Deep Scan using the original targetPath before discovering Codex on PATH.",
      );
    const codex = await resolveTrustedCodex(
      explicit === undefined
        ? environment
        : { ...environment, CODEX_CLI_PATH: explicit },
      [
        input.scan.targetPath,
        ...(input.scan.targetProtectionRoots ?? []),
        ...(await gitProtectionRoots(input.scan.targetPath, signal)),
        ...(
          await Promise.all(
            [
              executionPaths["model_instructions_file"],
              executionPaths["experimental_compact_prompt_file"],
            ].map((path) =>
              typeof path === "string" ? gitProtectionRoots(path, signal) : [],
            ),
          )
        ).flat(),
        ...(knowledgeBaseSnapshot?.protectedRoots ??
          (await Promise.all(
            (knowledgeBaseSnapshot?.sources ?? []).map(
              async (source) =>
                (await gitMarkerRoot(source, signal, "outermost")) ?? source,
            ),
          ))),
      ],
      process.platform,
      originalCwd,
    );
    if (codex === null) {
      throw new CodexSecurityError(
        `Could not resolve a Codex executable outside the scan target or knowledge base: ${resolveCodexPath(environment, process.platform, originalCwd)}`,
      );
    }
    Object.assign(environment, codex.environment, {
      CODEX_CLI_PATH: codex.executable,
    });
    return { command: codex.executable };
  };
  if (input.stateDirectory)
    environment.CODEX_SECURITY_STATE_DIR = input.stateDirectory;
  const savedPermissions =
    recipe.inheritedPermissions as ScanOptions["inheritedPermissions"];
  let inheritedPermissions = savedPermissions;
  if (!publicationOnly) {
    const parentSandbox =
      typeof input.parentSandbox === "function"
        ? input.parentSandbox()
        : input.parentSandbox;
    const savedGlobDepth = savedPermissions?.filesystem.glob_scan_max_depth;
    for (const path of parentSandbox.literalFilesystemDenies ?? []) {
      const saved = savedPermissions?.filesystem[path];
      if (/[?*\[]/u.test(path) && (saved === "deny" || saved === "none"))
        throw new CodexSecurityError(
          "Saved glob and current literal filesystem denials with the same key cannot be preserved.",
        );
    }
    for (const path of parentSandbox.filesystemDenies) {
      const saved = savedPermissions?.filesystem[path];
      if (
        /[?*\[]/u.test(path) &&
        isRecord(saved) &&
        (saved["."] === "deny" || saved["."] === "none")
      )
        throw new CodexSecurityError(
          "Saved literal and current glob filesystem denials with the same key cannot be preserved.",
        );
    }
    inheritedPermissions = {
      filesystem: Object.fromEntries([
        [":workspace_roots", parentSandbox.workspaceAccess],
        ...Object.entries(
          parentSandbox.workspaceAccess === "read"
            ? readOnlyFilesystem(savedPermissions?.filesystem ?? {})
            : (savedPermissions?.filesystem ?? {}),
        ),
        ...parentSandbox.filesystemDenies.map((path) => [path, "deny"]),
        ...(parentSandbox.literalFilesystemDenies ?? []).map((path) => [
          path,
          { ".": "deny" },
        ]),
        ...(parentSandbox.globScanMaxDepth === undefined
          ? []
          : [
              [
                "glob_scan_max_depth",
                typeof savedGlobDepth === "number"
                  ? Math.max(savedGlobDepth, parentSandbox.globScanMaxDepth)
                  : parentSandbox.globScanMaxDepth,
              ],
            ]),
      ]) as JsonObject,
      network: { enabled: false },
    };
    const hasUncappedDenials =
      (savedGlobDepth === undefined &&
        Object.entries(savedPermissions?.filesystem ?? {}).some(
          ([path, access]) =>
            (access === "deny" || access === "none") && /[*?\[\]]/.test(path),
        )) ||
      (parentSandbox.globScanMaxDepth === undefined &&
        parentSandbox.filesystemDenies.some((path) => /[*?\[\]]/.test(path)));
    if (hasUncappedDenials)
      delete inheritedPermissions.filesystem["glob_scan_max_depth"];
  }
  const options = ScanSettingsSchema.parse({
    ...input.savedDeepScanSettings,
    ...semanticInputs?.deepScanSettings,
    ...(recipe.deepScan as JsonObject | undefined),
    auth: recipe.auth,
    cyberAccessProgram: recipe.cyberAccessProgram,
    knowledgeBasePaths: publicationOnly
      ? undefined
      : (recipe.knowledgeBasePaths ??
        (semanticInputs
          ? semanticInputs.knowledgeBasePaths
          : input.recipe === undefined && knowledgeBasePath
            ? [knowledgeBasePath]
            : undefined)),
    maxCostUsd: recipe.maxCostUsd,
    postScanPrompt,
    failureSeverity: recipe.failOnSeverity,
    mode: "deep",
    scanPrompt: input.scan.userContext ?? undefined,
    outputDir: input.scan.scanDir,
  });
  const knowledgeBaseSnapshot = options.knowledgeBasePaths?.length
    ? input.recipe === undefined
      ? semanticInputs
        ? semanticInputs.knowledgeBaseSnapshot
        : await readKnowledgeBaseSnapshot(options.knowledgeBasePaths, signal)
      : await restoreScanKnowledge(
          input.scan.scanDir,
          input.scan.targetPath,
          recipe.scanInputs,
        )
    : undefined;
  const deep = await resolveDeepScanConfig(
    options,
    nativeDeepScanConfigPath(environment),
  );
  // The SDK validates the saved seal, owner and claim before publishing.
  // Read-only publication does not need the model's private configuration.
  const config = publicationOnly
    ? ((recipe.config as JsonObject | undefined) ?? {})
    : semanticInputs
      ? structuredClone(semanticInputs.config)
      : await nativeScanConfiguration(
          environment,
          input,
          deep.settings.subagents,
        );
  const executionPaths = publicationOnly
    ? {}
    : resolveExecutionPaths(config, input.scan.scanDir, environment);
  const command = publicationOnly ? undefined : await resolveCommand();
  const security = config["codex_security"];
  if (
    input.recipe === undefined &&
    isRecord(security) &&
    typeof security["cyber_access_program"] === "string"
  ) {
    options.cyberAccessProgram = security[
      "cyber_access_program"
    ] as ScanOptions["cyberAccessProgram"];
  }
  const ambientInput = {
    environment,
    ...(command === undefined ? {} : { command }),
    configuration: config,
    auth: options.auth,
    pluginRoot: input.pluginRoot,
  };
  const ambientExecution = publicationOnly
    ? {
        ...ambientInput,
        preserveProviderEnvironment:
          recipe.preserveProviderEnvironment === true,
      }
    : await prepareAmbientExecution(
        { ...ambientInput, command: command! },
        signal,
      );
  if (!publicationOnly && input.parentTurn) {
    const parentProgram = await readDeepScanParentCyberAccessProgram({
      codexPath: command!.command,
      cwd: input.scan.targetPath,
      configOverrides: Object.entries(ambientExecution.configuration).map(
        ([name, value]) => `${name}=${inlineToml(value)}`,
      ),
      env: Object.fromEntries(
        Object.entries(ambientExecution.environment).filter(
          (entry): entry is [string, string] => entry[1] !== undefined,
        ),
      ),
      signal: signal ?? new AbortController().signal,
      parentTurn: input.parentTurn,
    });
    if (parentProgram !== undefined) {
      options.cyberAccessProgram = parentProgram;
      const configuredFeatures = ambientExecution.configuration["features"];
      const features = isRecord(configuredFeatures) ? configuredFeatures : {};
      if (features["api_key_cyber_access_programs"] === undefined)
        ambientExecution.configuration["features"] = {
          ...features,
          api_key_cyber_access_programs: true,
        };
    }
  }
  options.auth = ambientExecution.auth;
  const selectedEnvironment = ambientExecution.environment;
  const configuredProvider = ambientExecution.preserveProviderEnvironment;
  const client = new CodexSecurity(
    {
      pluginPath: input.pluginRoot,
      pythonPath: input.pythonPath,
      codexOverrides: ambientExecution.configuration,
    },
    {
      environment: selectedEnvironment,
      stateDirectory: input.stateDirectory,
      inheritedPermissions,
      ambientExecution,
      resolveCodexCommand: resolveCommand,
      acquireScanExecution: (state, directory, plugin) =>
        waitForScanExecution(state, directory, plugin, signal),
    },
    { surface: "sdk" },
  );
  return {
    client,
    options: {
      ...options,
      ...deep.settings,
      ...(knowledgeBaseSnapshot === undefined ? {} : { knowledgeBaseSnapshot }),
      ...(input.recipe === undefined
        ? {}
        : {
            resumeScanId: input.scan.scanId,
          }),
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
          : input.recipe === undefined
            ? environment.CODEX_SAFETY_IDENTIFIER
            : undefined,
      registeredScan: {
        scanId: input.scan.scanId,
        scanDir: input.scan.scanDir,
        threadId: input.threadId,
        handoffClaimToken: input.scan.handoffClaimToken,
      },
    },
  };
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
