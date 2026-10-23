import { join } from "node:path";
import {
  codexSecurityStateDirectory,
  requireModelSafeOutputDir,
  runWorkbench,
} from "../../../../sdk/typescript/src/runtime.js";
import { hasSealedScanArtifacts } from "../../../../sdk/typescript/src/scan-publication.js";
import {
  promptFileDigest,
  restoreScanKnowledge,
} from "../../../../sdk/typescript/src/scan-inputs.js";
import { isRecord } from "./record.js";
import {
  CodexSecurity,
  type ScanOptions,
} from "../../../../sdk/typescript/src/api.js";
import {
  mergedCodexConfig,
  scanModelConfiguration,
  type JsonObject,
} from "../../../../sdk/typescript/src/config.js";
import {
  readKnowledgeBaseSnapshot,
  type KnowledgeBaseSnapshot,
} from "../../../../sdk/typescript/src/knowledge-base.js";
import {
  ScanSettingsSchema,
  type DeepScanOptions,
} from "../../../../sdk/typescript/src/scan-settings.js";
import type { SavedScanRecipe } from "../../../../sdk/typescript/src/scan-registration.js";
import { restoreProviderProfile } from "../../../../sdk/typescript/src/provider-profile.js";
import { configuredCodexHome } from "../../../../sdk/typescript/src/auth.js";
import {
  environmentValue,
  expandHome,
} from "../../../../sdk/typescript/src/codex-home.js";
import { gitMarkerRoot } from "../../../../sdk/typescript/src/targets.js";
import { CodexSecurityError } from "../../../../sdk/typescript/src/errors.js";
import { resolveDeepScanConfig } from "../../../../sdk/typescript/src/deep-config.js";
import {
  acquireScanExecution,
  ScanTransportClosedError,
  ScanFailedError,
} from "../../../../sdk/typescript/src/scan-execution.js";
import type { ScanResult } from "../../../../sdk/typescript/src/result.js";
import {
  resolveCodexPath,
  resolveTrustedCodex,
  snapshotNativeEnvironment,
} from "./native-executable.js";
import type { NativeParentSandbox } from "./native-permissions.js";
import {
  nativeScanConfiguration,
  readOnlyFilesystem,
  resolveExecutionPaths,
} from "../../../../sdk/typescript/src/execution-preparation.js";
export { nativeScanConfiguration } from "../../../../sdk/typescript/src/execution-preparation.js";
import type { ScanResults } from "./types.js";

export interface NativeScanSemanticInputs {
  knowledgeBasePaths?: string[];
  knowledgeBaseSnapshot?: KnowledgeBaseSnapshot;
  deepScanSettings: Required<DeepScanOptions>;
  config: JsonObject;
  modelSettings: ReturnType<typeof scanModelConfiguration>;
  instructionSettingsMatch: boolean;
}

export interface NativeScanInput {
  scan: ScanResults;
  recipe?: SavedScanRecipe;
  savedDeepScanSettings?: DeepScanOptions;
  semanticInputs?: NativeScanSemanticInputs;
  threadId: string;
  pluginRoot: string;
  pythonPath: string;
  model?: string;
  reasoningEffort?: string;
  parentSandbox: NativeParentSandbox | (() => NativeParentSandbox);
  stateDirectory?: string;
}

type NativeClient = Pick<CodexSecurity, "run" | "close">;
type PreparedNativeScan = {
  client: NativeClient;
  options: ScanOptions;
  releaseExecution?: () => void;
};

interface NativeScanOwnership {
  environment: Record<string, string>;
  stateDirectory: string;
  release(): void;
}

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

  constructor(private readonly prepare = prepareOwnedNativeScan) {}

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
          const { client, options, releaseExecution } = await this.prepare(
            input,
            controller.signal,
          );
          try {
            controller.signal.throwIfAborted();
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
            releaseExecution?.();
          }
        })
        .finally(() => this.active.delete(input.scan.scanId));
      active = { controller, promise };
      this.active.set(input.scan.scanId, active);
      void promise.catch(() => undefined);
    }
    return waitForScan(active.promise, waiterSignal);
  }

  async cancel(
    scanId: string,
    reason = "user_canceled_scan",
    status: "canceled" | "failed" = "canceled",
  ): Promise<void> {
    const active = this.active.get(scanId);
    if (!active) return;
    active.controller.abort(
      status === "failed" ? new ScanFailedError(reason) : new Error(reason),
    );
    await active.promise.catch(() => undefined);
  }

  async wait(scanId: string): Promise<void> {
    await this.active.get(scanId)?.promise.catch(() => undefined);
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
  return (
    environment.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH?.trim() ||
    join(
      environment.CODEX_HOME || configuredCodexHome(environment),
      "codex-security",
      "config.toml",
    )
  );
}

/** Capture completed-result identity and the inputs for any replacement scan together. */
export async function readNativeScanSemanticInputs(
  modelSettings: Pick<NativeScanInput, "model" | "reasoningEffort"> = {},
  signal?: AbortSignal,
  savedRecipe?: SavedScanRecipe,
): Promise<NativeScanSemanticInputs> {
  const environment = await snapshotNativeEnvironment();
  const knowledgeBasePath = environmentValue(
    environment,
    "CODEX_SECURITY_KNOWLEDGE_BASE",
  );
  const knowledgeBasePaths = knowledgeBasePath
    ? [knowledgeBasePath]
    : undefined;
  const knowledgeBaseSnapshot = knowledgeBasePaths
    ? await readKnowledgeBaseSnapshot(knowledgeBasePaths, signal)
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
  const savedConfig = await restoreProviderProfile(
    savedRecipe?.config ?? {},
    savedRecipe?.providerProfile,
    environment,
  );
  return {
    knowledgeBasePaths,
    knowledgeBaseSnapshot,
    deepScanSettings,
    config,
    instructionSettingsMatch:
      config["developer_instructions"] ===
        savedConfig["developer_instructions"] &&
      config["model_instructions_file"] ===
        savedConfig["model_instructions_file"] &&
      (await promptFileDigest(
        typeof config["model_instructions_file"] === "string"
          ? config["model_instructions_file"]
          : undefined,
        signal,
      )) ===
        (savedRecipe?.scanInputs?.["modelInstructionsFileSha256"] ?? null) &&
      config["experimental_compact_prompt_file"] ===
        savedConfig["experimental_compact_prompt_file"] &&
      (await promptFileDigest(
        typeof config["experimental_compact_prompt_file"] === "string"
          ? config["experimental_compact_prompt_file"]
          : undefined,
        signal,
      )) === (savedRecipe?.scanInputs?.["compactPromptFileSha256"] ?? null),
    modelSettings: scanModelConfiguration(
      await mergedCodexConfig({ codexOverrides: config }),
    ),
  };
}

async function prepareOwnedNativeScan(
  input: NativeScanInput,
  signal?: AbortSignal,
): Promise<PreparedNativeScan> {
  const environment = await snapshotNativeEnvironment();
  const stateDirectory =
    input.stateDirectory ?? codexSecurityStateDirectory(environment);
  requireModelSafeOutputDir(stateDirectory);
  environment.CODEX_SECURITY_STATE_DIR = stateDirectory;
  const release = await acquireScanExecution(
    stateDirectory,
    input.scan.scanDir,
    join(input.pluginRoot, "mcp", "native"),
    true,
    signal,
  );
  try {
    // A queued host may have joined before the first host saved its recipe.
    const current = await runWorkbench(
      {
        python: input.pythonPath,
        pluginRoot: input.pluginRoot,
        environment,
        stateDirectory,
        signal,
        protectedRoot: [input.scan.targetPath, input.scan.scanDir],
      },
      ["get-scan", "--scan-id", input.scan.scanId],
    );
    return await prepareNativeScan(
      {
        ...input,
        stateDirectory,
        recipe: isRecord(current["recipe"])
          ? (current["recipe"] as unknown as SavedScanRecipe)
          : undefined,
      },
      signal,
      { environment, stateDirectory, release },
    );
  } catch (error) {
    release();
    throw error;
  }
}

export async function prepareNativeScan(
  input: NativeScanInput,
  signal?: AbortSignal,
  ownership?: NativeScanOwnership,
): Promise<PreparedNativeScan> {
  const inheritedEnvironment =
    ownership?.environment ?? (await snapshotNativeEnvironment());
  const recipe = input.recipe;
  const semanticInputs =
    recipe === undefined ? input.semanticInputs : undefined;
  const knowledgeBasePath = environmentValue(
    inheritedEnvironment,
    "CODEX_SECURITY_KNOWLEDGE_BASE",
  );
  const options = ScanSettingsSchema.parse({
    ...input.savedDeepScanSettings,
    ...semanticInputs?.deepScanSettings,
    ...recipe?.deepScan,
    auth: recipe?.auth,
    knowledgeBasePaths:
      recipe !== undefined
        ? recipe.knowledgeBasePaths
        : semanticInputs
          ? semanticInputs.knowledgeBasePaths
          : knowledgeBasePath
            ? [knowledgeBasePath]
            : undefined,
    maxCostUsd: recipe?.maxCostUsd,
    cyberAccessProgram: recipe?.cyberAccessProgram,
    postScanPrompt: recipe?.postScanPrompt,
    failureSeverity: recipe?.failOnSeverity,
    mode: "deep",
    scanPrompt: input.scan.userContext ?? undefined,
    outputDir: input.scan.scanDir,
  });
  const publicationOnly =
    recipe !== undefined &&
    !options.postScanPrompt?.trim() &&
    (await hasSealedScanArtifacts(input.scan.scanDir, signal));
  const savedPermissions = recipe?.inheritedPermissions;
  let inheritedPermissions = savedPermissions;
  if (!publicationOnly) {
    const parentSandbox =
      typeof input.parentSandbox === "function"
        ? input.parentSandbox()
        : input.parentSandbox;
    const workspaceAccess = parentSandbox.workspaceAccess;
    const savedFilesystem =
      workspaceAccess === "read"
        ? readOnlyFilesystem(savedPermissions?.filesystem ?? {})
        : (savedPermissions?.filesystem ?? {});
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
        [":workspace_roots", workspaceAccess],
        ...Object.entries(savedFilesystem),
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
  const configurationEnvironment = {
    ...inheritedEnvironment,
    ...(input.stateDirectory
      ? { CODEX_SECURITY_STATE_DIR: input.stateDirectory }
      : {}),
  };
  const deep = await resolveDeepScanConfig(
    options,
    nativeDeepScanConfigPath(configurationEnvironment),
  );
  // The SDK still validates the seal, owner and claim before publication.
  const config = publicationOnly
    ? (recipe.config ?? {})
    : (semanticInputs?.config ??
      (await nativeScanConfiguration(
        configurationEnvironment,
        input,
        deep.settings.subagents,
      )));
  const executionPaths = publicationOnly
    ? {}
    : resolveExecutionPaths(config, input.scan.scanDir, inheritedEnvironment);
  const protectedRoots = [
    input.scan.scanDir,
    ...(await Promise.all(
      [
        input.scan.targetPath,
        ...(options.knowledgeBasePaths ?? []),
        ...[
          executionPaths["model_instructions_file"],
          executionPaths["experimental_compact_prompt_file"],
        ].filter((path): path is string => typeof path === "string"),
      ].map(async (path) => {
        const source = expandHome(path, inheritedEnvironment);
        return (await gitMarkerRoot(source, signal, "outermost")) ?? source;
      }),
    )),
  ];
  const codex = publicationOnly
    ? null
    : await resolveTrustedCodex(inheritedEnvironment, protectedRoots);
  if (!publicationOnly && codex === null) {
    throw new CodexSecurityError(
      `Could not resolve a Codex executable outside the scan target: ${resolveCodexPath(inheritedEnvironment)}`,
    );
  }
  const environment: NodeJS.ProcessEnv = {
    ...(codex?.environment ?? inheritedEnvironment),
    ...(codex === null ? {} : { CODEX_CLI_PATH: codex.executable }),
  };
  // The SDK forwards the prepared documents, including a saved empty selection.
  delete environment.CODEX_SECURITY_KNOWLEDGE_BASE;
  if (input.stateDirectory)
    environment.CODEX_SECURITY_STATE_DIR = input.stateDirectory;
  const security = config["codex_security"];
  if (
    recipe === undefined &&
    security !== null &&
    typeof security === "object" &&
    !Array.isArray(security) &&
    typeof security["cyber_access_program"] === "string"
  )
    options.cyberAccessProgram = security[
      "cyber_access_program"
    ] as ScanOptions["cyberAccessProgram"];
  const ambientExecution = {
    environment,
    ...(codex === null ? {} : { command: { command: codex.executable } }),
    configuration: config,
    auth: options.auth,
    pluginRoot: input.pluginRoot,
  };
  const client = new CodexSecurity(
    {
      pluginPath: input.pluginRoot,
      pythonPath: input.pythonPath,
      codexOverrides: ambientExecution.configuration,
    },
    {
      environment,
      stateDirectory: input.stateDirectory,
      inheritedPermissions,
      ambientExecution,
      acquireScanExecution: (state, directory, nativeRoot) =>
        ownership &&
        state === ownership.stateDirectory &&
        directory === input.scan.scanDir
          ? Promise.resolve(() => {})
          : acquireScanExecution(state, directory, nativeRoot, true, signal),
    },
    { surface: "sdk" },
  );
  return {
    client,
    ...(ownership === undefined ? {} : { releaseExecution: ownership.release }),
    options: {
      ...options,
      ...deep.settings,
      ...(input.recipe === undefined
        ? { knowledgeBaseSnapshot: semanticInputs?.knowledgeBaseSnapshot }
        : {
            resumeScanId: input.scan.scanId,
            ...(options.knowledgeBasePaths?.length
              ? {
                  knowledgeBaseSnapshot: await restoreScanKnowledge(
                    input.scan.scanDir,
                    input.scan.targetPath,
                    input.recipe.scanInputs,
                  ),
                }
              : {}),
          }),
      inheritedPermissions,
      target:
        recipe?.target?.kind === "paths"
          ? recipe.target.paths
          : input.scan.scope && input.scan.scope !== "."
            ? [input.scan.scope]
            : "repository",
      safetyIdentifier:
        recipe === undefined
          ? environment.CODEX_SAFETY_IDENTIFIER
          : recipe.safetyIdentifier,
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
