import { join } from "node:path";
import {
  CodexSecurity,
  type ScanOptions,
} from "../../../../sdk/typescript/src/api.js";
import type { JsonObject } from "../../../../sdk/typescript/src/config.js";
import { ScanSettingsSchema } from "../../../../sdk/typescript/src/scan-settings.js";
import type { SavedScanRecipe } from "../../../../sdk/typescript/src/scan-registration.js";
import { configuredCodexHome } from "../../../../sdk/typescript/src/auth.js";
import { expandHome } from "../../../../sdk/typescript/src/codex-home.js";
import { gitMarkerRoot } from "../../../../sdk/typescript/src/targets.js";
import { CodexSecurityError } from "../../../../sdk/typescript/src/errors.js";
import { resolveDeepScanConfig } from "../../../../sdk/typescript/src/deep-config.js";
import { ScanTransportClosedError } from "../../../../sdk/typescript/src/scan-execution.js";
import type { ScanResult } from "../../../../sdk/typescript/src/result.js";
import {
  resolveCodexPath,
  resolveTrustedCodex,
  snapshotNativeEnvironment,
} from "./native-executable.js";
import type { NativeParentSandbox } from "./native-permissions.js";
import {
  prepareAmbientExecution,
  nativeScanConfiguration,
} from "../../../../sdk/typescript/src/execution-preparation.js";
export { nativeScanConfiguration } from "../../../../sdk/typescript/src/execution-preparation.js";
import type { ScanResults } from "./types.js";

export interface NativeScanInput {
  scan: ScanResults;
  recipe?: SavedScanRecipe;
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

export async function prepareNativeScan(
  input: NativeScanInput,
  signal?: AbortSignal,
): Promise<PreparedNativeScan> {
  const inheritedEnvironment = await snapshotNativeEnvironment();
  const recipe = input.recipe;
  const options = ScanSettingsSchema.parse({
    ...recipe?.deepScan,
    auth: recipe?.auth,
    knowledgeBasePaths:
      recipe !== undefined
        ? recipe.knowledgeBasePaths
        : inheritedEnvironment.CODEX_SECURITY_KNOWLEDGE_BASE
          ? [inheritedEnvironment.CODEX_SECURITY_KNOWLEDGE_BASE]
          : undefined,
    maxCostUsd: recipe?.maxCostUsd,
    postScanPrompt: recipe?.postScanPrompt,
    failureSeverity: recipe?.failOnSeverity,
    mode: "deep",
    scanPrompt: input.scan.userContext ?? undefined,
    outputDir: input.scan.scanDir,
  });
  const protectedRoots = [
    input.scan.scanDir,
    ...(await Promise.all(
      [input.scan.targetPath, ...(options.knowledgeBasePaths ?? [])].map(
        async (path) => {
          const source = expandHome(path, inheritedEnvironment);
          return (await gitMarkerRoot(source, signal, "outermost")) ?? source;
        },
      ),
    )),
  ];
  const codex = await resolveTrustedCodex(inheritedEnvironment, protectedRoots);
  if (codex === null) {
    throw new CodexSecurityError(
      `Could not resolve a Codex executable outside the scan target: ${resolveCodexPath(inheritedEnvironment)}`,
    );
  }
  const environment: NodeJS.ProcessEnv = {
    ...codex.environment,
    CODEX_CLI_PATH: codex.executable,
  };
  // The SDK forwards the prepared documents, including a saved empty selection.
  delete environment.CODEX_SECURITY_KNOWLEDGE_BASE;
  if (input.stateDirectory)
    environment.CODEX_SECURITY_STATE_DIR = input.stateDirectory;
  const savedPermissions = recipe?.inheritedPermissions;
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
  const deep = await resolveDeepScanConfig(
    options,
    environment.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH?.trim() ||
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
  const ambientExecution = await prepareAmbientExecution(
    {
      environment,
      command: { command: codex.executable },
      configuration: config,
      auth: options.auth,
      pluginRoot: input.pluginRoot,
    },
    signal,
  );
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
      inheritedPermissions,
      ambientExecution,
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
        recipe?.target?.kind === "paths"
          ? recipe.target.paths
          : input.scan.scope && input.scan.scope !== "."
            ? [input.scan.scope]
            : "repository",
      safetyIdentifier:
        recipe?.safetyIdentifier ?? environment.CODEX_SAFETY_IDENTIFIER,
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
