import { promises as fs } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, relative, sep, win32 } from "node:path";
import type { CodexOptions, CyberAccessProgram } from "@openai/codex-sdk";
import { parse as parseToml } from "smol-toml";
import {
  bedrockProviderConfig,
  resolveCodexProfile,
  workerModelSelection,
  type JsonObject,
} from "../codex-profile.js";
import { writeCodexConfig } from "../private-config.js";
import { requirePrivateWindowsDirectory } from "../windows-credential-acl.js";
import { parentSessionEvents } from "./parent-session.js";
import {
  resolveCodexPath,
  workerRuntimeConfiguration,
  workerRuntimeConfigDigest,
  type WorkerRuntimeConfigSource,
  workerRuntimeSettingsFromConfig,
  type CodexSdkWorkerRuntimeSettings,
} from "./executor.js";
import { isRecord } from "../record.js";
import type { DeepWorkerParentSandbox } from "./parent-sandbox.js";
import type { DeepScanRunState } from "./types.js";

/** Credentials and arbitrary environment/configuration stay with Codex. */
export interface DeepScanExecutionSettings {
  codexPath: string;
  codexHome: string;
  model?: string;
  modelProvider?: string;
  reasoningEffort?: string;
  reasoningSummary?: string;
  serviceTier?: string;
  /** Effective program from the originating native turn, ahead of runner configuration. */
  cyberAccessProgram?: CyberAccessProgram;
  /** The native snapshot recorded no request tier; serviceTier preserves its wire behavior. */
  nativeServiceTierAbsent?: true;
  providerConfig?: JsonObject;
  parentSandbox?: DeepWorkerParentSandbox;
  runtimeSettings?: CodexSdkWorkerRuntimeSettings;
  runtimeConfigPath?: string;
  runtimeConfigSource?: WorkerRuntimeConfigSource;
}

export interface DeepScanLegacySettingsContext {
  config?: JsonObject;
  usageOwner?: DeepScanRunState["usageOwner"];
}

export interface DeepScanExecutionSettingsSnapshot {
  version: number;
  settings: DeepScanExecutionSettings;
}

/** Only Bedrock selectors are persisted. Other provider metadata stays in the native home. */
function recoveryModelConfig(config: JsonObject): JsonObject {
  const resolved = resolveCodexProfile(config);
  const selected = workerModelSelection(resolved);
  if (selected.model_provider === "amazon-bedrock") {
    const provider = bedrockProviderConfig(resolved);
    if (provider) selected.model_providers = provider;
  }
  return selected;
}

/** Existing runs can be joined without capturing a usable current runtime. */
export async function beginDeepScanWithCapturedSettings<T>(
  capture: () => Promise<DeepScanExecutionSettings>,
  begin: (settings: DeepScanExecutionSettings | null) => Promise<T>,
): Promise<T> {
  let captureError: unknown;
  const settings = await capture().catch((error: unknown) => {
    captureError = error;
    return null;
  });
  try {
    return await begin(settings);
  } catch (error) {
    if (settings !== null) throw error;
    const detail = (failure: unknown) =>
      failure instanceof Error ? failure.message : String(failure);
    throw new AggregateError(
      [error, captureError],
      `${detail(error)} Original execution settings could not be captured: ${detail(captureError)}`,
    );
  }
}

export async function captureDeepScanExecutionSettings(
  original: Pick<
    DeepScanRunState,
    "model" | "reasoningEffort" | "serviceTier" | "usageOwner"
  >,
  parentSandbox: DeepWorkerParentSandbox,
  environment: NodeJS.ProcessEnv = process.env,
  parent?: { threadId: string; turnId?: string; startedAt?: string },
): Promise<DeepScanExecutionSettings> {
  const configuredHome = environment.CODEX_HOME || join(homedir(), ".codex");
  const codexHome =
    !isAbsolute(configuredHome) ||
    (process.platform === "win32" &&
      ["\\", "/"].includes(win32.parse(configuredHome).root))
      ? await fs.realpath(configuredHome)
      : configuredHome;
  // Preserve symlink/.. traversal in an absolute home instead of joining lexically.
  const configPath =
    environment.CODEX_SECURITY_CONFIG_PATH ?? `${codexHome}${sep}config.toml`;
  let config: JsonObject;
  let originalConfigPath: string | undefined = configPath;
  try {
    config = parseToml(await fs.readFile(configPath, "utf8")) as JsonObject;
  } catch (error) {
    if (
      environment.CODEX_SECURITY_CONFIG_PATH ||
      (error as NodeJS.ErrnoException).code !== "ENOENT"
    )
      throw error;
    config = {};
    originalConfigPath = undefined;
  }
  const resolved = resolveCodexProfile(config);
  const selected = recoveryModelConfig(resolved);
  // A recovered scan can have a different continuation. Only its recorded owner
  // establishes original history; null means that historical binding is missing.
  const owner =
    original.usageOwner === undefined ? parent : original.usageOwner;
  const native = !owner?.threadId
    ? {}
    : await originalParentSettings(codexHome, {
        ...owner,
        threadId: owner.threadId,
        startedAt: parent?.startedAt ?? owner.startedAt,
      });
  const runtimeSettings = workerRuntimeSettingsFromConfig(resolved);
  let runtimeConfigPath: string | undefined;
  let runtimeConfigSource: WorkerRuntimeConfigSource | undefined;
  const workerConfigPath = environment.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
  const workerSnapshot =
    workerConfigPath === undefined
      ? undefined
      : parseToml(await fs.readFile(workerConfigPath, "utf8")).worker_runtime;
  if (isRecord(workerSnapshot)) {
    const runtimeConfig = workerRuntimeConfiguration(config, workerSnapshot);
    runtimeSettings.features = workerRuntimeSettingsFromConfig({
      features: runtimeConfig.features,
    }).features;
    const digest = workerRuntimeConfigDigest(runtimeConfig);
    const privateHome = await protectedRuntimeHome(codexHome, parentSandbox);
    if (privateHome === undefined) {
      // Keep protected source inputs in place when a new copy would be readable
      // by the parent. Recovery verifies their original effective configuration.
      runtimeConfigSource = {
        ...(originalConfigPath === undefined
          ? {}
          : { configPath: await fs.realpath(originalConfigPath) }),
        workerConfigPath: await fs.realpath(workerConfigPath!),
        digest,
      };
    } else {
      const runtimeDirectory = join(
        privateHome,
        "codex-security-worker-settings",
      );
      await fs.mkdir(runtimeDirectory, { recursive: true, mode: 0o700 });
      const canonicalRuntimeDirectory = await fs.realpath(runtimeDirectory);
      if (!within(privateHome, canonicalRuntimeDirectory)) {
        throw new Error(
          "The worker settings directory is outside the protected Codex home.",
        );
      }
      if (process.platform === "win32") {
        await requirePrivateWindowsDirectory(
          canonicalRuntimeDirectory,
          "credential home",
        );
      }
      runtimeConfigPath = join(canonicalRuntimeDirectory, `${digest}.toml`);
      await writeCodexConfig(runtimeConfigPath, runtimeConfig as JsonObject);
    }
  }
  return executionSettings({
    codexPath: resolveCodexPath(
      environment,
      process.platform,
      process.arch,
      process.cwd(),
    ),
    codexHome,
    model:
      original.model ?? (selected.model as string | undefined) ?? native.model,
    reasoningEffort:
      original.reasoningEffort ??
      (selected.model_reasoning_effort as string | undefined) ??
      native.reasoningEffort,
    modelProvider:
      (selected.model_provider as string | undefined) ?? native.modelProvider,
    reasoningSummary:
      (selected.model_reasoning_summary as string | undefined) ??
      native.reasoningSummary,
    serviceTier:
      original.serviceTier ??
      (selected.service_tier as string | undefined) ??
      native.serviceTier,
    ...(original.serviceTier === undefined &&
    selected.service_tier === undefined &&
    native.nativeServiceTierAbsent
      ? { nativeServiceTierAbsent: true as const }
      : {}),
    providerConfig: selected.model_providers as JsonObject | undefined,
    cyberAccessProgram: native.cyberAccessProgram,
    runtimeSettings,
    runtimeConfigPath,
    runtimeConfigSource,
    parentSandbox,
  });
}

function within(root: string, child: string): boolean {
  const suffix = relative(root, child);
  return (
    suffix === "" ||
    (!isAbsolute(suffix) && suffix !== ".." && !suffix.startsWith(`..${sep}`))
  );
}

async function protectedRuntimeHome(
  codexHome: string,
  sandbox: DeepWorkerParentSandbox,
): Promise<string | undefined> {
  const home = await fs.realpath(codexHome);
  const literalDenials = new Set([
    ...(sandbox.literalFilesystemDenies ?? []),
    ...sandbox.filesystemDenies.filter((value) => !/[*?\[\]{}]/.test(value)),
  ]);
  for (const denied of literalDenials) {
    try {
      const canonical = await fs.realpath(denied);
      if (within(canonical, home) && (await fs.stat(canonical)).isDirectory())
        return home;
    } catch (error) {
      if (
        !["ENOENT", "ENOTDIR"].includes(
          (error as NodeJS.ErrnoException).code ?? "",
        )
      )
        throw error;
    }
  }
  return undefined;
}

async function originalParentSettings(
  codexHome: string,
  parent: { threadId: string; turnId?: string | null; startedAt?: string },
): Promise<Partial<DeepScanExecutionSettings>> {
  // Native config/read represents omitted selections as null. Recover recorded
  // selections from the original parent; some native records omit the summary.
  // Missing historical sessions are allowed; a failed read cannot establish the original selection.
  try {
    const events = parentSessionEvents(
      await fs.realpath(codexHome),
      parent.threadId,
    );
    const settings: Partial<DeepScanExecutionSettings> = {};
    let applied: Partial<DeepScanExecutionSettings> | undefined;
    let summaryIsCompatibilityOnly = false;
    const cutoff =
      parent.startedAt === undefined ? Infinity : Date.parse(parent.startedAt);
    for await (const event of events) {
      const timestamp =
        typeof event.timestamp === "string"
          ? Date.parse(event.timestamp)
          : undefined;
      if (timestamp !== undefined && timestamp > cutoff) continue;
      const payload = event.payload;
      if (!payload || typeof payload !== "object" || Array.isArray(payload))
        continue;
      const context = payload as Record<string, unknown>;
      if (
        event.type === "event_msg" &&
        context.type === "thread_settings_applied"
      ) {
        if (
          typeof context.thread_id === "string" &&
          context.thread_id !== parent.threadId
        )
          continue;
        const snapshot = context.thread_settings;
        if (
          !snapshot ||
          typeof snapshot !== "object" ||
          Array.isArray(snapshot)
        )
          continue;
        const value = snapshot as Record<string, unknown>;
        applied = {
          model: typeof value.model === "string" ? value.model : undefined,
          modelProvider:
            typeof value.model_provider_id === "string"
              ? value.model_provider_id
              : undefined,
          reasoningEffort:
            typeof value.reasoning_effort === "string"
              ? value.reasoning_effort
              : undefined,
          reasoningSummary:
            typeof value.reasoning_summary === "string"
              ? value.reasoning_summary
              : undefined,
          // A persisted native absent tier and explicit standard both omit the
          // request tier. This does not infer a tier from missing history.
          serviceTier:
            typeof value.service_tier === "string"
              ? value.service_tier
              : value.service_tier === undefined
                ? "default"
                : undefined,
          ...(value.service_tier === undefined
            ? { nativeServiceTierAbsent: true as const }
            : {}),
        };
      }
      if (event.type === "session_meta") {
        if (typeof context.model_provider === "string")
          settings.modelProvider = context.model_provider;
        // Codex 0.133 replaced turn_context.summary with a compatibility default.
        // Fresh threads need not have a thread_settings_applied record to replace it.
        const version =
          typeof context.cli_version === "string"
            ? /^(\d+)\.(\d+)\./u.exec(context.cli_version)
            : null;
        summaryIsCompatibilityOnly =
          version !== null &&
          (Number(version[1]) > 0 || Number(version[2]) >= 133);
      }
      if (event.type === "turn_context") {
        if (parent.turnId && context.turn_id !== parent.turnId) continue;
        settings.cyberAccessProgram =
          typeof context.cyber_access_program === "string"
            ? (context.cyber_access_program as CyberAccessProgram)
            : undefined;
        if (typeof context.model === "string") settings.model = context.model;
        if (typeof context.effort === "string")
          settings.reasoningEffort = context.effort;
        if (!summaryIsCompatibilityOnly && typeof context.summary === "string")
          settings.reasoningSummary = context.summary;
      }
    }
    // Applied snapshots contain native selected values. Newer turn-context
    // summaries are only a compatibility field, not the active selection.
    return { ...settings, ...applied };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    return {};
  }
}

/** Read recorded execution settings or original legacy facts. */
export async function loadDeepScanExecutionSettings(
  original?: Pick<
    DeepScanRunState,
    | "model"
    | "reasoningEffort"
    | "usageOwner"
    | "createdAt"
    | "workflowVersion"
    | "executionSettings"
  >,
  readLegacyContext?: () => Promise<DeepScanLegacySettingsContext>,
  environment: NodeJS.ProcessEnv = process.env,
): Promise<Partial<DeepScanExecutionSettings>> {
  // Only the workbench creation transaction records the launch selection. Scan
  // artifacts are model-writable and cannot select a preflight executable/home.
  const saved = original?.executionSettings;
  let settings: DeepScanExecutionSettings;
  if (saved) {
    if (saved.version !== 1) {
      throw new Error(
        "This Deep Scan uses an unsupported execution settings version.",
      );
    }
    settings = executionSettings(saved.settings);
  } else {
    if (
      original?.workflowVersion === "deep-security-scan/v1" ||
      original?.workflowVersion === "deep-scan-mcp/v1"
    ) {
      // Legacy runs predate the binding. Their saved recipe and recorded owner
      // can recover selections, but cannot establish an original executable or
      // home. Leave those unknown and retain the existing native launch behavior.
      const context = await readLegacyContext?.();
      const resolved = resolveCodexProfile(context?.config ?? {});
      const selected = recoveryModelConfig(resolved);
      const owner = original.usageOwner ?? context?.usageOwner;
      const home = environment.CODEX_HOME || join(homedir(), ".codex");
      const native = !owner?.threadId
        ? {}
        : await originalParentSettings(home, {
            ...owner,
            threadId: owner.threadId,
            startedAt: original.createdAt ?? owner.startedAt,
          });
      return {
        cyberAccessProgram: native.cyberAccessProgram,
        runtimeSettings: workerRuntimeSettingsFromConfig(resolved),
        model:
          original.model ??
          (selected.model as string | undefined) ??
          native.model,
        reasoningEffort:
          original.reasoningEffort ??
          (selected.model_reasoning_effort as string | undefined) ??
          native.reasoningEffort,
        modelProvider:
          (selected.model_provider as string | undefined) ??
          native.modelProvider,
        reasoningSummary:
          (selected.model_reasoning_summary as string | undefined) ??
          native.reasoningSummary,
        serviceTier:
          (selected.service_tier as string | undefined) ?? native.serviceTier,
        ...(selected.service_tier === undefined &&
        native.nativeServiceTierAbsent
          ? { nativeServiceTierAbsent: true as const }
          : {}),
        providerConfig:
          selected.model_provider === "amazon-bedrock"
            ? (selected.model_providers as JsonObject | undefined)
            : undefined,
      };
    }
    throw new Error(
      "This Deep Scan has no recorded original execution settings; its executable and Codex home cannot be recovered.",
    );
  }
  if (
    !original ||
    (settings.model !== undefined &&
      settings.reasoningEffort !== undefined &&
      settings.modelProvider !== undefined &&
      settings.reasoningSummary !== undefined &&
      settings.serviceTier !== undefined &&
      settings.cyberAccessProgram !== undefined)
  )
    return settings;
  // Earlier snapshots can omit native selections. Recover only from the saved
  // home and recorded owner; the continuation's current config is not history.
  const owner = original.usageOwner;
  const native = !owner?.threadId
    ? {}
    : await originalParentSettings(settings.codexHome, {
        ...owner,
        threadId: owner.threadId,
        startedAt: original.createdAt,
      });
  // History reads can outlive this coordinator. Project missing selections for
  // its workers without overwriting a snapshot owned by a newer coordinator.
  return executionSettings({
    ...settings,
    cyberAccessProgram:
      settings.cyberAccessProgram ?? native.cyberAccessProgram,
    model: settings.model ?? original.model ?? native.model,
    reasoningEffort:
      settings.reasoningEffort ??
      original.reasoningEffort ??
      native.reasoningEffort,
    modelProvider: settings.modelProvider ?? native.modelProvider,
    reasoningSummary: settings.reasoningSummary ?? native.reasoningSummary,
    serviceTier: settings.serviceTier ?? native.serviceTier,
    ...(settings.serviceTier === undefined && native.nativeServiceTierAbsent
      ? { nativeServiceTierAbsent: true as const }
      : {}),
  });
}

export function restoredDeepScanWorkerSettings(
  settings: Partial<DeepScanExecutionSettings>,
  currentParentSandbox: DeepWorkerParentSandbox,
  environment: () => NodeJS.ProcessEnv = () => process.env,
): {
  nativeProfileHome: string;
  protectedCredentialHome: (home: string) => Promise<string | undefined>;
  runtimeConfigPath?: string;
  runtimeConfigSource?: WorkerRuntimeConfigSource;
  codexOptions: CodexOptions;
  parentCyberAccessProgram?: CyberAccessProgram;
  model?: string;
  reasoningEffort?: string;
  parentSandbox: DeepWorkerParentSandbox;
  runtimeSettings?: CodexSdkWorkerRuntimeSettings;
} {
  const originalSandbox = settings.parentSandbox;
  const depths = [
    originalSandbox?.globScanMaxDepth,
    currentParentSandbox.globScanMaxDepth,
  ].filter((depth): depth is number => depth !== undefined);
  // Native depth caps limit deny-glob expansion, not allowed traversal. Keep
  // the larger finite cap, or no cap when either known policy has uncapped globs.
  const uncapped = [originalSandbox, currentParentSandbox].some(
    (sandbox) =>
      sandbox?.globScanMaxDepth === undefined &&
      sandbox?.filesystemDenies.some((path) =>
        ["*", "?", "[", "]"].some((character) => path.includes(character)),
      ),
  );
  const config = recoveryModelConfig({
    ...(settings.model === undefined ? {} : { model: settings.model }),
    ...(settings.reasoningEffort === undefined
      ? {}
      : { model_reasoning_effort: settings.reasoningEffort }),
    ...(settings.modelProvider === undefined
      ? {}
      : { model_provider: settings.modelProvider }),
    ...(settings.reasoningSummary === undefined
      ? {}
      : { model_reasoning_summary: settings.reasoningSummary }),
    ...(settings.serviceTier === undefined
      ? {}
      : { service_tier: settings.serviceTier }),
    ...(settings.providerConfig === undefined
      ? {}
      : { model_providers: settings.providerConfig }),
  });
  return {
    protectedCredentialHome: (home) =>
      protectedRuntimeHome(home, currentParentSandbox),
    get nativeProfileHome() {
      return environment().CODEX_HOME || join(homedir(), ".codex");
    },
    model: settings.model,
    reasoningEffort: settings.reasoningEffort,
    ...(settings.runtimeConfigPath === undefined
      ? {}
      : { runtimeConfigPath: settings.runtimeConfigPath }),
    ...(settings.runtimeConfigSource === undefined
      ? {}
      : { runtimeConfigSource: settings.runtimeConfigSource }),
    parentCyberAccessProgram: settings.cyberAccessProgram,
    ...(settings.runtimeSettings === undefined
      ? {}
      : { runtimeSettings: settings.runtimeSettings }),
    parentSandbox: {
      // Named read access comes from the current parent, including when resuming.
      ...(currentParentSandbox.pluginReadRoot === undefined
        ? {}
        : { pluginReadRoot: currentParentSandbox.pluginReadRoot }),
      ...(currentParentSandbox.sourceReadRoot === undefined
        ? {}
        : { sourceReadRoot: currentParentSandbox.sourceReadRoot }),
      filesystemDenies: [
        ...new Set([
          ...(originalSandbox?.filesystemDenies ?? []),
          ...currentParentSandbox.filesystemDenies,
        ]),
      ],
      ...((originalSandbox?.literalFilesystemDenies?.length ?? 0) ||
      currentParentSandbox.literalFilesystemDenies?.length
        ? {
            literalFilesystemDenies: [
              ...new Set([
                ...(originalSandbox?.literalFilesystemDenies ?? []),
                ...(currentParentSandbox.literalFilesystemDenies ?? []),
              ]),
            ],
          }
        : {}),
      ...(uncapped || depths.length === 0
        ? {}
        : { globScanMaxDepth: Math.max(...depths) }),
    },
    codexOptions: {
      codexPathOverride: settings.codexPath,
      // The executor reads this property for each launch. API keys can refresh;
      // only the original account home and non-secret selections are bound.
      get env() {
        return Object.fromEntries(
          Object.entries({
            ...environment(),
            ...(settings.codexPath === undefined
              ? {}
              : { CODEX_CLI_PATH: settings.codexPath }),
            ...(settings.codexHome === undefined
              ? {}
              : { CODEX_HOME: settings.codexHome }),
          }).filter(
            (entry): entry is [string, string] => entry[1] !== undefined,
          ),
        );
      },
      config: config as NonNullable<CodexOptions["config"]>,
    },
  };
}

function executionSettings(
  value: DeepScanExecutionSettings,
): DeepScanExecutionSettings {
  // Only Bedrock's per-scan AWS selectors need persistence. Other provider
  // definitions remain in the original native home.
  const provider =
    value.modelProvider === "amazon-bedrock"
      ? (recoveryModelConfig({
          ...(value.modelProvider === undefined
            ? {}
            : { model_provider: value.modelProvider }),
          ...(value.providerConfig === undefined
            ? {}
            : { model_providers: value.providerConfig }),
        }).model_providers as JsonObject | undefined)
      : undefined;
  const settings: DeepScanExecutionSettings = {
    codexPath: value.codexPath,
    codexHome: value.codexHome,
    model: value.model,
    modelProvider: value.modelProvider,
    reasoningEffort: value.reasoningEffort,
    reasoningSummary: value.reasoningSummary,
    serviceTier: value.serviceTier,
    ...(value.cyberAccessProgram === undefined
      ? {}
      : { cyberAccessProgram: value.cyberAccessProgram }),
    ...(value.nativeServiceTierAbsent === true
      ? { nativeServiceTierAbsent: true }
      : {}),
    ...(provider === undefined ? {} : { providerConfig: provider }),
    ...(value.runtimeSettings === undefined
      ? {}
      : { runtimeSettings: structuredClone(value.runtimeSettings) }),
    ...(value.runtimeConfigPath === undefined
      ? {}
      : { runtimeConfigPath: value.runtimeConfigPath }),
    ...(value.runtimeConfigSource === undefined
      ? {}
      : { runtimeConfigSource: structuredClone(value.runtimeConfigSource) }),
    ...(value.parentSandbox === undefined
      ? {}
      : {
          parentSandbox: {
            filesystemDenies: [...value.parentSandbox.filesystemDenies],
            ...(value.parentSandbox.literalFilesystemDenies === undefined
              ? {}
              : {
                  literalFilesystemDenies: [
                    ...value.parentSandbox.literalFilesystemDenies,
                  ],
                }),
            ...(value.parentSandbox.globScanMaxDepth === undefined
              ? {}
              : {
                  globScanMaxDepth: value.parentSandbox.globScanMaxDepth,
                }),
          },
        }),
  };
  if (
    typeof settings.codexPath !== "string" ||
    typeof settings.codexHome !== "string"
  ) {
    throw new Error(
      "Deep Scan execution settings are missing the recorded executable or Codex home.",
    );
  }
  return settings;
}
