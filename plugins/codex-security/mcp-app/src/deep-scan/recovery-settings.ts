import { promises as fs } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, win32 } from "node:path";
import type { CodexOptions } from "@openai/codex-sdk";
import { parse as parseToml } from "smol-toml";
import { scanPreflightCodexConfig } from "../../../../../sdk/typescript/src/preflight-config.js";
import { resolveCodexProfile, type JsonObject } from "../../../../../sdk/typescript/src/config.js";
import { readScanLogs } from "../../../../../sdk/typescript/src/scan-logs.js";
import { writeJsonAtomic } from "./artifacts.js";
import { resolveCodexPath } from "./executor.js";
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
  /** The native snapshot recorded no request tier; serviceTier preserves its wire behavior. */
  nativeServiceTierAbsent?: true;
  providerConfig?: JsonObject;
  parentSandbox?: DeepWorkerParentSandbox;
}

export async function captureDeepScanExecutionSettings(
  original: Pick<DeepScanRunState, "model" | "reasoningEffort" | "usageOwner">,
  parentSandbox: DeepWorkerParentSandbox,
  environment: NodeJS.ProcessEnv = process.env,
  parent?: { threadId: string; startedAt?: string }
): Promise<DeepScanExecutionSettings> {
  const codexHome = environment.CODEX_HOME || join(homedir(), ".codex");
  const configPath = environment.CODEX_SECURITY_CONFIG_PATH ?? join(codexHome, "config.toml");
  let config: JsonObject;
  try {
    config = parseToml(await fs.readFile(configPath, "utf8")) as JsonObject;
  } catch (error) {
    if (environment.CODEX_SECURITY_CONFIG_PATH || (error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    config = {};
  }
  // Reuse the SDK projection: custom provider credentials belong in the native home.
  const selected = scanPreflightCodexConfig(resolveCodexProfile(config));
  // A recovered scan can have a different continuation. Only its recorded owner
  // establishes original history; null means that historical binding is missing.
  const owner = original.usageOwner === undefined ? parent : original.usageOwner;
  const native = !owner?.threadId ? {} : await originalParentSettings(codexHome, {
    ...owner, threadId: owner.threadId, startedAt: parent?.startedAt ?? owner.startedAt
  });
  return executionSettings({
    codexPath: resolveCodexPath(environment, process.platform, process.arch, process.cwd()),
    codexHome: !isAbsolute(codexHome)
      || (process.platform === "win32" && ["\\", "/"].includes(win32.parse(codexHome).root))
      ? await fs.realpath(codexHome) : codexHome,
    model: original.model ?? (selected.model as string | undefined) ?? native.model,
    reasoningEffort: original.reasoningEffort ?? (selected.model_reasoning_effort as string | undefined) ?? native.reasoningEffort,
    modelProvider: (selected.model_provider as string | undefined) ?? native.modelProvider,
    reasoningSummary: (selected.model_reasoning_summary as string | undefined) ?? native.reasoningSummary,
    serviceTier: (selected.service_tier as string | undefined) ?? native.serviceTier,
    ...(selected.service_tier === undefined && native.nativeServiceTierAbsent
      ? { nativeServiceTierAbsent: true as const } : {}),
    providerConfig: selected.model_providers as JsonObject | undefined,
    parentSandbox
  });
}

async function originalParentSettings(
  codexHome: string,
  parent: { threadId: string; turnId?: string | null; startedAt?: string }
): Promise<Partial<DeepScanExecutionSettings>> {
  // Native config/read represents omitted selections as null. The existing
  // parent record contains the provider and summary actually used by that turn.
  // History can be disabled or unavailable; configured selections still work.
  try {
    const log = await readScanLogs({
      scanId: parent.threadId, threadId: parent.threadId, executionThreadIds: [],
      codexHome, allowMissingRoot: true
    });
    const settings: Partial<DeepScanExecutionSettings> = {};
    let applied: Partial<DeepScanExecutionSettings> | undefined;
    const cutoff = parent.startedAt === undefined ? Infinity : Date.parse(parent.startedAt);
    for (const entry of log.events) {
      const event = entry.event as Record<string, unknown>;
      const timestamp = typeof event.timestamp === "string" ? Date.parse(event.timestamp) : undefined;
      if (timestamp !== undefined && timestamp > cutoff) continue;
      const payload = event.payload;
      if (!payload || typeof payload !== "object" || Array.isArray(payload)) continue;
      const context = payload as Record<string, unknown>;
      if (event.type === "event_msg" && context.type === "thread_settings_applied") {
        if (typeof context.thread_id === "string" && context.thread_id !== parent.threadId) continue;
        const snapshot = context.thread_settings;
        if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) continue;
        const value = snapshot as Record<string, unknown>;
        applied = {
          model: typeof value.model === "string" ? value.model : undefined,
          modelProvider: typeof value.model_provider_id === "string" ? value.model_provider_id : undefined,
          reasoningEffort: typeof value.reasoning_effort === "string" ? value.reasoning_effort : undefined,
          reasoningSummary: typeof value.reasoning_summary === "string" ? value.reasoning_summary : undefined,
          // A persisted native absent tier and explicit standard both omit the
          // request tier. This does not infer a tier from missing history.
          serviceTier: typeof value.service_tier === "string" ? value.service_tier
            : value.service_tier === undefined ? "default" : undefined,
          ...(value.service_tier === undefined ? { nativeServiceTierAbsent: true as const } : {})
        };
      }
      if (event.type === "session_meta" && typeof context.model_provider === "string") {
        settings.modelProvider = context.model_provider;
      }
      if (event.type === "turn_context") {
        if (parent.turnId && context.turn_id !== parent.turnId) continue;
        if (typeof context.model === "string") settings.model = context.model;
        if (typeof context.effort === "string") settings.reasoningEffort = context.effort;
        if (typeof context.summary === "string") settings.reasoningSummary = context.summary;
      }
    }
    // Applied snapshots contain native selected values. Newer turn-context
    // summaries are only a compatibility field, not the active selection.
    return { ...settings, ...applied };
  } catch {
    return {};
  }
}

/** Called by the acquired coordinator before it starts any worker. */
export async function loadOrCaptureDeepScanExecutionSettings(
  scanDir: string,
  capture: () => Promise<DeepScanExecutionSettings>,
  original?: Pick<DeepScanRunState, "model" | "reasoningEffort" | "usageOwner" | "createdAt">
): Promise<DeepScanExecutionSettings> {
  const path = join(scanDir, "artifacts", "deep_discovery", "execution-settings.json");
  let settings: DeepScanExecutionSettings;
  try {
    const saved = JSON.parse(await fs.readFile(path, "utf8"));
    if (saved.version !== 1) {
      throw new Error("This Deep Scan uses an unsupported execution settings version.");
    }
    settings = executionSettings(saved.settings);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    settings = executionSettings(await capture());
    await writeJsonAtomic(path, { version: 1, settings });
    return settings;
  }
  if (!original || (settings.model !== undefined && settings.reasoningEffort !== undefined
    && settings.modelProvider !== undefined && settings.reasoningSummary !== undefined
    && settings.serviceTier !== undefined)) return settings;
  // Earlier snapshots can omit native selections. Recover only from the saved
  // home and recorded owner; the continuation's current config is not history.
  const owner = original.usageOwner;
  const native = !owner?.threadId ? {} : await originalParentSettings(settings.codexHome, {
    ...owner, threadId: owner.threadId, startedAt: original.createdAt
  });
  const recovered = executionSettings({
    ...settings,
    model: settings.model ?? original.model ?? native.model,
    reasoningEffort: settings.reasoningEffort ?? original.reasoningEffort ?? native.reasoningEffort,
    modelProvider: settings.modelProvider ?? native.modelProvider,
    reasoningSummary: settings.reasoningSummary ?? native.reasoningSummary,
    serviceTier: settings.serviceTier ?? native.serviceTier,
    ...(settings.serviceTier === undefined && native.nativeServiceTierAbsent
      ? { nativeServiceTierAbsent: true as const } : {})
  });
  if (JSON.stringify(recovered) !== JSON.stringify(settings)) {
    await writeJsonAtomic(path, { version: 1, settings: recovered });
  }
  return recovered;
}

export function restoredDeepScanWorkerSettings(
  settings: DeepScanExecutionSettings,
  currentParentSandbox: DeepWorkerParentSandbox,
  environment: () => NodeJS.ProcessEnv = () => process.env
): {
  codexOptions: CodexOptions;
  model?: string;
  reasoningEffort?: string;
  parentSandbox: DeepWorkerParentSandbox;
} {
  const originalSandbox = settings.parentSandbox;
  const depths = [originalSandbox?.globScanMaxDepth, currentParentSandbox.globScanMaxDepth]
    .filter((depth): depth is number => depth !== undefined);
  return {
    model: settings.model,
    reasoningEffort: settings.reasoningEffort,
    parentSandbox: {
      filesystemDenies: [...new Set([
        ...(originalSandbox?.filesystemDenies ?? []), ...currentParentSandbox.filesystemDenies
      ])],
      ...(depths.length === 0 ? {} : { globScanMaxDepth: Math.max(...depths) })
    },
    codexOptions: {
      codexPathOverride: settings.codexPath,
      // The executor reads this property for each launch. API keys can refresh;
      // only the original account home and non-secret selections are bound.
      get env() {
        return Object.fromEntries(Object.entries({ ...environment(), CODEX_CLI_PATH: settings.codexPath, CODEX_HOME: settings.codexHome })
          .filter((entry): entry is [string, string] => entry[1] !== undefined));
      },
      config: {
        ...(settings.model === undefined ? {} : { model: settings.model }),
        ...(settings.reasoningEffort === undefined ? {} : { model_reasoning_effort: settings.reasoningEffort }),
        ...(settings.modelProvider === undefined ? {} : { model_provider: settings.modelProvider }),
        ...(settings.reasoningSummary === undefined ? {} : { model_reasoning_summary: settings.reasoningSummary }),
        ...(settings.serviceTier === undefined ? {} : { service_tier: settings.serviceTier }),
        ...(settings.providerConfig === undefined ? {} : { model_providers: settings.providerConfig as NonNullable<CodexOptions["config"]>[string] })
      }
    }
  };
}

function executionSettings(value: DeepScanExecutionSettings): DeepScanExecutionSettings {
  const provider = scanPreflightCodexConfig({
    ...(value.modelProvider === undefined ? {} : { model_provider: value.modelProvider }),
    ...(value.providerConfig === undefined ? {} : { model_providers: value.providerConfig })
  }).model_providers as JsonObject | undefined;
  const settings: DeepScanExecutionSettings = {
    codexPath: value.codexPath,
    codexHome: value.codexHome,
    model: value.model,
    modelProvider: value.modelProvider,
    reasoningEffort: value.reasoningEffort,
    reasoningSummary: value.reasoningSummary,
    serviceTier: value.serviceTier,
    ...(value.nativeServiceTierAbsent === true ? { nativeServiceTierAbsent: true } : {}),
    ...(provider === undefined ? {} : { providerConfig: provider }),
    ...(value.parentSandbox === undefined ? {} : { parentSandbox: {
      filesystemDenies: [...value.parentSandbox.filesystemDenies],
      ...(value.parentSandbox.globScanMaxDepth === undefined ? {} : {
        globScanMaxDepth: value.parentSandbox.globScanMaxDepth
      })
    } })
  };
  if (typeof settings.codexPath !== "string" || typeof settings.codexHome !== "string") {
    throw new Error("Deep Scan execution settings are missing the recorded executable or Codex home.");
  }
  return settings;
}
