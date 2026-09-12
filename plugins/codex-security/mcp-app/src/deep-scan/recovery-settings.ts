import { promises as fs } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, win32 } from "node:path";
import type { CodexOptions } from "@openai/codex-sdk";
import { parse as parseToml } from "smol-toml";
import { scanPreflightCodexConfig } from "../../../../../sdk/typescript/src/preflight-config.js";
import { resolveCodexProfile, type JsonObject } from "../../../../../sdk/typescript/src/config.js";
import { writeJsonAtomic } from "./artifacts.js";
import { resolveCodexPath } from "./executor.js";
import type { DeepWorkerParentSandbox } from "./parent-sandbox.js";

/** Credentials and arbitrary environment/configuration stay with Codex. */
export interface DeepScanExecutionSettings {
  codexPath: string;
  codexHome: string;
  model?: string;
  modelProvider?: string;
  reasoningEffort?: string;
  reasoningSummary?: string;
  serviceTier?: string;
  providerConfig?: JsonObject;
  parentSandbox?: DeepWorkerParentSandbox;
}

export async function captureDeepScanExecutionSettings(
  original: { model?: string; reasoningEffort?: string },
  parentSandbox: DeepWorkerParentSandbox,
  environment: NodeJS.ProcessEnv = process.env
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
  return executionSettings({
    codexPath: resolveCodexPath(environment, process.platform, process.arch, process.cwd()),
    codexHome: !isAbsolute(codexHome)
      || (process.platform === "win32" && ["\\", "/"].includes(win32.parse(codexHome).root))
      ? await fs.realpath(codexHome) : codexHome,
    model: original.model ?? selected.model as string | undefined,
    reasoningEffort: original.reasoningEffort ?? selected.model_reasoning_effort as string | undefined,
    modelProvider: selected.model_provider as string | undefined,
    reasoningSummary: selected.model_reasoning_summary as string | undefined,
    serviceTier: selected.service_tier as string | undefined,
    providerConfig: selected.model_providers as JsonObject | undefined,
    parentSandbox
  });
}

/** Called by the acquired coordinator before it starts any worker. */
export async function loadOrCaptureDeepScanExecutionSettings(
  scanDir: string,
  capture: () => Promise<DeepScanExecutionSettings>
): Promise<DeepScanExecutionSettings> {
  const path = join(scanDir, "artifacts", "deep_discovery", "execution-settings.json");
  try {
    const saved = JSON.parse(await fs.readFile(path, "utf8"));
    if (saved.version !== 1) {
      throw new Error("This Deep Scan uses an unsupported execution settings version.");
    }
    return executionSettings(saved.settings);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const settings = executionSettings(await capture());
  await writeJsonAtomic(path, { version: 1, settings });
  return settings;
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
