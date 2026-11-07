import { randomUUID } from "node:crypto";
import { lstat, mkdir, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import type { Codex, CodexOptions } from "@openai/codex-sdk";
import { parse } from "smol-toml";
import { CodexSecurityError } from "./errors.js";
import {
  configuredCodexHome,
  environmentEntry,
  resolveNativeCodexHome,
} from "./codex-home.js";
import {
  resolveCodexProfile,
  deepMerge,
  modelProviderConfigOverride,
  inlineToml,
  writeCodexConfig,
  writePrivateConfig,
  type JsonObject,
} from "./config.js";
import { isRecord } from "./record.js";
import { bundledCodexSdkEnvironment } from "./codex-sdk-environment.js";
import {
  acquireCodexSecurityCredentialHomeLock,
  bundledPluginRoot,
  codexSecurityCredentialHome,
  executablePathForSpawn,
  requirePrivateCredentialHome,
  requireSecureCredentialHome,
  resolveCodexCommand,
  type CodexCommand,
  type ProcessEnvironment,
} from "./runtime.js";

export interface ProviderProfile {
  name: string;
  path: string;
  cleanup(): Promise<void>;
}

export async function providerPreflightDefinitions(
  providers: JsonObject,
): Promise<JsonObject> {
  const client = await nativeProfileClient();
  return client.preflightProviderDefinitions(providers) as JsonObject;
}

/** Keep provider metadata, analytics consent, and attribution on no-turn commands. */
export async function providerPreflightCommand(
  command: CodexCommand,
  config: JsonObject,
): Promise<CodexCommand> {
  const resolved = resolveCodexProfile(config);
  const overrides: string[] = [];
  const providers = resolved["model_providers"];
  if (isRecord(providers) && Object.keys(providers).length > 0) {
    const definitions = await providerPreflightDefinitions(providers);
    overrides.push(
      ...modelProviderConfigOverride({ model_providers: definitions }),
    );
  }
  if (resolved["model_provider"] !== undefined)
    overrides.push(`model_provider=${inlineToml(resolved["model_provider"])}`);
  // These commands cannot load a private profile while preserving their auth
  // home. Exporter headers stay in native configuration, never copied into argv.
  for (const key of ["analytics", "responses_api_metadata"]) {
    const value = resolved[key];
    if (value !== undefined) overrides.push(`${key}=${inlineToml(value)}`);
  }
  if (overrides.length === 0) return command;
  return {
    ...command,
    args: [
      ...(command.args ?? []),
      ...overrides.flatMap((value) => ["-c", value]),
    ],
  };
}

/** Execution settings that must survive a saved scan's continuation. */
export function scanReplaySettings(config: JsonObject): JsonObject {
  return Object.fromEntries(
    [
      "analytics",
      "developer_instructions",
      "shell_environment_policy",
      "mcp_servers",
      "model_instructions_file",
      "experimental_compact_prompt_file",
      "model_catalog_json",
      "sqlite_home",
    ]
      .filter((key) => config[key] !== undefined)
      .map((key) => [key, config[key]!]),
  );
}

/** Retain explicit settings omitted from the readable recipe when its file reloads. */
export function privateReplayOverrides(
  config: JsonObject,
  recipe: JsonObject,
): JsonObject {
  const result: JsonObject = {};
  for (const [key, value] of Object.entries(config)) {
    const saved = recipe[key];
    if (value === null || saved === undefined) {
      result[key] = structuredClone(value);
    } else if (isRecord(value) && isRecord(saved)) {
      const nested = privateReplayOverrides(
        value as JsonObject,
        saved as JsonObject,
      );
      if (Object.keys(nested).length > 0) result[key] = nested;
    }
  }
  return result;
}

/** Provider definitions and saved execution settings use a private native file layer. */
export async function createProviderProfile(
  codexHome: string,
  config: JsonObject,
  options: Parameters<typeof requirePrivateCredentialHome>[2] & {
    replay?: boolean;
  } = {},
): Promise<ProviderProfile> {
  const name = `codex_security_${randomUUID()}`;
  const path = join(
    codexHome,
    `${name}.config.${options.replay ? "json" : "toml"}`,
  );
  if ((options.platform ?? process.platform) === "win32") {
    await mkdir(codexHome, { recursive: true, mode: 0o700 });
    await requirePrivateCredentialHome(
      await lstat(codexHome),
      codexHome,
      options,
    );
  }
  if (options.replay) {
    await writePrivateConfig(path, JSON.stringify(config));
  } else {
    const resolved = resolveCodexProfile(config);
    const providers = resolved["model_providers"];
    const settings = scanReplaySettings(resolved);
    for (const key of ["openai_base_url", "chatgpt_base_url"]) {
      if (typeof resolved[key] === "string") settings[key] = resolved[key];
    }
    await writeCodexConfig(path, {
      model_providers: isRecord(providers) ? providers : {},
      ...settings,
    });
  }
  return { name, path, cleanup: () => rm(path, { force: true }) };
}

/** Restore private replay settings from the credential home, never scan artifacts. */
export async function restoreProviderProfile(
  config: JsonObject,
  profile: unknown,
  environment: ProcessEnvironment,
): Promise<JsonObject> {
  if (profile === undefined) return config;
  if (
    !isRecord(profile) ||
    typeof profile["name"] !== "string" ||
    (profile["home"] !== "ambient" && profile["home"] !== "managed") ||
    !/^codex_security_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(
      profile["name"],
    )
  ) {
    throw new CodexSecurityError(
      "The saved scan contains an invalid provider profile.",
    );
  }
  const requestedHome = environmentEntry(environment, "CODEX_HOME");
  const codexHome =
    profile["home"] === "ambient"
      ? await resolveNativeCodexHome(
          requestedHome?.trim()
            ? requestedHome
            : configuredCodexHome(environment),
          environment,
        )
      : codexSecurityCredentialHome(environment);
  if (profile["home"] === "managed")
    await requireSecureCredentialHome(codexHome);
  let saved: unknown;
  try {
    saved = JSON.parse(
      await readFile(join(codexHome, `${profile["name"]}.config.json`), "utf8"),
    );
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    saved = parse(
      await readFile(join(codexHome, `${profile["name"]}.config.toml`), "utf8"),
    );
  }
  if (
    !isRecord(saved) ||
    (saved["model_providers"] !== undefined &&
      saved["model_providers"] !== null &&
      !isRecord(saved["model_providers"]))
  ) {
    throw new CodexSecurityError(
      "The saved provider profile contains no provider configuration.",
    );
  }
  const { model_providers: providers, ...overrides } = saved;
  return {
    ...deepMerge({ ...config }, overrides as JsonObject),
    ...(providers === null ||
    (isRecord(providers) && Object.keys(providers).length > 0)
      ? { model_providers: providers as JsonObject | null }
      : {}),
  };
}

/** The pinned SDK lacks the native CLI's private profile-file option. */
export async function createProfileCodex(
  options: CodexOptions,
  profileName: string,
  requestedPermissionProfile?: string,
): Promise<Codex> {
  const command =
    options.codexPathOverride ?? resolveCodexCommand(options.env).command;
  const client = await nativeProfileClient();
  return client.createCodexProfileClient({
    ...options,
    codexPathOverride: executablePathForSpawn(command),
    profileName,
    requestedPermissionProfile,
    ...(options.env === undefined
      ? {}
      : { env: bundledCodexSdkEnvironment(command, options.env) }),
  }) as Codex;
}

async function nativeProfileClient() {
  return await import(
    pathToFileURL(
      join(await bundledPluginRoot(), "scripts", "codex_profile.mjs"),
    ).href
  );
}

export async function withCodexPreflightLock<T>(
  env: Record<string, string> | undefined,
  signal: AbortSignal | undefined,
  operation: () => Promise<T>,
): Promise<T> {
  // App-server treats concurrent cold-home SQLite initialization as fatal.
  // Keep the lock in a private child so a readable native home stays readable.
  const lockDirectory = join(
    configuredCodexHome(env ?? process.env),
    ".codex-security-preflight",
  );
  await mkdir(lockDirectory, { recursive: true, mode: 0o700 });
  const release = await acquireCodexSecurityCredentialHomeLock(
    lockDirectory,
    signal,
  );
  try {
    return await operation();
  } finally {
    await release();
  }
}
