import { randomUUID } from "node:crypto";
import { lstat, mkdir, readFile, realpath, rm } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { parse } from "smol-toml";
import { CodexSecurityError } from "./errors.js";
import type { Codex, CodexOptions } from "@openai/codex-sdk";
import { configuredCodexHome } from "./auth.js";
import { environmentEntry, expandHomePath } from "./codex-home.js";
import {
  resolveCodexProfile,
  modelProviderConfigOverride,
  inlineToml,
  writeCodexConfig,
  type JsonObject,
} from "./config.js";
import { isRecord } from "./record.js";
import { bundledCodexSdkEnvironment } from "./codex-sdk-environment.js";
import {
  bundledPluginRoot,
  codexSecurityCredentialHome,
  requireSecureCredentialHome,
  type ProcessEnvironment,
  acquireCodexSecurityCredentialHomeLock,
  executablePathForSpawn,
  requirePrivateCredentialHome,
  resolveCodexCommand,
  type CodexCommand,
} from "./runtime.js";

export interface ProviderProfile {
  name: string;
  path: string;
  cleanup(): Promise<void>;
}

/** Native no-turn commands need provider metadata when managed policy selects it. */
export async function providerPreflightCommand(
  command: CodexCommand,
  config: JsonObject,
): Promise<CodexCommand> {
  const resolved = resolveCodexProfile(config);
  const overrides: string[] = [];
  const providers = resolved["model_providers"];
  if (isRecord(providers) && Object.keys(providers).length > 0) {
    const client = await nativeProfileClient();
    const definitions = client.preflightProviderDefinitions(
      providers,
    ) as JsonObject;
    overrides.push(
      ...modelProviderConfigOverride({ model_providers: definitions }),
    );
  }
  if (resolved["model_provider"] !== undefined)
    overrides.push(`model_provider=${inlineToml(resolved["model_provider"])}`);
  if (overrides.length === 0) return command;
  return {
    ...command,
    args: [
      ...(command.args ?? []),
      ...overrides.flatMap((value) => ["-c", value]),
    ],
  };
}

/** Provider definitions use a native file layer, never process arguments. */
export async function createProviderProfile(
  codexHome: string,
  config: JsonObject,
  options: Parameters<typeof requirePrivateCredentialHome>[2] = {},
): Promise<ProviderProfile> {
  const providers = resolveCodexProfile(config)["model_providers"];
  return createPrivateProfile(
    codexHome,
    {
      model_providers: isRecord(providers) ? providers : {},
    },
    options,
  );
}

/** Preserve credential-bearing replay tables outside readable scan history. */
export async function createReplayProfile(
  codexHome: string,
  config: JsonObject,
): Promise<ProviderProfile> {
  const resolved = resolveCodexProfile(config);
  const saved: JsonObject = {};
  for (const key of ["model_providers", "mcp_servers"]) {
    if (isRecord(resolved[key])) saved[key] = resolved[key] as JsonObject;
  }
  return createPrivateProfile(codexHome, saved);
}

async function createPrivateProfile(
  codexHome: string,
  config: JsonObject,
  options: Parameters<typeof requirePrivateCredentialHome>[2] = {},
): Promise<ProviderProfile> {
  const name = `codex_security_${randomUUID()}`;
  const path = join(codexHome, `${name}.config.toml`);
  if ((options.platform ?? process.platform) === "win32") {
    await mkdir(codexHome, { recursive: true, mode: 0o700 });
    await requirePrivateCredentialHome(
      await lstat(codexHome),
      codexHome,
      options,
    );
  }
  await writeCodexConfig(path, config);
  return { name, path, cleanup: () => rm(path, { force: true }) };
}

/** Restore saved private settings from the credential home, never from scan artifacts. */
export async function restoreReplayProfile(
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
      "The saved scan contains an invalid replay profile.",
    );
  }
  const requestedHome = environmentEntry(environment, "CODEX_HOME");
  const codexHome =
    profile["home"] === "ambient"
      ? await realpath(
          requestedHome?.trim()
            ? expandHomePath(requestedHome, environment)
            : configuredCodexHome(environment),
        )
      : codexSecurityCredentialHome(environment);
  // The managed home has stricter ownership rules. Native execution preserves
  // the invoking home's permissions and reads the same private profile files.
  if (profile["home"] === "managed")
    await requireSecureCredentialHome(codexHome);
  const saved = parse(
    await readFile(join(codexHome, `${profile["name"]}.config.toml`), "utf8"),
  );
  const restored: JsonObject = {};
  for (const key of ["model_providers", "mcp_servers"]) {
    if (isRecord(saved[key])) restored[key] = saved[key] as JsonObject;
  }
  if (Object.keys(restored).length === 0) {
    throw new CodexSecurityError(
      "The saved replay profile contains no private configuration.",
    );
  }
  return { ...config, ...restored };
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

/** Verify the effective helper policy before starting exec with a private profile. */
export async function preflightReadOnlyProfileCodex(
  options: CodexOptions,
  expectedProfile: JsonObject,
  providerConfig: JsonObject,
  cwd: string,
  signal?: AbortSignal,
): Promise<{ permissionProfileId: string; configOverrides: string[] }> {
  const preflight = await nativePermissionPreflight();
  const permissionProfileId =
    preflight.DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID as string;
  const configOverrides = [
    ...(options.configOverrides ?? []),
    `default_permissions=${JSON.stringify(permissionProfileId)}`,
    `permissions.${permissionProfileId}=${inlineToml(expectedProfile)}`,
  ];
  const command =
    options.codexPathOverride ?? resolveCodexCommand(options.env).command;
  const client = await nativeProfileClient();
  const providers = resolveCodexProfile(providerConfig)["model_providers"];
  const definitions = isRecord(providers)
    ? (client.preflightProviderDefinitions(providers) as JsonObject)
    : {};
  const env =
    options.env === undefined
      ? undefined
      : bundledCodexSdkEnvironment(command, options.env);
  await withCodexPreflightLock(env, signal, async () => {
    await preflight.preflightDeepScanWorkerPermissionProfile({
      codexPath: executablePathForSpawn(command),
      cwd,
      configOverrides: [
        ...client.profileConfigOverrides(options.config ?? {}),
        ...configOverrides,
      ],
      providerConfigOverrides: modelProviderConfigOverride({
        model_providers: definitions,
      }),
      ...(env === undefined
        ? {}
        : {
            env: {
              ...env,
              ...(options.apiKey === undefined
                ? {}
                : { CODEX_API_KEY: options.apiKey }),
            },
          }),
      expectedProfile,
      signal: signal ?? new AbortController().signal,
      context: "helper",
    });
  });
  return { permissionProfileId, configOverrides };
}

/** Older workers must inherit the same effective provider as the parent scan. */
export async function legacyWorkerUsesScanProvider(
  command: CodexCommand,
  environment: Record<string, string>,
  cwd: string,
  modelProvider: string,
  signal?: AbortSignal,
): Promise<boolean> {
  const preflight = await nativePermissionPreflight();
  const env = bundledCodexSdkEnvironment(command.command, environment);
  return await withCodexPreflightLock(env, signal, async () => {
    const options = {
      codexPath: executablePathForSpawn(command.command),
      commandArgs: command.args,
      cwd,
      env,
      signal: signal ?? new AbortController().signal,
      context: "helper",
    };
    const worker = await preflight.readDeepScanRuntimeConfig({
      ...options,
      configOverrides: [],
    });
    const parent = await preflight.readDeepScanRuntimeConfig({
      ...options,
      configOverrides: [`model_provider=${JSON.stringify(modelProvider)}`],
    });
    return (
      (worker.model_provider ?? "openai") ===
      (parent.model_provider ?? "openai")
    );
  });
}

async function withCodexPreflightLock<T>(
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

async function nativePermissionPreflight() {
  return await import(
    pathToFileURL(
      join(
        await bundledPluginRoot(),
        "mcp",
        "permission-profile-preflight.mjs",
      ),
    ).href
  );
}

async function nativeProfileClient() {
  return await import(
    pathToFileURL(
      join(await bundledPluginRoot(), "scripts", "codex_profile.mjs"),
    ).href
  );
}
