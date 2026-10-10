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
  await writeCodexConfig(path, {
    model_providers: isRecord(providers) ? providers : {},
  });
  return { name, path, cleanup: () => rm(path, { force: true }) };
}

/** Restore a saved provider from the credential home, never from scan artifacts. */
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
  // The managed home has stricter ownership rules. Native execution preserves
  // the invoking home's permissions and reads the same private profile files.
  if (profile["home"] === "managed")
    await requireSecureCredentialHome(codexHome);
  const saved = parse(
    await readFile(join(codexHome, `${profile["name"]}.config.toml`), "utf8"),
  );
  if (!isRecord(saved["model_providers"])) {
    throw new CodexSecurityError(
      "The saved provider profile contains no provider configuration.",
    );
  }
  return { ...config, model_providers: saved["model_providers"] as JsonObject };
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
