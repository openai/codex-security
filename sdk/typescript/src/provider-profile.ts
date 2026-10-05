import { randomUUID } from "node:crypto";
import { lstat, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import type { Codex, CodexOptions } from "@openai/codex-sdk";
import {
  resolveCodexProfile,
  modelProviderConfigOverride,
  writeCodexConfig,
  type JsonObject,
} from "./config.js";
import { isRecord } from "./record.js";
import { bundledCodexSdkEnvironment } from "./codex-sdk-environment.js";
import {
  bundledPluginRoot,
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
  const providers = resolveCodexProfile(config)["model_providers"];
  if (!isRecord(providers) || Object.keys(providers).length === 0)
    return command;
  const client = await nativeProfileClient();
  const definitions = client.preflightProviderDefinitions(
    providers,
  ) as JsonObject;
  if (Object.keys(definitions).length === 0) return command;
  return {
    ...command,
    args: [
      ...(command.args ?? []),
      ...modelProviderConfigOverride({ model_providers: definitions }).flatMap(
        (value) => ["-c", value],
      ),
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

/** The pinned SDK lacks the native CLI's private profile-file option. */
export async function createProfileCodex(
  options: CodexOptions,
  profileName: string,
): Promise<Codex> {
  const command =
    options.codexPathOverride ?? resolveCodexCommand(options.env).command;
  const client = await nativeProfileClient();
  return client.createCodexProfileClient({
    ...options,
    codexPathOverride: executablePathForSpawn(command),
    profileName,
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
