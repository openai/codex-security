import { randomUUID } from "node:crypto";
import { rm } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import type { Codex, CodexOptions } from "@openai/codex-sdk";
import {
  resolveCodexProfile,
  writeCodexConfig,
  type JsonObject,
} from "./config.js";
import { isRecord } from "./record.js";
import { bundledCodexSdkEnvironment } from "./codex-sdk-environment.js";
import {
  bundledPluginRoot,
  executablePathForSpawn,
  resolveCodexCommand,
} from "./runtime.js";

export interface ProviderProfile {
  name: string;
  path: string;
  cleanup(): Promise<void>;
}

/** Provider definitions use a native file layer, never process arguments. */
export async function createProviderProfile(
  codexHome: string,
  config: JsonObject,
): Promise<ProviderProfile> {
  const effective = resolveCodexProfile(config);
  const providers = effective["model_providers"];
  const provider = effective["model_provider"];
  const selected = isRecord(providers)
    ? typeof provider === "string" && Object.hasOwn(providers, provider)
      ? { [provider]: providers[provider]! }
      : providers
    : {};
  const name = `codex_security_${randomUUID()}`;
  const path = join(codexHome, `${name}.config.toml`);
  await writeCodexConfig(path, { model_providers: selected });
  return { name, path, cleanup: () => rm(path, { force: true }) };
}

/** The pinned SDK lacks the native CLI's private profile-file option. */
export async function createProfileCodex(
  options: CodexOptions,
  profileName: string,
): Promise<Codex> {
  const command =
    options.codexPathOverride ?? resolveCodexCommand(options.env).command;
  const client = await import(
    pathToFileURL(
      join(await bundledPluginRoot(), "scripts", "codex_profile.mjs"),
    ).href
  );
  return client.createCodexProfileClient({
    ...options,
    codexPathOverride: executablePathForSpawn(command),
    profileName,
    ...(options.env === undefined
      ? {}
      : { env: bundledCodexSdkEnvironment(command, options.env) }),
  }) as Codex;
}
