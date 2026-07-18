import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  rename,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import { parse } from "smol-toml";
import { ConfigurationError } from "./errors.js";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | JsonObject;
export interface JsonObject {
  [key: string]: JsonValue;
}

export interface CodexSecurityConfig {
  pluginPath?: string;
  codexOverrides?: JsonObject;
  pythonPath?: string;
}

export const DEFAULT_CODEX_CONFIG: Readonly<JsonObject> = {
  cli_auth_credentials_store: "file",
  features: {
    plugins: true,
    multi_agent: true,
    enable_fanout: true,
    goals: true,
  },
  agents: {
    max_threads: 12,
    max_depth: 2,
  },
};

export const NATIVE_V2_CODEX_CONFIG: Readonly<JsonObject> = {
  cli_auth_credentials_store: "file",
  features: {
    plugins: true,
    goals: true,
    multi_agent_v2: {
      enabled: true,
      max_concurrent_threads_per_session: 9,
    },
  },
};

deepFreezeJson(DEFAULT_CODEX_CONFIG);
deepFreezeJson(NATIVE_V2_CODEX_CONFIG);

const BARE_KEY = /^[A-Za-z0-9_-]+$/;

export async function mergedCodexConfig(
  config: CodexSecurityConfig,
  options: { pluginRoot?: string } = {},
): Promise<JsonObject> {
  if (config.codexOverrides !== undefined && !isObject(config.codexOverrides)) {
    throw new ConfigurationError("codexOverrides must be an object.");
  }
  const overrides = cloneJson(config.codexOverrides ?? {});
  validateOverrides(overrides);
  const nativeV2 =
    options.pluginRoot !== undefined &&
    (await supportsNativeMultiAgentV2(options.pluginRoot));
  if (nativeV2) {
    validateNativeMultiAgentV2Overrides(overrides);
  }
  const defaults = nativeV2 ? NATIVE_V2_CODEX_CONFIG : DEFAULT_CODEX_CONFIG;
  return deepMerge(cloneJson(defaults), overrides);
}

export async function writeCodexConfig(
  path: string,
  config: JsonObject,
): Promise<void> {
  const parent = dirname(path);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const lines = flatten(config).map(
    ([keys, value]) => `${keys.map(tomlKey).join(".")} = ${tomlValue(value)}`,
  );
  const temporary = join(parent, `.${randomUUID()}.config.toml.tmp`);
  let created = false;
  try {
    const handle = await open(temporary, "wx", 0o600);
    created = true;
    try {
      await handle.chmod(0o600);
      await handle.writeFile(`${lines.join("\n")}\n`, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, path);
    created = false;
  } finally {
    if (created) {
      await unlink(temporary).catch(() => undefined);
    }
  }
}

async function supportsNativeMultiAgentV2(
  pluginRoot: string,
): Promise<boolean> {
  const profilesPath = join(
    pluginRoot,
    "preflight",
    "capability-profiles.toml",
  );
  let source: string;
  let file: FileHandle | undefined;
  let discovered = false;
  try {
    const parent = dirname(profilesPath);
    const parentMetadata = await lstat(parent);
    const metadata = await lstat(profilesPath);
    discovered = true;
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error("capability profile is not a regular file");
    }
    file = await open(
      profilesPath,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const opened = await file.stat();
    if (
      !opened.isFile() ||
      opened.dev !== metadata.dev ||
      opened.ino !== metadata.ino
    ) {
      throw new Error("capability profile changed before reading");
    }
    const bytes = await file.readFile();
    const currentParent = await lstat(parent);
    const current = await lstat(profilesPath);
    if (
      !currentParent.isDirectory() ||
      currentParent.isSymbolicLink() ||
      currentParent.dev !== parentMetadata.dev ||
      currentParent.ino !== parentMetadata.ino ||
      !current.isFile() ||
      current.isSymbolicLink() ||
      current.dev !== opened.dev ||
      current.ino !== opened.ino
    ) {
      throw new Error("capability profile changed while reading");
    }
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    const code = nodeErrorCode(error);
    if (code === "ENOENT" && !discovered) {
      return false;
    }
    throw new ConfigurationError(
      `Selected plugin has an unreadable capability profile: ${profilesPath}: ${String(error)}`,
      { cause: error },
    );
  } finally {
    await file?.close();
  }

  let data: unknown;
  try {
    data = parse(source);
  } catch (error) {
    throw new ConfigurationError(
      `Selected plugin has an unreadable capability profile: ${profilesPath}: ${String(error)}`,
      { cause: error },
    );
  }
  if (!isObject(data)) {
    throw new ConfigurationError(
      "Selected plugin capability profiles must be a TOML table.",
    );
  }
  const profiles = data["profiles"] ?? {};
  if (!isObject(profiles)) {
    throw new ConfigurationError(
      "Selected plugin capability profiles must be a TOML table.",
    );
  }
  const deepProfile = profiles["deep_security_scan"];
  if (deepProfile === undefined) {
    return false;
  }
  if (!isObject(deepProfile)) {
    throw new ConfigurationError(
      "Selected plugin deep_security_scan capability profile must be a TOML table.",
    );
  }
  const requirements = deepProfile["requirements"] ?? [];
  if (!Array.isArray(requirements) || !requirements.every(isObject)) {
    throw new ConfigurationError(
      "Selected plugin deep_security_scan requirements must be TOML tables.",
    );
  }
  if (
    requirements.some(
      (requirement) =>
        requirement["capability"] === "native_multi_agent_v2" &&
        requirement["severity"] === "block",
    )
  ) {
    return true;
  }

  const remediation = deepProfile["remediation"] ?? {};
  if (!isObject(remediation)) {
    throw new ConfigurationError(
      "Selected plugin deep_security_scan remediation must be a TOML table.",
    );
  }
  const variants = remediation["variants"] ?? [];
  if (!Array.isArray(variants) || !variants.every(isObject)) {
    throw new ConfigurationError(
      "Selected plugin deep_security_scan remediation variants must be TOML tables.",
    );
  }
  for (const variant of variants) {
    if (variant["mode"] !== "v2") {
      continue;
    }
    const patches = variant["patches"] ?? [];
    if (!Array.isArray(patches) || !patches.every(isObject)) {
      throw new ConfigurationError(
        "Selected plugin v2 remediation patches must be TOML tables.",
      );
    }
    return patches.some(
      (patch) =>
        patch["path"] === "features.multi_agent_v2.enabled" &&
        patch["value"] === true,
    );
  }
  return false;
}

function validateOverrides(overrides: JsonObject): void {
  if ("plugins" in overrides || "marketplaces" in overrides) {
    throw new ConfigurationError(
      "Codex Security owns plugin loading configuration.",
    );
  }
  const features = overrides["features"];
  if ("features" in overrides && !isObject(features)) {
    throw new ConfigurationError(
      "Codex override features must be a TOML table.",
    );
  }
  if (isObject(features) && "plugins" in features) {
    throw new ConfigurationError(
      "Codex Security owns plugin loading configuration.",
    );
  }
  const profiles = overrides["profiles"];
  if (profiles === undefined) {
    return;
  }
  if (!isObject(profiles)) {
    throw new ConfigurationError(
      "Codex override profiles must be TOML tables.",
    );
  }
  for (const [name, profile] of Object.entries(profiles)) {
    if (!isObject(profile)) {
      throw new ConfigurationError(
        `Codex override profile ${name} must be a TOML table.`,
      );
    }
    const profileFeatures = profile["features"];
    if (profileFeatures !== undefined && !isObject(profileFeatures)) {
      throw new ConfigurationError(
        `Codex override profile ${name} features must be a TOML table.`,
      );
    }
    if (isObject(profileFeatures) && "plugins" in profileFeatures) {
      throw new ConfigurationError(
        `Codex Security owns plugin loading configuration in profile ${name}.`,
      );
    }
  }
}

function validateNativeMultiAgentV2Overrides(overrides: JsonObject): void {
  const agents = overrides["agents"];
  if (isObject(agents) && "max_threads" in agents) {
    throw new ConfigurationError(
      "The selected Codex Security plugin requires native multi-agent v2; " +
        "agents.max_threads is a legacy v1 setting. Use " +
        "features.multi_agent_v2.max_concurrent_threads_per_session instead.",
    );
  }
  if ("features" in overrides) {
    const features = overrides["features"];
    if (!isObject(features)) {
      throw new ConfigurationError(
        "The selected Codex Security plugin requires native multi-agent v2; " +
          "features must remain a table containing features.multi_agent_v2.",
      );
    }
    if ("multi_agent_v2" in features) {
      const multiAgentV2 = features["multi_agent_v2"];
      if (!isObject(multiAgentV2)) {
        throw new ConfigurationError(
          "The selected Codex Security plugin requires native multi-agent v2; " +
            "features.multi_agent_v2 must remain a table with enabled = true.",
        );
      }
      if ("enabled" in multiAgentV2 && multiAgentV2["enabled"] !== true) {
        throw new ConfigurationError(
          "The selected Codex Security plugin requires native multi-agent v2; " +
            "features.multi_agent_v2.enabled cannot be disabled.",
        );
      }
    }
  }

  const profiles = overrides["profiles"];
  if (!isObject(profiles)) {
    return;
  }
  for (const [name, profile] of Object.entries(profiles)) {
    if (!isObject(profile)) {
      continue;
    }
    const profileAgents = profile["agents"];
    if (isObject(profileAgents) && "max_threads" in profileAgents) {
      throw new ConfigurationError(
        `The selected Codex Security plugin requires native multi-agent v2; profile ${name} agents.max_threads is a legacy v1 setting.`,
      );
    }
    const profileFeatures = profile["features"];
    if (!isObject(profileFeatures) || !("multi_agent_v2" in profileFeatures)) {
      continue;
    }
    const profileV2 = profileFeatures["multi_agent_v2"];
    if (
      !isObject(profileV2) ||
      ("enabled" in profileV2 && profileV2["enabled"] !== true)
    ) {
      throw new ConfigurationError(
        `The selected Codex Security plugin requires native multi-agent v2; profile ${name} features.multi_agent_v2 cannot be disabled.`,
      );
    }
  }
}

function deepMerge(base: JsonObject, overrides: JsonObject): JsonObject {
  for (const [key, value] of Object.entries(overrides)) {
    const existing = Object.hasOwn(base, key) ? base[key] : undefined;
    const merged =
      isObject(value) && isObject(existing)
        ? deepMerge({ ...existing }, value)
        : cloneJson(value);
    Object.defineProperty(base, key, {
      value: merged,
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
  return base;
}

function flatten(
  value: JsonObject,
  prefix: readonly string[] = [],
): Array<[readonly string[], Exclude<JsonValue, JsonObject>]> {
  const result: Array<[readonly string[], Exclude<JsonValue, JsonObject>]> = [];
  for (const key of Object.keys(value).sort()) {
    if (key.length === 0) {
      throw new ConfigurationError(
        "Codex configuration keys must be non-empty strings.",
      );
    }
    const item = value[key];
    if (item === undefined) {
      throw new ConfigurationError(
        `Missing Codex configuration value at ${[...prefix, key].join(".")}.`,
      );
    }
    const path = [...prefix, key];
    if (isObject(item)) {
      if (Object.keys(item).length === 0) {
        throw new ConfigurationError(
          `Empty Codex configuration object at ${path.join(".")}.`,
        );
      }
      result.push(...flatten(item, path));
    } else {
      result.push([path, item]);
    }
  }
  return result;
}

function tomlKey(value: string): string {
  requireWellFormedTomlString(value);
  return BARE_KEY.test(value) ? value : JSON.stringify(value);
}

function tomlValue(value: Exclude<JsonValue, JsonObject>): string {
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "string") {
    requireWellFormedTomlString(value);
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (Number.isNaN(value)) return "nan";
    if (value === Number.POSITIVE_INFINITY) return "inf";
    if (value === Number.NEGATIVE_INFINITY) return "-inf";
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new ConfigurationError(
        "TOML-backed Codex overrides cannot contain unsafe integer values.",
      );
    }
    return String(value);
  }
  if (Array.isArray(value)) {
    return `[${value
      .map((item) => (isObject(item) ? tomlInlineTable(item) : tomlValue(item)))
      .join(", ")}]`;
  }
  if (value === null) {
    throw new ConfigurationError(
      "TOML-backed Codex overrides cannot contain null values.",
    );
  }
  return unsupportedValue(value);
}

function tomlInlineTable(value: JsonObject): string {
  const entries = Object.keys(value)
    .sort()
    .map((key) => {
      if (key.length === 0) {
        throw new ConfigurationError(
          "Codex configuration keys must be non-empty strings.",
        );
      }
      const item = value[key];
      if (item === undefined) {
        throw new ConfigurationError(
          `Missing Codex configuration value at ${key}.`,
        );
      }
      return `${tomlKey(key)} = ${isObject(item) ? tomlInlineTable(item) : tomlValue(item)}`;
    });
  return `{ ${entries.join(", ")} }`;
}

function unsupportedValue(value: unknown): never {
  const type = Array.isArray(value) ? "array" : typeof value;
  throw new ConfigurationError(
    `Unsupported Codex configuration value: ${type}`,
  );
}

function cloneJson<T extends JsonValue>(value: T): T {
  return structuredClone(value);
}

function deepFreezeJson(value: JsonValue): void {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) {
    return;
  }
  for (const item of Array.isArray(value) ? value : Object.values(value)) {
    deepFreezeJson(item);
  }
  Object.freeze(value);
}

function isObject(value: unknown): value is Record<string, JsonValue> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function requireWellFormedTomlString(value: string): void {
  if (Buffer.from(value, "utf8").toString("utf8") !== value) {
    throw new ConfigurationError(
      "TOML-backed Codex overrides cannot contain malformed Unicode strings.",
    );
  }
}

function nodeErrorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String(error.code)
    : undefined;
}
