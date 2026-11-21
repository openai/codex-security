import { parse, stringify } from "smol-toml";
import { ConfigurationError } from "./config-errors.js";
import { isRecord } from "./record.js";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | JsonObject;
export interface JsonObject {
  [key: string]: JsonValue;
}

export function selectedScanProfile(
  config: Readonly<JsonObject>,
): Record<string, JsonValue> | undefined {
  const profileName = config["profile"];
  const profiles = config["profiles"];
  const configuredProfile =
    typeof profileName === "string" &&
    isObject(profiles) &&
    Object.hasOwn(profiles, profileName)
      ? profiles[profileName]
      : undefined;
  return isObject(configuredProfile) ? configuredProfile : undefined;
}

export const NULL_TOML_VALUE_MESSAGE =
  "Codex TOML overrides cannot contain null values.";

function containsNullArrayElement(value: JsonValue): boolean {
  if (Array.isArray(value))
    return value.some(
      (item) => item === null || containsNullArrayElement(item),
    );
  return isObject(value) && Object.values(value).some(containsNullArrayElement);
}

export function serializeCodexConfig(config: JsonObject): string {
  try {
    return stringify(config);
  } catch (error) {
    const message =
      error instanceof TypeError && containsNullArrayElement(config)
        ? NULL_TOML_VALUE_MESSAGE
        : `Invalid Codex configuration: ${error instanceof Error ? error.message : String(error)}`;
    throw new ConfigurationError(message, { cause: error });
  }
}

export function resolveCodexProfile(config: JsonObject): JsonObject {
  const normalized = parse(serializeCodexConfig(config)) as JsonObject;
  const resolved = deepMerge(normalized, selectedScanProfile(normalized) ?? {});
  delete resolved["profile"];
  delete resolved["profiles"];
  return resolved;
}

/** @internal */
export function deepMerge(base: JsonObject, overrides: JsonObject): JsonObject {
  for (const [key, value] of Object.entries(overrides)) {
    const existing = Object.hasOwn(base, key) ? base[key] : undefined;
    base[key] =
      isObject(value) && isObject(existing)
        ? deepMerge({ ...existing }, value)
        : structuredClone(value);
  }
  return base;
}

export function isObject(value: unknown): value is Record<string, JsonValue> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function safeConfigString(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    !/[\u0000-\u001f\u007f]/u.test(value)
  );
}

/** Select model settings that can be persisted without provider credentials. */
export function workerModelSelection(source: JsonObject): JsonObject {
  const result: JsonObject = {};
  for (const key of [
    "model",
    "model_reasoning_effort",
    "model_reasoning_summary",
    "model_provider",
    "service_tier",
  ]) {
    const value = source[key];
    if (safeConfigString(value)) result[key] = value;
  }
  return result;
}

export function bedrockProviderConfig(
  source: JsonObject,
): JsonObject | undefined {
  const providers = source["model_providers"];
  const provider = isRecord(providers)
    ? providers["amazon-bedrock"]
    : undefined;
  const aws = isRecord(provider) ? provider["aws"] : undefined;
  if (isRecord(aws)) {
    const sanitized: JsonObject = {};
    for (const key of ["region", "profile"]) {
      const value = aws[key];
      if (safeConfigString(value)) sanitized[key] = value;
    }
    if (Object.keys(sanitized).length > 0) {
      return {
        "amazon-bedrock": { aws: sanitized },
      };
    }
  }
  return undefined;
}
