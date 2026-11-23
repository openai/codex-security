import { isRecord } from "../record.js";
import type { JsonObject } from "../types.js";

const providerDefaults = {
  openrouter: {
    name: "OpenRouter",
    base_url: "https://openrouter.ai/api/v1",
    env_key: "OPENROUTER_API_KEY",
    wire_api: "responses",
  },
  fireworks: {
    name: "Fireworks AI",
    base_url: "https://api.fireworks.ai/inference/v1",
    env_key: "FIREWORKS_API_KEY",
    wire_api: "responses",
  },
};

export function resolveWorkerProfile(config: JsonObject): JsonObject {
  const profiles = config["profiles"];
  const profile =
    typeof config["profile"] === "string" &&
    isRecord(profiles) &&
    Object.hasOwn(profiles, config["profile"])
      ? profiles[config["profile"]]
      : undefined;
  const resolved = merge(
    structuredClone(config),
    isRecord(profile) ? profile : {},
  );
  delete resolved["profile"];
  delete resolved["profiles"];
  return resolved;
}
function merge(base: JsonObject, overrides: JsonObject): JsonObject {
  for (const [key, value] of Object.entries(overrides)) {
    const existing = Object.hasOwn(base, key) ? base[key] : undefined;
    base[key] =
      isRecord(value) && isRecord(existing)
        ? merge({ ...existing }, value)
        : structuredClone(value);
  }
  return base;
}

/** The non-secret launch projection also used by SDK scan preflight. */
export function projectWorkerSettings(config: JsonObject): JsonObject {
  const result: JsonObject = {};
  for (const key of [
    "model",
    "model_reasoning_effort",
    "model_reasoning_summary",
    "model_provider",
    "service_tier",
  ]) {
    const value = config[key];
    if (
      typeof value === "string" &&
      value.length > 0 &&
      !/[\u0000-\u001f\u007f]/u.test(value)
    )
      result[key] = value;
  }
  if (isRecord(config["features"])) {
    const features: JsonObject = {};
    for (const key of [
      "api_key_cyber_access_programs",
      "api_key_model_discovery",
    ]) {
      if (typeof config["features"][key] === "boolean")
        features[key] = config["features"][key];
    }
    if (Object.keys(features).length > 0) result["features"] = features;
  }
  const selected = result["model_provider"];
  if (
    typeof selected === "string" &&
    Object.hasOwn(providerDefaults, selected)
  ) {
    const provider = {
      ...providerDefaults[selected as keyof typeof providerDefaults],
    };
    const providers = config["model_providers"];
    const configured = isRecord(providers) ? providers[selected] : undefined;
    if (isRecord(configured)) {
      for (const key of ["name", "base_url", "env_key", "wire_api"] as const) {
        if (typeof configured[key] === "string")
          provider[key] = configured[key];
      }
    }
    result["model_providers"] = { [selected]: provider };
  } else if (selected === "amazon-bedrock") {
    const providers = config["model_providers"];
    const provider = isRecord(providers) ? providers[selected] : undefined;
    const aws = isRecord(provider) ? provider["aws"] : undefined;
    if (isRecord(aws)) {
      const selectors: JsonObject = {};
      for (const key of ["region", "profile"]) {
        const value = aws[key];
        if (
          typeof value === "string" &&
          value.length > 0 &&
          !/[\u0000-\u001f\u007f]/u.test(value)
        )
          selectors[key] = value;
      }
      if (Object.keys(selectors).length > 0)
        result["model_providers"] = { [selected]: { aws: selectors } };
    }
  }
  return result;
}
