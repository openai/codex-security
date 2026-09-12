import { isAbsolute } from "node:path";
import {
  EXTERNAL_CODEX_PROVIDERS,
  isExternalModelProvider,
  resolveCodexProfile,
  scanModelProvider,
  type JsonObject,
} from "./config.js";

export function scanPreflightCodexConfig(config: JsonObject): JsonObject {
  const safeString = (value: unknown): value is string =>
    typeof value === "string" &&
    value.length > 0 &&
    !/[\u0000-\u001f\u007f]/u.test(value);
  const safeProfileName = (value: unknown): value is string =>
    safeString(value) && /^[A-Za-z0-9_-]+$/u.test(value);
  const safeInteger = (value: unknown): value is number =>
    typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
  const capabilityFeatures = (value: unknown): JsonObject => {
    if (!isRecord(value)) return {};
    const result: JsonObject = {};
    for (const key of ["goals", "multi_agent", "enable_fanout"]) {
      if (typeof value[key] === "boolean") result[key] = value[key];
    }
    const multiAgent = value["multi_agent_v2"];
    if (typeof multiAgent === "boolean") {
      result["multi_agent_v2"] = multiAgent;
    } else if (isRecord(multiAgent)) {
      const sanitized: JsonObject = {};
      if (typeof multiAgent["enabled"] === "boolean") {
        sanitized["enabled"] = multiAgent["enabled"];
      }
      const capacity = multiAgent["max_concurrent_threads_per_session"];
      if (safeInteger(capacity)) {
        sanitized["max_concurrent_threads_per_session"] = capacity;
      }
      if (Object.keys(sanitized).length > 0) {
        result["multi_agent_v2"] = sanitized;
      }
    }
    return result;
  };
  const executionConfig = (source: JsonObject): JsonObject => {
    const result: JsonObject = {};
    for (const key of [
      "model",
      "model_reasoning_effort",
      "model_reasoning_summary",
      "model_provider",
      "service_tier",
    ]) {
      const value = source[key];
      if (safeString(value)) result[key] = value;
    }
    const features = capabilityFeatures(source["features"]);
    if (Object.keys(features).length > 0) result["features"] = features;
    const agents = source["agents"];
    if (isRecord(agents)) {
      const sanitized: JsonObject = {};
      for (const key of ["max_threads", "max_depth"]) {
        const value = agents[key];
        if (safeInteger(value)) sanitized[key] = value;
      }
      if (Object.keys(sanitized).length > 0) result["agents"] = sanitized;
    }
    const multiagent = source["multiagent_config"];
    if (isRecord(multiagent) && safeInteger(multiagent["max_concurrency"])) {
      result["multiagent_config"] = {
        max_concurrency: multiagent["max_concurrency"],
      };
    }
    return result;
  };
  const result = executionConfig(config);
  // Keep the effective summary even when preflight filters the profile name.
  const reasoningSummary =
    resolveCodexProfile(config)["model_reasoning_summary"];
  if (safeString(reasoningSummary)) {
    result["model_reasoning_summary"] = reasoningSummary;
  }
  const selectedProfile = safeProfileName(config["profile"])
    ? config["profile"]
    : undefined;
  if (selectedProfile !== undefined) {
    result["profile"] = selectedProfile;
  }
  const profiles = config["profiles"];
  if (isRecord(profiles)) {
    const sanitized: JsonObject = {};
    for (const [name, profile] of Object.entries(profiles)) {
      if (!safeProfileName(name) || !isRecord(profile)) continue;
      const projected = executionConfig(profile as JsonObject);
      if (Object.keys(projected).length === 0) continue;
      sanitized[name] = projected;
    }
    if (Object.keys(sanitized).length > 0) result["profiles"] = sanitized;
  }
  const modelProvider = scanModelProvider(result);
  if (isExternalModelProvider(modelProvider)) {
    result["model_providers"] = {
      [modelProvider]: { ...EXTERNAL_CODEX_PROVIDERS[modelProvider] },
    };
  } else if (modelProvider === "amazon-bedrock") {
    const providers = config["model_providers"];
    const provider = isRecord(providers) ? providers[modelProvider] : undefined;
    const aws = isRecord(provider) ? provider["aws"] : undefined;
    if (isRecord(aws)) {
      const sanitized: JsonObject = {};
      for (const key of ["region", "profile"]) {
        const value = aws[key];
        if (safeString(value)) sanitized[key] = value;
      }
      if (Object.keys(sanitized).length > 0) {
        result["model_providers"] = {
          [modelProvider]: { aws: sanitized },
        };
      }
    }
  }
  const rootMarkers = config["project_root_markers"];
  if (Array.isArray(rootMarkers)) {
    result["project_root_markers"] = rootMarkers.filter(safeString);
  }
  const projects = config["projects"];
  if (isRecord(projects)) {
    const sanitized: JsonObject = {};
    for (const [path, project] of Object.entries(projects)) {
      if (!safeString(path) || !isAbsolute(path) || !isRecord(project)) {
        continue;
      }
      const trust = project["trust_level"];
      if (trust !== "trusted" && trust !== "untrusted") continue;
      sanitized[path] = { trust_level: trust };
    }
    if (Object.keys(sanitized).length > 0) result["projects"] = sanitized;
  }
  return result;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
