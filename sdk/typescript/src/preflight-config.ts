import { isSafeNonNegativeInteger as safeInteger } from "./value.js";
import { isAbsolute } from "node:path";
import {
  EXTERNAL_CODEX_PROVIDERS,
  MODEL_FILE_SETTINGS,
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
  const capabilityFeatures = (value: unknown): JsonObject => {
    if (!isRecord(value)) return {};
    const result: JsonObject = {};
    for (const key of [
      "goals",
      "multi_agent",
      "enable_fanout",
      "cli_daybreak",
      "api_key_cyber_access_programs",
      "api_key_model_discovery",
      "shell_tool",
      "unified_exec",
    ]) {
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
    const codeMode = value["code_mode"];
    if (typeof codeMode === "boolean" || isRecord(codeMode)) {
      result["code_mode"] = structuredClone(codeMode) as JsonObject[string];
    }
    return result;
  };
  const copyWorkerSettings = (result: JsonObject, source: JsonObject): void => {
    for (const key of [
      ...MODEL_FILE_SETTINGS,
      "model_verbosity",
      "web_search",
    ]) {
      const value = source[key];
      if (typeof value === "string") result[key] = value;
    }
  };
  const executionConfig = (source: JsonObject): JsonObject => {
    const result: JsonObject = {};
    // OTel exporters can contain credentials. Native runtime settings retain
    // them; model-readable preflight files and saved recipes must not.
    for (const key of ["analytics", "responses_api_metadata"]) {
      if (Object.hasOwn(source, key))
        result[key] = structuredClone(source[key]!);
    }
    if (typeof source["daybreak"] === "boolean") {
      result["daybreak"] = source["daybreak"];
    }
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
    copyWorkerSettings(result, source);
    const features = capabilityFeatures(source["features"]);
    if (Object.keys(features).length > 0) result["features"] = features;
    const skills = source["skills"];
    if (isRecord(skills) && Array.isArray(skills["config"])) {
      result["skills"] = {
        config: skills["config"].flatMap((entry) =>
          isRecord(entry) &&
          safeString(entry["path"]) &&
          typeof entry["enabled"] === "boolean"
            ? [{ path: entry["path"], enabled: entry["enabled"] }]
            : [],
        ),
      };
    }
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
  const resolved = resolveCodexProfile(config);
  const result = executionConfig(
    safeProfileName(config["profile"]) ? config : resolved,
  );
  // Keep effective execution settings even when preflight filters the profile name.
  copyWorkerSettings(result, resolved);
  for (const key of ["model_reasoning_summary", "service_tier"]) {
    const value = resolved[key];
    if (safeString(value)) result[key] = value;
  }
  if (typeof resolved["daybreak"] === "boolean") {
    result["daybreak"] = resolved["daybreak"];
  }
  const resolvedFeatures = capabilityFeatures(resolved["features"]);
  for (const key of [
    "code_mode",
    "cli_daybreak",
    "api_key_cyber_access_programs",
    "api_key_model_discovery",
    "shell_tool",
    "unified_exec",
  ]) {
    if (resolvedFeatures[key] !== undefined) {
      result["features"] = {
        ...(isRecord(result["features"]) ? result["features"] : {}),
        [key]: resolvedFeatures[key],
      };
    }
  }
  const profileName = config["profile"];
  const profiles = config["profiles"];
  const selectedProfile =
    safeProfileName(profileName) &&
    isRecord(profiles) &&
    isRecord(profiles[profileName])
      ? profileName
      : undefined;
  if (selectedProfile !== undefined) {
    result["profile"] = selectedProfile;
  }
  if (isRecord(profiles)) {
    const sanitized: JsonObject = {};
    for (const [name, profile] of Object.entries(profiles)) {
      if (!safeProfileName(name) || !isRecord(profile)) continue;
      const projected = executionConfig(profile as JsonObject);
      if (Object.keys(projected).length === 0 && name !== selectedProfile)
        continue;
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
    const providers = resolved["model_providers"];
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
