import {
  hasCommandAuth,
  scanModelProvider,
  type JsonObject,
  type ScanModelConfiguration,
} from "./config.js";
import { environmentEntry } from "./auth.js";
import { readModelCatalog, type CatalogModel } from "./model-catalog.js";
import { type CodexCommand, type ProcessEnvironment } from "./runtime.js";

/** @internal The CLI may change settings for this scan after explicit consent. */
export type ScanModelSelector = (
  configuration: ScanModelConfiguration,
  loadModels: () => Promise<readonly CatalogModel[] | undefined>,
  signal: AbortSignal,
) => Promise<ScanModelConfiguration>;

export async function availableScanModels(
  options: {
    command: CodexCommand;
    environment: ProcessEnvironment;
    config: JsonObject;
    apiKey: string | null;
    signal: AbortSignal;
  },
  dependencies = { readModelCatalog, fetch: globalThis.fetch },
): Promise<readonly CatalogModel[] | undefined> {
  const { command, environment, config, apiKey, signal } = options;
  const provider = scanModelProvider(config);
  if (
    (provider !== undefined && provider !== "openai") ||
    hasCommandAuth(config)
  )
    return undefined;
  const profiles = config["profiles"];
  const selectedProfile =
    typeof config["profile"] === "string" && isObject(profiles)
      ? profiles[config["profile"]]
      : undefined;
  if (
    apiKey === null &&
    (config["model_catalog_json"] !== undefined ||
      (isObject(selectedProfile) &&
        selectedProfile["model_catalog_json"] !== undefined))
  )
    return undefined;
  const catalog = await dependencies.readModelCatalog(command, environment, {
    config,
    ...(apiKey === null ? {} : { apiKey }),
    signal,
  });
  if (apiKey === null) return catalog;

  // The API-key Codex catalog advertises API support, not account access.
  // Check the same provider endpoint and credential used for this scan.
  // Codex ignores model_providers.openai overrides for its built-in provider.
  const configuredBaseUrl = config["openai_base_url"];
  const baseUrl =
    typeof configuredBaseUrl === "string" && configuredBaseUrl.length > 0
      ? configuredBaseUrl
      : "https://api.openai.com/v1";
  const url = new URL(`${baseUrl.replace(/\/+$/, "")}/models`);
  const headers = new Headers();
  const environmentHeaders = {
    "OpenAI-Organization": "OPENAI_ORGANIZATION",
    "OpenAI-Project": "OPENAI_PROJECT",
  };
  for (const [name, variable] of Object.entries(environmentHeaders)) {
    const value = environmentEntry(environment, variable);
    if (value?.trim()) headers.set(name, value);
  }
  headers.set("Authorization", `Bearer ${apiKey}`);
  const response = await dependencies.fetch(url, { headers, signal });
  if (!response.ok) {
    throw new Error(
      `Could not check model availability (HTTP ${response.status}).`,
    );
  }
  const body = (await response.json()) as { data: { id: string }[] };
  const available = new Set(body.data.map((model) => model.id));
  // Keep retired source nodes so their declared upgrade edges remain usable.
  return catalog.map((model) =>
    available.has(model.model) || available.has(model.id)
      ? model
      : { ...model, hidden: true },
  );
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
