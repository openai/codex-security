import {
  AppServerPreflightClient,
  type AppServerPreflightClientOptions,
} from "./deep-scan/permission-profile-preflight.js";

export interface CatalogModel {
  readonly id: string;
  readonly model: string;
  readonly hidden: boolean;
  readonly isDefault: boolean;
  readonly upgrade?: string | null;
  readonly upgradeInfo?: { readonly model: string } | null;
  readonly supportedReasoningEfforts: readonly {
    readonly reasoningEffort: string;
  }[];
}

/** Read Codex picker metadata using the supplied launch context, without starting a turn. */
export async function readModelCatalog(
  options: AppServerPreflightClientOptions,
): Promise<readonly CatalogModel[] | undefined> {
  options.signal.throwIfAborted();
  const client = new AppServerPreflightClient(options);
  try {
    await client.initialize();
    const account = await client.request("account/read", {
      refreshToken: false,
    });
    if (record(account.account)?.type !== "chatgpt") return undefined;

    const response = await client.request("config/read", {
      cwd: options.cwd,
      includeLayers: false,
    });
    const config = record(response.config);
    const profile =
      typeof config?.profile === "string"
        ? record(record(config.profiles)?.[config.profile])
        : undefined;
    const provider = profile?.model_provider ?? config?.model_provider;
    const catalogPath =
      profile?.model_catalog_json ?? config?.model_catalog_json;
    if (
      !config ||
      catalogPath != null ||
      (provider != null && provider !== "openai")
    ) {
      return undefined;
    }

    const models: CatalogModel[] = [];
    const seenCursors = new Set<string>();
    let cursor: string | undefined;
    while (true) {
      const page = await client.request("model/list", {
        includeHidden: true,
        ...(cursor === undefined ? {} : { cursor }),
      });
      if (!Array.isArray(page.data))
        throw new Error("Codex returned an invalid model catalog.");
      for (const value of page.data) {
        const model = record(value);
        if (
          !model ||
          typeof model.id !== "string" ||
          typeof model.model !== "string" ||
          typeof model.hidden !== "boolean" ||
          typeof model.isDefault !== "boolean" ||
          (model.upgrade != null && typeof model.upgrade !== "string") ||
          (model.upgradeInfo != null &&
            typeof record(model.upgradeInfo)?.model !== "string") ||
          !Array.isArray(model.supportedReasoningEfforts) ||
          !model.supportedReasoningEfforts.every(
            (effort) => typeof record(effort)?.reasoningEffort === "string",
          )
        ) {
          throw new Error("Codex returned an invalid model catalog.");
        }
        models.push(model as unknown as CatalogModel);
      }
      if (page.nextCursor === null) return models;
      if (
        typeof page.nextCursor !== "string" ||
        seenCursors.has(page.nextCursor)
      ) {
        throw new Error("Codex returned an invalid model catalog cursor.");
      }
      seenCursors.add(page.nextCursor);
      cursor = page.nextCursor;
    }
  } finally {
    await client.close();
  }
}

export function findCatalogModel(
  model: string,
  catalog: readonly CatalogModel[],
): CatalogModel | undefined {
  return catalog.find((entry) => entry.model === model || entry.id === model);
}

/** Follow declared upgrades; model names and catalog order do not imply release order. */
export function latestAvailableUpgrade(
  currentModel: string,
  catalog: readonly CatalogModel[],
): CatalogModel | undefined {
  return followDeclaredUpgrades(
    currentModel,
    catalog,
    (model) =>
      !model.hidden &&
      (!isCyberModel(model.model) ||
        /(?:^|[-_/])astra(?:$|[-_/])/i.test(model.model)),
  );
}

function followDeclaredUpgrades(
  currentModel: string,
  catalog: readonly CatalogModel[],
  eligible: (model: CatalogModel) => boolean,
): CatalogModel | undefined {
  let current = findCatalogModel(currentModel, catalog);
  const visited = new Set<string>();
  let recommendation: CatalogModel | undefined;
  while (current) {
    if (visited.has(current.model)) return undefined;
    visited.add(current.model);
    const next = current.upgradeInfo?.model ?? current.upgrade;
    if (!next) return recommendation;
    current = findCatalogModel(next, catalog);
    if (current && eligible(current)) recommendation = current;
  }
  return recommendation;
}

/** The catalog default is a recommendation, not evidence that it is a newer release. */
export function recommendedNonCyberModel(
  catalog: readonly CatalogModel[],
): CatalogModel | undefined {
  const preferred = catalog.find((model) => model.isDefault);
  if (!preferred) return undefined;
  return (
    followDeclaredUpgrades(preferred.model, catalog, isNonCyberPickerModel) ??
    (isNonCyberPickerModel(preferred) ? preferred : undefined)
  );
}

function isNonCyberPickerModel(model: CatalogModel): boolean {
  return !model.hidden && !isCyberModel(model.model);
}

export function isCyberModel(model: string): boolean {
  return /(?:^|[-_/])cyber(?:$|[-_/])/i.test(model);
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}
