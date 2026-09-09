import type { ScanModelConfiguration } from "./config.js";
import type { CatalogModel } from "./model-catalog.js";

export interface ScanModelAdvice {
  cyberWarning?: string;
  modelUpgrade?: CatalogModel;
  recommendXhigh: boolean;
}

export function getScanModelAdvice({
  model,
  reasoningEffort,
  availableModels,
}: ScanModelConfiguration & {
  availableModels: readonly CatalogModel[] | undefined;
}): ScanModelAdvice {
  const selectedModel = findModel(availableModels, model);
  const modelUpgrade = latestUpgrade(
    selectedModel,
    availableModels,
    (candidate) => !isNonAstraCyberModel(candidate.model),
  );
  let cyberWarning: string | undefined;
  if (isNonAstraCyberModel(selectedModel?.model ?? model)) {
    const defaultModel = availableModels?.find(
      (candidate) =>
        candidate.isDefault &&
        !candidate.hidden &&
        !isCyberModel(candidate.model),
    );
    const recommendedModel =
      latestUpgrade(
        selectedModel,
        availableModels,
        (candidate) => !isCyberModel(candidate.model),
      ) ??
      latestUpgrade(
        defaultModel,
        availableModels,
        (candidate) => !isCyberModel(candidate.model),
      ) ??
      defaultModel;
    const recommendation =
      recommendedModel?.model ?? "the latest non-cyber model available to you";
    cyberWarning =
      `${model} is designed for dynamic exploitation. ` +
      `You may get better vulnerability scanning results with ${recommendation}.`;
  }
  return {
    ...(cyberWarning === undefined ? {} : { cyberWarning }),
    ...(modelUpgrade === undefined ? {} : { modelUpgrade }),
    recommendXhigh: shouldRecommendXhigh(reasoningEffort, selectedModel),
  };
}

export function isNonAstraCyberModel(model: string): boolean {
  return isCyberModel(model) && !/(?:^|[-_/])astra(?:[-_/]|$)/i.test(model);
}

function isCyberModel(model: string): boolean {
  return /(?:^|[-_/])cyber(?:[-_/]|$)/i.test(model);
}

function findModel(
  availableModels: readonly CatalogModel[] | undefined,
  model: string,
): CatalogModel | undefined {
  return availableModels?.find(
    (candidate) => candidate.model === model || candidate.id === model,
  );
}

function latestUpgrade(
  model: CatalogModel | undefined,
  availableModels: readonly CatalogModel[] | undefined,
  eligible: (candidate: CatalogModel) => boolean,
): CatalogModel | undefined {
  let candidate = model;
  let upgrade: CatalogModel | undefined;
  const visited = new Set<string>();
  while (candidate !== undefined) {
    visited.add(candidate.id);
    visited.add(candidate.model);
    const nextModel = candidate.upgradeInfo?.model ?? candidate.upgrade;
    if (nextModel == null) break;
    candidate = findModel(availableModels, nextModel);
    if (candidate === undefined) break;
    if (visited.has(candidate.id) || visited.has(candidate.model))
      return undefined;
    if (!candidate.hidden && eligible(candidate)) upgrade = candidate;
  }
  return upgrade;
}

function shouldRecommendXhigh(
  reasoningEffort: string,
  model: CatalogModel | undefined,
): boolean {
  if (!["none", "minimal", "low", "medium", "high"].includes(reasoningEffort)) {
    return false;
  }
  return (
    model === undefined ||
    model.supportedReasoningEfforts.some(
      (effort) => effort.reasoningEffort === "xhigh",
    )
  );
}
