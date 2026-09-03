import {
  findCatalogModel,
  isCyberModel,
  latestAvailableUpgrade,
  recommendedNonCyberModel,
  type CatalogModel,
} from "./model-catalog.js";

export function isNonAstraCyberModel(model: string): boolean {
  return isCyberModel(model) && !/(?:^|[-_/])astra(?:$|[-_/])/i.test(model);
}

export function isBelowXhigh(reasoningEffort: string): boolean {
  return ["none", "minimal", "low", "medium", "high"].includes(reasoningEffort);
}

export function scanModelGuidance(
  settings: {
    model?: string;
    reasoningEffort?: string;
  },
  catalog?: readonly CatalogModel[],
): string {
  const { model, reasoningEffort } = settings;
  const current =
    model && catalog ? findCatalogModel(model, catalog) : undefined;
  const upgrade =
    model && catalog ? latestAvailableUpgrade(model, catalog) : undefined;
  const nonCyberModel =
    upgrade && !isCyberModel(upgrade.model)
      ? upgrade
      : catalog
        ? recommendedNonCyberModel(catalog)
        : undefined;
  const messages = [
    model
      ? `Current scan model: ${model}.`
      : "The host did not provide the current scan model.",
    reasoningEffort
      ? `Current reasoning effort: ${reasoningEffort}.`
      : "The host did not provide the current reasoning effort.",
  ];
  if (model && isNonAstraCyberModel(current?.model ?? model)) {
    messages.push(
      `${model} is designed for dynamic exploitation. You may get better vulnerability scanning results with ${nonCyberModel?.model ?? "the latest non-cyber model available to you"}.`,
    );
  }
  if (upgrade) {
    messages.push(
      `A newer recommended model, ${upgrade.model}, is available in your Codex model catalog. Would you like to use it for better scanning results?`,
    );
  }
  const efforts = current?.supportedReasoningEfforts.map(
    ({ reasoningEffort: effort }) => effort,
  );
  const supportsXhigh = efforts?.includes("xhigh");
  const belowXhigh = reasoningEffort && isBelowXhigh(reasoningEffort);
  if (belowXhigh && supportsXhigh !== false) {
    messages.push(
      `For the best scanning results, would you like to use xhigh reasoning${supportsXhigh ? "" : " if your model supports it"}?`,
    );
  }
  messages.push(
    ...(catalog
      ? []
      : [
          "The available-model catalog could not be established. Do not claim a newer model is available without current host catalog evidence.",
        ]),
    "In the app, present applicable guidance as a brief text nudge. The user can change the model selector or keep going; do not change settings or wait for an answer.",
  );
  return messages.join("\n");
}
