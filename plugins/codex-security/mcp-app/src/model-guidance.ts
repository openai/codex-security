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
  const nudge: string[] = [];
  if (model && isNonAstraCyberModel(current?.model ?? model)) {
    nudge.push(
      `${model} is designed for dynamic exploitation. You may get better vulnerability scanning results with ${nonCyberModel?.model ?? "the latest non-cyber model available to you"}.`,
    );
  }
  if (upgrade) {
    nudge.push(
      `A newer recommended model, ${upgrade.model}, is available in your Codex model catalog.`,
    );
  }
  const efforts = (upgrade ?? current)?.supportedReasoningEfforts.map(
    ({ reasoningEffort: effort }) => effort,
  );
  const supportsXhigh = efforts?.includes("xhigh");
  const belowXhigh = reasoningEffort && isBelowXhigh(reasoningEffort);
  const suggestions: string[] = [];
  if (upgrade) suggestions.push(upgrade.model);
  if (belowXhigh && supportsXhigh !== false) {
    suggestions.push(
      `xhigh reasoning${supportsXhigh ? "" : " if your model supports it"}`,
    );
  }
  if (suggestions.length > 0) {
    nudge.push(
      `For the best scanning results, would you like to use ${suggestions.join(" with ")}?`,
    );
  }
  if (nudge.length > 0) {
    nudge.push(
      "You can change the model or reasoning selector, or keep going with your current settings.",
    );
    messages.push(nudge.join(" "));
  }
  messages.push(
    ...(catalog
      ? []
      : [
          "The available-model catalog could not be established. Do not claim a newer model is available without current host catalog evidence.",
        ]),
    "In the app, combine all applicable guidance into a single brief text nudge with at most one question. Do not emit separate warnings or questions for each setting. The user can change the model selector or keep going; do not change settings or wait for an answer.",
  );
  return messages.join("\n");
}
