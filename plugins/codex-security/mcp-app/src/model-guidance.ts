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
  if (!catalog) {
    messages.push(
      "The available-model catalog could not be established. Do not claim a newer model is available without current host catalog evidence.",
    );
  }
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
    messages.push(
      "Send this nudge now in one user-visible commentary message before calling another scan tool:",
      nudge.join(" "),
      "This tool result does not deliver the nudge to the user. After sending the commentary, continue the scan without waiting for a reply or changing settings.",
    );
  }
  return messages.join("\n");
}
