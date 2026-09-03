import type { BulkScanPrompt } from "./bulk-scan-discovery.js";
import type { ScanModelConfiguration } from "./config.js";
import { estimateScanCost } from "./cost.js";
import { getScanModelAdvice } from "./model-advice.js";
import type { CatalogModel } from "./model-catalog.js";
import type { ScanModelSelector } from "./scan-model-selection.js";
import { abortable } from "./targets.js";

export function createScanModelSelector(options: {
  interactive: boolean;
  maxCostUsd?: number;
  prompt: Pick<BulkScanPrompt, "isInteractive" | "confirm">;
  write(message: string): void;
}): ScanModelSelector {
  const choices = new Map<string, Promise<ScanModelConfiguration>>();
  return (configuration, loadModels, signal) => {
    const key = JSON.stringify(configuration);
    let choice = choices.get(key);
    if (choice === undefined) {
      choice = choose(configuration, loadModels, signal);
      choices.set(key, choice);
    }
    return choice;
  };

  async function choose(
    configuration: ScanModelConfiguration,
    loadModels: () => Promise<readonly CatalogModel[] | undefined>,
    signal: AbortSignal,
  ): Promise<ScanModelConfiguration> {
    let availableModels: readonly CatalogModel[] | undefined;
    const warnings: string[] = [];
    try {
      availableModels = await loadModels();
    } catch {
      signal.throwIfAborted();
      warnings.push(
        "Could not check available scan models. Continuing with the configured model.",
      );
    }
    signal.throwIfAborted();
    const interactive = options.interactive && options.prompt.isInteractive();
    const proposed = { ...configuration };
    let advice = getScanModelAdvice({ ...configuration, availableModels });
    if (advice.cyberWarning !== undefined) warnings.push(advice.cyberWarning);

    const upgrade = advice.modelUpgrade;
    if (upgrade !== undefined) {
      warnings.push(
        `${upgrade.model} is available as an upgrade to ${configuration.model} and may give better scanning results.`,
      );
      if (
        options.maxCostUsd !== undefined &&
        estimateScanCost(upgrade.model, {
          input_tokens: 0,
          output_tokens: 0,
        }) === null
      ) {
        warnings.push(
          `Cost tracking is unavailable for ${upgrade.model}. Keeping the configured model to preserve the scan cost limit.`,
        );
      } else if (
        upgrade.supportedReasoningEfforts.some(
          ({ reasoningEffort }) =>
            reasoningEffort === configuration.reasoningEffort,
        )
      ) {
        proposed.model = upgrade.model;
        advice = getScanModelAdvice({ ...proposed, availableModels });
      } else {
        warnings.push(
          `${upgrade.model} does not support the configured ${configuration.reasoningEffort} reasoning effort. Keeping the configured model.`,
        );
      }
    }
    if (advice.recommendXhigh) {
      warnings.push(
        `The configured reasoning effort is ${configuration.reasoningEffort}. Use xhigh for the best scanning results.`,
      );
      const model = availableModels?.find(
        (candidate) =>
          candidate.model === proposed.model || candidate.id === proposed.model,
      );
      if (
        model?.supportedReasoningEfforts.some(
          ({ reasoningEffort }) => reasoningEffort === "xhigh",
        )
      ) {
        proposed.reasoningEffort = "xhigh";
      }
    }
    if (warnings.length > 0) {
      try {
        options.write(`codex-security: warning: ${warnings.join(" ")}\n`);
      } catch {}
    }
    const changeModel = proposed.model !== configuration.model;
    const changeEffort =
      proposed.reasoningEffort !== configuration.reasoningEffort;
    if (interactive && (changeModel || changeEffort)) {
      const question = changeModel
        ? `Use ${proposed.model}${changeEffort ? " with xhigh reasoning" : ""} for this scan?`
        : "Use xhigh reasoning for this scan?";
      const accepted = await abortable(
        () => options.prompt.confirm(question, false, signal),
        signal,
      );
      signal.throwIfAborted();
      if (accepted) return proposed;
    }
    signal.throwIfAborted();
    return { ...configuration };
  }
}
