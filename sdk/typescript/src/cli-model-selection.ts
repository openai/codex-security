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
    const warn = (message: string): void => {
      try {
        options.write(`codex-security: warning: ${message}\n`);
      } catch {}
    };
    try {
      availableModels = await loadModels();
    } catch {
      signal.throwIfAborted();
      warn(
        "Could not check available scan models. Continuing with the configured model.",
      );
    }
    signal.throwIfAborted();
    const interactive = options.interactive && options.prompt.isInteractive();
    const selected = { ...configuration };
    let advice = getScanModelAdvice({ ...selected, availableModels });
    if (advice.cyberWarning !== undefined) warn(advice.cyberWarning);

    const upgrade = advice.modelUpgrade;
    if (upgrade !== undefined) {
      warn(
        `${upgrade.model} is available as an upgrade to ${selected.model} and may give better scanning results.`,
      );
      if (
        options.maxCostUsd !== undefined &&
        estimateScanCost(upgrade.model, {
          input_tokens: 0,
          output_tokens: 0,
        }) === null
      ) {
        warn(
          `Cost tracking is unavailable for ${upgrade.model}. Keeping the configured model to preserve the scan cost limit.`,
        );
      } else if (
        upgrade.supportedReasoningEfforts.some(
          ({ reasoningEffort }) => reasoningEffort === selected.reasoningEffort,
        )
      ) {
        if (
          interactive &&
          (await abortable(
            () =>
              options.prompt.confirm(
                `Use ${upgrade.model} for this scan?`,
                false,
                signal,
              ),
            signal,
          ))
        ) {
          selected.model = upgrade.model;
          advice = getScanModelAdvice({ ...selected, availableModels });
        }
      } else {
        warn(
          `${upgrade.model} does not support the configured ${selected.reasoningEffort} reasoning effort. Keeping the configured model and effort.`,
        );
      }
    }
    if (advice.recommendXhigh) {
      warn(
        `The configured reasoning effort is ${selected.reasoningEffort}. Use xhigh for the best scanning results.`,
      );
      const model = availableModels?.find(
        (candidate) =>
          candidate.model === selected.model || candidate.id === selected.model,
      );
      if (
        interactive &&
        model?.supportedReasoningEfforts.some(
          ({ reasoningEffort }) => reasoningEffort === "xhigh",
        ) &&
        (await abortable(
          () =>
            options.prompt.confirm(
              "Use xhigh reasoning for this scan?",
              false,
              signal,
            ),
          signal,
        ))
      ) {
        selected.reasoningEffort = "xhigh";
      }
    }
    signal.throwIfAborted();
    return selected;
  }
}
