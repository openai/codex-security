import { ConfigurationError } from "./errors.js";
import type { ScanCost } from "./cost.js";
import type { ScanSettings } from "./scan-settings.js";

export function batchScanBudget(
  share: number | undefined,
  settings: Pick<
    ScanSettings,
    "maxCostUsd" | "postScanPrompt" | "postScanPromptFile"
  >,
): {
  maxCostUsd?: number;
  skipFindingMatching?: true;
  ownerSuggestions?: false;
} {
  if (share === undefined) return { maxCostUsd: settings.maxCostUsd };
  if (
    settings.postScanPrompt !== undefined ||
    settings.postScanPromptFile !== undefined
  )
    throw new ConfigurationError(
      "--max-total-cost cannot cover a post-scan prompt. Remove the post-scan prompt and run it separately.",
    );
  return {
    maxCostUsd: Math.min(share, settings.maxCostUsd ?? share),
    skipFindingMatching: true,
    ownerSuggestions: false,
  };
}

/** Reserve before dispatch, including in-flight attempts. Charge observed overruns to the remaining pool. */
export class BatchCostPool {
  #remaining: number;
  readonly share: number;

  constructor(totalUsd: number, slots: number) {
    this.#remaining = totalUsd;
    this.share = totalUsd / slots;
    if (!Number.isFinite(this.share) || this.share <= 0)
      throw new ConfigurationError(
        "The total cost limit must allow a positive USD amount per scan attempt.",
      );
  }

  reserve(share = this.share) {
    const maxCostUsd = Math.min(share, this.#remaining);
    if (maxCostUsd <= 0)
      throw new ConfigurationError(
        "The invocation cost limit is exhausted. No further scan attempts can start.",
      );
    this.#remaining -= maxCostUsd;
    let charged = maxCostUsd;
    return {
      maxCostUsd,
      record: (cost: Readonly<ScanCost> | null | undefined) => {
        if (cost && cost.estimatedUsd > charged) {
          this.#remaining -= cost.estimatedUsd - charged;
          charged = cost.estimatedUsd;
        }
      },
    };
  }
}
