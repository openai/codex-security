import type { ScanOptions } from "./api.js";
import type { ScanMode } from "./targets.js";
import type { ScanCost, ScanCostTracker } from "./cost.js";
import type { WorkbenchCommandOptions, runWorkbench } from "./runtime.js";
import type { ScanProgress } from "./worker-progress.js";
import {
  CodexSecurityError,
  ScanCostLimitExceededError,
  errorMessage,
} from "./errors.js";
import { notifyObserver } from "./scan-events.js";

/** Each scan owns its budget request and any accepted limit increase. */
export function createScanCostReporter({
  options,
  scanDir,
  costAbortController,
  budgetSignal,
  getActiveScan,
  workbench,
}: {
  options: Pick<
    ScanOptions,
    | "maxCostUsd"
    | "onCost"
    | "onBudgetApproaching"
    | "onWarning"
    | "onObserverError"
  >;
  scanDir: string;
  costAbortController: AbortController;
  budgetSignal: AbortSignal;
  getActiveScan: () => { id: string; options: WorkbenchCommandOptions } | null;
  workbench: typeof runWorkbench;
}): (cost: Readonly<ScanCost>) => void {
  let maxCostUsd = options.maxCostUsd;
  let latestCost: Readonly<ScanCost> | null = null;
  let notifiedLimit: number | undefined;
  return (cost: Readonly<ScanCost>): void => {
    latestCost = cost;
    notifyObserver(options, "onCost")(cost, maxCostUsd);
    if (maxCostUsd !== undefined && cost.estimatedUsd > maxCostUsd) {
      costAbortController.abort(
        new ScanCostLimitExceededError(maxCostUsd, cost, scanDir),
      );
      return;
    }
    const request = options.onBudgetApproaching;
    if (
      request === undefined ||
      maxCostUsd === undefined ||
      budgetSignal.aborted ||
      notifiedLimit === maxCostUsd ||
      cost.estimatedUsd < maxCostUsd * 0.8
    )
      return;
    const limit = maxCostUsd;
    notifiedLimit = limit;
    void Promise.resolve()
      .then(async () => {
        if (budgetSignal.aborted) return;
        const next = await request({
          maxCostUsd: limit,
          cost,
          signal: budgetSignal,
        });
        const activeScan = getActiveScan();
        if (next === undefined || budgetSignal.aborted || activeScan === null)
          return;
        if (
          !Number.isFinite(next) ||
          next <= Math.max(limit, latestCost!.estimatedUsd)
        ) {
          throw new CodexSecurityError(
            "The new cost limit must exceed the current limit and estimated cost.",
          );
        }
        await workbench({ ...activeScan.options, signal: budgetSignal }, [
          "set-scan-cost-limit",
          "--scan-id",
          activeScan.id,
          "--max-cost-usd",
          String(next),
        ]);
        if (budgetSignal.aborted) return;
        maxCostUsd = next;
        notifyObserver(options, "onCost")(latestCost!, maxCostUsd);
      })
      .catch((error: unknown) => {
        if (!budgetSignal.aborted) {
          notifyObserver(
            options,
            "onWarning",
          )(`Could not increase scan cost limit: ${errorMessage(error)}`);
        }
      });
  };
}

export class ScanProgressReporter {
  scopeFileCount: number | null = null;
  reviewedFileCount = 0;

  constructor(
    private readonly mode: ScanMode,
    private readonly options: Pick<
      ScanOptions,
      "onProgress" | "onObserverError"
    >,
  ) {}

  readonly report = (progress: ScanProgress): void => {
    if (
      this.scopeFileCount === null ||
      progress.filesTotal > this.scopeFileCount ||
      progress.filesCompleted < this.reviewedFileCount
    )
      return;
    this.reviewedFileCount = progress.filesCompleted;
    notifyObserver(
      this.options,
      "onProgress",
    )({ ...progress, filesTotal: this.scopeFileCount });
  };

  preflight(fileCount: number | null, tracker: ScanCostTracker): void {
    this.scopeFileCount = fileCount;
    if (fileCount === null) return;
    tracker.setExpectedFilesTotal(fileCount);
    notifyObserver(
      this.options,
      "onProgress",
    )({ phase: "preflight", filesCompleted: 0, filesTotal: fileCount });
  }

  fromScan(progress: ScanProgress, tracker: ScanCostTracker): void {
    if (
      progress.phase === "discovery" &&
      progress.filesCompleted === 0 &&
      this.reviewedFileCount === 0 &&
      progress.filesTotal !== this.scopeFileCount
    ) {
      this.scopeFileCount = progress.filesTotal;
      tracker.setExpectedFilesTotal(this.scopeFileCount);
    }
    this.report({
      ...progress,
      phase: this.mode === "deep" ? "discovery" : progress.phase,
    });
  }
}
