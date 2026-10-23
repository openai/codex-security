import { workbenchArgs } from "./workbench-arguments.js";
import type { ScanOptions } from "./api.js";
import type { ScanMode } from "./targets.js";
import type { ScanCost, ScanCostTracker } from "./cost.js";
import type { WorkbenchCommandOptions, runWorkbench } from "./runtime.js";
import {
  scanPhaseSchema,
  type ScanProgress,
  type ScanWorkerStatus,
} from "./worker-progress.js";
import type { SavedScanProgress } from "./scan-progress.js";
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
}): (cost: Readonly<ScanCost>, complete?: boolean) => void {
  let maxCostUsd = options.maxCostUsd;
  let latestCost: Readonly<ScanCost> | null = null;
  let notifiedLimit: number | undefined;
  let latestCostComplete = false;
  return (cost: Readonly<ScanCost>, complete = true): void => {
    latestCost = cost;
    latestCostComplete = complete;
    if (complete)
      notifyObserver(
        "onCost",
        options.onCost,
        options.onObserverError,
        cost,
        maxCostUsd,
      );
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
        await workbench(
          { ...activeScan.options, signal: budgetSignal },
          workbenchArgs("set-scan-cost-limit", {
            scanId: activeScan.id,
            maxCostUsd: String(next),
          }),
        );
        if (budgetSignal.aborted) return;
        maxCostUsd = next;
        if (latestCostComplete)
          notifyObserver(
            "onCost",
            options.onCost,
            options.onObserverError,
            latestCost!,
            maxCostUsd,
          );
      })
      .catch((error: unknown) => {
        if (!budgetSignal.aborted) {
          notifyObserver(
            "onWarning",
            options.onWarning,
            options.onObserverError,
            `Could not increase scan cost limit: ${errorMessage(error)}`,
          );
        }
      });
  };
}

export class ScanProgressReporter {
  scopeFileCount: number | null = null;
  reviewedFileCount = 0;
  phase: ScanProgress["phase"] = "preflight";
  reviewItems: ScanProgress["reviewItems"];

  constructor(
    private readonly mode: ScanMode,
    private readonly options: Pick<
      ScanOptions,
      "onProgress" | "onWorkerStatus" | "onObserverError"
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
    if (
      this.mode === "deep" ||
      scanPhaseSchema.options.indexOf(progress.phase) >
        scanPhaseSchema.options.indexOf(this.phase)
    )
      this.phase = progress.phase;
    notifyObserver(
      "onProgress",
      this.options.onProgress,
      this.options.onObserverError,
      {
        ...progress,
        phase: this.phase,
        filesTotal: this.scopeFileCount,
        ...(this.reviewItems === undefined
          ? {}
          : { reviewItems: this.reviewItems }),
      },
    );
  };

  readonly worker = (status: ScanWorkerStatus): void => {
    if (this.mode !== "deep") {
      const phase =
        status.phase === "ranking" || status.phase === "file_review"
          ? "discovery"
          : status.phase;
      if (
        scanPhaseSchema.options.indexOf(phase) <
        scanPhaseSchema.options.indexOf(this.phase)
      )
        return;
      this.phase = phase;
    }
    notifyObserver(
      "onWorkerStatus",
      this.options.onWorkerStatus,
      this.options.onObserverError,
      status,
    );
  };

  fromSaved(progress: SavedScanProgress, tracker: ScanCostTracker): void {
    this.reviewItems = progress.reviewItems;
    if (this.scopeFileCount === null && progress.filesTotal !== null) {
      this.scopeFileCount = progress.filesTotal;
      tracker.setExpectedFilesTotal(this.scopeFileCount);
    }
    if (this.scopeFileCount !== null)
      this.report({
        phase: progress.phase,
        filesCompleted: this.reviewedFileCount,
        filesTotal: this.scopeFileCount,
      });
  }

  preflight(fileCount: number | null, tracker: ScanCostTracker): void {
    this.scopeFileCount = fileCount;
    if (fileCount === null) return;
    tracker.setExpectedFilesTotal(fileCount);
    notifyObserver(
      "onProgress",
      this.options.onProgress,
      this.options.onObserverError,
      { phase: "preflight", filesCompleted: 0, filesTotal: fileCount },
    );
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
