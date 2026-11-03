import { workbenchArgs } from "./workbench-arguments.js";
import type { ScanOptions } from "./api.js";
import type { ScanMode } from "./targets.js";
import type {
  ParentProgressSource,
  ScanCost,
  ScanCostTracker,
} from "./cost.js";
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

  #lastProgress: string | null = null;

  constructor(
    private readonly mode: ScanMode,
    private readonly options: Pick<
      ScanOptions,
      "onProgress" | "onWorkerStatus" | "onObserverError"
    >,
    private readonly isValidating?: () => boolean,
  ) {}

  readonly report = (
    progress: ScanProgress,
    source?: ParentProgressSource,
    tracker?: ScanCostTracker,
  ): void => {
    const liveEvent = source?.reconciled === true ? undefined : source?.event;
    if (
      liveEvent !== undefined &&
      tracker !== undefined &&
      !tracker.recordParentProgress(progress, liveEvent)
    )
      return;
    const inventory =
      source?.inventory === true ||
      (progress.phase === "discovery" &&
        this.reviewedFileCount === 0 &&
        progress.filesCompleted === 0);
    const filesTotal = inventory ? progress.filesTotal : this.scopeFileCount;
    if (
      filesTotal === null ||
      progress.filesTotal > filesTotal ||
      (source?.inventory !== true &&
        progress.filesCompleted < this.reviewedFileCount)
    ) {
      if (liveEvent !== undefined) tracker?.deferParentInventory(liveEvent);
      return;
    }
    if (inventory) {
      this.scopeFileCount = filesTotal;
      tracker?.setExpectedFilesTotal(filesTotal);
    }
    this.reviewedFileCount = progress.filesCompleted;
    if (liveEvent !== undefined)
      tracker?.acceptParentProgress(progress, liveEvent);
    if (
      source !== undefined ||
      this.mode === "deep" ||
      scanPhaseSchema.options.indexOf(progress.phase) >
        scanPhaseSchema.options.indexOf(this.phase)
    )
      this.phase = progress.phase;
    const update = {
      ...progress,
      phase: this.isValidating?.() ? ("validation" as const) : this.phase,
      filesTotal,
      ...(this.reviewItems === undefined
        ? {}
        : { reviewItems: this.reviewItems }),
    };
    const key = `${update.phase}:${update.filesCompleted}:${update.filesTotal}:${update.reviewItems?.completed}:${update.reviewItems?.total}`;
    if (key === this.#lastProgress) return;
    this.#lastProgress = key;
    notifyObserver(
      "onProgress",
      this.options.onProgress,
      this.options.onObserverError,
      update,
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

  fromScan(
    progress: ScanProgress,
    tracker: ScanCostTracker,
    source?: ParentProgressSource,
  ): void {
    this.report(
      {
        ...progress,
        phase: this.mode === "deep" ? "discovery" : progress.phase,
      },
      source,
      tracker,
    );
  }
}
