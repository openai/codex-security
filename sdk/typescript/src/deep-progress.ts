import { isRecord } from "./record.js";
import { isSafeNonNegativeInteger } from "./value.js";

export interface DeepScanProgress {
  completed: number;
  active: number;
  maximum: number;
  /** Whether the coordinator is reducing results or has finished. */
  consolidating?: boolean;
}

interface DeepScanProgressTrackerOptions {
  read: (signal: AbortSignal) => Promise<unknown>;
  onProgress: (progress: DeepScanProgress) => void;
  onError?: (error: unknown) => void;
}

const DEEP_PROGRESS_POLL_INTERVAL_MS = 5_000;

export class DeepScanProgressTracker {
  readonly #options: DeepScanProgressTrackerOptions;
  #timer: NodeJS.Timeout | null = null;
  #pending: Promise<void> | null = null;
  readonly #abortController = new AbortController();
  #lastProgress: DeepScanProgress | null = null;

  public constructor(options: DeepScanProgressTrackerOptions) {
    this.#options = options;
  }

  public start(): void {
    if (this.#timer !== null || this.#abortController.signal.aborted) return;
    const poll = () => {
      void this.refresh().catch((error: unknown) => {
        this.#options.onError?.(error);
      });
    };
    this.#timer = setInterval(poll, DEEP_PROGRESS_POLL_INTERVAL_MS);
    this.#timer.unref();
    poll();
  }

  public async refresh(): Promise<void> {
    if (this.#abortController.signal.aborted) return;
    if (this.#pending !== null) return await this.#pending;
    const abortController = this.#abortController;
    let update: Promise<void> | null = null;
    update = (async () => {
      try {
        const progress = deepScanProgressFromWorkbench(
          await this.#options.read(abortController.signal),
        );
        if (
          abortController.signal.aborted ||
          progress === null ||
          sameProgress(progress, this.#lastProgress)
        ) {
          return;
        }
        this.#lastProgress = progress;
        this.#options.onProgress(progress);
      } catch (error) {
        if (abortController.signal.aborted) return;
        throw error;
      } finally {
        if (this.#pending === update) this.#pending = null;
      }
    })();
    this.#pending = update;
    await update;
  }

  public stop(): void {
    if (this.#abortController.signal.aborted) return;
    clearInterval(this.#timer ?? undefined);
    this.#timer = null;
    this.#abortController.abort();
  }
}

export function deepScanProgressFromWorkbench(
  result: unknown,
): DeepScanProgress | null {
  if (!isRecord(result) || !isRecord(result["scan"])) return null;
  const progress = result["scan"]["progress"];
  if (!isRecord(progress)) return null;
  const independentReviews = progress["independentReviews"];
  if (independentReviews === undefined) return null;
  if (isRecord(independentReviews)) {
    const { completed, active, maximum, consolidating } = independentReviews;
    if (
      isSafeNonNegativeInteger(completed) &&
      isSafeNonNegativeInteger(active) &&
      isSafeNonNegativeInteger(maximum) &&
      maximum > 0 &&
      (consolidating === undefined || typeof consolidating === "boolean")
    ) {
      return {
        completed,
        active,
        maximum,
        ...(typeof consolidating === "boolean" ? { consolidating } : {}),
      };
    }
  }
  throw new Error(
    "Codex Security workbench returned invalid Deep Scan progress.",
  );
}

function sameProgress(
  left: DeepScanProgress,
  right: DeepScanProgress | null,
): boolean {
  return (
    right !== null &&
    left.completed === right.completed &&
    left.active === right.active &&
    left.maximum === right.maximum &&
    left.consolidating === right.consolidating
  );
}
