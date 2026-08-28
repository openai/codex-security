export interface DeepScanProgress {
  completed: number;
  active: number;
  maximum: number;
}

interface DeepScanProgressTrackerOptions {
  read: (signal: AbortSignal) => Promise<unknown>;
  onProgress: (progress: DeepScanProgress) => void;
  onError?: (error: unknown) => void;
  pollIntervalMs?: number;
}

const DEEP_PROGRESS_POLL_INTERVAL_MS = 5_000;

export class DeepScanProgressTracker {
  readonly #options: DeepScanProgressTrackerOptions;
  #timer: NodeJS.Timeout | null = null;
  #pending: Promise<void> | null = null;
  #abortController: AbortController | null = null;
  #lastProgress: DeepScanProgress | null = null;
  #stopped = false;

  public constructor(options: DeepScanProgressTrackerOptions) {
    this.#options = options;
  }

  public start(): void {
    if (this.#timer !== null || this.#stopped) return;
    const poll = () => {
      void this.refresh().catch((error: unknown) => {
        this.#options.onError?.(error);
      });
    };
    this.#timer = setInterval(
      poll,
      this.#options.pollIntervalMs ?? DEEP_PROGRESS_POLL_INTERVAL_MS,
    );
    this.#timer.unref();
    poll();
  }

  public async refresh(): Promise<void> {
    if (this.#stopped) return;
    if (this.#pending !== null) return await this.#pending;
    const abortController = new AbortController();
    this.#abortController = abortController;
    let update: Promise<void> | null = null;
    update = (async () => {
      try {
        const progress = deepScanProgressFromWorkbench(
          await this.#options.read(abortController.signal),
        );
        if (
          this.#stopped ||
          abortController.signal.aborted ||
          progress === null ||
          sameProgress(progress, this.#lastProgress)
        ) {
          return;
        }
        this.#lastProgress = progress;
        this.#options.onProgress(progress);
      } catch (error) {
        if (this.#stopped || abortController.signal.aborted) return;
        throw error;
      } finally {
        if (this.#pending === update) this.#pending = null;
        if (this.#abortController === abortController) {
          this.#abortController = null;
        }
      }
    })();
    this.#pending = update;
    await update;
  }

  public stop(): void {
    if (this.#stopped) return;
    this.#stopped = true;
    if (this.#timer !== null) {
      clearInterval(this.#timer);
      this.#timer = null;
    }
    this.#abortController?.abort();
    this.#abortController = null;
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
  if (
    !isRecord(independentReviews) ||
    !isCount(independentReviews["completed"]) ||
    !isCount(independentReviews["active"]) ||
    !isPositiveCount(independentReviews["maximum"])
  ) {
    throw new Error(
      "Codex Security workbench returned invalid Deep Scan progress.",
    );
  }
  return {
    completed: independentReviews["completed"],
    active: independentReviews["active"],
    maximum: independentReviews["maximum"],
  };
}

function sameProgress(
  left: DeepScanProgress,
  right: DeepScanProgress | null,
): boolean {
  return (
    right !== null &&
    left.completed === right.completed &&
    left.active === right.active &&
    left.maximum === right.maximum
  );
}

function isCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isPositiveCount(value: unknown): value is number {
  return isCount(value) && value > 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
