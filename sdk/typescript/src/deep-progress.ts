export interface DeepScanProgress {
  completed: number;
  active: number;
  maximum: number;
}

interface DeepScanProgressTrackerOptions {
  read: () => Promise<unknown>;
  onProgress: (progress: DeepScanProgress) => void;
  onError?: (error: unknown) => void;
  pollIntervalMs?: number;
}

const DEEP_PROGRESS_POLL_INTERVAL_MS = 5_000;

export class DeepScanProgressTracker {
  readonly #options: DeepScanProgressTrackerOptions;
  #timer: NodeJS.Timeout | null = null;
  #pending: Promise<void> = Promise.resolve();
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
    const update = this.#pending.then(async () => {
      if (this.#stopped) return;
      const progress = deepScanProgressFromWorkbench(
        await this.#options.read(),
      );
      if (progress === null || sameProgress(progress, this.#lastProgress))
        return;
      this.#lastProgress = progress;
      this.#options.onProgress(progress);
    });
    this.#pending = update.catch(() => {});
    await update;
  }

  public async stop(): Promise<void> {
    if (this.#stopped) return;
    if (this.#timer !== null) {
      clearInterval(this.#timer);
      this.#timer = null;
    }
    try {
      await this.refresh();
    } catch (error) {
      this.#options.onError?.(error);
    }
    this.#stopped = true;
    await this.#pending;
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
