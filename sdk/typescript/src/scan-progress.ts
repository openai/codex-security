import { isRecord } from "./record.js";
import { z } from "zod";
import { scanPhaseSchema, type ScanProgress } from "./worker-progress.js";

const deepProgressSchema = z
  .object({
    completed: z.int().nonnegative(),
    active: z.int().nonnegative(),
    maximum: z.int().positive(),
    consolidating: z.boolean().optional(),
  })
  .transform(({ consolidating, ...counts }) => ({
    ...counts,
    ...(consolidating === undefined ? {} : { consolidating }),
  }));

export interface DeepScanProgress extends z.output<typeof deepProgressSchema> {
  /** Whether the coordinator is reducing results or has finished. */
  consolidating?: boolean;
}

interface ScanProgressTrackerOptions {
  read: (signal: AbortSignal) => Promise<unknown>;
  onProgress?: (progress: SavedScanProgress) => void;
  onDeepProgress?: (progress: DeepScanProgress) => void;
  onError?: (error: unknown) => void;
}

const PROGRESS_POLL_INTERVAL_MS = 5_000;

export class ScanProgressTracker {
  readonly #options: ScanProgressTrackerOptions;
  #timer: NodeJS.Timeout | null = null;
  #pending: Promise<void> | null = null;
  readonly #abortController = new AbortController();
  #lastDeepProgress: DeepScanProgress | null = null;
  #lastScanProgress: string | null = null;

  public constructor(options: ScanProgressTrackerOptions) {
    this.#options = options;
  }

  public start(): void {
    if (this.#timer !== null || this.#abortController.signal.aborted) return;
    const poll = () => {
      void this.refresh().catch((error: unknown) => {
        this.#options.onError?.(error);
      });
    };
    this.#timer = setInterval(poll, PROGRESS_POLL_INTERVAL_MS);
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
        const result = await this.#options.read(abortController.signal);
        if (abortController.signal.aborted) return;
        if (this.#options.onProgress !== undefined) {
          const progress = scanProgressFromWorkbench(result);
          if (progress !== null) {
            const key = JSON.stringify(progress);
            if (key !== this.#lastScanProgress) {
              this.#lastScanProgress = key;
              this.#options.onProgress(progress);
            }
          }
        }
        if (this.#options.onDeepProgress === undefined) return;
        const progress = deepScanProgressFromWorkbench(result);
        if (
          abortController.signal.aborted ||
          progress === null ||
          (progress.completed === this.#lastDeepProgress?.completed &&
            progress.active === this.#lastDeepProgress?.active &&
            progress.maximum === this.#lastDeepProgress?.maximum &&
            progress.consolidating === this.#lastDeepProgress?.consolidating)
        ) {
          return;
        }
        this.#lastDeepProgress = progress;
        this.#options.onDeepProgress(progress);
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

const savedProgressSchema = z.object({
  phase: scanPhaseSchema,
  coverage: z
    .object({
      filesTotal: z.int().nonnegative().nullable(),
      closedRows: z.int().nonnegative(),
      worklistRows: z.int().nonnegative(),
    })
    .refine(({ closedRows, worklistRows }) => closedRows <= worklistRows),
});

export interface SavedScanProgress {
  phase: ScanProgress["phase"];
  filesTotal: number | null;
  reviewItems: NonNullable<ScanProgress["reviewItems"]>;
}

export function scanProgressFromWorkbench(
  result: unknown,
): SavedScanProgress | null {
  if (!isRecord(result) || !isRecord(result["scan"])) return null;
  const progress = result["scan"]["progress"];
  if (!isRecord(progress) || progress["coverage"] === undefined) return null;
  const parsed = savedProgressSchema.safeParse(progress);
  if (!parsed.success) {
    throw new Error("Codex Security workbench returned invalid scan progress.");
  }
  return {
    phase: parsed.data.phase,
    filesTotal: parsed.data.coverage.filesTotal,
    reviewItems: {
      completed: parsed.data.coverage.closedRows,
      total: parsed.data.coverage.worklistRows,
    },
  };
}

export function deepScanProgressFromWorkbench(
  result: unknown,
): DeepScanProgress | null {
  if (!isRecord(result) || !isRecord(result["scan"])) return null;
  const progress = result["scan"]["progress"];
  if (!isRecord(progress)) return null;
  const independentReviews = progress["independentReviews"];
  if (independentReviews === undefined) return null;
  const parsed = deepProgressSchema.safeParse(independentReviews);
  if (parsed.success) return parsed.data;
  throw new Error(
    "Codex Security workbench returned invalid Deep Scan progress.",
  );
}
