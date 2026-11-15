import { setTimeout as delay } from "node:timers/promises";
import { z } from "zod";
import { PROGRESS_POLL_INTERVAL_MS } from "./scan-progress.js";

const findingUpdateSchema = z.object({
  cursor: z.int().positive(),
  findingId: z.string(),
  kind: z.enum(["reviewed", "updated", "withdrawn", "finalized"]),
  title: z.string(),
  severity: z.string(),
  summary: z.string(),
  validation: z.string(),
  changedFields: z.array(z.string()).optional(),
  locations: z.array(z.object({ file: z.string(), line: z.int() })),
});

export interface FindingUpdate extends z.infer<typeof findingUpdateSchema> {
  scanId: string;
}

const pageSchema = z.object({
  scanId: z.string(),
  nextCursor: z.int().nonnegative(),
  hasMore: z.boolean(),
  updates: z.array(findingUpdateSchema),
});

interface FindingUpdateOptions {
  scanId: string;
  supportsProgressRead?: boolean;
  read: (cursor: number, signal: AbortSignal) => Promise<unknown>;
  onUpdate: (update: FindingUpdate) => void;
  onError: (error: unknown) => void;
}

export class FindingUpdateTracker {
  readonly #options: FindingUpdateOptions;
  readonly #pollController = new AbortController();
  #cursor = 0;
  #polling?: Promise<void>;

  constructor(options: FindingUpdateOptions) {
    this.#options = options;
  }

  start(readWithProgress?: FindingUpdateOptions["read"]): void {
    this.#polling ??= this.#poll(readWithProgress);
  }

  async #poll(readWithProgress?: FindingUpdateOptions["read"]): Promise<void> {
    const signal = this.#pollController.signal;
    let nextProgressRead = 0;
    const readLivePage: FindingUpdateOptions["read"] = async (
      cursor,
      signal,
    ) => {
      // A long journal replay can span several progress polling intervals.
      if (readWithProgress && performance.now() >= nextProgressRead) {
        nextProgressRead = performance.now() + PROGRESS_POLL_INTERVAL_MS;
        const page = await readWithProgress(cursor, signal);
        if (page !== undefined || signal.aborted) return page;
      }
      return this.#options.read(cursor, signal);
    };
    let warned = false;
    while (!signal.aborted) {
      try {
        await this.#readPages(signal, readLivePage);
        warned = false;
      } catch (error) {
        if (!signal.aborted && !warned) this.#options.onError(error);
        warned = true;
      }
      const wait = readWithProgress
        ? Math.max(0, Math.ceil(nextProgressRead - performance.now()))
        : PROGRESS_POLL_INTERVAL_MS;
      await delay(wait, undefined, { signal, ref: false }).catch(() => {});
    }
  }

  async #readPages(
    signal: AbortSignal,
    read = this.#options.read,
    retryRead = false,
  ): Promise<void> {
    while (!signal.aborted) {
      let result: unknown;
      try {
        result = await read(this.#cursor, signal);
      } catch (error) {
        if (!retryRead || signal.aborted) throw error;
        retryRead = false;
        continue;
      }
      if (signal.aborted) return;
      const page = pageSchema.parse(result);
      let previous = this.#cursor;
      for (const update of page.updates) {
        if (update.cursor <= previous)
          throw new Error("Workbench finding update cursors are out of order.");
        previous = update.cursor;
      }
      if (
        page.scanId !== this.#options.scanId ||
        page.nextCursor !== previous ||
        (page.hasMore && page.updates.length === 0)
      )
        throw new Error(
          "Workbench returned an inconsistent finding update page.",
        );
      for (const update of page.updates) {
        this.#options.onUpdate({ scanId: page.scanId, ...update });
      }
      this.#cursor = page.nextCursor;
      if (!page.hasMore) return;
    }
  }

  /** Stop any poll started before the terminal write, then read its committed updates. */
  async finish(signal: AbortSignal): Promise<void> {
    this.#pollController.abort();
    await this.#polling;
    // A transient read failure has no next poll after sealing.
    await this.#readPages(signal, this.#options.read, true).catch(
      (error: unknown) => {
        if (!signal.aborted) this.#options.onError(error);
      },
    );
  }

  get supportsProgressRead(): boolean {
    return this.#options.supportsProgressRead === true;
  }
}
