import { setTimeout as delay } from "node:timers/promises";
import { z } from "zod";

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

  start(): void {
    this.#polling ??= this.#poll();
  }

  async #poll(): Promise<void> {
    const signal = this.#pollController.signal;
    let warned = false;
    while (!signal.aborted) {
      try {
        await this.#readPages(signal);
        warned = false;
      } catch (error) {
        if (!signal.aborted && !warned) this.#options.onError(error);
        warned = true;
      }
      await delay(5000, undefined, { signal, ref: false }).catch(() => {});
    }
  }

  async #readPages(
    signal: AbortSignal,
    read: FindingUpdateOptions["read"] = this.#options.read,
  ): Promise<void> {
    while (!signal.aborted) {
      const result = await read(this.#cursor, signal);
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
    // There is no next poll after sealing. Retry a failed transport read once
    // from the last delivered page, without replaying an accepted page.
    let retry = true;
    await this.#readPages(signal, async (cursor, active) => {
      try {
        return await this.#options.read(cursor, active);
      } catch (error) {
        if (!retry || active.aborted) throw error;
        retry = false;
        return await this.#options.read(cursor, active);
      }
    }).catch((error: unknown) => {
      if (!signal.aborted) this.#options.onError(error);
    });
  }
}
