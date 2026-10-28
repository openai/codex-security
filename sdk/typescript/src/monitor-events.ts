import { isDeepStrictEqual } from "node:util";
import type { CodexSecuritySurface } from "./api.js";
import { CodexSecurityError, errorMessage } from "./errors.js";
import {
  DEFAULT_EVENT_BATCH_SIZE,
  DEFAULT_EVENT_MAX_WAIT_SECONDS,
  ReviewEventSettingsSchema,
} from "./project-config-schema.js";
import {
  parseSecurityEventBatch,
  securityEventId,
  reviewSecurityEventsInternal,
  type ReviewSecurityEventsOptions,
  type SecurityEventBatch,
  type SecurityEventInput,
  type SecurityEventReview,
} from "./review-events.js";
import { abortable } from "./targets.js";

export interface MonitorSecurityEventsOptions extends ReviewSecurityEventsOptions {
  /** Flush after this many input batches (default 10). */
  batchSize?: number;
  /** Flush this many seconds after the first pending batch (default 600). */
  maxWaitSeconds?: number;
}

/** Inclusive, one-based input record positions within this monitor invocation. */
export interface LiveSecurityEventReview extends SecurityEventReview {
  firstLine: number;
  lastLine: number;
}

type Event = SecurityEventBatch["groups"][number]["events"][number];

function combine(records: SecurityEventBatch[]): SecurityEventBatch {
  const groups = new Map<
    string,
    { fresh: Map<string, Event>; history: Map<string, Event> }
  >();
  for (const record of records) {
    for (const { id, events, contextEvents } of record.groups) {
      const group = groups.get(id) ?? {
        fresh: new Map<string, Event>(),
        history: new Map<string, Event>(),
      };
      groups.set(id, group);
      for (const [items, destination] of [
        [events, group.fresh],
        [contextEvents ?? [], group.history],
      ] as const) {
        for (const event of items) {
          const eventId = securityEventId(event);
          const previous =
            group.fresh.get(eventId) ?? group.history.get(eventId);
          if (previous && !isDeepStrictEqual(previous, event))
            throw new CodexSecurityError(
              `Conflicting event ${eventId} in group ${id}.`,
            );
          destination.set(eventId, event);
        }
      }
    }
  }
  return {
    ...records[0]!,
    groups: Array.from(groups, ([id, { fresh, history }]) => ({
      id,
      events: [...fresh.values()],
      contextEvents: [...history.values()].filter(
        (event) => !fresh.has(securityEventId(event)),
      ),
    })),
  };
}

/** Review an ordered stream of native inputs or version 1 batches, yielding one result per window. */
export function monitorSecurityEvents(
  batches: AsyncIterable<SecurityEventInput>,
  options: MonitorSecurityEventsOptions = {},
): AsyncGenerator<LiveSecurityEventReview> {
  return monitorSecurityEventsInternal(batches, options, "sdk");
}

const timeout = Symbol("window deadline");

async function readUntil<T>(
  read: Promise<T>,
  deadline: number,
): Promise<T | typeof timeout> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      read,
      new Promise<typeof timeout>((resolve) => {
        timer = setTimeout(
          () => resolve(timeout),
          Math.ceil(deadline - performance.now()),
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/** @internal */
export async function* monitorSecurityEventsInternal(
  batches: AsyncIterable<unknown>,
  options: MonitorSecurityEventsOptions,
  surface: CodexSecuritySurface,
  review = reviewSecurityEventsInternal,
): AsyncGenerator<LiveSecurityEventReview> {
  const { signal } = options;
  const batchSize =
    ReviewEventSettingsSchema.shape.batch_size.parse(options.batchSize) ??
    DEFAULT_EVENT_BATCH_SIZE;
  const wait =
    1000 *
    (ReviewEventSettingsSchema.shape.max_wait_seconds.parse(
      options.maxWaitSeconds,
    ) ?? DEFAULT_EVENT_MAX_WAIT_SECONDS);
  const iterator = batches[Symbol.asyncIterator]();
  const readNext = async () => ({
    next: await abortable(() => iterator.next(), signal),
    received: performance.now(),
  });
  let pending: ReturnType<typeof readNext> | undefined;
  let records: SecurityEventBatch[] = [];
  let deadline = 0;
  let count = 0;
  let first = 1;
  async function flush() {
    const window = records;
    records = [];
    try {
      return {
        ...(await review(combine(window), options, surface)),
        firstLine: first,
        lastLine: first + window.length - 1,
      };
    } catch (cause) {
      signal?.throwIfAborted();
      throw new CodexSecurityError(
        `Live input lines ${first}–${first + window.length - 1}: ${errorMessage(cause)}`,
        { cause },
      );
    }
  }
  try {
    while (true) {
      signal?.throwIfAborted();
      if (
        records.length &&
        (records.length === batchSize || performance.now() >= deadline)
      ) {
        yield await flush();
        continue;
      }
      // A deadline can win while the next read is pending. Reuse that read after
      // yielding the window so quiet streams neither lose records nor issue two reads.
      pending ??= readNext();
      const read = pending;
      const item = records.length
        ? await readUntil(read, deadline)
        : await read;
      if (item === timeout) {
        yield await flush();
        continue;
      }
      pending = undefined;
      const { next, received } = item;
      if (next.done) {
        if (records.length) yield await flush();
        return;
      }
      count++;
      let record: SecurityEventBatch;
      try {
        record = parseSecurityEventBatch(next.value);
      } catch (cause) {
        throw new CodexSecurityError(
          `Live input line ${count}: ${errorMessage(cause)}`,
          { cause },
        );
      }
      const previous = records[0];
      if (
        previous &&
        (record.source !== previous.source ||
          record.serviceContext !== previous.serviceContext ||
          received >= deadline)
      ) {
        yield await flush();
      }
      if (!records.length) {
        first = count;
        deadline = received + wait;
      }
      records.push(record);
    }
  } finally {
    const cleanup = iterator.return?.();
    // An async generator may queue return behind an outstanding read. Its
    // producer owns cancellation of that read (the CLI destroys stdin).
    if (pending) void cleanup?.catch(() => {});
    else await cleanup;
  }
}
