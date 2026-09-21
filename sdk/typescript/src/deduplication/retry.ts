import { setTimeout } from "node:timers/promises";
import type { DeduplicationReviewFailurePolicy } from "./review-failure.js";

export function retryDelay(attempt: number, random = Math.random): number {
  return 1_000 * 2 ** (attempt - 1) * (1 + random());
}

export async function waitForRetry(
  delayMs: number,
  signal?: AbortSignal,
): Promise<void> {
  signal?.throwIfAborted();
  try {
    await setTimeout(delayMs, undefined, { signal });
  } catch (error) {
    signal?.throwIfAborted();
    throw error;
  }
}

export async function runReviewSessions<T>(
  runSession: (session: number) => Promise<T>,
  failurePolicy: (
    error: unknown,
  ) => DeduplicationReviewFailurePolicy | undefined,
  options: {
    signal?: AbortSignal;
    wait?: typeof waitForRetry;
    random?: () => number;
  } = {},
): Promise<T> {
  for (let session = 1; ; session++) {
    options.signal?.throwIfAborted();
    try {
      return await runSession(session);
    } catch (error) {
      options.signal?.throwIfAborted();
      if (session >= 3 || failurePolicy(error)?.retryable !== true) throw error;
      await (options.wait ?? waitForRetry)(
        retryDelay(session, options.random),
        options.signal,
      );
    }
  }
}
