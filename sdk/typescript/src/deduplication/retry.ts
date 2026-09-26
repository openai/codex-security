import { setTimeout } from "node:timers/promises";

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
