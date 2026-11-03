import { setTimeout } from "node:timers/promises";

const MAX_TIMER_DELAY_MS = 2_147_483_647;

export function retryDelay(attempt: number, random = Math.random): number {
  return 1_000 * 2 ** (attempt - 1) * (1 + random());
}

export async function waitForRetry(
  delayMs: number,
  signal?: AbortSignal,
): Promise<void> {
  signal?.throwIfAborted();
  try {
    while (delayMs > MAX_TIMER_DELAY_MS) {
      await setTimeout(MAX_TIMER_DELAY_MS, undefined, { signal });
      delayMs -= MAX_TIMER_DELAY_MS;
    }
    await setTimeout(delayMs, undefined, { signal });
  } catch (error) {
    signal?.throwIfAborted();
    throw error;
  }
}
