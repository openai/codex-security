import { setTimeout as delay } from "node:timers/promises";

/**
 * Windows can temporarily deny a rename while a file or descendant is open.
 * @param {() => Promise<void>} operation
 * @param {() => Promise<void>} [rollback]
 * @param {AbortSignal} [signal]
 */
export async function retryWindowsRename(operation, rollback, signal) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await operation();
    } catch (error) {
      await rollback?.();
      if (
        process.platform !== "win32" ||
        !["EPERM", "EACCES", "EBUSY"].includes(error?.code) ||
        attempt === 5
      ) {
        throw error;
      }
      await delay(100 * (attempt + 1), undefined, { signal });
    }
  }
}
