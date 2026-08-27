import type { DashboardSnapshot } from "../src/server/dashboard-types.js";

/** Poll immediately and every five seconds, without overlapping requests. */
export function pollDashboard(
  read: (signal: AbortSignal) => Promise<DashboardSnapshot>,
  onData: (snapshot: DashboardSnapshot) => void,
  onError: (error: unknown) => void,
  clock: Pick<typeof globalThis, "setInterval" | "clearInterval"> = globalThis,
): () => void {
  const controller = new AbortController();
  let pending = false;
  async function refresh() {
    if (pending || controller.signal.aborted) return;
    pending = true;
    try {
      const snapshot = await read(controller.signal);
      if (!controller.signal.aborted) onData(snapshot);
    } catch (error) {
      if (!controller.signal.aborted) onError(error);
    } finally {
      pending = false;
    }
  }
  void refresh();
  const timer = clock.setInterval(() => void refresh(), 5_000);
  return () => {
    controller.abort();
    clock.clearInterval(timer);
  };
}
