interface HeadDriftMonitorOptions {
  expectedRevision: string;
  readRevision: (signal: AbortSignal) => Promise<string | null>;
  signal: AbortSignal;
  onDrift: () => void;
}

export function startHeadDriftMonitor(
  options: HeadDriftMonitorOptions,
): () => void {
  const controller = new AbortController();
  const signal = AbortSignal.any([options.signal, controller.signal]);
  let timer: NodeJS.Timeout | undefined;
  signal.addEventListener("abort", () => clearTimeout(timer), { once: true });

  async function check(): Promise<void> {
    if (signal.aborted) return;
    try {
      const revision = await options.readRevision(signal);
      if (
        !signal.aborted &&
        revision !== null &&
        revision !== options.expectedRevision
      ) {
        controller.abort();
        options.onDrift();
      }
    } catch {
      // Failed reads and warning observers must not interrupt the scan.
    }
    if (!signal.aborted) timer = setTimeout(check, 1_000).unref();
  }

  void check();
  return () => controller.abort();
}
