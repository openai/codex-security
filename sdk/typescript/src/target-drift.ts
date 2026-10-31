export interface HeadDriftMonitorOptions {
  expectedRevision: string;
  readRevision: (signal: AbortSignal) => Promise<string | null>;
  signal: AbortSignal;
  onDrift: () => void;
  intervalMs?: number;
}

export interface HeadDriftMonitor {
  readonly ready: Promise<void>;
  check(): Promise<void>;
  stop(): void;
}

const DEFAULT_HEAD_DRIFT_INTERVAL_MS = 1_000;

export function startHeadDriftMonitor(
  options: HeadDriftMonitorOptions,
): HeadDriftMonitor {
  const controller = new AbortController();
  const signal = AbortSignal.any([options.signal, controller.signal]);
  let checking = false;

  const check = async (): Promise<void> => {
    if (signal.aborted || checking) return;
    checking = true;
    try {
      const revision = await options.readRevision(signal);
      if (
        !signal.aborted &&
        revision !== null &&
        revision !== options.expectedRevision
      ) {
        stop();
        options.onDrift();
      }
    } catch {
      // A transient inability to read HEAD should not interrupt a scan. The
      // final target validation remains authoritative if the repository is
      // unavailable or changes before completion.
    } finally {
      checking = false;
    }
  };

  const timer = setInterval(() => {
    void check();
  }, options.intervalMs ?? DEFAULT_HEAD_DRIFT_INTERVAL_MS);
  timer.unref();
  const stop = () => {
    clearInterval(timer);
    controller.abort();
  };
  signal.addEventListener("abort", () => clearInterval(timer), { once: true });
  if (signal.aborted) clearInterval(timer);

  return { ready: check(), check, stop };
}
