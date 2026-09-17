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
  let stopped = false;
  let warned = false;
  let checking = false;

  const check = async (): Promise<void> => {
    if (stopped || warned || options.signal.aborted || checking) return;
    checking = true;
    try {
      const revision = await options.readRevision(options.signal);
      if (
        !stopped &&
        !options.signal.aborted &&
        revision !== null &&
        revision !== options.expectedRevision &&
        !warned
      ) {
        warned = true;
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
  const ready = check();

  return {
    ready,
    check,
    stop: () => {
      if (stopped) return;
      stopped = true;
      clearInterval(timer);
    },
  };
}
