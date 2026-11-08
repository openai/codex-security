import { randomUUID } from "node:crypto";

/** Content-free publication accounting, also stored on existing publication receipts. */
export interface PublicationTelemetry {
  schemaVersion: 1;
  attemptId: string;
  destination: "linear" | "custom";
  startedAt: string;
  observedAt: string;
  /** Elapsed time through this snapshot; receipt persistence may follow. */
  durationMs: number;
  attempted: boolean;
  outcome: "completed" | "failed" | "canceled" | "indeterminate" | "preview";
  counts: {
    /** Null when preparation did not determine the selected findings. */
    selected: number | null;
    /** Findings handed to publication; this is not an HTTP request count. */
    submitted: number;
    /** Confirmed creations, excluding unverified mutations; null when not reported. */
    created: number | null;
    /** Confirmed reuse; null when remote upserts do not distinguish existing records. */
    reused: number | null;
    /** Findings acknowledged by the destination, whether new or already present. */
    acknowledged: number | null;
    /** Reconciled failures; null when the mutation outcome is unknown. */
    failed: number | null;
  };
}

export type PublicationTelemetryObserver = (
  telemetry: Readonly<PublicationTelemetry>,
) => void;

/** Enrich receipts and notify an optional host; no transport or additional storage. */
export class PublicationTelemetryRecorder {
  readonly attemptId = randomUUID();
  readonly startedAt = new Date().toISOString();
  readonly started = performance.now();
  attempted = false;
  counts: PublicationTelemetry["counts"] = {
    selected: null,
    submitted: 0,
    created: 0,
    reused: 0,
    acknowledged: 0,
    failed: 0,
  };
  outcome: PublicationTelemetry["outcome"] = "failed";

  private constructor(
    private readonly destination: PublicationTelemetry["destination"],
    private readonly observer?: PublicationTelemetryObserver,
  ) {}

  static async observe<T extends { telemetry?: PublicationTelemetry }>(
    destination: PublicationTelemetry["destination"],
    options: {
      onTelemetry?: PublicationTelemetryObserver;
      signal?: AbortSignal;
      dryRun?: boolean;
    },
    publish: (telemetry: PublicationTelemetryRecorder) => Promise<T>,
  ): Promise<T> {
    const recorder = new PublicationTelemetryRecorder(
      destination,
      options.onTelemetry,
    );
    try {
      const result = await publish(recorder);
      result.telemetry ??= recorder.snapshot(
        options.dryRun ? "preview" : "completed",
      );
      recorder.notify(result.telemetry);
      return result;
    } catch (error) {
      recorder.notify(
        recorder.snapshot(
          recorder.outcome === "indeterminate"
            ? "indeterminate"
            : options.signal?.aborted
              ? "canceled"
              : "failed",
        ),
      );
      throw error;
    }
  }

  snapshot(outcome = this.outcome): PublicationTelemetry {
    return Object.freeze({
      schemaVersion: 1,
      attemptId: this.attemptId,
      destination: this.destination,
      startedAt: this.startedAt,
      observedAt: new Date().toISOString(),
      durationMs: Math.max(0, performance.now() - this.started),
      attempted: this.attempted,
      outcome,
      counts: Object.freeze({ ...this.counts }),
    });
  }

  private notify(telemetry: PublicationTelemetry): void {
    void Promise.resolve()
      .then(() => this.observer?.(telemetry))
      .catch(() => {});
  }
}
