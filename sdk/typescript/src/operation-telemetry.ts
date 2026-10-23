import { createHash, randomUUID } from "node:crypto";
import {
  appendFile,
  mkdir,
  readFile,
  readdir,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import type { ScanUsageMeasurement } from "./cost.js";
import {
  canonicalConfigPath,
  requireOutputOutsideRepositories,
  requireSecureOutputAncestry,
} from "./runtime.js";
import { gitProtectionRoots } from "./targets.js";
import { VERSION } from "./version.js";

export type OperationOutcome =
  "completed" | "failed" | "canceled" | "unresolved";
export type OperationFailureCategory =
  | "configuration"
  | "authentication"
  | "input"
  | "budget"
  | "execution"
  | "canceled";

/** Content-free operational receipts. IDs are for joins, never metric labels. */
export interface OperationTelemetryEvent {
  schemaVersion: 1;
  eventId: string;
  operationId: string;
  attemptId: string;
  parentAttemptId?: string;
  /** Resumed scans share a cumulative measurement scope; never sum those receipts. */
  usageScopeId: string;
  occurredAt: string;
  observedAt: string;
  type: "attempt_started" | "attempt_finished";
  command:
    | "scan"
    | "patch"
    | "validate"
    | "policy"
    | "verify-fix"
    | "assess-patch-risk";
  surface: "cli" | "sdk";
  packageVersion: string;
  mode?: "standard" | "deep";
  resumed: boolean;
  /** True when this call returned a saved result without starting new work. */
  reusedResult?: boolean;
  outcome?: OperationOutcome;
  failureCategory?: OperationFailureCategory;
  durationMs?: number;
  measurement?: Readonly<ScanUsageMeasurement>;
  findingCount?: number;
  reviewedSurfaceCount?: number;
  deferredCount?: number;
  pluginVersion?: string;
  providerFamily?: string;
  validationDisposition?:
    "reportable" | "suppressed" | "not_applicable" | "deferred";
  artifactComplete?: boolean;
  collection: { persisted: number; writeFailures: number };
}

interface OperationTelemetryOptions {
  directory: string;
  protectedRepository?: string;
  protectedOutput?: string;
  command: OperationTelemetryEvent["command"];
  surface: OperationTelemetryEvent["surface"];
  mode?: OperationTelemetryEvent["mode"];
  resumeScanId?: string;
  deferPersistence?: boolean;
  context?: { operationId: string; parentAttemptId?: string };
  onEvent?: (event: Readonly<OperationTelemetryEvent>) => void;
  onError?: (error: unknown) => void;
}

/** Local journal only. Export, acknowledgement and retention belong to the host. */
export class OperationTelemetry {
  readonly attemptId = randomUUID();
  operationId: string;
  measurement: Readonly<ScanUsageMeasurement> | undefined;
  reusedResult = false;
  readonly #started = performance.now();
  readonly #startedAt = new Date().toISOString();
  readonly #options: OperationTelemetryOptions;
  readonly #directory: string;
  #persisted = 0;
  #writeFailures = 0;
  #ready = false;
  #runtime: Pick<OperationTelemetryEvent, "pluginVersion" | "providerFamily"> =
    {};
  #finished = false;
  #usageScopeId: string = this.attemptId;
  #deferred: boolean;
  #startedEvent: OperationTelemetryEvent | undefined;

  constructor(options: OperationTelemetryOptions) {
    this.#options = options;
    this.operationId = options.context?.operationId ?? randomUUID();
    this.#directory = join(options.directory, "telemetry");
    this.#deferred = options.deferPersistence === true;
  }

  get context() {
    return {
      operationId: this.operationId,
      attemptId: this.attemptId,
      ...(this.#options.context?.parentAttemptId === undefined
        ? {}
        : { parentAttemptId: this.#options.context.parentAttemptId }),
    };
  }

  async start(): Promise<void> {
    if (!this.#deferred) await this.#preparePersistence();
    await this.#emit("attempt_started");
  }

  /** Callers establish repository and artifact protection before any writes. */
  async activatePersistence(protectedRoots: readonly string[]): Promise<void> {
    if (!this.#deferred || this.#finished) return;
    this.#deferred = false;
    await this.#preparePersistence(protectedRoots);
    if (this.#startedEvent !== undefined) {
      const event = {
        ...this.#startedEvent,
        ...this.context,
        usageScopeId: this.#usageScopeId,
        collection: {
          persisted: this.#persisted + (this.#ready ? 1 : 0),
          writeFailures: this.#writeFailures,
        },
      };
      if (this.#ready) await this.#persist(event);
      if (this.#options.resumeScanId !== undefined) this.#notify(event);
    }
    this.#startedEvent = undefined;
  }

  async #preparePersistence(
    additionalRoots: readonly string[] = [],
  ): Promise<void> {
    try {
      const protectedRoots = [...additionalRoots];
      if (this.#options.protectedOutput !== undefined) {
        protectedRoots.push(
          await canonicalConfigPath(this.#options.protectedOutput),
        );
      }
      if (this.#options.protectedRepository !== undefined) {
        const repository = await canonicalConfigPath(
          this.#options.protectedRepository,
        );
        protectedRoots.push(
          repository,
          ...(await gitProtectionRoots(this.#options.protectedRepository)),
        );
      }
      if (protectedRoots.length > 0) {
        requireOutputOutsideRepositories(
          protectedRoots,
          await canonicalConfigPath(this.#directory),
          "runtime",
        );
      }
      await requireSecureOutputAncestry(this.#directory);
      await mkdir(this.#directory, { recursive: true, mode: 0o700 });
      this.#ready = true;
      if (this.#options.resumeScanId !== undefined) {
        try {
          const saved = JSON.parse(
            await readFile(
              this.#bindingPath(this.#options.resumeScanId),
              "utf8",
            ),
          ) as { operationId: string; usageScopeId: string };
          this.operationId = saved.operationId;
          this.#usageScopeId = saved.usageScopeId;
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT")
            this.#error(error);
        }
      }
    } catch (error) {
      this.#error(error);
    }
  }

  async bindScan(scanId: string): Promise<void> {
    if (!this.#ready) return;
    try {
      await writeFile(
        this.#bindingPath(scanId),
        JSON.stringify({
          ...this.context,
          usageScopeId: this.#usageScopeId,
        }),
        {
          mode: 0o600,
        },
      );
    } catch (error) {
      this.#error(error);
    }
  }

  describe(
    runtime: Pick<OperationTelemetryEvent, "pluginVersion" | "providerFamily">,
  ): void {
    this.#runtime = runtime;
  }

  async finish(
    outcome: OperationOutcome,
    details: Pick<
      OperationTelemetryEvent,
      | "failureCategory"
      | "findingCount"
      | "artifactComplete"
      | "reviewedSurfaceCount"
      | "deferredCount"
      | "validationDisposition"
    > = {},
  ): Promise<void> {
    if (this.#finished) return;
    this.#finished = true;
    if (
      this.#startedEvent !== undefined &&
      this.#options.resumeScanId !== undefined
    ) {
      this.#notify(this.#startedEvent);
      this.#startedEvent = undefined;
    }
    await this.#emit("attempt_finished", {
      outcome,
      reusedResult: this.reusedResult,
      durationMs: Math.max(0, performance.now() - this.#started),
      ...(this.measurement === undefined
        ? {}
        : { measurement: this.measurement }),
      ...this.#runtime,
      ...details,
    });
  }

  #bindingPath(scanId: string): string {
    return join(
      this.#directory,
      `${createHash("sha256").update(scanId).digest("hex")}.binding.json`,
    );
  }

  #error(error: unknown): void {
    this.#writeFailures++;
    try {
      this.#options.onError?.(error);
    } catch {}
  }

  async #persist(event: OperationTelemetryEvent): Promise<void> {
    try {
      await appendFile(
        join(this.#directory, `${this.attemptId}.jsonl`),
        `${JSON.stringify(event)}\n`,
        { mode: 0o600 },
      );
      this.#persisted++;
    } catch (error) {
      this.#error(error);
      event.collection = {
        persisted: this.#persisted,
        writeFailures: this.#writeFailures,
      };
    }
  }

  async #emit(
    type: OperationTelemetryEvent["type"],
    details: Partial<OperationTelemetryEvent> = {},
  ): Promise<void> {
    const time = new Date().toISOString();
    const event: OperationTelemetryEvent = {
      schemaVersion: 1,
      eventId: `${this.attemptId}:${type}`,
      ...this.context,
      usageScopeId: this.#usageScopeId,
      occurredAt: type === "attempt_started" ? this.#startedAt : time,
      observedAt: time,
      type,
      command: this.#options.command,
      surface: this.#options.surface,
      packageVersion: VERSION,
      ...(this.#options.mode === undefined ? {} : { mode: this.#options.mode }),
      resumed: this.#options.resumeScanId !== undefined,
      ...details,
      collection: {
        persisted: this.#persisted + (this.#ready ? 1 : 0),
        writeFailures: this.#writeFailures,
      },
    };
    if (this.#ready) await this.#persist(event);
    else if (this.#deferred && type === "attempt_started") {
      this.#startedEvent = event;
      // Resume identity is restored only after the caller protects output paths.
      if (this.#options.resumeScanId !== undefined) return;
    }
    this.#notify(event);
  }

  #notify(event: OperationTelemetryEvent): void {
    // Observers cannot delay or fail the operation. Replay uses the same event ID.
    void Promise.resolve()
      .then(() => this.#options.onEvent?.(event))
      .catch(() => {});
  }
}

/** Read durable receipts, retaining explicit evidence of truncated/corrupt records. */
export async function readOperationTelemetry(stateDirectory: string): Promise<{
  events: OperationTelemetryEvent[];
  parseFailures: number;
}> {
  const directory = join(stateDirectory, "telemetry");
  const events: OperationTelemetryEvent[] = [];
  let parseFailures = 0;
  const names = await readdir(directory).catch(
    (error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return [];
      throw error;
    },
  );
  for (const name of names.filter((name) => name.endsWith(".jsonl")).sort()) {
    for (const line of (await readFile(join(directory, name), "utf8")).split(
      "\n",
    )) {
      if (!line) continue;
      try {
        const event = JSON.parse(line) as OperationTelemetryEvent;
        if (
          event.schemaVersion !== 1 ||
          typeof event.eventId !== "string" ||
          typeof event.attemptId !== "string" ||
          typeof event.operationId !== "string" ||
          typeof event.usageScopeId !== "string" ||
          !["attempt_started", "attempt_finished"].includes(event.type) ||
          ((event.type === "attempt_finished" || event.outcome !== undefined) &&
            !["completed", "failed", "canceled", "unresolved"].includes(
              event.outcome ?? "",
            )) ||
          (event.measurement !== undefined &&
            !["complete", "partial", "unavailable"].includes(
              event.measurement?.coverage,
            ))
        ) {
          parseFailures++;
        } else events.push(event);
      } catch {
        parseFailures++;
      }
    }
  }
  return { events, parseFailures };
}

/** Attempts without a terminal receipt remain unresolved, including process loss. */
export function summarizeOperationTelemetry(
  events: readonly OperationTelemetryEvent[],
) {
  const seen = new Set<string>();
  const attempts = new Map<string, OperationTelemetryEvent>();
  let duplicates = 0;
  for (const event of events) {
    if (seen.has(event.eventId)) {
      duplicates++;
      continue;
    }
    seen.add(event.eventId);
    const previous = attempts.get(event.attemptId);
    if (
      previous?.type !== "attempt_finished" ||
      event.type === "attempt_finished"
    )
      attempts.set(event.attemptId, event);
  }
  const operations = new Map<string, boolean>();
  const outcomes = { completed: 0, failed: 0, canceled: 0, unresolved: 0 };
  const usageCoverage = { complete: 0, partial: 0, unavailable: 0 };
  const durationMs: number[] = [];
  let observedCostUsd = 0;
  let pricedAttempts = 0;
  let reusedAttempts = 0;
  const costsByScope = new Map<string, number>();
  for (const event of attempts.values()) {
    operations.set(
      event.operationId,
      operations.get(event.operationId) === true ||
        event.outcome === "completed",
    );
    outcomes[event.outcome ?? "unresolved"]++;
    if (event.reusedResult === true) reusedAttempts++;
    else usageCoverage[event.measurement?.coverage ?? "unavailable"]++;
    if (event.durationMs !== undefined) durationMs.push(event.durationMs);
    if (event.measurement?.cost != null) {
      costsByScope.set(
        event.usageScopeId,
        Math.max(
          costsByScope.get(event.usageScopeId) ?? 0,
          event.measurement.cost.estimatedUsd,
        ),
      );
      pricedAttempts++;
    }
  }
  for (const cost of costsByScope.values()) observedCostUsd += cost;
  return {
    operations: operations.size,
    successfulOperations: [...operations.values()].filter(Boolean).length,
    attempts: attempts.size,
    outcomes,
    usageCoverage,
    durationMs,
    observedCostUsd,
    pricedAttempts,
    reusedAttempts,
    duplicates,
  };
}
