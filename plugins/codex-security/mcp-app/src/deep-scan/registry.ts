import { setTimeout as delay } from "node:timers/promises";
import { DeepScanCoordinator } from "./coordinator.js";
import type { CoordinatorOptions } from "./coordinator.js";
import { isTransientPersistenceError } from "./store.js";
import type { BeginDeepScanResult, DeepScanCoordinatorClaim, DeepScanRunState } from "./types.js";

const COORDINATOR_LEASE_MS = 30_000;
const COORDINATOR_POLL_MS = 1_000;

export { DeepScanCoordinator, DeepScanNonRetryableError } from "./coordinator.js";

/** Owns the live coordinators in this MCP server process. */
export class DeepScanCoordinatorRegistry {
  private readonly coordinators = new Map<string, DeepScanCoordinator>();

  get(scanId: string): DeepScanCoordinator | undefined {
    return this.coordinators.get(scanId);
  }

  start(options: CoordinatorOptions): DeepScanCoordinator {
    const existing = this.coordinators.get(options.run.scanId);
    if (existing) return existing;
    const { observeReplacement: _unused, ...remoteOptions } = options;
    let coordinator!: DeepScanCoordinator;
    coordinator = new DeepScanCoordinator({
      ...options,
      observeReplacement: async (run) => {
        if (this.coordinators.get(run.scanId) === coordinator) {
          this.coordinators.delete(run.scanId);
        }
        const observer = new DeepScanRemoteCoordinator({
          run,
          registry: this,
          options: remoteOptions
        });
        return await observer.wait(undefined);
      }
    });
    this.coordinators.set(options.run.scanId, coordinator);
    const removeCoordinator = (): void => {
      if (this.coordinators.get(options.run.scanId) === coordinator) {
        this.coordinators.delete(options.run.scanId);
      }
    };
    void coordinator.settled().then(removeCoordinator, removeCoordinator);
    coordinator.start();
    return coordinator;
  }

  cancel(scanId: string, reason: string): boolean {
    const coordinator = this.coordinators.get(scanId);
    if (!coordinator) return false;
    coordinator.cancel(reason);
    return true;
  }

  async cancelAndWait(
    scanId: string,
    reason: string,
    persistCancellation: () => Promise<void>
  ): Promise<boolean> {
    const coordinator = this.coordinators.get(scanId);
    if (!coordinator) return false;
    await coordinator.cancelAfterPersistence(reason, persistCancellation);
    return true;
  }

  failExternallyPersisted(scanId: string, reason: string): boolean {
    const coordinator = this.coordinators.get(scanId);
    if (!coordinator) return false;
    coordinator.failExternallyPersisted(reason);
    return true;
  }

  shutdown(reason: string): void {
    for (const coordinator of this.coordinators.values()) coordinator.cancel(reason);
  }
}

/** Serializes start-or-join calls so one scan can create only one coordinator. */
export class DeepScanStartLock {
  private tail: Promise<void> = Promise.resolve();

  async run<T>(operation: () => Promise<T>): Promise<T> {
    const predecessor = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>((resolvePromise) => {
      release = resolvePromise;
    });
    await predecessor;
    try {
      return await operation();
    } finally {
      release();
    }
  }
}

/** Observes another MCP process without failing or duplicating its coordinator. */
export class DeepScanRemoteCoordinator {
  private nextClaimAt = Date.now() + COORDINATOR_LEASE_MS;

  constructor(
    private readonly input: {
      run: DeepScanRunState;
      registry: Pick<DeepScanCoordinatorRegistry, "get" | "start">;
      options: Omit<CoordinatorOptions, "run" | "observeReplacement">;
    }
  ) {}

  async wait(signal: AbortSignal | undefined): Promise<DeepScanRunState>;
  async wait(
    signal: AbortSignal | undefined,
    timeoutMs: number
  ): Promise<DeepScanRunState | undefined>;
  async wait(
    signal: AbortSignal | undefined,
    timeoutMs?: number
  ): Promise<DeepScanRunState | undefined> {
    const { options, registry } = this.input;
    const threadId = options.threadId;
    if (!threadId) {
      throw new Error("Observing a Deep Scan requires its owning Codex thread.");
    }
    const deadline = timeoutMs === undefined ? undefined : Date.now() + timeoutMs;
    while (true) {
      if (signal?.aborted) throw remoteAbortError(signal.reason);
      let run: DeepScanRunState;
      try {
        run = await options.store.get(this.input.run.scanId, threadId);
      } catch (error) {
        if (!isTransientPersistenceError(error)) throw error;
        const remaining = deadline === undefined ? COORDINATOR_POLL_MS : deadline - Date.now();
        if (remaining <= 0) return undefined;
        await delay(Math.min(COORDINATOR_POLL_MS, remaining), undefined, { signal });
        continue;
      }
      if (run.status !== "running") return run;

      const heartbeat = run.updatedAt ? Date.parse(run.updatedAt) : Number.NaN;
      if (
        (!Number.isFinite(heartbeat) || Date.now() - heartbeat >= COORDINATOR_LEASE_MS)
        && Date.now() >= this.nextClaimAt
      ) {
        const local = registry.get(run.scanId);
        if (local) {
          return deadline === undefined
            ? await local.wait(signal)
            : await local.wait(signal, Math.max(0, deadline - Date.now()));
        }
        let claim: DeepScanCoordinatorClaim | undefined;
        try {
          claim = await options.store.claimCoordinator({
            scanId: run.scanId,
            threadId,
            handoffClaimToken: options.handoffClaimToken
          });
        } catch (error) {
          if (!isTransientPersistenceError(error)) {
            try {
              const latest = await options.store.get(run.scanId, threadId);
              if (latest.status !== "running") return latest;
              throw error;
            } catch (readError) {
              if (!isTransientPersistenceError(readError)) throw readError;
            }
          }
        }
        if (claim?.acquired) {
          const coordinator = registry.start({ ...options, run: claim.run });
          return deadline === undefined
            ? await coordinator.wait(signal)
            : await coordinator.wait(signal, Math.max(0, deadline - Date.now()));
        }
        if (claim) this.nextClaimAt = Date.now() + COORDINATOR_LEASE_MS;
      }

      const remaining = deadline === undefined ? COORDINATOR_POLL_MS : deadline - Date.now();
      if (remaining <= 0) return undefined;
      await delay(Math.min(COORDINATOR_POLL_MS, remaining), undefined, { signal });
    }
  }
}

export async function startOrJoinDeepScanCoordinator(input: {
  begin: BeginDeepScanResult;
  registry: Pick<DeepScanCoordinatorRegistry, "get" | "start">;
  options: Omit<CoordinatorOptions, "run" | "observeReplacement">;
}): Promise<{
  coordinator: DeepScanCoordinator | DeepScanRemoteCoordinator;
  joined: boolean;
}> {
  const existing = input.registry.get(input.begin.run.scanId);
  if (existing) return { coordinator: existing, joined: true };
  const threadId = input.options.threadId;
  if (!threadId) {
    throw new Error("Starting or joining a Deep Scan requires its owning Codex thread.");
  }
  const claim = await input.options.store.claimCoordinator({
    scanId: input.begin.run.scanId,
    threadId,
    handoffClaimToken: input.options.handoffClaimToken
  });
  if (!claim.acquired) {
    return {
      coordinator: new DeepScanRemoteCoordinator({
        run: claim.run,
        registry: input.registry,
        options: input.options
      }),
      joined: true
    };
  }
  return {
    coordinator: input.registry.start({ ...input.options, run: claim.run }),
    joined: false
  };
}

function remoteAbortError(reason: unknown): Error {
  const error = new Error("Deep Scan observation was aborted.", { cause: reason });
  error.name = "AbortError";
  return error;
}
