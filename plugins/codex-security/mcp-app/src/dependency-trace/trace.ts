import { availableParallelism } from "node:os";
import { createTraceCache } from "./cache.ts";
import { localProvider } from "./provider.ts";
import type {
  ScopeResult,
  TraceProvider,
  TraceRequest,
  TraceResult,
  TraceScope,
} from "./types.ts";

// Bound both the scheduler's working set and the model-visible response.
const MAX_SCOPES = 96;
const MAX_EVIDENCE = 128;
const MAX_TEXT_MATCHES = 128;
const MAX_EXPANSIONS = 256;

// A native scan runs one job with a 256 MiB rule limit, plus process overhead.
// Leave headroom when many CPU threads share a small memory allocation.
const BYTES_PER_LOOKUP = 512 * 1024 * 1024;

export function traceConcurrency(
  threads = availableParallelism(),
  availableBytes = process.availableMemory(),
): number {
  return Math.max(
    1,
    Math.min(threads, Math.floor(availableBytes / BYTES_PER_LOOKUP)),
  );
}

function scopeKey(scope: TraceScope) {
  return JSON.stringify([
    scope.kind,
    scope.package,
    scope.version,
    scope.symbol,
    scope.source_symbol,
    scope.path,
  ]);
}

type Lookup = (scope: TraceScope, signal: AbortSignal) => Promise<ScopeResult>;

export async function processTrace(
  request: TraceRequest,
  lookup: Lookup,
  concurrency: number,
  signal?: AbortSignal,
): Promise<TraceResult> {
  signal?.throwIfAborted();
  const controller = new AbortController();
  const stopped = AbortSignal.any([
    controller.signal,
    ...(signal ? [signal] : []),
  ]);
  const deadline = setTimeout(() => controller.abort(), request.time_budget_ms);
  const interrupted = Promise.withResolvers<undefined>();
  const onStop = () => interrupted.resolve(undefined);
  stopped.addEventListener("abort", onStop, { once: true });
  const scopes: TraceResult["scopes"] = [];
  const ids = new Map<string, number>();
  const queue: number[] = [];
  const results = new Map<number, TraceScope[]>();
  const edges = new Map<string, TraceResult["expansions"][number]>();
  const limits = new Set<string>();
  const atHopLimit = new Set<number>();
  let evidenceCount = 0;
  let textMatchCount = 0;

  function schedule(scope: TraceScope, hops: number) {
    const key = scopeKey(scope);
    const existing = ids.get(key);
    if (existing !== undefined) {
      // An out-of-order completion can reveal a shorter path to a known scope.
      if (hops < scopes[existing].hops) {
        scopes[existing].hops = hops;
        expand(existing);
      }
      return existing;
    }
    if (scopes.length >= MAX_SCOPES) {
      limits.add("scope limit");
      return;
    }
    const id = scopes.length;
    ids.set(key, id);
    scopes.push({ id, scope, hops, evidence: [], complete: false });
    queue.push(id);
    return id;
  }

  function expand(id: number) {
    const next = results.get(id);
    if (!next?.length) return;
    const depth = scopes[id].hops;
    if (depth >= request.max_hops) {
      atHopLimit.add(id);
      return;
    }
    atHopLimit.delete(id);
    for (const scope of next) {
      const to = schedule(scope, depth + 1);
      if (to === undefined) continue;
      const key = id + "/" + to;
      if (edges.size < MAX_EXPANSIONS || edges.has(key))
        edges.set(key, { from: id, to });
      else limits.add("expansion limit");
    }
  }

  const running = new Map<
    number,
    Promise<{ id: number; result: ScopeResult }>
  >();
  try {
    for (const path of request.paths) {
      const base = {
        kind: "search" as const,
        package: request.package,
        version: request.version,
        path,
      };
      schedule(
        {
          ...base,
          symbol: request.symbol,
          source_symbol: request.source_symbol,
        },
        0,
      );
      if (request.symbol) schedule({ ...base, kind: "manifests" }, 0);
    }
    while (!stopped.aborted && (queue.length || running.size)) {
      while (queue.length && running.size < concurrency) {
        const id = queue.shift()!;
        const task = lookup(scopes[id].scope, stopped).catch(
          (error: unknown): ScopeResult => ({
            evidence: [],
            next: [],
            complete: false,
            reason: error instanceof Error ? error.message : String(error),
          }),
        );
        running.set(
          id,
          task.then((result) => ({ id, result })),
        );
      }
      const done = await Promise.race([
        interrupted.promise,
        ...running.values(),
      ]);
      if (!done || stopped.aborted) break;
      const { id, result } = done;
      running.delete(id);
      const node = scopes[id];
      node.evidence = result.evidence.slice(0, MAX_EVIDENCE - evidenceCount);
      evidenceCount += node.evidence.length;
      node.complete = result.complete;
      node.reason = result.reason;
      if (node.evidence.length < result.evidence.length) {
        limits.add("evidence limit");
        node.complete = false;
        node.reason ??= "Evidence limit reached.";
      }
      if (result.textMatches?.length) {
        node.textMatches = result.textMatches.slice(
          0,
          MAX_TEXT_MATCHES - textMatchCount,
        );
        textMatchCount += node.textMatches.length;
        if (node.textMatches.length < result.textMatches.length) {
          limits.add("text match limit");
          node.complete = false;
          node.reason ??= "Text match limit reached.";
        }
      }
      results.set(id, result.next);
      expand(id);
    }
    signal?.throwIfAborted();
    if (stopped.aborted) limits.add("time budget");
    const frontier = new Map<string, TraceScope>();
    for (const id of atHopLimit) {
      for (const scope of results.get(id) ?? []) {
        if (!ids.has(scopeKey(scope))) {
          limits.add("hop limit");
          if (frontier.size < 12) frontier.set(scopeKey(scope), scope);
        }
      }
    }
    return {
      frontier: [...frontier.values()],
      complete: limits.size === 0 && scopes.every((entry) => entry.complete),
      limits: [...limits],
      scopes,
      expansions: [...edges.values()],
    };
  } finally {
    clearTimeout(deadline);
    stopped.removeEventListener("abort", onStop);
    controller.abort();
  }
}

// Every tool call in one check shares the native process slots and cache.
export function createDependencyTracer(
  root: string,
  provider: TraceProvider = localProvider(root),
  concurrency = traceConcurrency(),
) {
  const running = new Set<Promise<ScopeResult>>();
  const cache = createTraceCache();
  const lifetime = new AbortController();

  async function lookup(scope: TraceScope, signal: AbortSignal) {
    signal.throwIfAborted();
    const fingerprint = () =>
      provider.fingerprint?.(scope, signal).catch(() => undefined);
    const key = (identity: string) =>
      JSON.stringify([scopeKey(scope), identity]);
    const before = await fingerprint();
    if (before) {
      const cached = cache.read(key(before));
      if (cached) return cached;
    }
    signal.throwIfAborted();
    const result = await provider.run(scope, signal);
    if (result.complete && result.fingerprint) {
      signal.throwIfAborted();
      if (result.fingerprint !== (await fingerprint())) {
        return {
          ...result,
          complete: false,
          reason: "Source changed during analysis.",
        };
      }
      if (!signal.aborted) cache.store(key(result.fingerprint), result);
    }
    return result;
  }

  async function acquireAndRun(scope: TraceScope, signal: AbortSignal) {
    while (running.size >= concurrency) {
      signal.throwIfAborted();
      await Promise.race(running).catch(() => {});
    }
    signal.throwIfAborted();
    const task = lookup(scope, signal);
    running.add(task);
    try {
      return await task;
    } finally {
      running.delete(task);
    }
  }

  return {
    trace(request: TraceRequest, signal?: AbortSignal) {
      const stop = signal
        ? AbortSignal.any([lifetime.signal, signal])
        : lifetime.signal;
      return processTrace(request, acquireAndRun, concurrency, stop);
    },
    async close() {
      lifetime.abort();
      await Promise.allSettled(running);
      cache.clear();
    },
  };
}
