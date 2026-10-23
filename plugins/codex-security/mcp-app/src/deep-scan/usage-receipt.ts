import { promises as fs } from "node:fs";
import { dirname, join } from "node:path";
import { requireArtifactRoot } from "../artifact-io.js";
import { writeJsonAtomic } from "./artifacts.js";
import type { DeepScanWorkerKind } from "./types.js";

export interface WorkerTokenUsage {
  input_tokens: number;
  cached_input_tokens: number;
  cache_write_input_tokens: number;
  cache_write_input_tokens_reported?: false;
  output_tokens: number;
  reasoning_output_tokens: number;
  total_tokens: number;
}

/** One host invocation records the SDK's cumulative thread usage. */
export interface WorkerUsageReceipt {
  schemaVersion: 1;
  source: "codex_sdk";
  usageScope: "thread_cumulative";
  scanId: string;
  workerId: string;
  kind: DeepScanWorkerKind;
  attemptId: string;
  attempt: number;
  resumed: boolean;
  threadId?: string;
  turnId?: string;
  startedAt: string;
  observedAt: string;
  outcome: "running" | "succeeded" | "failed" | "canceled";
  usage: WorkerTokenUsage | null;
}

/** Retain numeric usage only; model and diagnostic text are not receipt fields. */
export function workerTokenUsage(
  value: unknown,
  cacheWritesMayBeDefaulted = false,
): WorkerTokenUsage | null {
  if (value === null || typeof value !== "object") return null;
  const raw = value as Record<string, unknown>;
  const input = raw.input_tokens;
  const cached = raw.cached_input_tokens ?? 0;
  const legacyCacheWrite = raw.cache_write_tokens;
  const fields = {
    input_tokens: input,
    cached_input_tokens: cached,
    cache_write_input_tokens:
      raw.cache_write_input_tokens === 0 &&
      typeof input === "number" &&
      typeof cached === "number" &&
      typeof legacyCacheWrite === "number" &&
      Number.isSafeInteger(legacyCacheWrite) &&
      legacyCacheWrite > 0 &&
      cached + legacyCacheWrite <= input
        ? legacyCacheWrite
        : (raw.cache_write_input_tokens ?? raw.cache_write_tokens ?? 0),
    output_tokens: raw.output_tokens,
    reasoning_output_tokens: raw.reasoning_output_tokens ?? 0,
  };
  if (
    Object.values(fields).some(
      (count) =>
        typeof count !== "number" || !Number.isSafeInteger(count) || count < 0,
    )
  )
    return null;
  const usage = fields as Omit<WorkerTokenUsage, "total_tokens">;
  if (
    usage.cached_input_tokens + usage.cache_write_input_tokens >
      usage.input_tokens ||
    usage.reasoning_output_tokens > usage.output_tokens
  )
    return null;
  return {
    ...usage,
    total_tokens: usage.input_tokens + usage.output_tokens,
    ...(raw.cache_write_input_tokens_reported === false ||
    (cacheWritesMayBeDefaulted && usage.cache_write_input_tokens === 0) ||
    (raw.cache_write_input_tokens == null && raw.cache_write_tokens == null)
      ? { cache_write_input_tokens_reported: false as const }
      : {}),
  };
}

export async function writeWorkerUsageReceipt(
  directory: string,
  receipt: WorkerUsageReceipt,
): Promise<void> {
  const privateHome = dirname(dirname(directory));
  await requireArtifactRoot(dirname(privateHome), "Worker usage");
  for (const path of [privateHome, dirname(directory), directory]) {
    await fs
      .mkdir(path, { mode: 0o700 })
      .catch((error: NodeJS.ErrnoException) => {
        if (error.code !== "EEXIST") throw error;
      });
    await requireArtifactRoot(path, "Worker usage");
  }
  await writeJsonAtomic(join(directory, `${receipt.attemptId}.json`), receipt);
}
