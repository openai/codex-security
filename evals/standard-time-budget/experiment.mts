import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { GradeReport, Result } from "./grade.mts";
import type { PreparedStandardEval } from "./fixtures.mts";
import type { StandardRunner, StandardRunOptions } from "./production.mts";

export interface ExperimentConfig {
  model: string;
  pairs: number;
  budgetMinutes: number;
}
export type Variant = "baseline" | "time-aware";
/** Retained arm state must not be exposed to a later arm. */
export class StateCleanupError extends AggregateError {}
export type RunReport = GradeReport & {
  scanId?: string;
  scanDir?: string;
  reportPath?: string;
};
interface RunMetadata {
  pair: number;
  variant: Variant;
  startedAt: string;
  advisoryBudgetMinutes: number | null;
  promptSha256: string | null;
  elapsedMs: number;
  usage: unknown;
}
type RunOutcome =
  | { status: "completed"; report: RunReport; error?: never }
  | { status: "failed"; error: string; report?: never };
export type RunRecord = RunMetadata & RunOutcome;
export type CompletedRunRecord = Extract<RunRecord, { status: "completed" }>;
interface ComparisonOptions {
  prepared: PreparedStandardEval;
  config: ExperimentConfig;
  signal?: AbortSignal;
  run: StandardRunner;
  elapsedNow?: () => number;
  onStart?: (record: Pick<RunMetadata, "pair" | "variant">) => Promise<unknown>;
  onResult?: (
    record: RunRecord,
    result: Result | undefined,
    records: RunRecord[],
    prompt: string | undefined,
  ) => Promise<unknown>;
}

export function validateExperiment(config: ExperimentConfig) {
  if (typeof config?.model !== "string" || !config.model.trim()) {
    throw new Error("The experiment requires an explicit model.");
  }
  if (!Number.isSafeInteger(config.pairs) || config.pairs < 1) {
    throw new Error("Experiment pairs must be a positive integer.");
  }
  if (!Number.isFinite(config.budgetMinutes) || config.budgetMinutes <= 0) {
    throw new Error("Experiment budgetMinutes must be a positive number.");
  }
  return {
    model: config.model,
    pairs: config.pairs,
    budgetMinutes: config.budgetMinutes,
  };
}

export function hashText(text: string | Uint8Array) {
  return createHash("sha256").update(text).digest("hex");
}

export async function snapshotEvaluator(directory = import.meta.dirname) {
  const files: Record<string, string> = {};
  for (const path of [
    "run.mts",
    "production.mts",
    "experiment.mts",
    "fixtures.mts",
    "grade.mts",
    "summary.mts",
    "../secret-discovery/fixtures.mts",
    "../secret-discovery/runtime.mts",
  ]) {
    files[path] = hashText(await readFile(join(directory, path)));
  }
  return files;
}

export async function snapshotFiles(directory: string, prefix = "") {
  const files: Record<string, string> = {};
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries.sort((first, second) =>
    first.name.localeCompare(second.name),
  )) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      Object.assign(files, await snapshotFiles(path, relative));
    } else {
      files[relative] = hashText(await readFile(path));
    }
  }
  return files;
}

export async function runComparison({
  prepared,
  config,
  signal,
  run,
  elapsedNow = () => performance.now(),
  onStart = async () => {},
  onResult = async () => {},
}: ComparisonOptions) {
  config = validateExperiment(config);
  const records: RunRecord[] = [];
  for (let pair = 1; pair <= config.pairs; pair += 1) {
    const variants: Variant[] =
      pair % 2 === 1 ? ["baseline", "time-aware"] : ["time-aware", "baseline"];
    for (const variant of variants) {
      signal?.throwIfAborted();
      await onStart({ pair, variant });
      signal?.throwIfAborted();
      const startedAt = new Date().toISOString();
      const startedElapsed = elapsedNow();
      const observation: StandardRunOptions["observation"] = {};
      let outcome: RunOutcome;
      let semanticResult: Result | undefined;
      let cleanupFailure: StateCleanupError | undefined;
      try {
        const result = await run(prepared, {
          model: config.model,
          pair,
          variant,
          signal,
          ...(variant === "time-aware"
            ? { maxTimeMinutes: config.budgetMinutes }
            : {}),
          observation,
        });
        outcome = { status: "completed", report: result.report };
        semanticResult = result.semanticResult;
      } catch (error) {
        if (error instanceof StateCleanupError) cleanupFailure = error;
        outcome = {
          status: "failed",
          error: error instanceof Error ? error.message : String(error),
        };
      }
      const elapsedMs = elapsedNow() - startedElapsed;
      const record: RunRecord = {
        pair,
        variant,
        startedAt,
        advisoryBudgetMinutes:
          variant === "time-aware" ? config.budgetMinutes : null,
        promptSha256:
          observation.prompt === undefined
            ? null
            : hashText(observation.prompt),
        ...outcome,
        elapsedMs,
        usage: observation.usage ?? null,
      };
      records.push(record);
      await onResult(record, semanticResult, records, observation.prompt);
      if (cleanupFailure !== undefined) throw cleanupFailure;
      signal?.throwIfAborted();
    }
  }
  return records;
}
