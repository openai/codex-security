import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { artifactSourcePath } from "./artifact-io.js";
import type { JsonObject } from "./types.js";
import { dirname, join, posix, relative, sep } from "node:path";
import type { ArtifactContext } from "./artifact-context.js";
import {
  parsePersistedScanDraft,
  readAcceptedWorkerCheckpoints,
  reconcileAcceptedWorkerHistory,
  readArchivedWorkerCheckpoints,
  workerCoverageReceiptLocation,
  retainRecordedReceiptOwnership,
  saveScanDraftCheckpoint,
} from "./artifact-scan-draft.js";
import { artifactSchemaDocuments } from "./artifact-contracts.js";
import { saveThreatModelDocument } from "./threat-model-document.js";
import {
  createDeepScanArtifacts,
  readJsonObject,
  requireRegularFile,
  writeJsonAtomic,
} from "./deep-scan/artifacts.js";
import {
  deepReductionForPersistence,
  parseDeepReduction,
  projectDiscoveryCoverage,
  parseStoredScanDraft,
  reconcileDeepReduction,
  type DeepReductionInput,
  type DeepReductionSources,
} from "./deep-scan/artifact-validation.js";

const reducerDefinitions = artifactSchemaDocuments["tools/deep-reducer"].$defs;
export const deepReducerInputsInputSchema = reducerDefinitions.reducerInputs;
export { deepReductionInputSchema } from "./deep-scan/artifact-validation.js";

/** Read the findings and scan context assigned to this reducer. */
export async function getCodexSecurityDeepReducerInputs(
  context: ArtifactContext,
): Promise<DeepReductionSources> {
  const inputs = await readDeepReductionSources(context);
  return {
    discoveries: inputs.discoveries.map(({ workerId, result }) => ({
      workerId,
      result,
    })),
    previous: inputs.previous,
  };
}

/** Snapshot accepted source review separately from the reducer's model inputs. */
export async function readDeepReductionSources(
  context: ArtifactContext,
): Promise<DeepReductionSources> {
  return withLogicalReducerErrors(context, async () => {
    const bound = bindDeepReducer(context);
    const discoveries = await Promise.all(
      bound.state.claimedWorkers.map(async (worker) => {
        await requireRegularFile(
          worker.resultPath,
          bound.artifacts.workersRoot,
        );
        const stored = await readJsonObject(worker.resultPath);
        await retainRecordedReceiptOwnership(
          { ...context, root: dirname(worker.resultPath), layout: "worker" },
          stored,
        );
        let result = parseStoredScanDraft(
          stored,
          "Accepted Standard worker " + worker.id,
          bound.scanId,
          parsePersistedScanDraft,
          " has an invalid Standard scan result: ",
          " belongs to a different scan.",
        );
        if (result.complete === false)
          throw new Error(
            "An assigned Standard worker wrote only a checkpoint, not a complete result.",
          );
        const workerContext = {
          ...context,
          root: dirname(worker.resultPath),
          layout: "worker" as const,
          scanId: result.scanId,
        };
        const archived = await readArchivedWorkerCheckpoints(
          workerContext,
          true,
        ).catch(() => []);
        const current = await readAcceptedWorkerCheckpoints(
          workerContext,
          result,
        );
        const receiptDigests = new Map<string, string>();
        const receiptSources = archived.length
          ? [
              result.coverage,
              ...current.map(({ input }) => input.coverage),
              ...archived.map(({ input }) => input.coverage),
            ]
          : [];
        for (const source of receiptSources) {
          for (const surface of source.surfaces as JsonObject[]) {
            for (const value of (surface.receiptRefs as string[] | undefined) ??
              []) {
              const ref = posix.normalize(value);
              const shared =
                (
                  (surface.provenance as JsonObject | undefined)
                    ?.scanReceiptRefs as string[] | undefined
                )?.includes(ref) ?? false;
              const key = JSON.stringify([shared, ref]);
              if (receiptDigests.has(key)) continue;
              try {
                const location = workerCoverageReceiptLocation(
                  workerContext,
                  surface,
                  ref,
                );
                const path = await artifactSourcePath(
                  location.context,
                  location.components,
                  "Saved discovery receipt",
                );
                receiptDigests.set(
                  key,
                  createHash("sha256")
                    .update(await readFile(path))
                    .digest("hex"),
                );
              } catch {
                // Missing evidence cannot establish an earlier receipt origin.
              }
            }
          }
        }
        if (current.length || archived.length)
          result = await reconcileAcceptedWorkerHistory(
            workerContext,
            result,
            [...current, ...archived],
            receiptDigests,
          );
        for (const [index, finding] of result.findings.entries()) {
          const provenance = finding.provenance as Record<string, unknown>;
          provenance.sourceFindingIds = [`${worker.id}:${index}`];
        }
        const { coverage, ...reduction } = result;
        const scanReceiptRefs = new Map<number, ReadonlySet<string>>();
        for (const [index, surface] of (
          coverage.surfaces as Record<string, unknown>[]
        ).entries()) {
          const surfaceScanRefs = new Set<string>();
          scanReceiptRefs.set(index, surfaceScanRefs);
          for (const ref of (surface.receiptRefs as string[] | undefined) ??
            []) {
            const normalized = posix.normalize(ref);
            const inheritedScanRefs = (
              surface.provenance as Record<string, unknown> | undefined
            )?.scanReceiptRefs;
            if (
              Array.isArray(inheritedScanRefs) &&
              inheritedScanRefs.includes(normalized)
            ) {
              surfaceScanRefs.add(normalized);
              continue;
            }
            try {
              await requireRegularFile(
                join(dirname(worker.resultPath), normalized),
                dirname(worker.resultPath),
                true,
              );
              continue;
            } catch {
              // Shared receipts are a fallback when no valid worker-local file was found.
            }
            try {
              await requireRegularFile(
                join(bound.artifacts.scanDir, normalized),
                bound.artifacts.scanDir,
                true,
              );
              surfaceScanRefs.add(normalized);
            } catch {
              // Worker-local receipts are qualified below; finalization validates evidence.
            }
          }
        }
        return {
          workerId: worker.id,
          coverage: projectDiscoveryCoverage(
            coverage,
            worker,
            relative(bound.artifacts.scanDir, dirname(worker.resultPath))
              .split(sep)
              .join("/"),
            scanReceiptRefs,
            archived.flatMap(({ input, attempt }) => {
              const number = /^attempt-(\d+)$/.exec(attempt ?? "")?.[1];
              return number === undefined
                ? []
                : [{ attempt: Number(number), coverage: input.coverage }];
            }),
            receiptDigests,
          ),
          result: reduction,
        };
      }),
    );
    const previous = await readPreviousReduction(bound);
    const scanId =
      bound.scanId ?? previous?.scanId ?? discoveries[0]?.result.scanId;
    for (const discovery of discoveries) {
      if (discovery.result.scanId !== scanId) {
        throw new Error(
          "Accepted Standard worker " +
            discovery.workerId +
            " belongs to a different scan.",
        );
      }
    }
    return { discoveries, previous };
  });
}

/** Check and save the reducer's finished result. */
export async function recordCodexSecurityDeepReduction(
  context: ArtifactContext,
  input: unknown,
): Promise<{
  findingCount: number;
  consumedWorkerIds: string[];
  warnings?: string[];
}> {
  return withLogicalReducerErrors(context, async () => {
    const bound = bindDeepReducer(context);
    let reduction = parseDeepReduction(input);
    if (reduction.complete === false)
      throw new Error(
        "Deep reduction is only a checkpoint, not a complete result.",
      );
    const inputs = await readDeepReductionSources(context);
    const expectedScanId =
      bound.scanId ??
      inputs.previous?.scanId ??
      inputs.discoveries[0]?.result.scanId;
    if (reduction.scanId !== expectedScanId) {
      throw new Error(
        "Deep reduction scanId does not match its assigned Standard results.",
      );
    }
    reduction = reconcileDeepReduction(
      reduction,
      inputs.discoveries,
      inputs.previous,
    );

    const persisted = deepReductionForPersistence(reduction);
    await saveScanDraftCheckpoint(context, persisted);
    await writeJsonAtomic(bound.resultPath, persisted);
    const documentWarning = await saveThreatModelDocument(
      context,
      reduction.threatModel,
    );
    return {
      findingCount: reduction.findings.length,
      consumedWorkerIds: bound.state.claimedWorkers.map((worker) => worker.id),
      ...(documentWarning === undefined ? {} : { warnings: [documentWarning] }),
    };
  });
}

function bindDeepReducer(context: ArtifactContext) {
  const state = context.deepReducer;
  if (context.layout !== "reducer" || !state) {
    throw new Error(
      "No active Deep reducer is bound to this scan; " +
        "start an assigned Deep reduction before using reducer operations.",
    );
  }
  if (state.claimedWorkers.length === 0) {
    throw new Error(
      "The active Deep reducer has no assigned Standard scan workers.",
    );
  }
  const workerIds = new Set<string>();
  for (const worker of state.claimedWorkers) {
    if (!worker.id.trim()) {
      throw new Error(
        "An assigned Standard scan worker has no worker identity.",
      );
    }
    if (workerIds.has(worker.id)) {
      throw new Error(
        "The active Deep reducer repeats assigned Standard scan worker " +
          worker.id +
          ".",
      );
    }
    workerIds.add(worker.id);
  }

  return {
    artifacts: createDeepScanArtifacts(state.scanRoot),
    state,
    resultPath: join(context.root, "result.json"),
    ...(context.scanId === undefined ? {} : { scanId: context.scanId }),
  };
}

async function readPreviousReduction(
  bound: ReturnType<typeof bindDeepReducer>,
): Promise<DeepReductionInput | null> {
  const { previousReducerResultPath } = bound.state;
  if (!previousReducerResultPath) return null;
  await requireRegularFile(
    previousReducerResultPath,
    bound.artifacts.dedupRoot,
  );
  return parseStoredScanDraft(
    await readJsonObject(previousReducerResultPath),
    "The previous accepted Deep reduction",
    bound.scanId,
    parseDeepReduction,
    " has an invalid Standard scan result: ",
    " belongs to a different scan.",
  );
}

async function withLogicalReducerErrors<Result>(
  context: ArtifactContext,
  run: () => Promise<Result>,
): Promise<Result> {
  try {
    return await run();
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    let message = error.message;
    const roots = [context.deepReducer?.scanRoot, context.root]
      .filter((value): value is string => Boolean(value))
      .sort((left, right) => right.length - left.length);
    for (const root of roots) {
      message = message.replaceAll(root, "<scan artifacts>");
    }
    message = message.replace(
      /<scan artifacts>\/[\w./-]*/gu,
      "<scan artifact>",
    );
    if (message === error.message) throw error;
    const publicError = new Error(message, { cause: error });
    for (const key of ["code", "jsonPointer", "expected"] as const) {
      if (key in error) {
        Object.defineProperty(publicError, key, {
          configurable: true,
          enumerable: true,
          value: Reflect.get(error, key),
          writable: true,
        });
      }
    }
    throw publicError;
  }
}
