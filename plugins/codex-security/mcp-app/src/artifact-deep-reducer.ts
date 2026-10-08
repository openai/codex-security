import { createHash } from "node:crypto";
import { readArtifactBytes } from "./artifact-io.js";
import type { JsonObject } from "./types.js";
import { dirname, join, relative, sep } from "node:path";
import type { ZodType } from "zod/v4";
import commonSchema from "../../schemas/definitions/artifact-common.schema.json";
import reducerSchema from "../../schemas/tools/deep-reducer.schema.json";
import scanDraftSchema from "../../schemas/tools/scan-draft.schema.json";
import type {
  ArtifactContext,
  DeepReducerContext,
} from "./artifact-context.js";
import type { DeepReducerPageInput } from "./artifact-deep-reducer-pages.js";
import {
  normalizeSavedScanCoverage,
  parsePersistedScanDraft,
  preserveScanDraft,
  readArchivedWorkerCheckpoints,
  saveScanDraftCheckpoint,
} from "./artifact-scan-draft.js";
import {
  loadArtifactZodSchema,
  type SchemaDocument,
} from "./artifact-schema-loader.js";
import { saveThreatModelDocument } from "./threat-model-document.js";
import {
  createDeepScanArtifacts,
  readJsonObject,
  requireRegularFile,
  writeJsonAtomic,
  type DeepScanArtifacts,
} from "./deep-scan/artifacts.js";
import {
  deepReductionForPersistence,
  parseDeepReduction,
  projectDiscoveryCoverage,
  matchesSavedCoverageSource,
  parseStoredScanDraft,
  reconcileDeepReduction,
  type DeepReductionInput,
  type DeepReductionSources,
} from "./deep-scan/artifact-validation.js";

const schemaDocuments = [
  commonSchema,
  scanDraftSchema,
  reducerSchema,
] as SchemaDocument[];

export const deepReducerInputsInputSchema = loadArtifactZodSchema(
  schemaDocuments,
  reducerSchema.$id,
  "reducerInputs",
) as ZodType<DeepReducerPageInput>;

export const deepReductionInputSchema = loadArtifactZodSchema(
  schemaDocuments,
  reducerSchema.$id,
  "reductionInput",
) as ZodType<DeepReductionInput>;

interface BoundReducer {
  artifacts: DeepScanArtifacts;
  state: DeepReducerContext;
  resultPath: string;
  scanId?: string;
}

/** Read the findings and scan context assigned to this reducer. */
export async function getCodexSecurityDeepReducerInputs(
  context: ArtifactContext,
): Promise<DeepReductionSources> {
  const inputs = await readDeepReductionSources(context);
  const { sourceCoverage: _coverage, ...previous } = inputs.previous ?? {};
  return {
    discoveries: inputs.discoveries.map(({ workerId, result }) => ({
      workerId,
      result,
    })),
    previous:
      inputs.previous === null ? null : (previous as DeepReductionInput),
  };
}

/** Capture host coverage alongside the reducer's immutable finding inputs. */
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
        let result = parseStoredScanDraft(
          await readJsonObject(worker.resultPath),
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
        // Accepted direct-file results may follow an unreadable failed checkpoint.
        const archived = await readArchivedWorkerCheckpoints(
          {
            ...context,
            root: dirname(worker.resultPath),
            layout: "worker",
            scanId: result.scanId,
          },
          true,
        ).catch(() => []);
        const originalArchivedCoverage = archived.map(({ input }) =>
          structuredClone(input.coverage),
        );
        const originalCoverage = structuredClone(result.coverage);
        const artifactPrefix = relative(
          bound.artifacts.scanDir,
          dirname(worker.resultPath),
        )
          .split(sep)
          .join("/");
        const archivePrefix =
          artifactPrefix.slice(0, artifactPrefix.lastIndexOf("/")) +
          "/attempts/";
        const receiptRefs = new Set(
          [originalCoverage, ...originalArchivedCoverage].flatMap((source) =>
            (source.surfaces as JsonObject[]).flatMap(
              (surface) => (surface.receiptRefs as string[] | undefined) ?? [],
            ),
          ),
        );
        const receiptDigests = new Map<string, string>();
        await Promise.all(
          [...receiptRefs].map(async (ref) => {
            try {
              const bytes = await readArtifactBytes(
                {
                  ...context,
                  root: ref.startsWith(archivePrefix)
                    ? bound.artifacts.scanDir
                    : dirname(worker.resultPath),
                },
                ref
                  .split("/")
                  .filter(
                    (component, index) =>
                      component !== "." && (component !== "" || index === 0),
                  ),
                "Saved discovery receipt",
              );
              receiptDigests.set(
                ref,
                createHash("sha256").update(bytes).digest("hex"),
              );
            } catch {
              // Unreadable evidence cannot establish an earlier receipt origin.
            }
          }),
        );
        const normalizedCurrent = structuredClone(result);
        normalizeSavedScanCoverage([normalizedCurrent]);
        for (const { input } of archived) {
          const matchedCurrentSurfaces = new Set<number>();
          for (const surface of input.coverage.surfaces as JsonObject[]) {
            if (surface.id !== undefined) continue;
            const currentIndex = (
              originalCoverage.surfaces as JsonObject[]
            ).findIndex(
              (current, index) =>
                !matchedCurrentSurfaces.has(index) &&
                matchesSavedCoverageSource(
                  "surfaces",
                  current,
                  surface,
                  archivePrefix,
                  receiptDigests,
                ),
            );
            if (currentIndex !== -1) {
              matchedCurrentSurfaces.add(currentIndex);
              surface.id = (
                normalizedCurrent.coverage.surfaces as JsonObject[]
              )[currentIndex]!.id;
            }
          }
        }
        normalizeSavedScanCoverage([
          result,
          ...archived.map(({ input }) => input),
        ]);
        let currentCheckpointCoverage: (typeof originalCoverage)[] = [];
        if (archived.length) {
          const preserved = await preserveScanDraft(
            {
              ...context,
              root: dirname(worker.resultPath),
              layout: "worker",
              scanId: result.scanId,
            },
            result,
            false,
            archived,
          );
          result = preserved.input;
          currentCheckpointCoverage = preserved.originalCurrentCoverage;
        }
        result.findings = result.findings.map((finding, index) => ({
          ...finding,
          provenance: {
            ...(finding.provenance as Record<string, unknown>),
            sourceFindingIds: [`${worker.id}:${index}`],
          },
        }));
        const { coverage, ...reduction } = result;
        return {
          workerId: worker.id,
          coverage: projectDiscoveryCoverage(
            coverage,
            worker,
            artifactPrefix,
            archived.flatMap(({ attempt }, index) => {
              const number = /^attempt-(\d+)$/.exec(attempt ?? "")?.[1];
              return number === undefined
                ? []
                : [
                    {
                      attempt: Number(number),
                      coverage: originalArchivedCoverage[index],
                    },
                  ];
            }),
            [originalCoverage, ...currentCheckpointCoverage],
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
    const submitted = deepReductionInputSchema.parse(input);
    let reduction = parseDeepReduction(submitted);
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

    const persisted = deepReductionForPersistence(
      reduction,
      bound.state.persistSourceCoverage,
    );
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

function bindDeepReducer(context: ArtifactContext): BoundReducer {
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
  bound: BoundReducer,
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
    (value) => parseDeepReduction(value, true),
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
