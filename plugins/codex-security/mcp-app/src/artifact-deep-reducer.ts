import { join } from "node:path";
import type { ZodType } from "zod/v4";
import commonSchema from "../../schemas/definitions/artifact-common.schema.json";
import reducerSchema from "../../schemas/tools/deep-reducer.schema.json";
import scanDraftSchema from "../../schemas/tools/scan-draft.schema.json";
import type { ArtifactContext, DeepReducerContext } from "./artifact-context.js";
import {
  parsePersistedScanDraft,
  parseScanDraft,
  saveScanDraftCheckpoint,
  type ScanDraftInput
} from "./artifact-scan-draft.js";
import {
  loadArtifactZodSchema,
  type SchemaDocument
} from "./artifact-schema-loader.js";
import {
  createDeepScanArtifacts,
  readJsonObject,
  requireRegularFile,
  writeJsonAtomic,
  type DeepScanArtifacts
} from "./deep-scan/artifacts.js";
import { reconcileDeepReduction } from "./deep-scan/artifact-validation.js";

const schemaDocuments = [
  commonSchema,
  scanDraftSchema,
  reducerSchema
] as SchemaDocument[];

export const deepReducerInputsInputSchema = loadArtifactZodSchema(
  schemaDocuments,
  reducerSchema.$id,
  "reducerInputs"
) as ZodType<Record<string, never>>;

export const deepReductionInputSchema = loadArtifactZodSchema(
  schemaDocuments,
  reducerSchema.$id,
  "reductionInput"
) as ZodType<ScanDraftInput>;

interface DeepReducerInputs {
  discoveries: {
    workerId: string;
    result: ScanDraftInput;
  }[];
  previous: ScanDraftInput | null;
}

interface BoundReducer {
  artifacts: DeepScanArtifacts;
  state: DeepReducerContext;
  resultPath: string;
  scanId?: string;
}

/** Return complete Standard results without exposing their artifact locations. */
export async function getCodexSecurityDeepReducerInputs(
  context: ArtifactContext
): Promise<DeepReducerInputs> {
  return withLogicalReducerErrors(context, async () => {
    const bound = bindDeepReducer(context);
    const discoveries = await Promise.all(bound.state.claimedWorkers.map(async (worker) => {
      await requireRegularFile(worker.resultPath, bound.artifacts.workersRoot);
      const result = parseStoredScanDraft(
        await readJsonObject(worker.resultPath),
        "Accepted Standard worker " + worker.id,
        bound.scanId
      );
      if (result.complete === false) throw new Error("An assigned Standard worker wrote only a checkpoint, not a complete result.");
      result.findings = result.findings.map((finding, index) => ({
        ...finding,
        provenance: {
          ...finding.provenance as Record<string, unknown>,
          sourceFindingIds: [`${worker.id}:${index}`],
        },
      }));
      return { workerId: worker.id, result };
    }));
    const previous = await readPreviousReduction(bound);
    const scanId = bound.scanId ?? previous?.scanId ?? discoveries[0]?.result.scanId;
    for (const discovery of discoveries) {
      if (discovery.result.scanId !== scanId) {
        throw new Error(
          "Accepted Standard worker "
          + discovery.workerId
          + " belongs to a different scan."
        );
      }
    }
    if (previous && previous.scanId !== scanId) {
      throw new Error("The previous accepted Deep reduction belongs to a different scan.");
    }
    return { discoveries, previous };
  });
}

/** Validate and durably replace this reducer's complete semantic Standard result. */
export async function recordCodexSecurityDeepReduction(
  context: ArtifactContext,
  input: unknown
): Promise<{
  findingCount: number;
  consumedWorkerIds: string[];
}> {
  return withLogicalReducerErrors(context, async () => {
    const bound = bindDeepReducer(context);
    let reduction = parseScanDraft(input as ScanDraftInput);
    if (reduction.complete === false) throw new Error("Deep reduction is only a checkpoint, not a complete result.");
    const inputs = await getCodexSecurityDeepReducerInputs(context);
    const expectedScanId = bound.scanId
      ?? inputs.previous?.scanId
      ?? inputs.discoveries[0]?.result.scanId;
    if (reduction.scanId !== expectedScanId) {
      throw new Error("Deep reduction scanId does not match its assigned Standard results.");
    }
    reduction = reconcileDeepReduction(reduction, inputs.discoveries, inputs.previous);

    await saveScanDraftCheckpoint(context, reduction);
    await writeJsonAtomic(bound.resultPath, reduction);
    return {
      findingCount: reduction.findings.length,
      consumedWorkerIds: bound.state.claimedWorkers.map((worker) => worker.id)
    };
  });
}


function bindDeepReducer(context: ArtifactContext): BoundReducer {
  const state = context.deepReducer;
  if (context.layout !== "reducer" || !state) {
    throw new Error(
      "No active Deep reducer is bound to this scan; "
      + "start an assigned Deep reduction before using reducer operations."
    );
  }
  if (state.claimedWorkers.length === 0) {
    throw new Error("The active Deep reducer has no assigned Standard scan workers.");
  }
  const workerIds = new Set<string>();
  for (const worker of state.claimedWorkers) {
    if (!worker.id.trim()) {
      throw new Error("An assigned Standard scan worker has no worker identity.");
    }
    if (workerIds.has(worker.id)) {
      throw new Error(
        "The active Deep reducer repeats assigned Standard scan worker "
        + worker.id
        + "."
      );
    }
    workerIds.add(worker.id);
  }

  return {
    artifacts: createDeepScanArtifacts(state.scanRoot),
    state,
    resultPath: join(context.root, "result.json"),
    ...(context.scanId === undefined ? {} : { scanId: context.scanId })
  };
}

async function readPreviousReduction(
  bound: BoundReducer
): Promise<ScanDraftInput | null> {
  const { previousReducerResultPath } = bound.state;
  if (!previousReducerResultPath) return null;
  await requireRegularFile(previousReducerResultPath, bound.artifacts.dedupRoot);
  return parseStoredScanDraft(
    await readJsonObject(previousReducerResultPath),
    "The previous accepted Deep reduction",
    bound.scanId
  );
}

function parseStoredScanDraft(
  value: Record<string, unknown>,
  label: string,
  expectedScanId?: string
): ScanDraftInput {
  let parsed: ScanDraftInput;
  try {
    parsed = parsePersistedScanDraft(value);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(label + " has an invalid Standard scan result: " + detail, { cause: error });
  }
  if (expectedScanId !== undefined && parsed.scanId !== expectedScanId) {
    throw new Error(label + " belongs to a different scan.");
  }
  return parsed;
}

async function withLogicalReducerErrors<Result>(
  context: ArtifactContext,
  run: () => Promise<Result>
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
      "<scan artifact>"
    );
    if (message === error.message) throw error;
    const publicError = new Error(message, { cause: error });
    for (const key of ["code", "jsonPointer", "expected"] as const) {
      if (key in error) {
        Object.defineProperty(publicError, key, {
          configurable: true,
          enumerable: true,
          value: Reflect.get(error, key),
          writable: true
        });
      }
    }
    throw publicError;
  }
}
