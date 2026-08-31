import type * as z from "zod/v4";
import workerThreatModelSchema from "../../schemas/tools/worker-threat-model.schema.json";
import type { ArtifactContext } from "./artifact-context.js";
import {
  artifactDestination,
  replaceArtifactText
} from "./artifact-io.js";
import {
  loadArtifactZodSchema,
  type SchemaDocument
} from "./artifact-schema-loader.js";

export interface WorkerThreatModelInput {
  content: string;
}

export interface RecordWorkerThreatModelResult {
  operation: "replace";
}

/** Derive the worker-only input from its checked-in JSON Schema. */
export const workerThreatModelInputSchema = loadArtifactZodSchema(
  [workerThreatModelSchema] as SchemaDocument[],
  workerThreatModelSchema.$id,
  "recordWorkerThreatModelInput"
) as z.ZodType<WorkerThreatModelInput>;

/** Preserve the full threat model at the discovery worker's fixed destination. */
export async function recordCodexSecurityWorkerThreatModel(
  input: WorkerThreatModelInput,
  context: ArtifactContext
): Promise<RecordWorkerThreatModelResult> {
  if (context.layout !== "worker") {
    throw new Error(
      "Worker threat model: only a bound discovery worker can record its threat model."
    );
  }

  const { content } = workerThreatModelInputSchema.parse(input);
  const destination = await artifactDestination(
    context,
    ["artifacts", "01_context", "threat_model.md"],
    "Worker threat model"
  );
  await replaceArtifactText(destination, content);
  return { operation: "replace" };
}
