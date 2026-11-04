import { hash, randomUUID } from "node:crypto";
import { z } from "zod";
import { HostExecutionError } from "../host-protocol.js";
import { DeduplicationReviewError } from "../errors.js";
import type { Finding } from "../models.js";
import { abortable } from "../targets.js";
import type { CodexReview } from "./codex-review.js";
import { FindingDeduplicator } from "./deduplication.js";
import { CodexDeduplicationReviewer } from "./deduplication-reviewer.js";
import {
  findingSchema,
  importedFindingSchema,
  requireFinding,
  requireImportedFinding,
  type ImportedFinding,
} from "./finding-schema.js";
import {
  sourceReviewInstructions,
  screeningInstructions,
  pairReviewInstructions,
  screeningFindingFormatInstructions,
  pairFindingFormatInstructions,
} from "./deduplication-prompts.js";
import type {
  DeduplicationReviewAttribution,
  DeduplicationReviewRequest,
  DeduplicationReviewRunner,
} from "./review.js";

/** A completed review failed without an unresolved execution or cleanup outcome. */
export class RecordsReviewFailure extends Error {}

const isolatableHostFailure = z.object({
  reviewFailure: z.object({
    version: z.literal(1),
    disposition: z.literal("isolate"),
  }),
});

export function recordsReviewAttribution(
  findingIds: readonly string[] | undefined,
  references: ReadonlyMap<string, string>,
  anchors: ReadonlyMap<string, readonly string[]>,
): DeduplicationReviewAttribution {
  if (!findingIds?.length)
    throw new Error("Records review is missing its comparison participants.");
  const participants = new Set(
    findingIds.map((findingId) => {
      const observationId = references.get(findingId);
      if (observationId === undefined)
        throw new Error(`Unknown records review finding ID: ${findingId}`);
      return observationId;
    }),
  );
  const beneficiaryObservationIds = [
    ...participants.intersection(anchors),
  ].sort();
  if (beneficiaryObservationIds.length === 0)
    throw new Error("Records review has no incoming observation participants.");
  return {
    version: 1,
    beneficiaryObservationIds,
    contextObservationIds: [...participants.difference(anchors)].sort(),
  };
}

function reviewFindingSchema(
  ids: readonly string[],
  importedIds: ReadonlySet<string>,
): object {
  const imported = ids.filter((id) => importedIds.has(id));
  if (!imported.length) return findingSchema();
  if (imported.length === ids.length) return importedFindingSchema();
  const native = findingSchema();
  return {
    ...importedFindingSchema(),
    if: { properties: { findingId: { enum: imported } } },
    else: {
      required: native.required,
      properties: { locations: native.properties.locations },
    },
  };
}

const id = z.string().min(1);
const record = z.discriminatedUnion("kind", [
  z.strictObject({
    id,
    kind: z.undefined().optional(),
    finding: z.unknown().transform(requireFinding),
  }),
  z.strictObject({
    id,
    kind: z.literal("imported"),
    finding: z.unknown().transform(requireImportedFinding),
  }),
]);

const deduplicateRecordsInputSchema = z.strictObject({
  version: z.literal(1),
  failurePolicy: z.literal("isolate").optional(),
  observations: z.array(record),
  candidateRelationships: z.array(
    z.strictObject({
      observationId: id,
      candidateObservationIds: z.array(id),
    }),
  ),
});

export interface DeduplicateRecordsInput extends z.infer<
  typeof deduplicateRecordsInputSchema
> {}
export interface DeduplicateRecordsOptions {
  reviewRunner: DeduplicationReviewRunner;
  signal?: AbortSignal;
}
export interface DeduplicateRecordsResult {
  version: 1;
  status: "completed" | "unresolved";
  groups: {
    representativeObservationId: string;
    observationIds: string[];
  }[];
  isolated?: {
    observationId: string;
    reason: "review_failed";
    message: string;
  }[];
  unresolved: {
    observationId: string;
    reason: "review_failed";
    message: string;
  }[];
}

/** Pure records workflow: no retrieval, local model execution, or persistence. */
export async function deduplicateRecords(
  input: DeduplicateRecordsInput,
  options: DeduplicateRecordsOptions,
): Promise<DeduplicateRecordsResult> {
  return await runRecords(
    input,
    (request) => options.reviewRunner.run(request, { signal: options.signal }),
    options.signal,
  );
}

/** The records transport can check a pending submission before releasing its host. */
export async function runRecords(
  input: DeduplicateRecordsInput,
  runReview: (
    request: DeduplicationReviewRequest,
    validate: (value: unknown) => void,
  ) => Promise<unknown>,
  signal?: AbortSignal,
): Promise<DeduplicateRecordsResult> {
  signal?.throwIfAborted();
  // Snapshot before yielding: a host cannot mutate evidence during the review.
  const data = deduplicateRecordsInputSchema.parse(structuredClone(input));
  const references = new Map<string, string>();
  const observations = new Map<string, Finding | ImportedFinding>();
  const importedIds = new Set<string>();
  for (const entry of data.observations) {
    if (observations.has(entry.id))
      throw new Error(`Duplicate observation ID: ${entry.id}`);
    // Original finding IDs can repeat across scans; host IDs identify observations.
    const findingId = `csf_${hash("sha256", entry.id).slice(0, 24)}`;
    if (entry.kind === "imported") importedIds.add(findingId);
    observations.set(entry.id, { ...entry.finding, findingId });
    references.set(findingId, entry.id);
  }
  const relationships = new Map<string, string[]>();
  for (const relation of data.candidateRelationships) {
    if (
      !observations.has(relation.observationId) ||
      relationships.has(relation.observationId)
    )
      throw new Error(
        "Each candidate relationship must name a different supplied observation.",
      );
    if (
      new Set(relation.candidateObservationIds).size !==
        relation.candidateObservationIds.length ||
      relation.candidateObservationIds.some(
        (id) => id === relation.observationId || !observations.has(id),
      )
    )
      throw new Error(
        "Candidates must name distinct supplied observations other than the anchor.",
      );
    relationships.set(relation.observationId, relation.candidateObservationIds);
  }
  const result: DeduplicateRecordsResult = {
    version: 1,
    status: "completed",
    groups: [],
    unresolved: [],
  };
  if (data.failurePolicy === "isolate") result.isolated = [];
  const sourceFindingIds = [...relationships.keys()].map(
    (id) => observations.get(id)!.findingId,
  );
  const runner = {
    async run<T>({
      validate,
      findingIds,
      ...review
    }: CodexReview<T>): Promise<T> {
      try {
        return await abortable(async () => {
          signal?.throwIfAborted();
          const submission = await runReview(
            {
              ...review,
              requestId: randomUUID(),
              attribution: recordsReviewAttribution(
                findingIds,
                references,
                relationships,
              ),
              trustedInstructions: [
                sourceReviewInstructions,
                review.stage === "screening"
                  ? screeningInstructions
                  : pairReviewInstructions,
                review.stage === "screening"
                  ? screeningFindingFormatInstructions
                  : pairFindingFormatInstructions,
              ].join("\n\n"),
              findingSchema: structuredClone(
                reviewFindingSchema(findingIds ?? [], importedIds),
              ),
            },
            validate,
          );
          try {
            return validate(submission);
          } catch (error) {
            throw new RecordsReviewFailure(
              error instanceof Error
                ? error.message
                : "Invalid review submission.",
              { cause: error },
            );
          }
        }, signal);
      } catch (error) {
        // The default records policy treats refusals as batch failures.
        if (
          error instanceof DeduplicationReviewError &&
          error.metadata.category === "refusal"
        )
          throw new Error(error.message, { cause: error });
        throw error;
      }
    },
  };
  const reviewer = new CodexDeduplicationReviewer(runner, {}, importedIds);
  const algorithm = new FindingDeduplicator(
    {
      async potentialDuplicates(findingId) {
        const observationId = references.get(findingId)!;
        return {
          finding: observations.get(observationId)!,
          potentialDuplicates: relationships
            .get(observationId)!
            .map((id) => observations.get(id)!),
        };
      },
    },
    reviewer,
    signal,
    1,
    data.failurePolicy === "isolate"
      ? (error, findingIds) => {
          if (
            !(error instanceof RecordsReviewFailure) &&
            !(
              error instanceof HostExecutionError &&
              error.code !== -32800 &&
              isolatableHostFailure.safeParse(error.data).success
            )
          )
            throw error;
          const attribution = recordsReviewAttribution(
            findingIds,
            references,
            relationships,
          );
          const isolated = result.isolated!;
          for (const observationId of attribution.beneficiaryObservationIds) {
            if (
              !isolated.some((entry) => entry.observationId === observationId)
            )
              isolated.push({
                observationId,
                reason: "review_failed",
                message: error.message,
              });
          }
          return attribution.beneficiaryObservationIds.map(
            (id) => observations.get(id)!.findingId,
          );
        }
      : undefined,
  );
  let groups: string[][];
  try {
    const decisions = await algorithm.run(sourceFindingIds);
    signal?.throwIfAborted();
    groups = decisions.duplicateGroups;
  } catch (error) {
    signal?.throwIfAborted();
    if (data.failurePolicy === "isolate") throw error;
    result.status = "unresolved";
    result.unresolved = [...relationships.keys()].map((id) => ({
      observationId: id,
      reason: "review_failed",
      message:
        error instanceof Error ? error.message : "Review did not complete.",
    }));
    return result;
  }
  const grouped = new Set(groups.flat());
  groups.push(
    ...sourceFindingIds.filter((id) => !grouped.has(id)).map((id) => [id]),
  );
  for (const group of groups) {
    const observationIds = group.map((id) => references.get(id)!);
    result.groups.push({
      representativeObservationId: observationIds[0]!,
      observationIds,
    });
  }
  return result;
}
