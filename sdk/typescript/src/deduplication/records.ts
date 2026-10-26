import { hash, randomUUID } from "node:crypto";
import { z } from "zod";
import { DeduplicationReviewError } from "../errors.js";
import type { Finding } from "../models.js";
import { abortable } from "../targets.js";
import type { CodexReview } from "./codex-review.js";
import { FindingDeduplicator } from "./deduplication.js";
import { CodexDeduplicationReviewer } from "./deduplication-reviewer.js";
import { findingSchema, requireFinding } from "./finding-schema.js";
import {
  sourceReviewInstructions,
  screeningInstructions,
  pairReviewInstructions,
  screeningFindingFormatInstructions,
  pairFindingFormatInstructions,
} from "./deduplication-prompts.js";
import type {
  DeduplicationReviewAttribution,
  DeduplicationReviewRunner,
} from "./review.js";

class RecordsReviewRefusal extends Error {
  constructor(readonly refusal: DeduplicationReviewError) {
    super(refusal.message, { cause: refusal });
  }
}

function reviewValidation<T>(
  validator: CodexReview<T>["validate"] | undefined,
  signal: AbortSignal | undefined,
  detailedErrors?: () => boolean | undefined,
) {
  let cancellation: { reason: unknown } | undefined;
  const check = (value: unknown, final: boolean): T => {
    if (cancellation) throw cancellation.reason;
    const currentSignal = signal;
    currentSignal?.throwIfAborted();
    const validate = validator;
    if (!validate) throw new Error("The review has already ended.");
    if (final) validator = undefined;
    try {
      return validate(value, final ? detailedErrors?.() : true);
    } finally {
      currentSignal?.throwIfAborted();
    }
  };
  return {
    result: (value: unknown) => check(value, true),
    preflight: (value: unknown): void => {
      check(value, false);
    },
    close: () => {
      if (signal?.aborted) cancellation = { reason: signal.reason };
      validator = undefined;
      detailedErrors = undefined;
      signal = undefined;
    },
  };
}

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

const id = z.string().min(1);
const record = z.strictObject({
  id,
  finding: z.unknown().transform((value) => requireFinding(value)),
});

const deduplicateRecordsInputSchema = z.strictObject({
  version: z.literal(1),
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
  /** Opt in to typed failures instead of the legacy unresolved result. */
  throwReviewErrors?: boolean;
}
export interface DeduplicateRecordsResult {
  version: 1;
  status: "completed" | "unresolved";
  groups: {
    representativeObservationId: string;
    observationIds: string[];
  }[];
  unresolved: {
    observationId: string;
    reason: "review_failed";
    message: string;
  }[];
}

/** Pure records workflow: no retrieval, local model execution, or persistence. */
export function deduplicateRecords(
  input: DeduplicateRecordsInput,
  options: DeduplicateRecordsOptions,
): Promise<DeduplicateRecordsResult> {
  return runDeduplicateRecords(input, options);
}

/** The hosted CLI can negotiate detailed failures during its first review. */
export async function runDeduplicateRecords(
  input: DeduplicateRecordsInput,
  options: DeduplicateRecordsOptions,
  hostFeedback?: () => boolean,
): Promise<DeduplicateRecordsResult> {
  const { signal } = options;
  signal?.throwIfAborted();
  const { throwReviewErrors } = options;
  const detailedErrors = hostFeedback ?? (() => throwReviewErrors);
  // Snapshot before yielding: a host cannot mutate evidence during the review.
  const data = deduplicateRecordsInputSchema.parse(structuredClone(input));
  const references = new Map<string, string>();
  const observations = new Map<string, Finding>();
  for (const entry of data.observations) {
    if (observations.has(entry.id))
      throw new Error(`Duplicate observation ID: ${entry.id}`);
    // Original finding IDs can repeat across scans; host IDs identify observations.
    const findingId = `csf_${hash("sha256", entry.id).slice(0, 24)}`;
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
  const sourceFindingIds = [...relationships.keys()].map(
    (id) => observations.get(id)!.findingId,
  );
  const reviewer = new CodexDeduplicationReviewer({
    async run<T>({
      validate,
      findingIds,
      ...review
    }: CodexReview<T>): Promise<T> {
      const validation = reviewValidation(validate, signal, detailedErrors);
      try {
        return await abortable(async () => {
          try {
            signal?.throwIfAborted();
            return validation.result(
              await options.reviewRunner.run(
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
                  findingSchema: structuredClone(findingSchema()),
                },
                Object.defineProperty({ signal }, "validate", {
                  value: validation.preflight,
                  writable: true,
                  configurable: true,
                }),
              ),
            );
          } finally {
            validation.close();
          }
        }, signal);
      } catch (error) {
        // Records mode discards the batch after any failed review.
        if (
          error instanceof DeduplicationReviewError &&
          error.metadata.category === "refusal"
        )
          throw new RecordsReviewRefusal(error);
        throw error;
      } finally {
        validation.close();
      }
    },
  });
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
  );
  let groups: string[][];
  try {
    const decisions = await algorithm.run(sourceFindingIds);
    signal?.throwIfAborted();
    groups = decisions.duplicateGroups;
  } catch (error) {
    signal?.throwIfAborted();
    if (detailedErrors())
      throw error instanceof RecordsReviewRefusal ? error.refusal : error;
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
