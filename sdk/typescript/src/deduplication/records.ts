import { randomUUID, hash } from "node:crypto";
import { z } from "incur";
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
  const beneficiaryObservationIds = [...participants]
    .filter((id) => anchors.has(id))
    .sort();
  if (beneficiaryObservationIds.length === 0)
    throw new Error("Records review has no incoming observation participants.");
  return {
    version: 1,
    beneficiaryObservationIds,
    contextObservationIds: [...participants]
      .filter((id) => !anchors.has(id))
      .sort(),
  };
}

const id = z.string().min(1);
const record = z
  .object({
    id,
    finding: z.unknown().transform((value) => requireFinding(value)),
  })
  .strict();

const deduplicateRecordsInputSchema: z.ZodType<DeduplicateRecordsInput> = z
  .object({
    version: z.literal(1),
    observations: z.array(record),
    candidateRelationships: z.array(
      z
        .object({
          observationId: id,
          candidateObservationIds: z.array(id),
        })
        .strict(),
    ),
  })
  .strict();

export interface DeduplicateRecordsInput {
  version: 1;
  observations: { id: string; finding: Finding }[];
  candidateRelationships: {
    observationId: string;
    candidateObservationIds: string[];
  }[];
}
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
  options.signal?.throwIfAborted();
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
  const sourceFindings = [...relationships.keys()].map((id) =>
    observations.get(id)!,
  );
  const reviewer = new CodexDeduplicationReviewer({
    async run<T>({
      validate,
      findingIds,
      ...review
    }: CodexReview<T>): Promise<T> {
      try {
        return await abortable(async () => {
          options.signal?.throwIfAborted();
          return validate(
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
                findingSchema: findingSchema(),
              },
              { signal: options.signal },
            ),
          );
        }, options.signal);
      } catch (error) {
        // Records mode discards the batch after any failed review.
        if (
          error instanceof DeduplicationReviewError &&
          error.metadata.category === "refusal"
        )
          throw new Error(error.message, { cause: error });
        throw error;
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
    options.signal,
    1,
  );
  let groups: string[][];
  try {
    const decisions = await algorithm.run(
      sourceFindings.map((finding) => finding.findingId),
    );
    options.signal?.throwIfAborted();
    groups = decisions.duplicateGroups;
  } catch (error) {
    options.signal?.throwIfAborted();
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
    ...sourceFindings
      .filter((finding) => !grouped.has(finding.findingId))
      .map((finding) => [finding.findingId]),
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
