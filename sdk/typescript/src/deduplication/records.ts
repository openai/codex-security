import { createHash, randomUUID } from "node:crypto";
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
  recordsPrompt,
} from "./deduplication-prompts.js";
import type { DeduplicationReviewRunner } from "./review.js";

const id = z.string().min(1);
const record = z
  .object({
    id,
    finding: z.custom<Finding>(requireFinding),
  })
  .strict();

const deduplicateRecordsInputSchema = z
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

export interface DeduplicateRecordsInput extends z.output<
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
    const findingId = `csf_${createHash("sha256")
      .update(entry.id)
      .digest("hex")
      .slice(0, 24)}`;
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
  const sourceFindings = [...relationships.keys()].map((id) =>
    observations.get(id)!,
  );
  const reviewer = new CodexDeduplicationReviewer(
    {
      async run<T>({ validate, ...review }: CodexReview<T>): Promise<T> {
        try {
          return await abortable(async () => {
            options.signal?.throwIfAborted();
            return validate(
              await options.reviewRunner.run(
                {
                  ...review,
                  requestId: randomUUID(),
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
    },
    recordsPrompt,
  );
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
    return {
      version: 1,
      status: "unresolved",
      groups: [],
      unresolved: [...relationships.keys()].map((observationId) => ({
        observationId,
        reason: "review_failed",
        message:
          error instanceof Error ? error.message : "Review did not complete.",
      })),
    };
  }
  const grouped = new Set(groups.flat());
  groups.push(
    ...sourceFindings
      .filter((finding) => !grouped.has(finding.findingId))
      .map((finding) => [finding.findingId]),
  );
  return {
    version: 1,
    status: "completed",
    groups: groups.map((group) => {
      const observationIds = group.map((id) => references.get(id)!);
      return {
        representativeObservationId: observationIds[0]!,
        observationIds,
      };
    }),
    unresolved: [],
  };
}
