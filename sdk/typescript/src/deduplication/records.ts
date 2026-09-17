import { createHash, randomUUID } from "node:crypto";
import { z } from "incur";
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
import type { DeduplicationReviewRunner } from "./review.js";

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
    canonicals: z.array(record),
    candidateRelationships: z.array(
      z
        .object({
          observationId: id,
          canonicalIds: z.array(id),
        })
        .strict(),
    ),
  })
  .strict();

export interface DeduplicateRecordsInput {
  version: 1;
  observations: { id: string; finding: Finding }[];
  canonicals: { id: string; finding: Finding }[];
  candidateRelationships: { observationId: string; canonicalIds: string[] }[];
}
export interface DeduplicateRecordsOptions {
  reviewRunner: DeduplicationReviewRunner;
  signal?: AbortSignal;
}
export interface DeduplicateRecordsResult {
  version: 1;
  status: "completed" | "unresolved";
  newGroups: {
    representativeObservationId: string;
    observationIds: string[];
  }[];
  matches: { observationId: string; canonicalId: string }[];
  unresolved: {
    observationId: string;
    reason: "review_failed" | "ambiguous_canonicals";
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
  const references = new Map<
    string,
    { kind: "observation" | "canonical"; id: string }
  >();
  const normalize = (
    records: typeof data.observations,
    kind: "observation" | "canonical",
  ) => {
    const result = new Map<string, Finding>();
    for (const entry of records) {
      if (result.has(entry.id))
        throw new Error(`Duplicate ${kind} ID: ${entry.id}`);
      // Finding IDs have a schema-defined format. Keep host identity in separate namespaces.
      const findingId = `csf_${createHash("sha256")
        .update(JSON.stringify([kind, entry.id]))
        .digest("hex")
        .slice(0, 24)}`;
      result.set(entry.id, { ...entry.finding, findingId });
      references.set(findingId, { kind, id: entry.id });
    }
    return result;
  };
  const observations = normalize(data.observations, "observation");
  const canonicals = normalize(data.canonicals, "canonical");
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
      new Set(relation.canonicalIds).size !== relation.canonicalIds.length ||
      relation.canonicalIds.some((id) => !canonicals.has(id))
    )
      throw new Error(
        "Canonical candidates must name distinct supplied canonical IDs.",
      );
    relationships.set(relation.observationId, relation.canonicalIds);
  }
  if (relationships.size !== observations.size)
    throw new Error(
      "Supply candidate relationships for every observation, including empty lists.",
    );

  const result: DeduplicateRecordsResult = {
    version: 1,
    status: "completed",
    newGroups: [],
    matches: [],
    unresolved: [],
  };
  const sourceFindings = [...observations.values()];
  const reviewer = new CodexDeduplicationReviewer({
    async run<T>({ validate, ...review }: CodexReview<T>): Promise<T> {
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
    },
  });
  const algorithm = new FindingDeduplicator(
    {
      async potentialDuplicates(findingId) {
        const reference = references.get(findingId)!;
        return {
          finding: observations.get(reference.id)!,
          potentialDuplicates: [
            ...sourceFindings.filter(
              (finding) => finding.findingId !== findingId,
            ),
            ...relationships
              .get(reference.id)!
              .map((id) => canonicals.get(id)!),
          ],
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
    result.unresolved = data.observations.map(({ id }) => ({
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
    const members = group.map((id) => references.get(id)!);
    const sourceIds = members
      .filter(({ kind }) => kind === "observation")
      .map(({ id }) => id);
    const canonicalIds = members
      .filter(({ kind }) => kind === "canonical")
      .map(({ id }) => id);
    if (canonicalIds.length > 1) {
      result.status = "unresolved";
      result.unresolved.push(
        ...sourceIds.map((observationId) => ({
          observationId,
          reason: "ambiguous_canonicals" as const,
          message:
            "Reviewed group connects multiple existing canonicals; host reconciliation is required.",
        })),
      );
    } else if (canonicalIds.length === 1) {
      result.matches.push(
        ...sourceIds.map((observationId) => ({
          observationId,
          canonicalId: canonicalIds[0]!,
        })),
      );
    } else {
      result.newGroups.push({
        representativeObservationId: sourceIds[0]!,
        observationIds: sourceIds,
      });
    }
  }
  return result;
}
