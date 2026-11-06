import { z } from "zod";
import type { DependencyCandidate } from "./dependency-candidates.js";
import type { createDependencyInventory } from "./dependency-inventory.js";
import { CodexSecurityError } from "./errors.js";

export const dependencyReviewStatusInputSchema = z.strictObject({
  candidates: z
    .strictObject({
      cursor: z
        .strictObject({
          generation: z.number().int().nonnegative(),
          after: z.string().min(1),
        })
        .optional(),
      limit: z.number().int().min(1).max(1000).optional(),
      unassignedOnly: z.boolean().optional(),
    })
    .optional()
    .describe(
      "Request a page of candidate locations only when needed. Defaults to 500 unassigned candidates, with a maximum requested page size of 1000. Follow nextCursor; new discovery invalidates a cursor. Queueing a page does not skip subsequent candidates.",
    ),
  inventoryReceipts: z
    .boolean()
    .optional()
    .describe(
      "Include current receipt metadata when choosing an explicit evidence binding. Prefer authenticated record selectors already returned by catalog mappings.",
    ),
});

interface ReviewStatus {
  candidateGeneration: number;
  candidates: readonly DependencyCandidate[];
  inventoryReceipts: ReturnType<
    ReturnType<typeof createDependencyInventory>["snapshot"]
  >;
  scope: string;
  limitations: readonly string[];
  items: readonly {
    id: string;
    revision: number;
    kind: string;
    candidateIds: readonly string[];
    status: string;
    feedback?: string | undefined;
  }[];
  queued: number;
  inFlight: number;
  closed: boolean;
}

/** Keep polling and queue acknowledgments independent of the full candidate ledger. */
export function summarizeDependencyReviewStatus(
  status: ReviewStatus,
  value: unknown = {},
) {
  const input = dependencyReviewStatusInputSchema.parse(value);
  const bindings = new Map<string, string[]>();
  for (const item of status.items) {
    for (const id of item.candidateIds) {
      const ids = bindings.get(id) ?? [];
      ids.push(item.id);
      bindings.set(id, ids);
    }
  }
  const unassigned = status.candidates.filter(
    (candidate) => !bindings.has(candidate.id),
  );
  let candidatePage;
  if (input.candidates) {
    const request = input.candidates;
    let start = 0;
    if (request.cursor) {
      if (request.cursor.generation !== status.candidateGeneration) {
        throw new CodexSecurityError(
          "Candidate discovery changed since this cursor. Request candidates: {} to start a current page; prior assessments remain accounted for.",
        );
      }
      const previous = status.candidates.findIndex(
        (candidate) => candidate.id === request.cursor!.after,
      );
      if (previous === -1)
        throw new CodexSecurityError(
          "Unknown candidate cursor. Request candidates: {} to start a current page.",
        );
      start = previous + 1;
    }
    const unassignedOnly = request.unassignedOnly !== false;
    const remaining = status.candidates
      .slice(start)
      .filter((candidate) => !unassignedOnly || !bindings.has(candidate.id));
    const page = remaining.slice(0, request.limit ?? 500);
    const last = page.at(-1);
    candidatePage = {
      generation: status.candidateGeneration,
      total: unassignedOnly ? unassigned.length : status.candidates.length,
      unassignedOnly,
      candidates: page.map((candidate) => ({
        id: candidate.id,
        path: candidate.path,
        line: candidate.line,
        ...(candidate.package && { package: candidate.package }),
        sourceBytes: candidate.sourceBytes,
        assessmentIds: bindings.get(candidate.id) ?? [],
      })),
      nextCursor:
        last && remaining.length > page.length
          ? { generation: status.candidateGeneration, after: last.id }
          : null,
    };
  }
  return {
    candidateGeneration: status.candidateGeneration,
    candidateCount: status.candidates.length,
    unassignedCandidateCount: unassigned.length,
    scope: status.scope,
    limitations: status.limitations,
    items: status.items.map((item) => ({
      id: item.id,
      revision: item.revision,
      kind: item.kind,
      candidateCount: item.candidateIds.length,
      status: item.status,
      ...((item.status === "rejected" || item.status === "error") &&
      item.feedback
        ? { feedback: item.feedback }
        : {}),
    })),
    queued: status.queued,
    inFlight: status.inFlight,
    closed: status.closed,
    nextAction: status.items.some(
      (item) => item.status === "rejected" || item.status === "error",
    )
      ? "Read the specific rejection/error feedback and revise affected active assessments. Complete unassigned candidate accounting, then finalize; pending review alone does not require polling."
      : unassigned.length
        ? "Request candidates: {} for unassigned locations; follow nextCursor and assess related locations together."
        : "If investigation is complete, finalize now even when items are queued or reviewing. Finalization starts pending reviews immediately and waits for them; polling is unnecessary.",
    ...(candidatePage ? { candidatePage } : {}),
    ...(input.inventoryReceipts
      ? {
          inventoryReceipts: status.inventoryReceipts.filter(
            (receipt) => receipt.current,
          ),
        }
      : {}),
  };
}
