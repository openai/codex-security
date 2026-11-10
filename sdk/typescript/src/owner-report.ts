import { z } from "zod";
import {
  collectOwnerEvidence,
  type ownerRepository,
  type OwnerContext,
  type OwnerEvidence,
} from "./owner-evidence.js";
import { CodexSecurityError, errorMessage } from "./errors.js";
import type { OwnerCandidate, OwnerSuggestion } from "./suggest-owners.js";

const text = z.string().refine((value) => value.trim().length > 0);
const locationSchema = z
  .object({
    path: text,
    startLine: z.number().int().positive().optional(),
    endLine: z.number().int().positive().optional(),
  })
  .refine(
    ({ startLine, endLine }) =>
      endLine === undefined ||
      (startLine !== undefined && endLine >= startLine),
  );
export const findingSchema = z.object({
  findingId: text,
  occurrenceId: text.optional(),
  title: text,
  summary: z.string(),
  remediation: z.string().optional(),
  sourceRevision: text.optional(),
  locations: z.array(locationSchema),
  extensions: z.record(z.string(), z.unknown()).optional(),
});

export type OwnerFinding = z.infer<typeof findingSchema>;
export const decisionSchema = z.strictObject({
  suggestions: z.array(
    z.strictObject({
      identityIndex: z.number().int().nonnegative(),
      reason: text,
      evidenceIds: z.array(text),
    }),
  ),
  reason: text,
});

export async function ownerResults(
  git: Awaited<ReturnType<typeof ownerRepository>>,
  inputs: readonly OwnerFinding[],
  signal: AbortSignal | undefined,
  decide: (finding: OwnerFinding, context: OwnerContext) => unknown,
): Promise<OwnerSuggestion[]> {
  const results: OwnerSuggestion[] = [];
  for (const finding of inputs) {
    signal?.throwIfAborted();
    const result: OwnerSuggestion = {
      findingId: finding.findingId,
      occurrenceId: finding.occurrenceId ?? null,
      status: "abstained",
      owner: null,
      reason: "No source with observed contributors was available.",
      evidence: [],
      suggestions: [],
      limitations: [],
    };
    results.push(result);
    try {
      const context = await collectOwnerEvidence(
        finding,
        git,
        decide === scanOwnerDecision,
      );
      signal?.throwIfAborted();
      result.limitations = context.limitations;
      for (const declared of context.declaredOwners)
        addSuggestion(result, {
          owner: declared.owner,
          reason: "Declared owner of an affected file in CODEOWNERS.",
          evidence: publicEvidence(
            context.evidence.filter(({ id }) =>
              declared.evidenceIds.includes(id),
            ),
          ),
        });
      if (
        context.identities.length === 0 ||
        !context.evidence.some(({ kind }) => kind === "source")
      )
        continue;
      const decision = decisionSchema.parse(await decide(finding, context));
      const candidates = decision.suggestions.map(
        (suggestion): OwnerCandidate => {
          const owner = context.identities[suggestion.identityIndex];
          const cited = suggestion.evidenceIds.map((id) =>
            context.evidence.find((item) => item.id === id),
          );
          if (
            owner === undefined ||
            !cited.every((item) => item !== undefined) ||
            !cited.some(
              (item) => item.identityIndex === suggestion.identityIndex,
            )
          ) {
            throw new CodexSecurityError(
              "The recommendation contains an unknown owner or unsupported citation.",
            );
          }
          return {
            owner,
            reason: suggestion.reason,
            evidence: publicEvidence(cited),
          };
        },
      );
      for (const candidate of candidates) addSuggestion(result, candidate);
      if (
        candidates.length > 0 &&
        context.declaredOwners.some(({ owner }) => owner.kind === "group")
      )
        result.limitations.push(
          "Git contributors are not verified members of the declared CODEOWNERS teams.",
        );
      if (result.suggestions.length === 0) result.reason = decision.reason;
    } catch (error) {
      signal?.throwIfAborted();
      if (result.suggestions.length > 0)
        result.limitations.push(
          `Additional contributor suggestions failed: ${errorMessage(error)}`,
        );
      else {
        result.status = "error";
        result.reason = errorMessage(error);
      }
    }
  }
  signal?.throwIfAborted();
  return results;
}

export function scanOwnerDecision(
  finding: OwnerFinding,
  context: OwnerContext,
) {
  const value = finding.extensions?.["ownerSuggestion"];
  if (
    value === undefined ||
    value === null ||
    (typeof value === "object" &&
      "suggestions" in value &&
      !("email" in value || "commit" in value || "reason" in value))
  )
    return {
      suggestions: [],
      reason: "The scan did not record a supported owner suggestion.",
    };
  const hint = z
    .object({ email: text, commit: text, reason: text })
    .parse(value);
  const supports = (item: OwnerEvidence) =>
    item.kind === "blame"
      ? item.blameCommit === hint.commit
      : item.commit === hint.commit;
  // Git keeps emails that differ only in case as separate identities.
  const identityIndex = context.identities.findIndex(
    (identity, index) =>
      identity.email.toLowerCase() === hint.email.toLowerCase() &&
      context.evidence.some(
        (item) => item.identityIndex === index && supports(item),
      ),
  );
  const cited = context.evidence.filter(
    (item) => item.identityIndex === identityIndex && supports(item),
  );
  if (identityIndex < 0 || cited.length === 0)
    throw new CodexSecurityError(
      "The scan owner is not supported by the finding's Git evidence.",
    );
  return {
    suggestions: [
      {
        identityIndex,
        reason: hint.reason,
        evidenceIds: cited.map((item) => item.id),
      },
    ],
    reason: hint.reason,
  };
}

function publicEvidence(
  evidence: readonly OwnerEvidence[],
): OwnerCandidate["evidence"] {
  return evidence.map(
    ({
      content: _content,
      blameCommit: _blameCommit,
      identityIndex: _index,
      ...citation
    }) => citation,
  );
}

function ownerKey(owner: OwnerCandidate["owner"]): string {
  return "email" in owner
    ? `email:${owner.email}`
    : `github:${owner.handle.toLowerCase()}`;
}

function addSuggestion(
  result: OwnerSuggestion,
  candidate: OwnerCandidate,
): void {
  const existing = result.suggestions.find(
    ({ owner }) => ownerKey(owner) === ownerKey(candidate.owner),
  );
  if (existing) {
    for (const citation of candidate.evidence)
      if (!existing.evidence.some(({ id }) => id === citation.id))
        existing.evidence.push(citation);
  } else result.suggestions.push(candidate);
  const primary = result.suggestions[0]!;
  result.owner = primary.owner;
  result.reason = primary.reason;
  result.evidence = primary.evidence;
  result.status = "identified";
}
