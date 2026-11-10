import { z } from "zod";
import {
  collectOwnerEvidence,
  hasScanOwnerHint,
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

type ModelDecision = (finding: OwnerFinding, context: OwnerContext) => unknown;
type OwnerPolicy =
  { kind: "scan" } | { kind: "standalone"; decide: ModelDecision };
type RankedResult = Pick<
  OwnerSuggestion,
  | "findingId"
  | "occurrenceId"
  | "status"
  | "suggestions"
  | "reason"
  | "limitations"
>;

export async function ownerResult(
  repository: Awaited<ReturnType<typeof ownerRepository>>,
  finding: OwnerFinding,
  signal: AbortSignal | undefined,
  policy: OwnerPolicy,
): Promise<RankedResult> {
  signal?.throwIfAborted();
  const result: RankedResult = {
    findingId: finding.findingId,
    occurrenceId: finding.occurrenceId ?? null,
    status: "abstained",
    suggestions: [],
    limitations: [],
    reason: "No source with observed contributors was available.",
  };
  try {
    const context = await collectOwnerEvidence(
      finding,
      repository,
      policy.kind,
    );
    signal?.throwIfAborted();
    result.limitations = context.limitations;
    if (context.declaredOwners.length) {
      for (const declared of context.declaredOwners)
        addSuggestion(result.suggestions, {
          owner: declared.owner,
          reason: "Declared owner of an affected file in CODEOWNERS.",
          evidence: publicEvidence(
            context.evidence.filter(({ id }) =>
              declared.evidenceIds.includes(id),
            ),
          ),
        });
    } else if (policy.kind === "scan") {
      if (hasScanOwnerHint(finding)) {
        const candidate = verifiedGitCandidate(finding, context);
        result.suggestions.push(candidate);
      } else
        result.reason = "The scan did not record a supported owner suggestion.";
    } else if (
      context.identities.length &&
      context.evidence.some(({ kind }) => kind === "source")
    ) {
      const decision = decisionSchema.parse(
        await policy.decide(finding, context),
      );
      signal?.throwIfAborted();
      const candidates = decision.suggestions.map(
        (suggestion): OwnerCandidate => {
          const owner = context.identities[suggestion.identityIndex];
          const cited = [...new Set(suggestion.evidenceIds)].map((id) =>
            context.evidence.find((item) => item.id === id),
          );
          if (
            !owner ||
            !cited.every((item) => item !== undefined) ||
            !cited.some(
              (item) => item.identityIndex === suggestion.identityIndex,
            )
          )
            throw new CodexSecurityError(
              "The recommendation contains an unknown owner or unsupported citation.",
            );
          return {
            owner,
            reason: suggestion.reason,
            evidence: publicEvidence(cited),
          };
        },
      );
      for (const candidate of candidates)
        addSuggestion(result.suggestions, candidate);
      result.reason = decision.reason;
    }
    if (result.suggestions.length) {
      result.status = "identified";
      result.reason = result.suggestions[0]!.reason;
    }
  } catch (error) {
    signal?.throwIfAborted();
    result.status = "error";
    result.reason = errorMessage(error);
  }
  return result;
}

export async function ownerResults(
  git: Awaited<ReturnType<typeof ownerRepository>>,
  inputs: readonly OwnerFinding[],
  signal: AbortSignal | undefined,
  policy: OwnerPolicy,
): Promise<OwnerSuggestion[]> {
  const results: OwnerSuggestion[] = [];
  for (const finding of inputs) {
    const ranked = await ownerResult(git, finding, signal, policy);
    const primary = ranked.suggestions[0];
    results.push({
      ...ranked,
      owner: primary?.owner ?? null,
      evidence: primary?.evidence ?? [],
    });
  }
  signal?.throwIfAborted();
  return results;
}

function verifiedGitCandidate(
  finding: OwnerFinding,
  context: OwnerContext,
): OwnerCandidate {
  const hint = z
    .object({ email: text, commit: text, reason: text })
    .parse(finding.extensions?.["ownerSuggestion"]);
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
    owner: context.identities[identityIndex]!,
    reason: hint.reason,
    evidence: publicEvidence(cited),
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
  suggestions: OwnerCandidate[],
  candidate: OwnerCandidate,
): void {
  const existing = suggestions.find(
    ({ owner }) => ownerKey(owner) === ownerKey(candidate.owner),
  );
  if (existing) {
    for (const citation of candidate.evidence)
      if (!existing.evidence.some(({ id }) => id === citation.id))
        existing.evidence.push(citation);
  } else suggestions.push(candidate);
}
