import { z } from "zod";
import {
  collectOwnerEvidence,
  collectGitOwnerEvidence,
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
  | { kind: "scan"; onWarning?: (warning: string) => void }
  | { kind: "standalone"; decide: ModelDecision };
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
    }
    if (policy.kind === "scan") {
      const stale =
        finding.sourceRevision !== undefined &&
        finding.sourceRevision !== repository.revision;
      await collectGitOwnerEvidence(
        finding,
        repository,
        context,
        stale,
        "scan",
      );
      const gitEvidence = context.evidence.filter(
        (e) => e.kind === "blame" || e.kind === "history",
      );
      const authors = new Set(
        context.identities.map(({ email }) => email.toLowerCase()),
      );
      const citedPaths = new Set(gitEvidence.map(({ path }) => path));
      if (
        authors.size === 1 &&
        finding.locations.every(({ path }) => citedPaths.has(path))
      ) {
        addSuggestion(result.suggestions, {
          owner: context.identities[0]!,
          reason: "Git attributes the affected source to this contributor.",
          evidence: publicEvidence(gitEvidence),
        });
      } else {
        result.reason =
          "Git did not identify a single contributor across the affected source.";
      }
    } else if (
      !result.suggestions.length &&
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
    if (result.suggestions.length) {
      result.status = "identified";
      result.reason = result.suggestions[0]!.reason;
      const warning = `Git owner lookup failed: ${errorMessage(error)}`;
      result.limitations.push(warning);
      if (policy.kind === "scan") policy.onWarning?.(warning);
    } else {
      signal?.throwIfAborted();
      result.status = "error";
      result.reason = errorMessage(error);
    }
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
    ? `email:${owner.email.toLowerCase()}`
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
