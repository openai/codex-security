import { z } from "zod";
import {
  collectOwnerEvidence,
  collectGitOwnerEvidence,
  type ownerRepository,
} from "./owner-evidence.js";
import { CodexSecurityError, errorMessage } from "../checkout/errors.js";
import type {
  OwnerCandidate,
  OwnerSuggestion,
  OwnerContext,
  OwnerEvidence,
  OwnerFinding,
  OwnerPolicy,
} from "./types.js";

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
      // One citation per author is enough to explain their place in the ranking.
      const latest = new Map<
        string,
        {
          owner: OwnerContext["identities"][number];
          evidence: OwnerEvidence;
          time: number;
        }
      >();
      const citedPaths = new Set<string>();
      for (const evidence of context.evidence) {
        if (
          evidence.identityIndex === null ||
          evidence.commitTime === undefined
        )
          continue;
        const owner = context.identities[evidence.identityIndex]!;
        const email = owner.email.toLowerCase();
        const previous = latest.get(email);
        citedPaths.add(evidence.path);
        if (!previous || evidence.commitTime > previous.time)
          latest.set(email, { owner, evidence, time: evidence.commitTime });
      }
      if (finding.locations.every(({ path }) => citedPaths.has(path))) {
        const ranked = [...latest.entries()].sort(
          ([emailA, a], [emailB, b]) =>
            b.time - a.time || (emailA < emailB ? -1 : emailA > emailB ? 1 : 0),
        );
        for (const [, candidate] of ranked.slice(0, 3))
          addSuggestion(result.suggestions, {
            owner: candidate.owner,
            reason: "Recent author of the affected source in Git.",
            evidence: publicEvidence([candidate.evidence]),
          });
      } else {
        result.reason = "Git evidence was unavailable for an affected path.";
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
      commitTime: _commitTime,
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
