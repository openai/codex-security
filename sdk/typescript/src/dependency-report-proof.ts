import type {
  Check,
  Citation,
  Section,
  Finding,
} from "./dependency-report-model.js";
import type { DependencyClaimReference } from "./dependency-stack-claims.js";
import { isRecord } from "./record.js";
export const citationKey = ({
  path,
  commit,
  startLine,
  endLine,
}: Pick<Citation, "path" | "commit" | "startLine" | "endLine">) =>
  JSON.stringify(
    commit ? [path, commit, startLine, endLine] : [path, startLine, endLine],
  );
type Claims = NonNullable<Check["claims"]>;
export function claimKey(ref: DependencyClaimReference) {
  return JSON.stringify([ref.id, ref.revision, ref.hash]);
}

// Visit each exact reference once, roots before premises. Keep missing
// references in order so readers can show gaps alongside decisions.
export function* walkClaims<
  T extends { dependencies: DependencyClaimReference[] },
>(roots: readonly DependencyClaimReference[], claims: ReadonlyMap<string, T>) {
  const pending = [...roots];
  const seen = new Set<string>();
  for (const ref of pending) {
    const key = claimKey(ref);
    if (seen.has(key)) continue;
    seen.add(key);
    const claim = claims.get(key);
    yield { ref, claim };
    if (claim)
      for (const dependency of claim.dependencies) pending.push(dependency);
  }
}

// Only use excerpts from claims attached to this finding, including their premises.
export function savedSnippets(
  section: Section,
  finding: Finding,
  claims: Map<string, Claims[number]>,
) {
  const result = new Map<string, string>();
  if (finding.kind === "stack") {
    for (const claim of finding.assessment.claims)
      for (const source of claim.sources)
        result.set(citationKey(source), source.text);
    return result;
  }
  const roots = [...(finding.item.supportingClaims ?? [])];
  if (finding.item.conclusionClaim) roots.push(finding.item.conclusionClaim);
  for (const { claim } of walkClaims(roots, claims)) {
    if (!claim) continue;
    for (const id of claim.evidence.sourceIds) {
      const source = section.check?.claimEvidence?.sources[id];
      if (!isRecord(source)) continue;
      const { path, commit, startLine, endLine } = source;
      const text = source["excerpt"] ?? source["text"];
      if (
        typeof text === "string" &&
        typeof path === "string" &&
        (commit === undefined || typeof commit === "string") &&
        typeof startLine === "number" &&
        typeof endLine === "number"
      )
        result.set(
          citationKey({ path, commit, startLine, endLine }),
          text.replace(/\n$/u, ""),
        );
    }
  }
  return result;
}
