import type {
  Check,
  Citation,
  Section,
  Finding,
} from "./dependency-report-model.js";
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
type ClaimRef = Pick<Claims[number], "id" | "revision" | "hash">;
export function claimKey(ref: ClaimRef) {
  return JSON.stringify([ref.id, ref.revision, ref.hash]);
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
  const pending = [...(finding.item.supportingClaims ?? [])];
  if (finding.item.conclusionClaim) pending.push(finding.item.conclusionClaim);
  const seen = new Set<string>();
  for (const ref of pending) {
    const key = claimKey(ref);
    if (seen.has(key)) continue;
    seen.add(key);
    const claim = claims.get(key);
    if (!claim) continue;
    pending.push(...claim.dependencies);
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
