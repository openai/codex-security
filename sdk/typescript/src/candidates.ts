import { isRecord } from "./record.js";
import type { CoverageDocument, DeferredCoverage, Finding } from "./models.js";

function candidateOwner(...values: unknown[]): string | undefined {
  return values.find(
    (value): value is string => typeof value === "string" && !!value.trim(),
  );
}

/** Candidate aliases in canonical precedence order. */
export function findingCandidateIds(
  finding: Pick<Finding, "provenance" | "extensions">,
): string[] {
  return [
    finding.provenance["candidateId"],
    finding.extensions?.candidateId,
    finding.extensions?.reportId,
    finding.extensions?.ledgerRowId,
  ].filter(
    (value): value is string =>
      typeof value === "string" && value.trim() !== "",
  );
}

export function findingCandidateOwner(
  finding: Pick<Finding, "provenance" | "extensions">,
): string | undefined {
  return candidateOwner(
    finding.provenance["sourceWorkerId"],
    finding.provenance["workerId"],
    finding.extensions?.["sourceWorkerId"],
  );
}

export function candidateIdentity(
  candidateId: string,
  sourceWorkerId: unknown,
): string {
  return JSON.stringify([candidateOwner(sourceWorkerId) ?? null, candidateId]);
}

export function coverageCandidateOwner(row: Record<string, unknown>): unknown {
  const provenance = row["provenance"];
  if (isRecord(provenance) && candidateOwner(provenance["workerId"]))
    return provenance["workerId"];
  const owner = row["sourceWorkerId"];
  return owner != null && typeof owner !== "string"
    ? owner
    : candidateOwner(owner, row["workerId"]);
}

export function coverageCandidateId(
  row: Record<string, unknown>,
): string | undefined {
  const id = row["candidateId"];
  if (typeof id !== "string" || !id.trim()) return undefined;
  const provenance = row["provenance"];
  const sourceId =
    isRecord(provenance) && candidateOwner(provenance["workerId"])
      ? (provenance["candidateId"] ?? id)
      : id;
  return typeof sourceId === "string" && sourceId.trim() ? sourceId : undefined;
}

export function coverageCandidateKey(
  row: Record<string, unknown>,
): string | undefined {
  const owner = coverageCandidateOwner(row);
  const id = coverageCandidateId(row);
  return id !== undefined && (owner == null || typeof owner === "string")
    ? candidateIdentity(id, owner)
    : undefined;
}

/** Saved candidate identities without a finding or terminal disposition. */
export function unresolvedCandidates(
  coverage: CoverageDocument,
  findings: readonly Finding[],
  sealed = false,
): DeferredCoverage[] {
  const resolved = new Set<string>();
  for (const finding of findings) {
    if (finding.provenance["candidateReopened"] === true) continue;
    const candidateId = findingCandidateIds(finding)[0];
    if (candidateId !== undefined) {
      resolved.add(
        candidateIdentity(candidateId, findingCandidateOwner(finding)),
      );
    }
  }
  // A reported surface can cover multiple candidates; findings confirm identities.
  for (const surface of [
    ...coverage.surfaces,
    ...(!sealed || coverage.receiptSealVersion === 1
      ? coverage.explicitExclusions
      : []),
  ]) {
    const key = coverageCandidateKey(surface);
    if (
      key !== undefined &&
      (surface["disposition"] === "rejected" ||
        surface["disposition"] === "not_applicable")
    )
      resolved.add(key);
  }
  const pending = new Map<string, DeferredCoverage>();
  for (const candidate of coverage.deferred) {
    const key = coverageCandidateKey(candidate);
    if (key !== undefined && !resolved.has(key) && !pending.has(key))
      pending.set(key, candidate);
  }
  return [...pending.values()];
}
