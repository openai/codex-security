import { isRecord } from "./record.js";

type JsonObject = Record<string, unknown>;

function candidateOwner(...values: unknown[]): string | undefined {
  return values.find(
    (value): value is string => typeof value === "string" && !!value.trim(),
  );
}

export function findingCandidateId(finding: JsonObject): string | undefined {
  const provenance = finding.provenance as JsonObject | undefined;
  const extensions = finding.extensions as JsonObject | undefined;
  return [
    provenance?.candidateId,
    extensions?.candidateId,
    extensions?.reportId,
    extensions?.ledgerRowId,
  ].find(
    (value): value is string => typeof value === "string" && !!value.trim(),
  );
}

export function candidateKey(id: unknown, owner?: unknown): string | undefined {
  return typeof id === "string" && id.trim()
    ? JSON.stringify([candidateOwner(owner) ?? null, id])
    : undefined;
}

export function findingCandidateOwner(finding: JsonObject): string | undefined {
  const provenance = finding.provenance as JsonObject | undefined;
  const extensions = finding.extensions as JsonObject | undefined;
  return candidateOwner(
    provenance?.sourceWorkerId,
    provenance?.workerId,
    extensions?.sourceWorkerId,
  );
}

export function findingCandidateKey(
  finding: JsonObject,
  owner?: string,
): string | undefined {
  return candidateKey(
    findingCandidateId(finding),
    candidateOwner(owner, findingCandidateOwner(finding)),
  );
}

export function coverageCandidateOwner(item: JsonObject): unknown {
  if (isRecord(item.provenance) && candidateOwner(item.provenance.workerId))
    return item.provenance.workerId;
  const owner = item.sourceWorkerId;
  return owner != null && typeof owner !== "string"
    ? owner
    : candidateOwner(owner, item.workerId);
}

export function coverageCandidateKey(
  item: JsonObject,
  owner?: string,
): string | undefined {
  const sourceOwner = candidateOwner(owner) ?? coverageCandidateOwner(item);
  if (sourceOwner != null && typeof sourceOwner !== "string") return undefined;
  const candidateId =
    owner === undefined &&
    typeof item.candidateId === "string" &&
    isRecord(item.provenance) &&
    candidateOwner(item.provenance.workerId)
      ? (item.provenance.candidateId ?? item.candidateId)
      : item.candidateId;
  return candidateKey(candidateId, sourceOwner);
}

/** Prefer the matching owner for duplicate raw IDs; unique references may be shared. */
export function surfaceReferenceKey(
  id: unknown,
  source: JsonObject,
  surfaces: JsonObject[],
  owner?: string,
): string | undefined {
  const matches = surfaces.filter((surface) => surface.id === id);
  const sameOwner = matches.find(
    (surface) =>
      candidateOwner(owner, coverageCandidateOwner(surface)) ===
      candidateOwner(owner, coverageCandidateOwner(source)),
  );
  const target = sameOwner ?? (matches.length === 1 ? matches[0]! : source);
  return candidateKey(
    id,
    candidateOwner(owner, coverageCandidateOwner(target)),
  );
}

export function isTerminalCandidateDecision<Item extends JsonObject>(
  item: Item,
): item is Item & {
  candidateId: string;
  disposition: "rejected" | "not_applicable";
} {
  return (
    typeof item.candidateId === "string" &&
    (item.disposition === "rejected" || item.disposition === "not_applicable")
  );
}

export function isCurrentCandidateFinding(finding: JsonObject): boolean {
  const provenance = finding.provenance as JsonObject | undefined;
  return provenance?.candidateReopened !== true;
}

export function resolvedCandidateKeys(
  input: {
    findings: JsonObject[];
    coverage: JsonObject;
  },
  owner?: string,
): Set<string> {
  return new Set(
    [
      ...input.findings
        .filter(isCurrentCandidateFinding)
        .map((finding) => findingCandidateKey(finding, owner)),
      ...[
        ...(input.coverage.surfaces as JsonObject[]),
        ...(input.coverage.explicitExclusions as JsonObject[]),
      ]
        .filter(isTerminalCandidateDecision)
        .map((item) => coverageCandidateKey(item, owner)),
    ].filter((value): value is string => typeof value === "string"),
  );
}
