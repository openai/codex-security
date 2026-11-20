import {
  stackInvestigationReportSchema,
  type StackInvestigationReport,
} from "./dependency-stack-assessment.js";
import type { DependencyClaimReference } from "./dependency-stack-claims.js";
import { isRecord } from "./record.js";

// A claim payload may be free text or structured JSON. Only project readable
// statements here. Packet receipts are deliberately excluded from the viewer.
function statement(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}
function projectClaim({
  id,
  revision,
  hash,
  dependencies,
  sources,
  payload,
}: StackInvestigationReport["claims"][number]) {
  return {
    id,
    revision,
    hash,
    dependencies,
    sources,
    fact: isRecord(payload)
      ? (statement(payload["fact"]) ??
        statement(payload["statement"]) ??
        statement(payload["comparison"]))
      : statement(payload),
    limits: isRecord(payload)
      ? (statement(payload["limits"]) ?? statement(payload["limitations"]))
      : undefined,
  };
}
type Claim = ReturnType<typeof projectClaim>;
export type StackAssessment =
  StackInvestigationReport["assessments"][number] & {
    claims: Claim[];
    missingClaims: DependencyClaimReference[];
  };
export type StackReport = Omit<
  StackInvestigationReport,
  "claims" | "assessments"
> & {
  assessments: StackAssessment[];
};
// The captured indices are leaf-first. Display caller-first without implying
// that two saved, nonadjacent frames represent a direct call.
export function stackFrames(
  sample: NonNullable<StackAssessment["observation"]>,
) {
  const sinks = new Set(sample.sinkMatches.map((match) => match.rawIndex));
  const frames = sample.frames.toSorted((a, b) => b.rawIndex - a.rawIndex);
  return frames.map(({ rawIndex, frame }, i) => ({
    rawIndex,
    frame,
    omittedBefore: i === 0 ? 0 : frames[i - 1]!.rawIndex - rawIndex - 1,
    source: rawIndex === sample.sourceIndex,
    sink: rawIndex === sample.sinkIndex || sinks.has(rawIndex),
  }));
}

function key(ref: DependencyClaimReference) {
  return JSON.stringify([ref.id, ref.revision, ref.hash]);
}

export function readStackReport(value: unknown): StackReport | undefined {
  if (
    !isRecord(value) ||
    value["schemaVersion"] !==
      stackInvestigationReportSchema.shape.schemaVersion.value
  )
    return;
  const { claims, assessments, ...report } =
    stackInvestigationReportSchema.parse(value);
  const records = new Map<string, Claim>();
  for (const record of claims) {
    const id = key(record);
    if (records.has(id))
      throw new Error("Duplicate stack claim reference: " + record.id);
    records.set(id, projectClaim(record));
  }
  const paths = assessments.map((item): StackAssessment => {
    const pending = [...item.supportingClaims];
    const seen = new Set<string>();
    const claims: Claim[] = [];
    const missingClaims: DependencyClaimReference[] = [];
    for (const ref of pending) {
      const id = key(ref);
      if (seen.has(id)) continue;
      seen.add(id);
      const record = records.get(id);
      if (record) {
        claims.push(record);
        for (const dependency of record.dependencies) pending.push(dependency);
      } else missingClaims.push(ref);
    }
    return { ...item, claims, missingClaims };
  });
  return { ...report, assessments: paths };
}
