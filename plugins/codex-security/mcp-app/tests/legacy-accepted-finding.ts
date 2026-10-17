import { finding } from "./scan-draft-fixture.ts";

/** Finding fields accepted before the current producer contract was narrowed. */
export function legacyAcceptedFinding(
  base = finding("historical-checkpoint", "fixture.py"),
) {
  const referenced = {
    summary: "Synthetic source reaches the response.",
    evidenceRefs: ["legacy-snippet"],
    evidence_refs: ["canonical-snippet"],
  };
  return {
    ...base,
    codeEvidence: [
      {
        id: "canonical-snippet",
        label: "Response",
        path: "fixture.py",
        startLine: 1,
        code: "return value",
        explanation: "The synthetic value reaches the response.",
      },
    ],
    code_evidence: [{ id: "legacy-snippet", code: "return value" }],
    rootCause: {
      ...referenced,
      code: "return value",
      language: "python",
    },
    root_cause: { ...referenced, code: "return value", language: "python" },
    validation: { ...referenced, status: "confirmed" },
    attackPath: {
      ...referenced,
      dataflow: { ...referenced },
      dataFlow: { ...referenced },
      data_flow: { ...referenced },
      reachability: { ...referenced },
    },
  };
}

/** Older discovery readers admitted these bytes without rewriting the file. */
export function legacyRawDiscoveryFinding(
  base = finding("historical-checkpoint", "fixture.py"),
): ReturnType<typeof finding> & Record<string, unknown> {
  const raw: ReturnType<typeof finding> & Record<string, unknown> =
    legacyAcceptedFinding(base);
  const attackPath = raw.attackPath as Record<string, unknown>;
  for (const detail of [
    raw.rootCause,
    raw.root_cause,
    raw.validation,
    attackPath,
    attackPath.dataflow,
    attackPath.dataFlow,
    attackPath.data_flow,
    attackPath.reachability,
  ]) {
    const section = detail as Record<string, unknown>;
    for (const field of ["evidenceRefs", "evidence_refs"])
      section[field] = (section[field] as string[])[0];
  }
  (raw.code_evidence as unknown[]).push(
    { id: "legacy-snippet", code: "duplicate()" },
    { id: "canonical-snippet", code: "duplicate()" },
    { id: "invalid", code: " " },
    null,
  );
  return raw;
}
