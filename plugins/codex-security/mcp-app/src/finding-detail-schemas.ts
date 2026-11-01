import * as z from "zod/v4";

export function findingDetailSchemas(
  text: z.ZodString,
  path: z.ZodString,
  line: z.ZodNumber,
) {
  const slug = z.string().regex(new RegExp("^[a-z0-9][a-z0-9._/-]*$"));
  const textList = z.array(text);
  const findingAssessment = z.union([
    text,
    z.looseObject({
      level: text.optional(),
      rationale: text.optional(),
      why: text.optional(),
    }),
  ]);

  const textOrSummary = z.union([
    text,
    z.looseObject({
      summary: text.optional(),
      source: text.optional(),
      sink: text.optional(),
      outcome: text.optional(),
      transformations: textList.optional(),
      evidenceRefs: textList.optional(),
      evidence_refs: z.never().optional(),
    }),
  ]);

  const findingReachability = z.union([
    text,
    z.looseObject({
      summary: text.optional(),
      attacker: text.optional(),
      entrypoint: text.optional(),
      source: text.optional(),
      sink: text.optional(),
      outcome: text.optional(),
      preconditions: textList.optional(),
      evidenceRefs: textList.optional(),
      evidence_refs: z.never().optional(),
    }),
  ]);

  const findingValidation = z.looseObject({
    assertions: textList.optional(),
    counterEvidence: textList.optional(),
    evidence: z.union([text, textList]).optional(),
    evidenceRefs: textList.optional(),
    evidence_refs: z.never().optional(),
    limitations: textList.optional(),
    method: text.optional(),
    status: z.union([text, z.null()]).optional(),
    summary: text.optional(),
    disposition: z.union([text, z.null()]).optional(),
    result: z.union([text, z.null()]).optional(),
  });

  const findingAttackPath = z.looseObject({
    assumptions: textList.optional(),
    blindspots: textList.optional(),
    controls: textList.optional(),
    dataFlow: z.never().optional(),
    data_flow: z.never().optional(),
    dataflow: textOrSummary.optional(),
    evidenceRefs: textList.optional(),
    evidence_refs: z.never().optional(),
    impact: z.union([findingAssessment, z.null()]).optional(),
    likelihood: z.union([findingAssessment, z.null()]).optional(),
    limitations: textList.optional(),
    preconditions: textList.optional(),
    reachability: findingReachability.optional(),
    steps: textList.optional(),
    summary: text.optional(),
  });

  return {
    textList,
    slug,
    identity: z.looseObject({ anchor: slug, instance: slug.optional() }),
    severity: z.looseObject({
      level: z.enum(["critical", "high", "medium", "low", "informational"]),
      score: z.number().min(0).max(10).optional(),
      scoringSystem: text.optional(),
      vector: text.optional(),
      rationale: text.optional(),
      changeConditions: text.optional(),
    }),
    confidence: z.looseObject({
      level: z.enum(["high", "medium", "low"]),
      rationale: text,
    }),
    location: z.looseObject({
      path,
      startLine: line,
      endLine: line.optional(),
      role: text.optional(),
    }),
    codeEvidence: z.looseObject({
      id: slug,
      label: text,
      path,
      startLine: line,
      endLine: line.optional(),
      language: text.optional(),
      role: text.optional(),
      code: text,
      explanation: text,
    }),
    findingAssessment,
    textOrSummary,
    findingReachability,
    findingValidation,
    findingAttackPath,
  };
}
