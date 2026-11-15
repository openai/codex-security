import { isRecord } from "../../sdk/typescript/src/record.ts";
import type { CommandVerdict } from "./cases.mts";
import type { EvidenceGroup } from "./grade.mts";

export const placeRubricVersion = "places-v2";

export interface SearchExpectation {
  source: string;
  tool: string;
  scope: readonly string[];
  result: "matches" | "no_match" | "returned" | "unknown" | "not_run";
  completeness:
    "complete" | "partial" | "unknown" | "unavailable" | "skipped" | "error";
  /** Independent receipt ID when the fixture supplies the original lookup. */
  evidenceReference?: string;
}

export function gradeRunSearchAudit(
  answer: Record<string, unknown>,
  sourcePackage: (value: unknown) => boolean,
  expectations: readonly SearchExpectation[],
  lookupProviderConfigured = false,
) {
  const searches = records(answer.searches);
  const sourceSearches = searches.filter(
    ({ source, tool, scope }) =>
      source === "Checkout trace graph" &&
      tool === "trace_codex_security_code" &&
      Array.isArray(scope) &&
      scope.some(
        (term) =>
          typeof term === "string" &&
          (/^(files|paths|searched|rules)=/u.test(term) ||
            term === "Checkout search scope"),
      ) &&
      scope.some(
        (term) =>
          typeof term === "string" &&
          term.startsWith("package=") &&
          sourcePackage(term.slice("package=".length)),
      ),
  );
  const valid = (search: Record<string, unknown>) => {
    const {
      scope,
      startedAt,
      finishedAt,
      result,
      completeness,
      details,
      evidenceReferences,
    } = search;
    return (
      Array.isArray(scope) &&
      scope.every((term) => typeof term === "string") &&
      typeof finishedAt === "string" &&
      Number.isFinite(Date.parse(finishedAt)) &&
      (startedAt === null ||
        (typeof startedAt === "string" &&
          Date.parse(startedAt) <= Date.parse(finishedAt))) &&
      Array.isArray(evidenceReferences) &&
      evidenceReferences.every(
        (ref) => typeof ref === "string" && ref.length > 0,
      ) &&
      Array.isArray(details) &&
      details.every((detail) => typeof detail === "string") &&
      ["matches", "no_match", "returned", "unknown", "not_run"].includes(
        String(result),
      ) &&
      [
        "complete",
        "partial",
        "error",
        "unknown",
        "unavailable",
        "skipped",
      ].includes(String(completeness)) &&
      (!["skipped", "unavailable"].includes(String(completeness)) ||
        result === "not_run") &&
      (completeness !== "error" || result === "unknown")
    );
  };
  const errors = [];
  if (
    !Array.isArray(answer.searches) ||
    searches.length !== answer.searches.length ||
    searches.some((search) => !valid(search))
  )
    errors.push(
      "Search audit contains an invalid scope, timestamp, outcome, completeness or reference",
    );
  if (
    !sourceSearches.some(
      (search) =>
        search.completeness === "error" ||
        search.completeness === "partial" ||
        search.completeness === "complete",
    )
  )
    errors.push(
      "Missing captured checkout tracer outcome for the expected package and scope",
    );
  const traceResult = sourceSearches.some(
    ({ completeness }) => completeness === "complete",
  )
    ? "some_complete"
    : sourceSearches.some(({ completeness }) => completeness === "partial")
      ? "partial"
      : sourceSearches.length
        ? "unresolved"
        : "missing";
  const missingLookup = expectations.filter(
    (expectation) =>
      !searches.some((record) => matchesExpectedSearch(record, expectation)),
  );
  return {
    sourceAuditCorrect: errors.length === 0,
    sourceTraceResult: traceResult,
    lookupCompleteness: expectations.length
      ? missingLookup.length
        ? "mismatch"
        : "verified"
      : "not_measurable",
    lookupProviderConfigured,
    missingLookup,
    errors,
  };
}

export interface PlaceScopeExpectation {
  id: string;
  location?: string;
  kind?: string;
  environment?: string;
  revision?: string;
  artifact?: string;
  observationWindow?: string;
  deploymentDetail?: string;
  deploymentBasis?:
    "observed" | "configured" | "unknown" | "assumed_not_deployed";
  verdict: CommandVerdict;
  /** State every required source identity link. Alternatives in one group are equivalent. */
  identityEvidence?: readonly EvidenceGroup[];
  evidenceGroups?: readonly EvidenceGroup[];
  versions?: readonly (string | null)[];
  /** The staged evidence contains an explicit observation of this place running. */
  observedBySource?: boolean;
  needsDecidingGap?: boolean;
  verifyExclusionProof?: boolean;
  conditions?: readonly {
    label: string;
    status: "met" | "unknown" | "ruled_out";
  }[];
  callSite?: { path: string; line: number };
  decidingReceiptId?: string;
  unresolvedQuestion?: string;
  searches?: readonly SearchExpectation[];
  unsupportedExpectation?: string;
}

function records(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.filter(isRecord) : [];
}

function hasBoundCall(
  use: Record<string, unknown>,
  cite: { path: unknown; line: unknown },
) {
  const { path, line } = cite;
  return (
    typeof path === "string" &&
    typeof line === "number" &&
    records(use.evidence).some(
      ({ path: evidencePath, startLine, endLine }) =>
        evidencePath === path &&
        typeof startLine === "number" &&
        typeof endLine === "number" &&
        startLine <= line &&
        endLine >= line,
    )
  );
}

function hasBoundConditionCitation(
  use: Record<string, unknown>,
  condition: Record<string, unknown>,
) {
  const cites = records(condition.citations);
  return (
    cites.length > 0 &&
    cites.every(({ path, line }) => hasBoundCall(use, { path, line }))
  );
}

export function hasStructuredScope(
  use: Record<string, unknown>,
  expected: PlaceScopeExpectation,
) {
  const place = isRecord(use.place) ? use.place : {};
  const fields = [
    "kind",
    "environment",
    "revision",
    "artifact",
    "observationWindow",
    "deploymentDetail",
    "deploymentBasis",
  ] as const;
  return fields.every(
    (field) =>
      expected[field] === undefined || expected[field] === place[field],
  );
}

export function matchesExpectedSearch(
  record: Record<string, unknown>,
  search: SearchExpectation,
  receiptId?: string,
) {
  const refs = record.evidenceReferences;
  const scope = record.scope;
  const started = record.startedAt;
  const finished = record.finishedAt;
  return (
    search.source === record.source &&
    search.tool === record.tool &&
    search.result === record.result &&
    search.completeness === record.completeness &&
    Array.isArray(scope) &&
    search.scope.every((term) => scope.includes(term)) &&
    typeof finished === "string" &&
    Number.isFinite(Date.parse(finished)) &&
    (started === null ||
      (typeof started === "string" &&
        Date.parse(started) <= Date.parse(finished))) &&
    Array.isArray(refs) &&
    (search.result === "not_run" || refs.length > 0) &&
    (receiptId === undefined || refs.includes(receiptId)) &&
    (search.evidenceReference === undefined ||
      refs.includes(search.evidenceReference))
  );
}

export function gradePlaceV2(
  use: Record<string, unknown> | undefined,
  answer: Record<string, unknown>,
  expected: PlaceScopeExpectation,
  sourceIdentityCorrect = false,
  decidingSourceCorrect = false,
) {
  const place = isRecord(use?.place) ? use.place : {};
  const proof = isRecord(use?.proof) ? use.proof : {};
  const sink = isRecord(proof.sink) ? proof.sink : {};
  const call = isRecord(sink.callSite) ? sink.callSite : {};
  const facts = new Set(
    records(use?.evidence)
      .concat(records(use?.observations))
      .flatMap(({ supports }) => (Array.isArray(supports) ? supports : [])),
  );
  const searches = records(answer.searches);
  const scopeCorrect =
    use !== undefined &&
    (expected.location === undefined || use.location === expected.location) &&
    hasStructuredScope(use, expected);
  const decisionRefs = records(use?.decidingEvidence);
  const receiptCorrect =
    expected.decidingReceiptId === undefined ||
    (decisionRefs.some(
      ({ kind, receiptId }) =>
        kind === "receipt" && receiptId === expected.decidingReceiptId,
    ) &&
      (expected.searches ?? []).some(
        (search) =>
          search.result === "matches" &&
          searches.some((record) =>
            matchesExpectedSearch(record, search, expected.decidingReceiptId),
          ),
      ));
  const discoveryCorrect =
    scopeCorrect &&
    (sourceIdentityCorrect ||
      (expected.decidingReceiptId !== undefined && receiptCorrect));
  const callCorrect =
    use !== undefined &&
    (expected.callSite === undefined ||
      (call.path === expected.callSite.path &&
        call.line === expected.callSite.line &&
        hasBoundCall(use, { path: call.path, line: call.line })));
  const conditionsCorrect =
    use !== undefined &&
    (expected.conditions ?? []).every(({ label, status }) =>
      records(proof.conditions).some(
        (condition) =>
          condition.label === label &&
          condition.status === status &&
          (status === "unknown" ||
            ((sourceIdentityCorrect || decidingSourceCorrect) &&
              hasBoundConditionCitation(use, condition))),
      ),
    );
  const question = expected.unresolvedQuestion;
  const gapCorrect =
    use !== undefined &&
    (!expected.needsDecidingGap ||
      (Array.isArray(place.unresolvedQuestions) &&
        place.unresolvedQuestions.some(
          (entry) => typeof entry === "string" && entry.trim().length > 0,
        ))) &&
    (question === undefined ||
      (Array.isArray(place.unresolvedQuestions) &&
        place.unresolvedQuestions.includes(question)));
  const observed = place.deploymentBasis === "observed";
  const assumed = place.deploymentBasis === "assumed_not_deployed";
  const explicitAssumption =
    typeof place.deploymentDetail === "string" &&
    Array.isArray(answer.assumptions) &&
    answer.assumptions.some(
      (assumption) =>
        typeof assumption === "string" &&
        assumption.includes(place.deploymentDetail as string),
    );
  const provedExclusion =
    decidingSourceCorrect &&
    use !== undefined &&
    records(proof.conditions).some(
      (condition) =>
        condition.status === "ruled_out" &&
        hasBoundConditionCitation(use, condition),
    );
  const deploymentCorrect =
    use !== undefined &&
    (!observed ||
      (use.deployment === "confirmed" &&
        facts.has("running") &&
        ((expected.observedBySource && sourceIdentityCorrect) ||
          (expected.decidingReceiptId !== undefined && receiptCorrect)))) &&
    (!assumed ||
      (explicitAssumption &&
        use.deployment !== "confirmed" &&
        (use.verdict !== "ruled_out" || decidingSourceCorrect) &&
        use.verdict !== "exploitable"));
  const verdictLabelCorrect = use?.verdict === expected.verdict;
  const verdictCorrect =
    verdictLabelCorrect &&
    discoveryCorrect &&
    callCorrect &&
    conditionsCorrect &&
    receiptCorrect &&
    gapCorrect &&
    deploymentCorrect &&
    (expected.verdict !== "ruled_out" || decidingSourceCorrect) &&
    (!expected.verifyExclusionProof ||
      expected.verdict !== "ruled_out" ||
      provedExclusion) &&
    (use?.verdict !== "exploitable" ||
      (observed &&
        facts.has("affected_copy") &&
        facts.has("affected_use") &&
        facts.has("access")));
  const missingSearches = (expected.searches ?? []).filter(
    (search) =>
      !searches.some((record) => matchesExpectedSearch(record, search)),
  );
  const completenessCorrect = expected.searches?.length
    ? missingSearches.length === 0
    : null;
  const errors = [
    ...(!discoveryCorrect ? [`Missing assessed place ${expected.id}`] : []),
    ...(!scopeCorrect ? [`Incorrect scope for ${expected.id}`] : []),
    ...(!callCorrect ? [`Incorrect source operation for ${expected.id}`] : []),
    ...(!conditionsCorrect
      ? [`Incorrect advisory conditions for ${expected.id}`]
      : []),
    ...(!receiptCorrect ? [`Missing deciding receipt for ${expected.id}`] : []),
    ...(!gapCorrect ? [`Missing deciding question for ${expected.id}`] : []),
    ...(!verdictCorrect
      ? [
          `The evidence does not justify the reported verdict for ${expected.id}`,
        ]
      : []),
    ...missingSearches.map(
      (search) =>
        `Missing ${search.completeness} search ${search.source}/${search.tool} for ${expected.id}`,
    ),
  ];
  return {
    rubric: placeRubricVersion,
    placeId: expected.id,
    pass: errors.length === 0,
    discoveryCorrect,
    scopeCorrect,
    callCorrect,
    conditionsCorrect,
    receiptCorrect,
    gapCorrect,
    verdictCorrect,
    verdictLabelCorrect,
    completenessCorrect,
    unsupportedExpectation: expected.unsupportedExpectation ?? null,
    errors,
  };
}
