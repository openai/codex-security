import { isRecord as isObject } from "./record.js";

type JsonObject = Record<string, unknown>;

/** Earlier discovery admission normalized a clone while retaining the raw file. */
export function normalizeAcceptedDiscoveryFinding(finding: JsonObject): void {
  const canonicalEvidence = Array.isArray(finding.codeEvidence)
    ? finding.codeEvidence
    : [];
  const evidenceIds = new Set(
    canonicalEvidence.flatMap((evidence) => {
      if (!isObject(evidence)) return [];
      return isNonEmptyString(evidence.id) ? [evidence.id] : [];
    }),
  );
  if (Array.isArray(finding.code_evidence)) {
    const compatibleEvidence: JsonObject[] = [];
    for (const evidence of finding.code_evidence) {
      if (!isObject(evidence)) continue;
      const { id, code } = evidence;
      if (
        !isNonEmptyString(id) ||
        !isNonEmptyString(code) ||
        evidenceIds.has(id)
      )
        continue;
      evidenceIds.add(id);
      compatibleEvidence.push(evidence);
    }
    finding.code_evidence = compatibleEvidence;
  } else {
    delete finding.code_evidence;
  }

  for (const [sectionName, listFields] of [
    ["rootCause", ["evidenceRefs", "evidence_refs"]],
    ["root_cause", ["evidenceRefs", "evidence_refs"]],
    [
      "validation",
      [
        "assertions",
        "counterEvidence",
        "evidence",
        "evidenceRefs",
        "evidence_refs",
        "limitations",
      ],
    ],
    [
      "attackPath",
      [
        "assumptions",
        "blindspots",
        "controls",
        "evidenceRefs",
        "evidence_refs",
        "limitations",
        "preconditions",
        "steps",
      ],
    ],
  ] satisfies Array<[string, string[]]>) {
    const section = finding[sectionName];
    if (isObject(section)) normalizeStringLists(section, listFields);
  }

  if (isObject(finding.rootCause)) {
    if (!isNonEmptyString(finding.rootCause.summary)) delete finding.rootCause;
    else removeUnsupportedStrings(finding.rootCause, ["code", "language"]);
  }
  if (isObject(finding.root_cause)) {
    removeUnsupportedStrings(finding.root_cause, [
      "summary",
      "code",
      "language",
    ]);
  } else if (!isNonEmptyString(finding.root_cause)) {
    delete finding.root_cause;
  }
  if (isObject(finding.validation)) {
    removeUnsupportedStrings(finding.validation, [
      "method",
      "status",
      "summary",
      "disposition",
      "result",
    ]);
  }
  if (!isObject(finding.attackPath)) return;
  const attackPath = finding.attackPath;
  removeUnsupportedStrings(attackPath, ["summary"]);
  for (const field of ["dataFlow", "data_flow", "dataflow", "reachability"]) {
    const detail = attackPath[field];
    if (!isObject(detail)) {
      if (!isNonEmptyString(detail)) delete attackPath[field];
      continue;
    }
    removeUnsupportedStrings(detail, [
      "summary",
      "source",
      "sink",
      "outcome",
      ...(field === "reachability" ? ["attacker", "entrypoint"] : []),
    ]);
    normalizeStringLists(detail, [
      "evidenceRefs",
      "evidence_refs",
      "transformations",
      ...(field === "reachability" ? ["preconditions"] : []),
    ]);
  }
  for (const field of ["impact", "likelihood"]) {
    const detail = attackPath[field];
    if (isObject(detail)) {
      removeUnsupportedStrings(detail, ["level", "rationale", "why"]);
    } else if (
      detail !== undefined &&
      detail !== null &&
      !isNonEmptyString(detail)
    ) {
      delete attackPath[field];
    }
  }

  function normalizeStringLists(section: JsonObject, fields: string[]): void {
    for (const field of fields) {
      const value = section[field];
      const normalized = isNonEmptyString(value)
        ? [value]
        : Array.isArray(value)
          ? value.filter(isNonEmptyString)
          : undefined;
      if (normalized !== undefined && normalized.length > 0)
        section[field] = normalized;
      else delete section[field];
    }
    for (const field of ["evidenceRefs", "evidence_refs"]) {
      const refs = section[field];
      if (Array.isArray(refs))
        section[field] = refs.filter((ref) => evidenceIds.has(ref));
    }
  }
}

function removeUnsupportedStrings(section: JsonObject, fields: string[]): void {
  for (const field of fields) {
    if (!isNonEmptyString(section[field])) delete section[field];
  }
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}
