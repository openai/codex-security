import { isRecord as isObject } from "./record.js";

type JsonObject = Record<string, unknown>;

/** Compatibility for historical report reads; never use this to admit new writes. */
export function normalizePersistedFindingDetails(finding: JsonObject): void {
  if (Array.isArray(finding["code_evidence"])) {
    finding["code_evidence"] = finding["code_evidence"].filter(
      (evidence) =>
        isObject(evidence) &&
        isNonEmptyString(evidence["id"]) &&
        isNonEmptyString(evidence["code"]),
    );
  } else if (finding["code_evidence"] !== null) {
    delete finding["code_evidence"];
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
    if (!isObject(section)) continue;
    normalizePersistedStringLists(section, listFields);
  }

  const legacyRootCause = finding["root_cause"];
  if (isObject(legacyRootCause)) {
    removeUnsupportedPersistedStrings(legacyRootCause, [
      "summary",
      "code",
      "language",
    ]);
  } else if (legacyRootCause !== null && typeof legacyRootCause !== "string") {
    delete finding["root_cause"];
  }

  const validation = finding["validation"];
  if (isObject(validation)) {
    removeUnsupportedPersistedStrings(
      validation,
      ["method", "status", "summary", "disposition", "result"].filter(
        (field) =>
          !["status", "disposition", "result"].includes(field) ||
          validation[field] !== null,
      ),
    );
  }

  const attackPath = finding["attackPath"];
  if (!isObject(attackPath)) return;
  removeUnsupportedPersistedStrings(attackPath, ["summary"]);
  for (const field of ["dataFlow", "data_flow", "dataflow", "reachability"]) {
    const detail = attackPath[field];
    if (!isObject(detail)) {
      if (!isNonEmptyString(detail)) delete attackPath[field];
      continue;
    }
    removeUnsupportedPersistedStrings(detail, [
      "summary",
      "source",
      "sink",
      "outcome",
      ...(field === "reachability" ? ["attacker", "entrypoint"] : []),
    ]);
    normalizePersistedStringLists(detail, [
      "evidenceRefs",
      "evidence_refs",
      "transformations",
      ...(field === "reachability" ? ["preconditions"] : []),
    ]);
  }
  for (const field of ["impact", "likelihood"]) {
    const detail = attackPath[field];
    if (isObject(detail)) {
      removeUnsupportedPersistedStrings(detail, ["level", "rationale", "why"]);
    } else if (
      detail !== undefined &&
      detail !== null &&
      !isNonEmptyString(detail)
    ) {
      delete attackPath[field];
    }
  }

  function normalizePersistedStringLists(
    section: JsonObject,
    fields: string[],
  ): void {
    for (const field of fields) {
      const value = section[field];
      if (isNonEmptyString(value)) {
        if (field !== "evidence") section[field] = [value];
      } else if (Array.isArray(value))
        section[field] = value.filter(isNonEmptyString);
      else delete section[field];
    }
  }

  function removeUnsupportedPersistedStrings(
    section: JsonObject,
    fields: string[],
  ): void {
    for (const field of fields) {
      if (!isNonEmptyString(section[field])) delete section[field];
    }
  }

  function isNonEmptyString(value: unknown): value is string {
    return typeof value === "string" && value.length > 0;
  }
}
