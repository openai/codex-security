import { isRecord as isObject } from "./record.js";

type JsonObject = Record<string, unknown>;

/** Compatibility for historical report reads; never use this to admit new writes. */
export function normalizePersistedFindingDetails(finding: JsonObject): void {
  if (Array.isArray(finding["code_evidence"])) {
    const compatibleEvidence: JsonObject[] = [];
    for (const evidence of finding["code_evidence"]) {
      if (!isObject(evidence)) continue;
      const id = evidence["id"];
      const code = evidence["code"];
      if (!isNonEmptyString(id) || !isNonEmptyString(code)) {
        continue;
      }
      compatibleEvidence.push(evidence);
    }
    finding["code_evidence"] = compatibleEvidence;
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
      if (field === "evidence" && isNonEmptyString(value)) continue;
      const normalized = isNonEmptyString(value)
        ? [value]
        : Array.isArray(value)
          ? value.filter(isNonEmptyString)
          : undefined;
      if (normalized !== undefined) section[field] = normalized;
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
