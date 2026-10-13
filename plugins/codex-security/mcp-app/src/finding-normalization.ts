import { isRecord as isObject } from "./record.js";

type JsonObject = Record<string, unknown>;

export function normalizePersistedFindingDetails(
  finding: JsonObject,
  profile: "draft" | "canonical",
): void {
  const canonicalEvidence =
    profile === "draft" && Array.isArray(finding["codeEvidence"])
      ? finding["codeEvidence"]
      : [];
  const evidenceIds = new Set(
    canonicalEvidence.flatMap((evidence) => {
      if (!isObject(evidence)) return [];
      const id = evidence["id"];
      return isNonEmptyString(id) ? [id] : [];
    }),
  );
  if (Array.isArray(finding["code_evidence"])) {
    const compatibleEvidence: JsonObject[] = [];
    for (const evidence of finding["code_evidence"]) {
      if (!isObject(evidence)) continue;
      const id = evidence["id"];
      const code = evidence["code"];
      if (
        !isNonEmptyString(id) ||
        !isNonEmptyString(code) ||
        (profile === "draft" && evidenceIds.has(id))
      ) {
        continue;
      }
      if (profile === "draft") evidenceIds.add(id);
      compatibleEvidence.push(evidence);
    }
    finding["code_evidence"] = compatibleEvidence;
  } else if (profile === "draft" || finding["code_evidence"] !== null) {
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

  const rootCause = finding["rootCause"];
  if (profile === "draft" && isObject(rootCause)) {
    if (!isNonEmptyString(rootCause["summary"])) {
      delete finding["rootCause"];
    } else {
      removeUnsupportedPersistedStrings(rootCause, ["code", "language"]);
    }
  }
  const legacyRootCause = finding["root_cause"];
  if (isObject(legacyRootCause)) {
    removeUnsupportedPersistedStrings(legacyRootCause, [
      "summary",
      "code",
      "language",
    ]);
  } else if (
    profile === "draft"
      ? !isNonEmptyString(legacyRootCause)
      : legacyRootCause !== null && typeof legacyRootCause !== "string"
  ) {
    delete finding["root_cause"];
  }

  const validation = finding["validation"];
  if (isObject(validation)) {
    removeUnsupportedPersistedStrings(
      validation,
      ["method", "status", "summary", "disposition", "result"].filter(
        (field) =>
          profile === "draft" ||
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
      if (
        profile === "canonical" &&
        field === "evidence" &&
        isNonEmptyString(value)
      )
        continue;
      const normalized = isNonEmptyString(value)
        ? [value]
        : Array.isArray(value)
          ? value.filter(isNonEmptyString)
          : undefined;
      if (
        normalized !== undefined &&
        (profile === "canonical" || normalized.length > 0)
      )
        section[field] = normalized;
      else delete section[field];
    }
    if (profile === "canonical") return;
    for (const field of ["evidenceRefs", "evidence_refs"]) {
      const refs = section[field];
      if (!Array.isArray(refs)) continue;
      section[field] = refs.filter((ref) => evidenceIds.has(ref));
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
    return (
      typeof value === "string" &&
      (profile === "canonical" ? value.length > 0 : value.trim().length > 0)
    );
  }
}
