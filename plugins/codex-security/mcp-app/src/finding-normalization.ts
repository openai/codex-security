import { isRecord as isObject } from "./record.js";
import { hasRequiredFindingText } from "./contract-values.js";

type JsonObject = Record<string, unknown>;

/** Compatibility for historical report reads; never use this to admit new writes. */
export function normalizePersistedFindingDetails(
  finding: JsonObject,
  profile: "sdk" | "tracking" = "sdk",
): void {
  const evidenceIds = new Set<string>();
  if (profile === "tracking" && Array.isArray(finding["codeEvidence"])) {
    for (const evidence of finding["codeEvidence"]) {
      if (isObject(evidence) && isNonEmptyString(evidence["id"]))
        evidenceIds.add(evidence["id"]);
    }
  }
  if (Array.isArray(finding["code_evidence"])) {
    finding["code_evidence"] = finding["code_evidence"].filter((evidence) => {
      if (
        !isObject(evidence) ||
        !isNonEmptyString(evidence["id"]) ||
        !isNonEmptyString(evidence["code"])
      )
        return false;
      if (profile === "sdk") return true;
      if (
        !hasRequiredFindingText(evidence["id"]) ||
        !hasRequiredFindingText(evidence["code"]) ||
        evidenceIds.has(evidence["id"])
      )
        return false;
      evidenceIds.add(evidence["id"]);
      return true;
    });
  } else if (profile === "tracking" || finding["code_evidence"] !== null) {
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
  } else if (
    legacyRootCause !== null &&
    (typeof legacyRootCause !== "string" ||
      (profile === "tracking" && legacyRootCause === ""))
  ) {
    delete finding["root_cause"];
  }

  const validation = finding["validation"];
  if (isObject(validation)) {
    removeUnsupportedPersistedStrings(
      validation,
      ["method", "status", "summary", "disposition", "result"].filter(
        (field) =>
          profile === "tracking" ||
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
      const accepted = (value: unknown): value is string =>
        isNonEmptyString(value) &&
        (profile === "sdk" || hasRequiredFindingText(value));
      if (accepted(value)) {
        if (profile === "tracking" || field !== "evidence")
          section[field] = [value];
      } else if (Array.isArray(value)) {
        const items = value.filter(accepted);
        if (profile === "tracking" && items.length === 0) delete section[field];
        else section[field] = items;
      } else delete section[field];
      if (
        profile === "tracking" &&
        (field === "evidenceRefs" || field === "evidence_refs") &&
        Array.isArray(section[field])
      ) {
        section[field] = section[field].filter(
          (ref) => typeof ref === "string" && evidenceIds.has(ref),
        );
      }
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
