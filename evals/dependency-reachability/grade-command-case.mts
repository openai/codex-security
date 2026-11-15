import { isRecord } from "../../sdk/typescript/src/record.ts";
import type { CommandVerdict } from "./cases.mts";
import { checkoutPlacesV2 } from "./checkout-places-v2.mts";
import { gradeEvidence, type EvidenceGroup } from "./grade.mts";
import {
  gradePlaceV2,
  gradeRunSearchAudit,
  type PlaceScopeExpectation,
  type SearchExpectation,
} from "./place-rubric-v2.mts";

interface ExpectedUse {
  id?: string;
  cve: string;
  component: string;
  version: string;
  commandVersion?: string | null | readonly (string | null)[];
  commandStatus?: CommandVerdict;
  commandCallSite?: { path: string; line: number };
  versionAliases?: readonly string[];
  verdict: CommandVerdict;
  evidenceGroups: readonly EvidenceGroup[];
  expectedPlacesV2?: readonly PlaceScopeExpectation[];
  expectedSearchesV2?: readonly SearchExpectation[];
  lookupProviderConfigured?: boolean;
}

function namesComponent(label: unknown, component: string) {
  if (typeof label !== "string") return false;
  if (component === "glibc") {
    // Match the assessed library, not another library's comparison with it.
    return /^(?:glibc|libc6|GNU\s+(?:libc|C\s+Library))(?=$|[\s.(,:/])/iu.test(
      label.trim(),
    );
  }
  const names: string[] =
    label.toLowerCase().match(/[a-z0-9]+(?:-[a-z0-9]+)*/gu) ?? [];
  return names.includes(component);
}

export async function gradeCommandCase(
  answer: unknown,
  expected: ExpectedUse,
  repoRoot: string,
) {
  const result = isRecord(answer) ? answer : {};
  const errors: string[] = [];
  if (result.cve !== expected.cve) errors.push(`Expected ${expected.cve}`);

  const uses: Record<string, unknown>[] = Array.isArray(result.uses)
    ? result.uses.filter(isRecord)
    : [];
  const v2 = result.schemaVersion === 2;
  const status =
    ["exploitable", "potentially_exploitable", "unknown", "ruled_out"].find(
      (verdict) => uses.some((use) => use.verdict === verdict),
    ) ?? "unknown";
  // Known uses can all be ruled out while checkout coverage remains incomplete.
  const consistent =
    result.status === status ||
    (status === "ruled_out" && result.status === "unknown");
  const statusCorrect =
    expected.commandStatus === undefined ||
    result.status === expected.commandStatus;
  const overallCorrect =
    consistent &&
    statusCorrect &&
    (status !== "exploitable" || expected.verdict === "exploitable");
  if (!v2 && !consistent)
    errors.push(`Expected aggregate ${status} for the reported uses`);
  if (!v2 && !statusCorrect)
    errors.push(
      `Expected report status ${expected.commandStatus}, received ${String(result.status)}`,
    );
  // No sibling use in these snapshots has separately demonstrated runtime access.
  if (!v2 && status === "exploitable" && expected.verdict !== "exploitable")
    errors.push("The snapshot does not establish a confirmed exploitable use");

  // A library checkout can expose another use of the same dependency with a
  // different verdict. Only the use citing this case's route and controls counts.
  const override = expected.commandVersion;
  const versions =
    override === undefined
      ? [expected.version, ...(expected.versionAliases ?? [])]
      : typeof override === "string" || override === null
        ? [override]
        : override;
  const matches = uses.filter((use) =>
    namesComponent(use.component, expected.component),
  );
  if (v2) {
    return gradeCommandPlaces(
      result,
      expected,
      repoRoot,
      matches,
      versions,
      errors,
    );
  }
  const grades = [];
  for (const use of matches) {
    const issues = await gradeEvidence(
      use.evidence,
      expected.evidenceGroups,
      repoRoot,
      "ranges",
    );
    const evidenceCorrect = !issues.length;
    const proof = isRecord(use.proof) ? use.proof : {};
    const sink = isRecord(proof.sink) ? proof.sink : {};
    const callSite = isRecord(sink.callSite) ? sink.callSite : {};
    const required = expected.commandCallSite;
    const operationCorrect =
      required === undefined ||
      (callSite.path === required.path &&
        callSite.line === required.line &&
        Array.isArray(use.evidence) &&
        use.evidence.some(
          (item) =>
            isRecord(item) &&
            item.path === required.path &&
            typeof item.startLine === "number" &&
            typeof item.endLine === "number" &&
            item.startLine <= required.line &&
            item.endLine >= required.line,
        ));
    if (required && !operationCorrect)
      issues.push(
        `Missing assessment of required operation at ${required.path}:${required.line}`,
      );
    const versionCorrect = versions.some((version) => use.version === version);
    const verdictCorrect = use.verdict === expected.verdict;
    if (!versionCorrect)
      issues.push(
        `Expected dependency version ${versions
          .map((version) => (version === null ? "null" : version))
          .join(" or ")}`,
      );
    if (!verdictCorrect) issues.push(`Expected verdict ${expected.verdict}`);
    if (use.verdict === "exploitable" && use.deployment !== "confirmed")
      issues.push("An exploitable verdict requires confirmed deployment");
    if (typeof use.reason !== "string" || !use.reason.trim())
      issues.push("Missing reason");
    if (typeof use.location !== "string" || !use.location.trim())
      issues.push("Missing location");
    grades.push({
      location: use.location,
      evidenceCorrect,
      operationCorrect,
      versionCorrect,
      verdictCorrect,
      issues,
    });
  }
  // Keep the diagnostics for a single use even when several partially match.
  const requiredOperations = grades.filter((grade) => grade.operationCorrect);
  const best = (requiredOperations.length ? requiredOperations : grades).sort(
    (a, b) => a.issues.length - b.issues.length,
  )[0];
  if (best) errors.push(...best.issues);
  else errors.push(`Missing use of ${expected.component}`);
  return {
    pass: errors.length === 0,
    overallCorrect,
    statusCorrect,
    rubric: "legacy-aggregate-v1" as const,
    componentCorrect: Boolean(best),
    operationCorrect: best?.operationCorrect ?? false,
    verdictCorrect: best?.verdictCorrect ?? false,
    versionCorrect: best?.versionCorrect ?? false,
    evidenceCorrect: best?.evidenceCorrect ?? false,
    location: best?.location ?? null,
    errors,
  };
}

async function gradeCommandPlaces(
  result: Record<string, unknown>,
  expected: ExpectedUse,
  repoRoot: string,
  uses: readonly Record<string, unknown>[],
  versions: readonly (string | null)[],
  errors: string[],
) {
  if (Object.hasOwn(result, "status"))
    errors.push("Version 2 has an aggregate status");
  const frozen =
    expected.id === undefined
      ? undefined
      : (checkoutPlacesV2 as Readonly<Record<string, PlaceScopeExpectation>>)[
          expected.id
        ];
  const places = expected.expectedPlacesV2 ?? [
    frozen ?? {
      id: "target",
      verdict: expected.verdict,
      callSite: expected.commandCallSite,
    },
  ];
  const audit = gradeRunSearchAudit(
    result,
    (label) => namesComponent(label, expected.component),
    [
      ...(expected.expectedSearchesV2 ?? []),
      ...places.flatMap((place) => place.searches ?? []),
    ],
    expected.lookupProviderConfigured,
  );
  const candidates = await Promise.all(
    places.map(async (place) => {
      const identity = place.identityEvidence ?? expected.evidenceGroups;
      const deciding = place.evidenceGroups ?? expected.evidenceGroups;
      const allowedVersions = place.versions ?? versions;
      return Promise.all(
        uses.map(async (use, index) => {
          const identityErrors = identity.length
            ? await gradeEvidence(use.evidence, identity, repoRoot, "ranges")
            : [];
          const sourceErrors = await gradeEvidence(
            use.evidence,
            deciding,
            repoRoot,
            "ranges",
          );
          const evidenceCorrect = sourceErrors.length === 0;
          const versionCorrect = allowedVersions.some(
            (version) => use.version === version,
          );
          const grade = gradePlaceV2(
            use,
            result,
            place,
            identity.length > 0 && !identityErrors.length,
            deciding.length > 0 && evidenceCorrect,
          );
          const issues = [...grade.errors, ...identityErrors, ...sourceErrors];
          if (!versionCorrect)
            issues.push(
              `Expected dependency version ${allowedVersions.map((version) => version ?? "null").join(" or ")}`,
            );
          if (typeof use.reason !== "string" || !use.reason.trim())
            issues.push("Missing reason");
          if (typeof use.location !== "string" || !use.location.trim())
            issues.push("Missing location");
          return {
            ...grade,
            index,
            location: use.location,
            versionCorrect,
            evidenceCorrect,
            verdictCorrect:
              grade.verdictCorrect && versionCorrect && evidenceCorrect,
            pass: issues.length === 0,
            errors: [...new Set(issues)],
          };
        }),
      );
    }),
  );
  const ordered = candidates.map((options) =>
    options
      .filter((option) => option.discoveryCorrect)
      .sort(
        (a, b) =>
          Number(b.pass) - Number(a.pass) || a.errors.length - b.errors.length,
      ),
  );
  // Give each assessment to at most one place. Reassign shared candidates only
  // if doing so does not replace a passing assessment with a failing one.
  const owners = new Map<number, number>();
  const assign = (
    placeIndex: number,
    seen: Set<number>,
    passingOnly: boolean,
  ): boolean => {
    for (const option of ordered[placeIndex]!) {
      if ((passingOnly && !option.pass) || seen.has(option.index)) continue;
      seen.add(option.index);
      const owner = owners.get(option.index);
      if (
        owner === undefined ||
        assign(
          owner,
          seen,
          passingOnly ||
            ordered[owner]!.some(
              (entry) => entry.index === option.index && entry.pass,
            ),
        )
      ) {
        owners.set(option.index, placeIndex);
        return true;
      }
    }
    return false;
  };
  for (const index of places.keys()) assign(index, new Set(), true);
  for (const index of places.keys())
    if (![...owners.values()].includes(index)) assign(index, new Set(), false);
  const placeGrades = places.map((place, index) => {
    const match = ordered[index]!.find(
      (option) => owners.get(option.index) === index,
    );
    if (match) return match;
    const nearest = candidates[index]!.filter(
      (option) => !option.discoveryCorrect,
    ).sort((a, b) => a.errors.length - b.errors.length)[0];
    const unassigned = gradePlaceV2(undefined, result, place);
    if (ordered[index]!.length) {
      unassigned.errors.push(
        `No independent assessment remains for ${place.id}; a matching assessment belongs to another place.`,
      );
    }
    return (
      nearest ?? {
        ...unassigned,
        location: null,
        versionCorrect: false,
        evidenceCorrect: false,
      }
    );
  });
  errors.push(
    ...audit.errors,
    ...audit.missingLookup.map(
      ({ source, tool }) =>
        `Missing expected lookup audit for ${source}/${tool}`,
    ),
    ...placeGrades.flatMap((grade) => grade.errors),
  );
  // There is no positive runtime verdict in this source-only cohort unless an
  // expected place has an independently identified original runtime record.
  if (
    uses.some(
      (use) =>
        use.verdict === "exploitable" &&
        !placeGrades.some(
          (grade) =>
            "index" in grade &&
            uses[grade.index] === use &&
            grade.verdictCorrect,
        ),
    )
  )
    errors.push(
      "The fixture does not establish a claimed confirmed exploitable place",
    );
  return {
    pass: errors.length === 0,
    rubric: "places-v2" as const,
    componentCorrect: uses.length > 0,
    discoveryCorrect: placeGrades.every((grade) => grade.discoveryCorrect),
    operationCorrect: placeGrades.every((grade) => grade.callCorrect),
    verdictCorrect: placeGrades.every((grade) => grade.verdictCorrect),
    versionCorrect: placeGrades.every((grade) => grade.versionCorrect),
    evidenceCorrect: placeGrades.every((grade) => grade.evidenceCorrect),
    location: placeGrades[0]?.location ?? null,
    audit,
    placeGrades,
    errors,
  };
}
