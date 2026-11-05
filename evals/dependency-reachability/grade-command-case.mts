import { isRecord } from "../../sdk/typescript/src/record.ts";
import type { CommandVerdict } from "./cases.mts";
import { gradeEvidence, type EvidenceGroup } from "./grade.mts";

interface ExpectedUse {
  cve: string;
  component: string;
  version: string;
  commandVersion?: string | null;
  versionAliases?: readonly string[];
  verdict: CommandVerdict;
  evidenceGroups: readonly EvidenceGroup[];
}

function namesComponent(label: unknown, component: string) {
  if (typeof label !== "string") return false;
  const names: string[] =
    label.toLowerCase().match(/[a-z0-9]+(?:-[a-z0-9]+)*/gu) ?? [];
  return (
    names.includes(component) ||
    (component === "glibc" &&
      (names.includes("libc6") || /\bGNU C Library\b/iu.test(label)))
  );
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
  const status =
    ["exploitable", "potentially_exploitable", "unknown", "ruled_out"].find(
      (verdict) => uses.some((use) => use.verdict === verdict),
    ) ?? "unknown";
  // Known uses can all be ruled out while checkout coverage remains incomplete.
  const consistent =
    result.status === status ||
    (status === "ruled_out" && result.status === "unknown");
  const overallCorrect =
    consistent &&
    (status !== "exploitable" || expected.verdict === "exploitable");
  if (!consistent)
    errors.push(`Expected aggregate ${status} for the reported uses`);
  // No sibling use in these snapshots has separately demonstrated runtime access.
  if (status === "exploitable" && expected.verdict !== "exploitable")
    errors.push("The snapshot does not establish a confirmed exploitable use");

  // A library checkout can expose another use of the same dependency with a
  // different verdict. Only the use citing this case's route and controls counts.
  const versions =
    expected.commandVersion !== undefined
      ? [expected.commandVersion]
      : [expected.version, ...(expected.versionAliases ?? [])];
  const matches = uses.filter((use) =>
    namesComponent(use.component, expected.component),
  );
  const grades = [];
  for (const use of matches) {
    const issues = await gradeEvidence(
      use.evidence,
      expected.evidenceGroups,
      repoRoot,
      "ranges",
    );
    const evidenceCorrect = !issues.length;
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
      versionCorrect,
      verdictCorrect,
      issues,
    });
  }
  // Keep the diagnostics for a single use even when several partially match.
  const best = grades.sort((a, b) => a.issues.length - b.issues.length)[0];
  if (best) errors.push(...best.issues);
  else errors.push(`Missing use of ${expected.component}`);
  return {
    pass: errors.length === 0,
    overallCorrect,
    componentCorrect: Boolean(best),
    verdictCorrect: best?.verdictCorrect ?? false,
    versionCorrect: best?.versionCorrect ?? false,
    evidenceCorrect: best?.evidenceCorrect ?? false,
    location: best?.location ?? null,
    errors,
  };
}
