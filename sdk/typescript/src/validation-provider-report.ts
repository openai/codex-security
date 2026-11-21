import type {
  ValidationItemRecord,
  ValidationProviderAssessment,
} from "./validation-provider.js";

/** Shorten narrative at a boundary; resource identifiers are shortened deliberately. */
export function validationText(value: unknown, limit = 320): string {
  let text =
    typeof value === "string" ? value.replace(/\s+/gu, " ").trim() : "";
  text = text.replace(
    /arn:[^\s)]+/gu,
    (arn) => arn.split("/").at(-1) ?? "AWS resource",
  );
  if (text.length <= limit) return text;
  const tokens = text.split(" ");
  let shortened = "";
  for (const token of tokens) {
    if ((shortened + " " + token).trim().length > limit) break;
    shortened = (shortened + " " + token).trim();
  }
  const sentence = shortened.match(/^(.+[.!?])\s/u)?.[1];
  return `${sentence ?? (shortened || "Details omitted")}…`;
}

function severity(value?: string): string {
  return value
    ? value.charAt(0).toUpperCase() + value.slice(1).toLowerCase()
    : "severity not returned";
}
function verdict(value?: string): string {
  return value?.toLowerCase().replaceAll("_", " ") ?? "verdict not returned";
}
export function validationHeadline(
  records: readonly ValidationItemRecord[],
): string {
  const first =
    records.find((record) => record.state === "validated") ?? records[0]!;
  const ratings = [
    ...new Set(records.map((record) => severity(record.codexSeverity))),
  ].join(" and ");
  if (first.state === "declined")
    return `Continuum declined this finding. Codex rated it ${ratings}.`;
  if (first.state === "pending")
    return `Continuum has not finished. Codex rated it ${ratings}.`;
  if (first.state === "unavailable")
    return `Continuum is unavailable. Codex rated it ${ratings}.`;
  const issue = first.issue!;
  const reachability =
    issue.reachableFromAttacker === true
      ? "reachable from an attacker"
      : issue.reachableFromAttacker === false
        ? "not reachable from an attacker"
        : "reachability unknown";
  return `Continuum: ${verdict(issue.verdict)}, ${severity(issue.severity)}, ${reachability}. Codex rated ${records.length === 1 ? "it" : "these occurrences"} ${ratings}.`;
}
function basis(value?: string): string {
  return (
    (
      {
        GRAPH: "from the deployment graph",
        CODE: "from the code",
        FINDING: "stated in the finding, not independently checked",
        INFERRED: "inferred",
      } as Record<string, string>
    )[value ?? "INFERRED"] ?? "as reported by Continuum"
  );
}
function date(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? "date not returned"
    : parsed.toLocaleString("en-US", {
        timeZone: "UTC",
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "numeric",
        minute: "2-digit",
      }) + " UTC";
}
export function validationBody(
  records: readonly ValidationItemRecord[],
): string {
  const first =
    records.find((record) => record.state === "validated") ?? records[0]!;
  const issue = first.issue;
  const headline = validationHeadline(records);
  const split = headline.indexOf(" Codex");
  const lines = [`**${headline.slice(0, split)}**${headline.slice(split)}`, ""];
  if (first.state !== "validated") {
    lines.push(
      `**Why:** ${validationText(first.unavailable ?? first.reasons[0]?.reason) || "No answer was returned."}`,
    );
  } else if (issue) {
    lines.push(
      `**What Continuum found:** ${validationText(issue.title) || "The issue has no title or synopsis."}`,
    );
    lines.push(
      `**Why:** ${validationText(issue.reachabilityReason) || "No reachability reason was returned."} (${basis(issue.reachabilityBasis)} [${issue.reachabilityBasis ?? "INFERRED"}]).`,
    );
    lines.push(
      `**How it was checked:** ${issue.checkedBy ?? "validation evidence"}.`,
    );
  }
  if (issue) {
    const count = issue.findingCount;
    lines.push(
      `**Scope:** This result is for the Continuum issue the ${records.length === 1 ? "finding was" : "findings were"} filed under, not individual finding validation.${count === undefined ? " The number of findings in the issue was not returned." : ` The issue holds ${count} ${count === 1 ? "finding" : "findings"}.`}`,
    );
    if (issue.validatedAt)
      lines.push(
        `**When:** ${date(issue.validatedAt)} — ${issue.validationBeforeSubmission ? "before this submission; Continuum had already validated the issue" : "after this submission"}.${issue.scoringBeforeSubmission ? ` Scoring was also written before this submission${issue.scoredAt ? ` (${date(issue.scoredAt)})` : ""}.` : ""}`,
      );
    lines.push(`**Issue:** ${issue.url}`);
  }
  for (const record of records) {
    if (record !== first && record.state !== "validated")
      lines.push(
        `**Occurrence ${record.itemId}:** ${record.state === "pending" ? "Continuum has not finished" : "Continuum is unavailable"}. ${validationText(record.unavailable)}`,
      );
    if (record.findingResult)
      lines.push(
        `**For this finding specifically (${record.itemId}):** Continuum returned ${verdict(record.findingResult.verdict)}.`,
      );
  }
  return lines.join("\n\n");
}

/** Both hosts use the same grouping and wording; no issue result is duplicated. */
export function validationReport(
  findings: readonly Record<string, unknown>[],
  assessments: readonly ValidationProviderAssessment[],
): { report: string; summary: string; items: ValidationItemRecord[] } {
  const groups = new Map<string, number[]>();
  assessments.forEach((assessment, index) => {
    const record = assessment.record;
    const key = record?.issue
      ? `${record.provider}:${record.issue.url}`
      : `item:${index}`;
    const indices = groups.get(key) ?? [];
    indices.push(index);
    groups.set(key, indices);
  });
  const sections: string[] = [];
  const summaries: string[] = [];
  for (const indices of groups.values()) {
    const first = indices[0]!;
    const finding = findings[first] ?? {};
    const records = indices.flatMap((index) =>
      assessments[index]?.record ? [assessments[index]!.record!] : [],
    );
    const title = validationText(finding["title"], 180) || "Submitted finding";
    const body = records.length
      ? validationBody(records)
      : assessments[first]!.report;
    const occurrences = indices.map((index) => {
      const item = findings[index] ?? {};
      const locations = Array.isArray(item["locations"])
        ? item["locations"]
        : [];
      const evidence = Array.isArray(item["codeEvidence"])
        ? item["codeEvidence"]
        : [];
      const paths = [
        ...new Set(
          [...locations, ...evidence].map((raw) => {
            const row = raw as Record<string, unknown>;
            return `${String(row["path"] ?? row["filePath"] ?? "location not returned")}${typeof row["startLine"] === "number" ? `:${row["startLine"]}${typeof row["endLine"] === "number" && row["endLine"] !== row["startLine"] ? `–${row["endLine"]}` : ""}` : ""}`;
          }),
        ),
      ];
      return `- ${String(item["occurrenceId"] ?? item["id"] ?? `occurrence ${index + 1}`)}: ${paths.join(", ") || validationText(item["location"]) || "location not returned"}${item["title"] !== finding["title"] ? ` — ${validationText(item["title"], 180)}` : ""}`;
    });
    sections.push(
      `## ${title}\n\n${body}\n\n**Codex's finding:** ${validationText(finding["summary"], 500) || title}\n\n**${indices.length === 1 ? "Occurrence" : "Occurrences"}:**\n${occurrences.join("\n")}\n`,
    );
    summaries.push(
      `${title}: ${records.length ? validationHeadline(records) : assessments[first]!.report}`,
    );
  }
  return {
    report: sections.join("\n---\n\n"),
    summary: summaries.join("\n"),
    items: assessments.flatMap((assessment) =>
      assessment.record ? [assessment.record] : [],
    ),
  };
}
