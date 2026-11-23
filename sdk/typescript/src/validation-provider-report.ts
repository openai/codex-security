import { formatSecurityPolicyText as escapeTerminalText } from "./security-policy.js";
import type {
  ValidationItemRecord,
  ValidationProviderAssessment,
} from "./validation-provider.js";

/** Shorten AWS resource names in narrative only. IDs and links remain intact. */
export function resourceNames(reason: string): string {
  return reason
    .replace(/\barn:aws[\w-]*:[^\s),]+/gu, (arn) => {
      const parts = arn.split("/");
      const name =
        arn.includes(":loadbalancer/") && parts.length >= 4
          ? parts.at(-2)
          : parts.at(-1);
      return name || arn;
    })
    .replaceAll("network://aws/internet", "the internet")
    .replaceAll("query_network_reachability", "A network reachability check")
    .replaceAll("returned EXPOSED via", "found public access through")
    .replaceAll(" -> ", " → ");
}

function itemConclusion(record: ValidationItemRecord, ids: string[]): string {
  const verdict = record.terminalStatus
    ? `${record.verdict} (validation run ${record.terminalStatus})`
    : record.verdict;
  const severity =
    record.severityBefore === record.severityAfter
      ? `Codex severity ${record.severityBefore} retained`
      : `${record.severityBefore} → ${record.severityAfter}`;
  const bases = [...new Set(record.reasons.map((reason) => reason.basis))];
  const items =
    ids.length === 1 ? `Item ${record.itemId}` : `Items ${ids.join(", ")}`;
  const lines = [`${items}: ${severity}.`];
  if (record.issueId) lines.push(`Issue ${record.issueId}.`);
  if (record.issueFindingCount !== undefined)
    lines.push(`Findings in issue: ${record.issueFindingCount}.`);
  if (record.resultScope === "issue") {
    lines.push(
      `Issue-level verdict: ${verdict}; issue severity: ${record.providerSeverity ?? "not returned"}.`,
      "Not individually validated.",
    );
  } else {
    lines.push(`Verdict: ${verdict}.`);
    if (record.issueVerdict)
      lines.push(`Issue-level verdict: ${record.issueVerdict}.`);
    if (record.providerSeverity)
      lines.push(`Issue severity: ${record.providerSeverity}.`);
    if (record.resultScope === "finding" && record.validationArtifactId)
      lines.push(
        "This provider verdict does not establish that the submitted flaw was reproduced.",
      );
  }
  if (record.statusMessage) lines.push(record.statusMessage);
  if (record.resultScope === "issue" || record.issueId) {
    const exposure =
      record.reachableFromAttacker === true
        ? "reachable from attacker"
        : record.reachableFromAttacker === false
          ? "not reachable from attacker"
          : "unknown";
    lines.push(`Issue reachability: ${exposure}.`);
    const context = record.reasons.find((reason) =>
      reason.reason.startsWith("Basis:"),
    );
    if (context) lines.push(`Context: ${resourceNames(context.reason)}`);
  }
  if (record.joinedValidatedIssue)
    lines.push("This finding joined an issue Continuum had already validated.");
  if (bases.length) lines.push(`Reason bases: ${bases.join(", ")}.`);
  if (record.freshness.stale) lines.push("Evidence predates this submission.");
  if (record.unavailable) lines.push(record.unavailable);
  return lines.join(" ");
}

/** Combine identical issue conclusions only. Preserve every detailed report and record. */
export function validationSummary(
  assessments: readonly ValidationProviderAssessment[],
) {
  const groups = new Map<
    string | number,
    { assessment: ValidationProviderAssessment; ids: string[] }
  >();
  for (const [index, assessment] of assessments.entries()) {
    const record = assessment.record;
    let key: string | number = index;
    if (
      record?.provider === "continuum" &&
      record.resultScope === "issue" &&
      record.issueArn &&
      record.validationArtifactId &&
      record.freshness.evidenceCreatedAt &&
      assessment.disposition === "reportable" &&
      !assessment.unavailable
    ) {
      // Exclude only submission identity. In particular, evidence IDs,
      // freshness, severity, reasons, and status must all agree.
      const { itemId, findingId, findingArn, submittedAt, ...issue } = record;
      key = JSON.stringify(issue);
    }
    const group = groups.get(key) ?? { assessment, ids: [] as string[] };
    if (record) group.ids.push(record.itemId);
    groups.set(key, group);
  }
  return Array.from(groups.values(), ({ assessment, ids }) =>
    assessment.record
      ? escapeTerminalText(itemConclusion(assessment.record, ids))
      : escapeTerminalText(assessment.report, true),
  ).join("\n");
}
