import {
  counts,
  findingLabels,
  findingState,
  quantity,
  type Finding,
  type Report,
} from "./dependency-report-model.js";
import { dependencyVerdictLabels } from "./dependency-stack-use.js";
import { formatSecurityPolicyText } from "./security-policy.js";

function scope(finding: Finding): string {
  if (finding.kind === "stack") {
    const s = finding.assessment.scope;
    return [
      s.environment,
      s.cluster,
      s.service,
      s.container === s.service ? undefined : s.container,
      s.image_digest ?? s.image_tag,
      s.window.start + " to " + s.window.end,
    ]
      .filter(Boolean)
      .join(" · ");
  }
  const place = finding.item.place;
  return [
    place?.environment,
    place?.workload,
    place?.variant,
    place?.platform,
    place?.artifact,
  ]
    .filter(Boolean)
    .join(" · ");
}

/** Keep stdout scannable at the terminal. The Markdown and JSON retain the full evidence. */
export function summarizeDependencyReport(report: Report): string {
  const lines = [
    report.sections.length
      ? report.title
      : report.title + ": no published advisories found.",
  ];
  if (report.target)
    lines.push(
      `Repository ${report.target.repository} · Analyzed commit ${report.target.sha}`,
    );
  for (const section of report.sections) {
    if (section.title !== report.title) lines.push("", section.title);
    if (section.pending) {
      lines.push(
        "Not investigated · Package investigation stopped before this advisory.",
      );
      continue;
    }
    if (section.blocked) {
      lines.push("Investigation blocked · " + section.blocked.reason);
      if (section.blocked.unblockCondition)
        lines.push("  Next: " + section.blocked.unblockCondition);
      continue;
    }
    const findings = section.prepared!.findings;
    const { reviewed, unresolved, outcomes } = counts(
      findings,
      section.stack?.verdict,
    );
    const totals = section.stack
      ? [
          dependencyVerdictLabels[section.stack.verdict],
          `${section.stack.coverage.assessed}/${section.stack.coverage.total} stack items assessed`,
        ]
      : [quantity(reviewed, "reviewed use")];
    totals.push(...outcomes);
    if (unresolved) totals.push(quantity(unresolved, "unresolved candidate"));
    lines.push(totals.join(" · "));
    if (section.stack) {
      const { coverage: c, assessments } = section.stack;
      const groups = new Set<string>();
      let cutStacks = 0;
      for (const a of assessments) {
        if (a.truncated) groups.add(JSON.stringify([a.queryId, a.groupId]));
        if (a.observation?.framesTruncated) cutStacks++;
      }
      const limits = [
        groups.size && quantity(groups.size, "truncated capture group"),
        cutStacks && quantity(cutStacks, "stack") + " with truncated frames",
        c.truncationUnknown.length &&
          c.truncationUnknown.length + " with unknown truncation",
        c.noMatch.length && c.noMatch.length + " without a match",
        c.noCoverage.length &&
          c.noCoverage.length + " with missing or incomplete coverage",
        c.scopeConflicts.length &&
          quantity(c.scopeConflicts.length, "scope conflict"),
      ].filter(Boolean);
      if (limits.length) lines.push("Capture limits: " + limits.join(" · "));
    }
    const scopes = findings.map(scope);
    const commonScope = new Set(scopes).size === 1 ? scopes[0] : undefined;
    if (commonScope) lines.push("Scope: " + commonScope);
    for (const [index, f] of findings.entries()) {
      const outcome = findingLabels[findingState(f)];
      const component =
        f.kind !== "coverage" && f.item.component
          ? f.item.component + "@" + (f.item.version ?? "unknown")
          : undefined;
      const site = f.anchor && f.anchor.path + ":" + f.anchor.line;
      const stack = f.kind === "stack" ? f.assessment : undefined;
      const label = stack?.use?.location ?? f.label;
      const sample = stack
        ? (stack.observation?.stackHash.slice(0, 12) ??
          stack.status.replaceAll("_", " "))
        : undefined;
      lines.push(
        "",
        `${index + 1}. ${[outcome, label, component, sample].filter(Boolean).join(" · ")}`,
      );
      if (site && site !== label)
        lines.push(
          "   " + (f.anchor?.kind === "call" ? "Call: " : "Reference: ") + site,
        );
      if (!commonScope && scopes[index])
        lines.push("   Scope: " + scopes[index]);
      const condition = f.item.openConditions?.[0];
      const question =
        stack?.remainingQuestions[0] ??
        condition?.decidingCheck ??
        condition?.question ??
        (f.kind === "coverage" ? f.item.handoff?.missing : undefined) ??
        f.item.place?.unresolvedQuestions[0];
      const unresolved =
        f.kind === "coverage" ||
        f.item.verdict === "unknown" ||
        f.item.verdict === "potentially_exploitable";
      if (unresolved && question && question !== f.item.reason)
        lines.push("   Next: " + question);
      else lines.push("   " + f.item.reason);
    }
    for (const note of section.check?.limitations ?? [])
      lines.push("  Gap: " + note);
  }
  if (report.contextHint) lines.push("", report.contextHint);
  return lines.map((line) => formatSecurityPolicyText(line)).join("\n");
}
