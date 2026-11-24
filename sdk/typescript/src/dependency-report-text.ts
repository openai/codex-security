import {
  captureLimits,
  counts,
  matchTraceFrame,
  prepareDependencyReport,
  findingLabels,
  findingState,
  quantity,
  rangeLabel,
  type Finding,
  type Report,
  advisoryFunctions,
  sectionAdvisories,
  type Section,
  type StackAssessment,
} from "./dependency-report-model.js";
import {
  inspectPath,
  sourceFrames,
  type PathFrame,
} from "./dependency-report-path.js";
import { dependencyVerdictLabels } from "./dependency-reachability.js";
import { formatSecurityPolicyText } from "./security-policy.js";

// Saved report text can contain Markdown or HTML. Keep it in the paragraph
// where it was cited, without turning a source string into a link or block.
const prose = (value: string) =>
  value
    .replace(/\s+/gu, " ")
    .trim()
    .split(/(`[^`]+`)/u)
    .map((part, i) =>
      i % 2 ? code(part.slice(1, -1)) : part.replace(/[\\[\]<>*`~]/gu, "\\$&"),
    )
    .join("")
    .replace(/^([#>+-]+)(?=\s)/u, "\\$1");
function code(value: string) {
  const line = value.replace(/[\r\n]+/gu, " ");
  let fence = "`";
  for (const match of line.matchAll(/`+/gu)) {
    if (match[0].length >= fence.length)
      fence = "`".repeat(match[0].length + 1);
  }
  const pad = line.startsWith("`") || line.endsWith("`") ? " " : "";
  return fence + pad + line + pad + fence;
}
const join = (
  pieces: (string | null | undefined | false)[],
  delimiter = " · ",
) => pieces.filter(Boolean).join(delimiter);
const blocks = (...pieces: (string | null | undefined | false)[]) =>
  join(pieces, "\n\n");
function list(items: string[], label?: string) {
  if (!items.length) return "";
  return blocks(
    label && "**" + label + "**",
    items.map((item) => "- " + item).join("\n"),
  );
}
function scopeLabel(scope: StackAssessment["scope"]) {
  const tags = new Set([scope.image_tag, ...(scope.image_tags ?? [])]);
  return join([
    scope.service && "service " + code(scope.service),
    scope.environment && code(scope.environment),
    scope.cluster && "cluster " + code(scope.cluster),
    scope.container && "container " + code(scope.container),
    scope.image_name && "image " + code(scope.image_name),
    ...[...tags].map((t) => t && "tag " + code(t)),
    scope.image_digest && "digest " + code(scope.image_digest),
    code(scope.window.start) + " – " + code(scope.window.end),
  ]);
}
function stackEvidence(f: Extract<Finding, { kind: "stack" }>) {
  const a = f.assessment;
  const obs = a.observation;
  const query = scopeLabel(a.queryScope),
    actual = scopeLabel(a.scope);
  const context = [
    "Work item " + code(a.workItemId),
    "Query " + code(a.queryId) + " · group " + code(a.groupId),
    "Query scope: " + query,
  ];
  if (obs) {
    context.push(
      "Sample " +
        code(obs.id) +
        (obs.observedAt ? " at " + code(obs.observedAt) : ""),
    );
  }
  if (actual !== query)
    context.push(`${obs ? "Assessment" : "Group"} scope: ${actual}`);
  const limits: string[] = [];
  if (a.status === "no_match")
    limits.push("The query returned no matching sample.");
  if (a.status === "no_coverage")
    limits.push("Sampling did not cover this query.");
  if (a.truncated)
    limits.push("The query returned only part of the matching stacks.");
  if (a.truncated === null) limits.push("Query completeness unknown.");
  for (const conflict of a.scopeConflicts)
    limits.push("Scope conflict: " + prose(conflict));
  const bindings =
    obs?.bindings.map((b) =>
      join([
        code(b.package + " " + b.version),
        b.frameIndices?.length
          ? "bound to frame " + b.frameIndices.join(", ")
          : "no frame association",
        b.imageDigest &&
          (b.imageDigest === a.scope.image_digest
            ? "same image digest as assessment"
            : code(b.imageDigest)),
        b.sourceSha && "source " + code(b.sourceSha),
        prose(b.provenance),
      ]),
    ) ?? [];
  const claimFacts = a.claims.map((c) =>
    join([
      c.fact && prose(c.fact),
      c.limits && prose(c.limits),
      c.sources.map((s) => code(rangeLabel(s))).join(", "),
      code(c.id + "@" + c.revision),
    ]),
  );
  for (const ref of a.missingClaims)
    limits.push(
      `Missing referenced claim ${code(ref.id + "@" + ref.revision)} · ${code(ref.hash)}`,
    );
  return blocks(
    limits.join(" "),
    a.reviewReason && "**Independent review** — " + prose(a.reviewReason),
    list(
      (a.questionChecks ?? []).map((q) =>
        join([
          prose(q.question),
          "**Checked** " + prose(q.checked),
          "**Missing evidence** " + prose(q.missingEvidence),
        ]),
      ),
      "Deciding checks",
    ),
    list(bindings, "Package evidence"),
    list(claimFacts, "Supporting evidence"),
    list(context, "Capture details"),
  );
}
function questions(f: Finding) {
  const asked = new Set<string>();
  const output: string[] = [];
  for (const q of f.item.openConditions ?? []) {
    output.push(
      join([
        prose(q.question),
        "Target: " + prose(q.target),
        q.decidingCheck && prose(q.decidingCheck),
        q.ruledOutIf && "Rules it out if: " + prose(q.ruledOutIf),
      ]),
    );
    asked.add(q.question);
  }
  const remaining =
    f.kind === "stack"
      ? f.assessment.remainingQuestions
      : (f.item.place?.unresolvedQuestions ?? []);
  for (const q of remaining)
    if (!asked.has(q) && q !== f.item.reason) {
      output.push(prose(q));
      asked.add(q);
    }
  return output;
}
const conditionLabels = {
  met: "Met",
  unknown: "Unknown",
  ruled_out: "Rules it out",
};
function conditions(f: Finding) {
  if (f.kind === "coverage") return;
  return list(
    (f.item.proof?.conditions ?? []).map((c) => {
      const refs = c.citations
        .map((s) => code(s.path + ":" + s.line))
        .join(", ");
      const label = "**" + conditionLabels[c.status] + "** — " + prose(c.label);
      return (
        label + "\n  " + prose(c.explanation) + (refs ? "\n  " + refs : "")
      );
    }),
    "Advisory conditions",
  );
}
function workload(f: Exclude<Finding, { kind: "stack" }>) {
  const runtime = f.item.runtimeContext;
  const place = f.item.place;
  const facts: string[] = [];
  if (runtime?.launch)
    facts.push(
      "Launch (" + runtime.launch.basis + "): " + code(runtime.launch.command),
    );
  if (runtime?.mitigation)
    facts.push(
      `Mitigation (${runtime.mitigation.basis}): ${prose(runtime.mitigation.detail)}`,
    );
  if (place?.deploymentDetail) facts.push(prose(place.deploymentDetail));
  if (place?.revision) facts.push("Revision " + code(place.revision));
  if (place?.observationWindow)
    facts.push("Observed window: " + prose(place.observationWindow));
  if (place?.platformManifest)
    facts.push("Platform image " + code(place.platformManifest));
  if (place?.artifact && place.artifact !== place.platformManifest)
    facts.push("Artifact " + code(place.artifact));
  if (place?.dependencySelection) facts.push(prose(place.dependencySelection));
  if (place?.patch) facts.push(prose(place.patch));
  for (const i of f.item.inspections ?? [])
    facts.push(
      join([
        `${prose(i.target.label)} (${i.target.relationship.replaceAll("_", " ")})`,
        prose(i.question),
        i.outcome.replaceAll("_", " "),
        i.result && prose(i.result),
        i.measurement &&
          i.measurement.count +
            (i.measurement.unit === "cpu_samples" ? " CPU samples" : " calls"),
        i.measurement &&
          i.completeness &&
          "completeness " + i.completeness.replaceAll("_", " "),
        i.transferBasis && prose(i.transferBasis),
      ]),
    );
  for (const o of f.item.observations)
    facts.push(prose(o.server) + ": " + prose(o.record));
  return list(facts, "Instance and checks");
}
function source(f: Finding) {
  const refs = f.item.evidence.map((c) =>
    join([code(rangeLabel(c)), c.commit && code(c.commit)]),
  );
  if (f.kind !== "stack") {
    for (const ref of f.item.decidingEvidence ?? []) {
      if (ref.kind === "receipt") refs.push("Receipt " + code(ref.receiptId));
    }
    const claims = [f.item.conclusionClaim, ...(f.item.supportingClaims ?? [])];
    for (const ref of claims)
      if (ref) refs.push("Claim " + code(ref.id + "@" + ref.revision));
  }
  return list([...new Set(refs)], "References");
}
function snippet(path: string, line: string) {
  const language = /\.([a-z0-9]+)$/iu.exec(path)?.[1]?.toLowerCase() ?? "";
  const fence = line.startsWith("```") ? "~~~" : "```";
  return fence + language + "\n" + line + "\n" + fence;
}
function sourceLine({ code, line }: PathFrame) {
  return code && line !== undefined
    ? code.text.split(/\r?\n/u)[line - code.startLine]?.trim()
    : undefined;
}
function trace(f: Finding) {
  const titles = { source: "Input", call: "Call", call_site: "Sink call" };
  const steps = sourceFrames(f).map((frame) => {
    if (frame.role === "gap") return "Missing link: " + prose(frame.label);
    const { label, path, line, argument } = frame;
    const text = sourceLine(frame);
    const symbol = /^[\w.$:#]+(?:\(\))?$/u.test(label)
      ? code(label)
      : prose(label);
    const heading = join([
      `**${titles[frame.role]}** ${symbol}`,
      code(path + ":" + line),
      argument && text?.includes(argument) && "follow " + code(argument),
    ]);
    return blocks(heading, text && snippet(path, text));
  });
  if (steps.length < 2) return steps[0] ?? "";
  const numbered = steps.map((step, i) => {
    const marker = i + 1 + ". ";
    return (
      marker + step.replace(/\n(?=[^\n])/gu, "\n" + " ".repeat(marker.length))
    );
  });
  return blocks("**Call path**", ...numbered);
}
function callPath(f: Finding, target?: Report["target"]) {
  if (f.kind !== "stack" || !f.assessment.observation) return trace(f);
  const { frames, notes } = inspectPath(f, target);
  const roles = {
    source: "source",
    sink: "matched sink",
    query_sink: "query sink",
    call_site: "call site",
    call: "",
    gap: "",
  };
  const steps: string[] = [];
  const site = f.item.proof?.sink?.callSite;
  const reviewed = site && matchTraceFrame(f, "sink", site);
  let includesReviewedCall = false;
  for (const frame of frames) {
    const { omittedBefore, line, code: excerpt } = frame;
    if (omittedBefore)
      steps.push(
        `… ${omittedBefore} intervening ${omittedBefore === 1 ? "frame" : "frames"} omitted`,
      );
    const path = excerpt?.path ?? frame.path;
    const location = path
      ? join([path, line?.toString()], ":")
      : line && "line " + line;
    const text = sourceLine(frame);
    const sink =
      text &&
      reviewed &&
      "index" in reviewed &&
      excerpt?.citationIndex === reviewed.index &&
      site?.line === line
        ? f.item.proof?.sink
        : undefined;
    if (sink) includesReviewedCall = true;
    const role = join(
      [
        roles[frame.role],
        frame.role !== "source" &&
          frame.rawIndex === f.assessment.observation.sourceIndex &&
          "source",
      ],
      ", ",
    );
    const label = join([
      code(frame.label),
      location ? code(location) : undefined,
      join([role, "frame " + frame.rawIndex], ", "),
      sink && sink.function !== frame.label && "calls " + code(sink.function),
      sink?.argument &&
        text?.includes(sink.argument) &&
        "follow " + code(sink.argument),
    ]);
    const step = blocks(label, excerpt && text && snippet(excerpt.path, text));
    steps.push(step.replace(/\n(?=[^\n])/gu, "\n  "));
  }
  const source = includesReviewedCall && !f.item.trace?.length ? "" : trace(f);
  return blocks(
    "**Sampled stack** · caller first",
    list(steps),
    notes.map(prose).join(" "),
    frames.length > 0 &&
      !frames.some((frame) => frame.code) &&
      "No source excerpts could be matched to the sampled frames.",
    source && blocks("**Source review**", source),
  );
}
function title(f: Finding, path?: string) {
  const status = findingLabels[findingState(f)];
  const site = f.anchor;
  if (!site) return prose(f.label) + " — " + status;
  const prefix = site.kind === "reference" ? "Reference " : "";
  return prefix + code((path ?? site.path) + ":" + site.line) + " — " + status;
}
function contextLabel(f: Finding) {
  if (f.kind === "stack") {
    const { scope, status } = f.assessment;
    return join([
      scope.service,
      scope.environment,
      scope.cluster,
      status.replaceAll("_", " "),
    ]);
  }
  const p = f.item.place;
  return join([
    f.item.services?.map((s) => s.name).join(", "),
    p?.workload,
    p?.variant,
    p?.environment,
    p?.platform,
    p && "deployment " + p.deploymentBasis.replaceAll("_", " "),
  ]);
}
function finding(f: Finding, heading: string, target?: Report["target"]) {
  const input = f.kind !== "stack" && f.item.inputSource;
  const exposure = {
    internet: "Internet exposed",
    not_internet: "Not Internet exposed",
    unknown: "Exposure unknown",
  };
  const dependency =
    f.kind !== "coverage" &&
    f.item.component &&
    code(join([f.item.component, f.item.version], " "));
  const handoff = f.kind === "coverage" && f.item.handoff;
  const context = prose(contextLabel(f));
  const [firstQuestion, ...others] = questions(f);
  // Prefer the explicit deciding conditions to a long explanation for open
  // stacks. Never invent a shorter verdict by truncating the agent's prose.
  const explainInDetails =
    f.kind === "stack" &&
    f.assessment.verdict === "unknown" &&
    f.item.proof?.conditions?.some((check) => check.status === "unknown") &&
    !!firstQuestion;
  const evidence = blocks(
    explainInDetails && prose(f.item.reason),
    list(others, "Other open questions"),
    f.kind === "stack" ? stackEvidence(f) : workload(f),
    source(f),
  );
  const decision = blocks(
    heading + " " + title(f),
    join([
      f.anchor && (f.kind === "stack" ? code(f.label) : prose(f.label)),
      context,
      dependency,
    ]),
    input &&
      join([
        "Input: " + exposure[input.exposure],
        input.endpoint && code(input.endpoint),
      ]),
    !explainInDetails && prose(f.item.reason),
    handoff &&
      blocks(
        "Last verified step: " + prose(handoff.verified),
        "Missing step: " + prose(handoff.missing),
      ),
    firstQuestion && "**What would decide this** — " + firstQuestion,
    callPath(f, target),
    conditions(f),
  );
  const identity = f.anchor
    ? code(f.anchor.path + ":" + f.anchor.line)
    : prose(f.label);
  return {
    context,
    decision,
    evidence:
      evidence && blocks(heading + "# " + join([identity, context]), evidence),
  };
}
function decisionIndex(findings: Finding[], scopes: string[]) {
  if (findings.length <= 1) return;
  // Use the short file name unless two different files share it.
  const basename = (path: string) => path.split(/[\\/]/u).at(-1)!;
  const paths = new Set(
    findings.flatMap((f) => (f.anchor ? [f.anchor.path] : [])),
  );
  const files = Map.groupBy(paths, basename);
  const common = scopes.every((s) => s === scopes[0]) ? scopes[0] : undefined;
  const rows = findings.map((f, i) => {
    const name = f.anchor && basename(f.anchor.path);
    const path = name && files.get(name)!.length === 1 ? name : f.anchor?.path;
    return join([title(f, path), !common && scopes[i]]);
  });
  const groups = Map.groupBy(rows, (row) => row);
  return blocks(
    join(["**Results**", common]),
    list(
      rows.map((row, i) => {
        if (groups.get(row)!.length === 1) return row;
        const f = findings[i]!;
        return join([
          row,
          f.kind === "stack" ? code(f.assessment.workItemId) : prose(f.label),
        ]);
      }),
    ),
  );
}
function sectionBody(section: Section, heading: string) {
  if (section.blocked) {
    const b = section.blocked;
    return blocks(
      (section.pending ? "**Not started**" : "**Investigation blocked**") +
        " — " +
        prose(b.reason),
      b.affectedScope && "Affected scope: " + prose(b.affectedScope),
      b.scopeImpact && prose(b.scopeImpact),
      b.unblockCondition && "To resume: " + prose(b.unblockCondition),
    );
  }
  const { findings, dismissed } = section.prepared!;
  const stack = section.stack;
  const { reviewed, unresolved, outcomes } = counts(findings, stack?.verdict);
  const totals = stack
    ? `**${dependencyVerdictLabels[stack.verdict]}** · ${stack.review ? "Independently reviewed" : "Finalized offline"} · ${stack.coverage.assessed}/${stack.coverage.total} work items assessed · ${stack.coverage.observed} observed`
    : join([
        quantity(reviewed, "reviewed use"),
        quantity(unresolved, "unresolved candidate"),
      ]);
  const notes = stack
    ? captureLimits(stack)
        .filter(([, ids]) => ids.length)
        .map(([label, ids]) => label + ": " + ids.length)
    : [];
  const check = section.check;
  const { details, urls } = sectionAdvisories(section);
  const advisory = details.map((a) =>
    blocks(
      a.summary && prose(a.summary),
      a.overview && a.overview !== a.summary && prose(a.overview),
      a.applicability && prose(a.applicability),
    ),
  );
  const results = findings.map((f) => finding(f, heading, stack?.target));
  const evidence = results.map((result) => result.evidence).filter(Boolean);
  const subsection = (title: string, items: string[]) =>
    items.length > 0 && blocks(heading + " " + title, list(items));
  return blocks(
    ...advisory,
    list(advisoryFunctions(details).map(code), "Vulnerable functions"),
    totals,
    join(outcomes),
    notes.length > 0 && "Capture limits · " + join(notes),
    stack?.advisoryLookupError &&
      "Advisory lookup failed · " + prose(stack.advisoryLookupError),
    stack &&
      "A sampled stack shows which functions ran. It does not measure call counts or establish who controlled the input.",
    list(
      (stack?.callerScope
        ? [stack.callerScope]
        : (check?.assumptions ?? [])
      ).map(prose),
      "Scope",
    ),
    decisionIndex(
      findings,
      results.map((r) => r.context),
    ),
    ...results.map((result) => result.decision),
    evidence.length > 0 && heading + " Evidence",
    ...evidence,
    stack?.review &&
      "Reviewed draft digest · " + code(stack.review.draftDigest),
    subsection(
      "Dismissed candidates",
      dismissed.map((f) => prose(f.label) + " — " + prose(f.item.reason)),
    ),
    subsection("Report limitations", check?.limitations?.map(prose) ?? []),
    subsection("Advisory references", urls.map(code)),
  );
}

export function renderPreparedDependencyReportMarkdown(report: Report): string {
  const sections = report.sections.map((section) => {
    const hasHeading =
      report.sections.length !== 1 || section.title !== report.title;
    return blocks(
      hasHeading && "## " + prose(section.title),
      sectionBody(section, hasHeading ? "###" : "##"),
    );
  });
  return (
    blocks(
      "# " + prose(report.title),
      report.target
        ? `Repository ${code(report.target.repository)} · Analyzed commit ${code(report.target.sha)}`
        : "Checkout not recorded",
      report.description && prose(report.description),
      sections.length === 0
        ? "No advisory checks recorded."
        : sections.join("\n\n"),
      report.contextHint,
    ) + "\n"
  );
}

export function renderDependencyReportMarkdown(value: unknown): string {
  return renderPreparedDependencyReportMarkdown(prepareDependencyReport(value));
}

function summaryScope(finding: Finding): string {
  if (finding.kind === "stack") {
    const s = finding.assessment.scope;
    return join([
      s.environment,
      s.cluster,
      s.service,
      s.container === s.service ? undefined : s.container,
      s.image_digest ?? s.image_tag,
      s.window.start + " to " + s.window.end,
    ]);
  }
  const place = finding.item.place;
  return join([
    place?.environment,
    place?.workload,
    place?.variant,
    place?.platform,
    place?.artifact,
  ]);
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
    const scopes = findings.map(summaryScope);
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
        `${index + 1}. ${join([outcome, label, component, sample])}`,
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
