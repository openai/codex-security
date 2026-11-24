import {
  escapeHtml as esc,
  renderDependencyCode,
} from "./dependency-report-code.js";
import {
  captureLimits,
  citationKey,
  rangeLabel,
  containsSource,
  matchesReceipt,
  tagsFor,
  type Check,
  type Finding,
  type DependencyReviewReference,
  type Section,
  type StackReport,
} from "./dependency-report-model.js";
import { asRecord, isRecord } from "./record.js";
import type { DependencyClaimReference } from "./dependency-stack-claims.js";
import { claimKey, walkClaims } from "./dependency-report-reader.js";

export const code = (value: string) => `<code>${esc(value)}</code>`;
const n = (count: number, noun: string) =>
  `${count.toLocaleString("en-US")} ${noun}${count === 1 ? "" : "s"}`;
export function safeLink(value: string, label = value) {
  const url = URL.parse(value);
  if (
    url &&
    (url.username ||
      url.password ||
      [...url.searchParams.keys()].some((key) =>
        /^(?:access_token|token|api[_-]?key|authorization|credential|sig|signature)$/iu.test(
          key,
        ),
      ))
  )
    return "<code>Link omitted (credentials in URL)</code>";
  return url && (url.protocol === "https:" || url.protocol === "http:")
    ? `<a href="${esc(url.href)}" rel="noreferrer">${esc(label)}</a>`
    : code(label);
}
export function prose(text: string) {
  return text
    .split(/(`[^`\n]+`|\*\*[^*\n]+\*\*)/u)
    .map((part) =>
      part.startsWith("`") && part.endsWith("`")
        ? code(part.slice(1, -1))
        : part.startsWith("**") && part.endsWith("**")
          ? `<strong>${esc(part.slice(2, -2))}</strong>`
          : esc(part),
    )
    .join("");
}
const exposureLabels = {
  internet: "Internet exposed",
  not_internet: "Not internet exposed",
  unknown: "Exposure unverified",
} as const;
const deploymentLabels = {
  observed: "Observed running",
  configured: "Configured",
  assumed_not_deployed: "Assumed not deployed in the stated scope",
  unknown: "Deployment unverified",
} as const;
const placeLabels = {
  service: "Service",
  job: "Job",
  configured_build: "Configured build",
  artifact: "Artifact",
  library_caller: "Library caller",
  unknown: "Place type unverified",
} as const;
const factLabels: Record<string, string> = {
  affected_copy: "Selected dependency copy",
  affected_use: "Applicable operation",
  running: "Running revision",
  access: "Caller access",
};
type Field = [string, string | null | undefined];
const str = (x: unknown) => (typeof x === "string" ? x : undefined);
function facts(rows: Field[]) {
  const body = rows
    .map(([key, value]) =>
      value ? `<dt>${esc(key)}</dt><dd>${esc(value)}</dd>` : "",
    )
    .join("");
  return body ? `<dl class="facts">${body}</dl>` : "";
}
const group = (label: string, html: string) =>
  html ? `<h4>${esc(label)}</h4>${html}` : "";
const audit = (label: string, html: string) =>
  html
    ? `<details class="audit"><summary>${esc(label)}</summary><div class="audit-body">${html}</div></details>`
    : "";
function list(entries: string[], idPrefix?: string) {
  if (!entries.length) return "";
  const rows = entries.map((value, i) => {
    const id = idPrefix ? ` id="${idPrefix}-${i + 1}"` : "";
    return `<li${id}>${value}</li>`;
  });
  return `<ul>${rows.join("")}</ul>`;
}
export const para = (value?: string | null) =>
  value ? `<p>${prose(value)}</p>` : "";
function sourceIndex(
  item: Finding["item"],
  ref: Extract<DependencyReviewReference, { kind: "source" }>,
) {
  return item.evidence.findIndex((c) => containsSource(c, ref));
}
function refLink(finding: Finding, ref: DependencyReviewReference) {
  const at =
    ref.kind === "source"
      ? sourceIndex(finding.item, ref)
      : finding.receipts.findIndex((r) => matchesReceipt(ref, r));
  const label = ref.kind === "source" ? rangeLabel(ref) : ref.receiptId;
  return at < 0
    ? code(label)
    : `<a href="#${finding.id}-${ref.kind}-${at + 1}">${code(label)}</a>`;
}
function referenceList(finding: Finding, refs: DependencyReviewReference[]) {
  return refs.map((ref) => refLink(finding, ref)).join(" · ");
}
function originalEvidence(f: Finding, check?: Check) {
  const supports = (keys: string[]) =>
    para(keys.map((k) => factLabels[k] ?? k).join(" · "));
  const sources = f.item.evidence.map((cite) => {
    const text = f.excerpts[citationKey(cite)];
    return `${code(rangeLabel(cite))}${cite.commit ? " · " + code(cite.commit) : ""}${supports(cite.supports)}${text !== undefined ? `<details><summary>Source excerpt</summary>${renderDependencyCode(text, cite.path, cite.startLine)}</details>` : ""}`;
  });
  const records = f.receipts.length
    ? Object.values(check?.claimEvidence?.receipts ?? {})
    : [];
  const receipts = check
    ? f.receipts.map((r) => {
        const m = asRecord(
          records.find((v) => isRecord(v) && matchesReceipt(r, v)),
        );
        const tool = asRecord(m?.["origin"])?.["tool"];
        const fields = facts([
          ["Server", str(m?.["server"])],
          ["Tool", str(isRecord(tool) ? tool["name"] : tool)],
          ["Outcome", str(m?.["outcome"])],
          ["SHA-256", r.originalPayloadSha256],
          [
            "Selected record",
            r.selection ? JSON.stringify(r.selection) : undefined,
          ],
        ]);
        return code(r.receiptId) + fields;
      })
    : [];
  const observations = list(
    f.item.observations.map(
      (o) =>
        `<strong>${esc(o.server)}</strong>${para(o.record)}${supports(o.supports)}`,
    ),
  );
  return (
    group("Source references", list(sources, f.id + "-source")) +
    group("Original receipts", list(receipts, f.id + "-receipt")) +
    group("Observations", observations)
  );
}
function target(f: Finding) {
  const p = f.item.place;
  const use = f.kind === "coverage" ? undefined : f.item;
  const fields = facts([
    ["Component", use?.component],
    ["Version", use?.version],
    ["Target", p ? placeLabels[p.kind] : undefined],
    ["Deployment", p ? deploymentLabels[p.deploymentBasis] : use?.deployment],
    ["Basis", p?.deploymentDetail],
    ["Workload", p?.workload],
    ["Environment", p?.environment],
    ["Variant", p?.variant],
    ["Role", p?.role],
    ["Source revision", p?.revision],
    ["Artifact", p?.artifact],
    ["Image index", p?.imageIndex],
    ["Platform manifest", p?.platformManifest],
    ["Platform", p?.platform],
    ["Observation window", p?.observationWindow],
    ["Selected copy", p?.dependencySelection],
    ["Patch or backport", p?.patch],
    ["Tags", tagsFor(f).join(" · ")],
  ]);
  const rows = list(
    (f.item.services ?? []).map(
      (s) =>
        `<strong>${esc(s.name)}</strong> · ${code(s.id)} · ${esc(s.source)} · ${referenceList(f, s.evidence)}`,
    ),
  );
  return (
    group("Target and dependency", fields) +
    group(
      "Service associations",
      f.unconfirmedServices
        ? para(
            "The proposed service mapping was not confirmed by this item’s evidence.",
          )
        : rows,
    )
  );
}
function context(f: Finding) {
  const { inputSource: input, runtimeContext: runtime } = f.item;
  const source = input
    ? `<p>${exposureLabels[input.exposure]}${input.endpoint ? " · " + safeLink(input.endpoint) : ""}</p><p>${referenceList(f, input.evidence)}</p><p>Internet exposure alone does not establish control of the input at the affected function.</p>`
    : "";
  const m = runtime?.mitigation;
  const launch = runtime
    ? facts([
        [`Launch (${runtime.launch?.basis ?? ""})`, runtime.launch?.command],
        [
          `Mitigation ${m?.state === "unknown" ? "unverified" : m?.state} (${m?.basis})`,
          m?.detail,
        ],
      ]) +
      (runtime.containerUrl
        ? `<p>Container: ${safeLink(runtime.containerUrl)}</p>`
        : "") +
      (runtime.traceUrl
        ? `<p>Reachability trace: ${safeLink(runtime.traceUrl)}</p>`
        : "") +
      `<p>${referenceList(f, runtime.evidence)}</p>`
    : "";
  return group("Input boundary", source) + group("Runtime", launch);
}
function questions(f: Finding) {
  const structured = f.item.openConditions ?? [];
  const other = new Set([
    ...(f.item.place?.unresolvedQuestions ?? []),
    ...(f.kind === "stack" ? f.assessment.remainingQuestions : []),
  ]);
  const entries = structured.map((q) => {
    other.delete(q.question);
    return (
      para(q.question) +
      facts([
        ["Target", q.target],
        ["Deciding check", q.decidingCheck],
        ["Rules this out if", q.ruledOutIf],
      ]) +
      (q.assignee
        ? `<p>Assignee: ${esc(q.assignee.name)} · ${referenceList(f, q.assignee.evidence)}</p>`
        : "")
    );
  });
  if (f.kind === "stack")
    for (const check of f.assessment.questionChecks ?? []) {
      other.delete(check.question);
      entries.push(
        para(check.question) +
          facts([
            ["Checked", check.checked],
            ["Missing evidence", check.missingEvidence],
          ]),
      );
    }
  return group(
    "What would decide this",
    list([...entries, ...Array.from(other, prose)]),
  );
}
const outcomes = {
  succeeded: "Completed",
  denied: "Access denied",
  unsupported: "Unsupported source",
  timeout: "Timed out",
  unavailable: "Unavailable",
  failed: "Failed",
  no_data: "No measurement or data",
  zero_results: "Returned zero",
  partial: "Partial result",
  insufficient_symbols: "Required symbols absent",
  not_attempted: "Not attempted",
};
function inspections(f: Finding) {
  const entries = (f.item.inspections ?? []).map((i) => {
    const t = i.target,
      m = i.measurement;
    const relation = {
      target: "Exact target",
      shared_artifact: "Shared immutable artifact",
      comparison: "Comparison workload",
    }[t.relationship];
    const fields = facts([
      [relation, t.label],
      ["Workload", t.workload],
      ["Environment", t.environment],
      ["Variant", t.variant],
      ["Role", t.role],
      ["Revision", t.revision],
      ["Observation window", t.observationWindow],
      ["Platform", t.platform],
      ["Image index", t.imageIndex],
      ["Platform manifest", t.platformManifest],
      ["Artifact", t.artifact],
      ["Source", i.source],
      ["Result", i.result],
      [
        "Count",
        m
          ? n(m.count, m.unit === "cpu_samples" ? "CPU sample" : "call")
          : undefined,
      ],
      ["Frames", m?.frameTypes?.join(", ")],
      [
        "Completeness",
        i.completeness
          ? {
              complete: "Reported complete",
              partial: "Backend reported partial",
              not_reported: "Not reported by backend",
            }[i.completeness]
          : undefined,
      ],
      ["Transfer basis", i.transferBasis],
    ]);
    return `<strong>${esc(i.question)}</strong> · ${outcomes[i.outcome]}${fields}${referenceList(f, i.evidence)}`;
  });
  return group("Inspections and results", list(entries));
}
function claimLabel(ref: DependencyClaimReference) {
  return `${code(ref.id)} · r${ref.revision} · ${code(ref.hash)}`;
}
function checkClaims(f: Finding, check: Check) {
  if (!f.item.conclusionClaim && !f.item.supportingClaims?.length) return "";
  const byKey = new Map(check.claims?.map((c) => [claimKey(c), c]));
  const refs = [...(f.item.supportingClaims ?? [])];
  if (f.item.conclusionClaim) refs.unshift(f.item.conclusionClaim);
  const entries: string[] = [];
  for (const { ref, claim } of walkClaims(refs, byKey)) {
    const refHtml = claimLabel(ref);
    entries.push(
      claim
        ? refHtml + para(claim.decision.reason)
        : "Missing claim: " + refHtml,
    );
  }
  return group("Claim decisions", list(entries));
}
type StackFinding = Extract<Finding, { kind: "stack" }>;
type SampleScope = StackFinding["assessment"]["scope"];
function sampleScope(scope: SampleScope) {
  return facts([
    ["Service", scope.service],
    ["Environment", scope.environment],
    ["Cluster", scope.cluster],
    ["Container", scope.container],
    ["Image", scope.image_name],
    ["Image digest", scope.image_digest],
    ["Image tag", scope.image_tag],
    ["Image tags", scope.image_tags?.join(", ")],
    ["Window", scope.window.start + " to " + scope.window.end],
  ]);
}
const truncated = (value: boolean | null) =>
  value === null ? "Unverified" : value ? "Yes" : "No";
function sampleRecords(finding: StackFinding) {
  const a = finding.assessment,
    o = a.observation;
  const records = facts([
    ["Work item", a.workItemId],
    ["Result", a.status.replaceAll("_", " ")],
    ["Conflicts", a.scopeConflicts.join("; ")],
    ["Source frame", o?.sourceIndex?.toString()],
    ["Query sink frame", o?.sinkIndex?.toString()],
    ["Query", a.queryId],
    ["Group", a.groupId],
    ["Query truncated", truncated(a.truncated)],
    ["Observation", o?.id],
    ["Observed at", o?.observedAt],
    ["Stack hash", o?.stackHash],
    ["Frames truncated", o && truncated(o.framesTruncated)],
    ["Captured sink IDs", o?.sinkIds?.join(", ")],
    ["Assessed frame indices", a.frameIndices?.join(", ")],
  ]);
  const bindings = (o?.bindings ?? []).map((b) =>
    facts([
      ["Package", b.package],
      ["Version", b.version],
      ["Provenance", b.provenance],
      ["Frames", b.frameIndices?.join(", ")],
      ["Image digest", b.imageDigest],
      ["Source revision", b.sourceSha],
      ["Source ranges", b.evidence?.map(rangeLabel).join(", ")],
    ]),
  );
  const scope = `<details><summary>Sampling scope and records</summary>
    ${records}<h4>Query scope</h4>${sampleScope(a.queryScope)}
    <h4>Assessment scope</h4>${sampleScope(a.scope)}
    ${group("Dependency bindings", list(bindings))}
    </details>`;
  const claims = a.claims.map((c) => {
    const sources = c.sources
      .map((s) => {
        const ref = { ...s, kind: "source" as const };
        const link = refLink(finding, ref);
        if (
          sourceIndex(finding.item, ref) >= 0 &&
          finding.excerpts[citationKey(ref)] === s.text
        )
          return `<p>${link} · ${code(s.commit)}</p>`;
        return `<details><summary>${link} · ${code(s.commit)}</summary>${renderDependencyCode(s.text, s.path, s.startLine)}</details>`;
      })
      .join("");
    const control = a.attackerControlClaim;
    const label =
      control && claimKey(control) === claimKey(c)
        ? "Input control claim"
        : "Claim";
    return `${para(c.fact || "No readable claim text recorded.")}${c.limits ? `<p class="muted">${prose(c.limits)}</p>` : ""}${sources}<details><summary>${label} reference</summary>${claimLabel(c)}</details>`;
  });
  for (const ref of a.missingClaims)
    claims.push("Missing claim " + claimLabel(ref));
  return claims.length
    ? scope +
        `<details><summary>Supporting claims (${a.claims.length} available)</summary>${list(claims)}</details>`
    : scope;
}

function frameRecords(f: StackFinding) {
  const o = f.assessment.observation;
  if (!o) return "";
  // Captured binaries, offsets, matches and full paths are kept out of the
  // walkthrough, but remain available for reproducing a sampled frame.
  const entries = o.frames
    .toSorted((a, b) => b.rawIndex - a.rawIndex)
    .map(({ rawIndex, frame }) => {
      const info = facts([
        ["Location", frame.location],
        ["Line", frame.line?.toString()],
        ["Type", frame.type],
        ["Binary", frame.binary],
        ["Build ID", frame.buildId],
        ["Build hash", frame.buildHash],
        ["Offset", frame.offset?.toString()],
        [
          "Matched sink IDs",
          o.sinkMatches
            .filter((m) => m.rawIndex === rawIndex)
            .map((m) => m.sinkId)
            .join(", "),
        ],
      ]);
      return `<strong>#${rawIndex} ${esc(frame.name)}</strong>${info}`;
    });
  return entries.length
    ? `<details><summary>Captured frame metadata</summary>${list(entries)}</details>`
    : "";
}
export function findingAudit(section: Section, finding: Finding) {
  const item = finding.item;
  const stack = finding.kind === "stack" ? finding : undefined;
  const useReason = stack?.assessment.use?.reason;
  const handoff =
    finding.kind === "coverage" ? finding.item.handoff : undefined;
  const parts = [
    group("Full assessment", para(item.reason)),
    useReason === item.reason
      ? ""
      : group("Source assessment", para(useReason)),
    group("Independent review", para(stack?.assessment.reviewReason)),
    questions(finding),
    handoff &&
      group(
        "Handoff",
        facts([
          ["Last verified", handoff.verified],
          ["Missing link", handoff.missing],
        ]),
      ),
    context(finding),
    target(finding),
    inspections(finding),
    stack && sampleRecords(stack) + frameRecords(stack),
    originalEvidence(finding, section.check),
    section.check && checkClaims(finding, section.check),
  ];
  return audit("Reasoning and evidence", parts.join(""));
}
function limitations(check: Check, findings: Finding[]) {
  const grouped = new Map<string, Set<string>>();
  for (const value of check.limitations) {
    const split = value.indexOf(" Unresolved source locations:");
    const reason = split < 0 ? value : value.slice(0, split);
    const refs = grouped.get(reason) ?? new Set<string>();
    if (split !== -1) refs.add(value.slice(split).trim());
    grouped.set(reason, refs);
  }
  const rows = [...grouped].map(([reason, refs]) => {
    const affected = findings
      .filter((f) => f.item.reason === reason)
      .map((f) => `<a href="#${f.id}">${esc(f.item.location ?? f.label)}</a>`);
    return (
      prose(reason) +
      (affected.length ? `<p>Affected: ${affected.join(", ")}</p>` : "") +
      [...refs].map(para).join("")
    );
  });
  return (
    list(rows) ||
    para(
      "Check each finding for missing evidence. No other limitations were recorded.",
    )
  );
}
function searchRecords(check: Check, dismissed: Finding[]) {
  const searches = check.searches.map(
    (s) =>
      `<strong>${esc(s.source)} / ${esc(s.tool)}</strong>` +
      facts([
        ["Scope", s.scope.join(", ")],
        ["Started", s.startedAt],
        ["Finished", s.finishedAt],
        ["Result", s.result.replaceAll("_", " ")],
        ["Completeness", s.completeness],
        ["Details", s.details.join("; ")],
        ["References", s.evidenceReferences.join(" · ")],
      ]),
  );
  const ignored = dismissed.map((f) => {
    const c = f.kind === "coverage" ? f.item.classification : undefined;
    return `<details id="${f.id}"><summary>${esc(f.item.location ?? f.label)}</summary>${para(f.item.reason)}${para(c?.replaceAll("_", " "))}${originalEvidence(f, check)}${checkClaims(f, check)}</details>`;
  });
  return (
    group("Assumptions", list(check.assumptions.map(prose))) +
    group(
      "Search records",
      list(searches) || para("No saved search records."),
    ) +
    group("Dismissed candidates", list(ignored))
  );
}
function sampleLimits(stack: StackReport, findings: Finding[]) {
  const byWorkItem = new Map(
    findings.flatMap((f) =>
      f.kind === "stack" ? [[f.assessment.workItemId, f] as const] : [],
    ),
  );
  const workItemLink = (id: string) => {
    const f = byWorkItem.get(id);
    if (!f) return code(id);
    const name = f.anchor ? `${f.anchor.path}:${f.anchor.line}` : f.label;
    return `<a href="#${f.id}">${esc(name)}</a> · ${code(id)}`;
  };
  const limits = captureLimits(stack)
    .map(([label, ids]) => group(label, list(ids.map(workItemLink))))
    .join("");
  const asked = new Set(stack.assessments.flatMap((a) => a.remainingQuestions));
  const other = stack.remainingQuestions.filter((q) => !asked.has(q));
  return (
    para(
      "Samples show what ran in one window. Missing samples do not rule out execution. Sample counts are not call counts.",
    ) +
    (stack.advisoryLookupError
      ? para("Advisory lookup failed · " + stack.advisoryLookupError)
      : "") +
    limits +
    group("Other open questions", list(other.map(prose)))
  );
}
export function sectionAudit(section: Section) {
  const { check, stack, prepared } = section;
  if (!prepared) return "";
  const { findings, dismissed } = prepared;
  let limits = "",
    scope = "";
  if (stack) {
    const c = stack.coverage;
    limits = sampleLimits(stack, findings);
    scope = facts([
      ["Caller scope", stack.callerScope],
      ["Review", stack.review ? "Independently reviewed" : "Finalized offline"],
      ["Reviewed draft digest", stack.review?.draftDigest],
      [
        "Work items",
        `${c.assessed} of ${c.total} assessed · ${c.observed} observed · ${c.noMatch.length} no match · ${c.noCoverage.length} without coverage`,
      ],
      ["Run", stack.runId],
      ["Attempt", stack.attemptId],
      ["Input digest", stack.inputDigest],
      ["Tool revision", stack.toolRevision],
    ]);
  } else if (check) {
    limits = limitations(check, findings);
    scope = searchRecords(check, dismissed);
  }
  return (
    audit("Report limitations", limits) +
    audit("Investigation scope and search coverage", scope)
  );
}
