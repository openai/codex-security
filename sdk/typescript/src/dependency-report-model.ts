import { z } from "zod";
import type { dependencyAdvisoryDetailsSchema } from "./dependency-advisory.js";
import {
  claimKey,
  walkClaims,
  readStackReport,
  type StackReport,
  type StackAssessment,
  dependencyInvestigationBlockedSchema,
  readDependencyCheckOutput,
  reviewedDependencyCheckSchema,
  type DependencyCoverageDisposition,
  type DependencyReviewReference,
  type DependencyUse,
  type DependencyVerdict,
  type ReviewedDependencyUse,
} from "./dependency-report-reader.js";
import type { DependencyTarget } from "./dependency-source-identity.js";
import { isRecord } from "./record.js";

export type {
  StackReport,
  StackAssessment,
  DependencyReviewReference,
  DependencyVerdict,
};
export type Check = z.infer<typeof reviewedDependencyCheckSchema>;
export type Advisory = z.infer<typeof dependencyAdvisoryDetailsSchema>;
export type Blocked = z.infer<typeof dependencyInvestigationBlockedSchema>;
export type Citation = DependencyUse["evidence"][number];
export type Service = NonNullable<ReviewedDependencyUse["services"]>[number];
export type InputSource = NonNullable<ReviewedDependencyUse["inputSource"]>;
export type RuntimeContext = NonNullable<
  ReviewedDependencyUse["runtimeContext"]
>;
type DependencyReportProof = NonNullable<ReviewedDependencyUse["proof"]>;
export type Site = NonNullable<DependencyReportProof["sink"]>["callSite"];
export type StepKind = "source" | "handoff" | "sink";
type Anchor = {
  path: string;
  line: number;
  kind: "call" | "reference";
};
type Entry = {
  id: string;
  anchor?: Anchor;
  label: string;
  excerpts: Record<string, string | undefined>;
};
export type PreparedCheck = {
  findings: Finding[];
  dismissed: Finding[];
};
export type Finding = Entry &
  (
    | {
        kind: "stack";
        assessment: StackAssessment;
        item: Partial<ReviewedDependencyUse> &
          Pick<
            ReviewedDependencyUse,
            | "reason"
            | "location"
            | "verdict"
            | "deployment"
            | "evidence"
            | "observations"
          >;
      }
    | {
        kind: "use";
        item: ReviewedDependencyUse;
      }
    | { kind: "coverage"; item: DependencyCoverageDisposition }
  );
export type Section = {
  title: string;
  check?: Check;
  blocked?: Blocked;
  pending?: boolean;
  stack?: StackReport;
  prepared?: PreparedCheck;
};
export type Report = {
  target?: DependencyTarget;
  contextHint?: string;
  title: string;
  context: string;
  description?: string;
  sections: Section[];
};
const findingOrder = [
  "exploitable",
  "potentially_exploitable",
  "unknown",
  "unresolved",
  "ruled_out",
] as const;
export const verdictOrder: DependencyVerdict[] = findingOrder.filter(
  (state) => state !== "unresolved",
);

function readReport(value: unknown): Report {
  const raw =
    isRecord(value) &&
    (value["answer"] !== undefined || value["data"] !== undefined)
      ? (value["answer"] ?? value["data"])
      : value;
  const stack = readStackReport(raw);
  if (stack)
    return {
      target: stack.target,
      title: stack.cve,
      context: "Sampled stacks",
      sections: [{ title: stack.cve, stack }],
    };
  if (
    isRecord(raw) &&
    raw["status"] === "blocked" &&
    raw["code"] === "INVESTIGATION_BLOCKED"
  ) {
    if (isRecord(raw["package"]) && Array.isArray(raw["checks"])) {
      const pkg = z
        .object({ ecosystem: z.string(), name: z.string() })
        .parse(raw["package"]);
      const sections = raw["checks"].map((entry): Section => {
        if (isRecord(entry) && entry["status"] === "blocked") {
          const { advisoryId, ...outcome } = entry;
          return {
            title:
              typeof advisoryId === "string" ? advisoryId : "Supplied advisory",
            blocked: dependencyInvestigationBlockedSchema.parse(outcome),
          };
        }
        const report = readDependencyCheckOutput({
          package: pkg,
          checks: [entry],
        });
        if ("cve" in report) throw new Error("Expected a package check.");
        const check = report.checks[0]!;
        return { title: check.advisoryId ?? "Supplied advisory", check };
      });
      const pending = z
        .array(z.string().nullable())
        .optional()
        .parse(raw["pendingAdvisories"]);
      for (const id of pending ?? [])
        sections.push({
          title: id ?? "Supplied advisory",
          pending: true,
          blocked: dependencyInvestigationBlockedSchema.parse(raw),
        });
      if (!sections.some((s) => s.blocked))
        sections.push({
          title: "Investigation",
          blocked: dependencyInvestigationBlockedSchema.parse(raw),
        });
      return {
        target: dependencyInvestigationBlockedSchema.shape.target.parse(
          raw["target"],
        ),
        title: pkg.name,
        context: `${pkg.ecosystem} package`,
        sections,
      };
    }
    const outcome = dependencyInvestigationBlockedSchema.parse(raw);
    return {
      target: outcome.target,
      title: outcome.cve ?? "Investigation blocked",
      context: "Run status",
      sections: [{ title: "Investigation", blocked: outcome }],
    };
  }
  const parsed = readDependencyCheckOutput(raw);
  if ("cve" in parsed)
    return {
      target: parsed.target,
      title: parsed.cve,
      context: "Dependency advisory",
      sections: [{ title: parsed.cve, check: parsed }],
    };
  return {
    target: parsed.target,
    title: parsed.package.name,
    context: `${parsed.package.ecosystem} package`,
    description: parsed.vulnDescription,
    sections: parsed.checks.map((check) => ({
      title: check.advisoryId ?? "Supplied advisory",
      check,
    })),
  };
}

export function refMatches(
  ref: DependencyReviewReference,
  deciding: DependencyReviewReference,
): boolean {
  if (ref.kind === "source" && deciding.kind === "source")
    return (
      ref.startLine <= ref.endLine &&
      ref.path === deciding.path &&
      ref.commit === deciding.commit &&
      deciding.startLine <= ref.startLine &&
      ref.endLine <= deciding.endLine
    );
  return (
    ref.kind === "receipt" &&
    deciding.kind === "receipt" &&
    ref.receiptId === deciding.receiptId &&
    ref.originalPayloadSha256 === deciding.originalPayloadSha256 &&
    JSON.stringify(ref.selection ?? null) ===
      JSON.stringify(deciding.selection ?? null)
  );
}
export function servicesFor(item: Finding["item"]): Service[] {
  return (item.services ?? []).filter((service) =>
    reviewedRefs(item, service.evidence),
  );
}
function reviewedRefs(
  item: Finding["item"],
  refs: DependencyReviewReference[],
) {
  return (
    refs.length > 0 &&
    refs.every((ref) =>
      item.decidingEvidence?.some((original) => refMatches(ref, original)),
    )
  );
}
export function inputFor(item: Finding["item"]): InputSource | undefined {
  return item.inputSource && reviewedRefs(item, item.inputSource.evidence)
    ? item.inputSource
    : undefined;
}
export function runtimeFor(item: Finding["item"]): RuntimeContext | undefined {
  return item.runtimeContext && reviewedRefs(item, item.runtimeContext.evidence)
    ? item.runtimeContext
    : undefined;
}
export function tagsFor(finding: Finding) {
  const p = finding.item.place;
  const names = [
    ...(finding.item.tags ?? [])
      .filter((tag) => reviewedRefs(finding.item, tag.evidence))
      .map((tag) => tag.name),
    p?.environment && `env:${p.environment}`,
    p?.variant && `variant:${p.variant}`,
    p?.role && `role:${p.role}`,
    p?.platform && `platform:${p.platform}`,
    p && p.kind !== "unknown" && `kind:${p.kind}`,
  ].filter((name): name is string => !!name);
  return [...new Set(names)];
}
function prepareCheck(check: Check, index: number) {
  const findings = check.uses.map((item, i): Finding => ({
    ...identity(item, item.proof),
    id: `use-${index}-${i + 1}`,
    kind: "use",
    item,
  }));
  const dismissed: Finding[] = [];
  for (const [i, item] of (check.coverage ?? []).entries()) {
    const group = item.kind === "dismissed" ? dismissed : findings;
    group.push({
      ...identity(item),
      id: `coverage-${index}-${i + 1}`,
      kind: "coverage",
      item,
    });
  }
  return prepareFindings(findings, dismissed);
}
function prepareFindings(
  findings: Finding[],
  dismissed: Finding[] = [],
): PreparedCheck {
  // Unresolved coverage follows unknown uses. Stable sorting keeps ties in input order.
  const rank = (f: Finding) =>
    findingOrder.indexOf(f.kind === "coverage" ? "unresolved" : f.item.verdict);
  findings.sort((a, b) => rank(a) - rank(b));
  return { findings, dismissed };
}
export function captureLimits({ coverage }: StackReport) {
  return [
    ["No matching sample", coverage.noMatch],
    ["Missing or incomplete sampling coverage", coverage.noCoverage],
    ["Conflicting scope", coverage.scopeConflicts],
    ["Truncated results or frames", coverage.truncated],
    ["Truncation unknown", coverage.truncationUnknown],
    ["Awaiting assessment", coverage.outstanding],
  ] as const;
}

export function counts(findings: readonly Finding[]) {
  const breakdown = Object.fromEntries(
    verdictOrder.map((v) => [v, 0]),
  ) as Record<DependencyVerdict, number>;
  let reviewed = 0,
    unresolved = 0;
  for (const finding of findings) {
    if (finding.kind === "use") reviewed++;
    if (finding.kind === "coverage") unresolved++;
    else breakdown[finding.item.verdict]++;
  }
  return { reviewed, unresolved, breakdown };
}

type Claims = NonNullable<Check["claims"]>;
function identity(
  item: Finding["item"],
  proof?: DependencyReportProof,
): Pick<Entry, "label" | "anchor" | "excerpts"> {
  const site = proof?.sink?.callSite;
  const cite =
    item.evidence.find((c) => c.supports.includes("affected_use")) ??
    item.evidence[0];
  const candidate =
    "locations" in item ? item.locations?.find((c) => c.line) : undefined;
  let anchor: Anchor | undefined;
  if (site) anchor = { kind: "call", path: site.path, line: site.line };
  else if (candidate?.line)
    anchor = { kind: "reference", path: candidate.path, line: candidate.line };
  else if (cite)
    anchor = { kind: "reference", path: cite.path, line: cite.startLine };
  const label =
    item.location ?? proof?.sink?.function ?? anchor?.path ?? item.reason;
  const excerpts = Object.fromEntries(
    item.evidence.map((c) => [citationKey(c), undefined]),
  );
  return { anchor, label, excerpts };
}
function stackFinding(
  assessment: StackAssessment,
  section: number,
  original: number,
): Finding {
  const { use, observation } = assessment;
  const nameAt = (index?: number | null) =>
    observation?.frames.find((f) => f.rawIndex === index)?.frame.name;
  const source = nameAt(observation?.sourceIndex);
  const sink = nameAt(observation?.sinkIndex);
  const location = use?.location ?? sink ?? assessment.queryId;
  const item = {
    ...use,
    location,
    verdict: assessment.verdict,
    reason: assessment.reason,
    evidence: use?.evidence ?? [],
    observations: [],
    deployment: use?.deployment ?? ("unknown" as const),
  };
  const proof = use?.proof;
  const label =
    source && sink
      ? source + " → " + sink
      : (proof?.sink?.function ?? location);
  return {
    ...identity(item, proof),
    id: `stack-${section}-${original + 1}`,
    kind: "stack",
    assessment,
    item,
    label,
  };
}
export const citationKey = ({
  path,
  commit,
  startLine,
  endLine,
}: Pick<Citation, "path" | "commit" | "startLine" | "endLine">) =>
  JSON.stringify(
    commit ? [path, commit, startLine, endLine] : [path, startLine, endLine],
  );
// Only use excerpts from claims attached to this finding, including their premises.
function loadExcerpts(
  section: Section,
  finding: Finding,
  claims: Map<string, Claims[number]>,
) {
  const { excerpts } = finding;
  if (!finding.item.evidence.length) return;
  function save(key: string, text: string) {
    if (Object.hasOwn(excerpts, key)) excerpts[key] = text;
  }
  if (finding.kind === "stack") {
    for (const claim of finding.assessment.claims)
      for (const source of claim.sources)
        save(citationKey(source), source.text);
    return;
  }
  const roots = [...(finding.item.supportingClaims ?? [])];
  if (finding.item.conclusionClaim) roots.push(finding.item.conclusionClaim);
  for (const { claim } of walkClaims(roots, claims)) {
    if (!claim) continue;
    for (const id of claim.evidence.sourceIds) {
      const source = section.check?.claimEvidence?.sources[id];
      if (!isRecord(source)) continue;
      const { path, commit, startLine, endLine } = source;
      const text = source["excerpt"] ?? source["text"];
      if (
        typeof text === "string" &&
        typeof path === "string" &&
        (commit === undefined || typeof commit === "string") &&
        typeof startLine === "number" &&
        typeof endLine === "number"
      )
        save(
          citationKey({ path, commit, startLine, endLine }),
          text.replace(/\n$/u, ""),
        );
    }
  }
}

export function prepareDependencyReport(value: unknown): Report {
  const report = readReport(value);
  for (const [i, section] of report.sections.entries()) {
    if (section.stack)
      section.prepared = prepareFindings(
        section.stack.assessments.map((a, j) => stackFinding(a, i + 1, j)),
      );
    if (section.check) {
      const check = section.check;
      if (check.advisoryDetails)
        check.advisoryDetails = check.advisoryDetails.filter((a) =>
          check.advisories.includes(a.url),
        );
      section.prepared = prepareCheck(check, i + 1);
    }
    if (!section.prepared) continue;
    const { findings, dismissed } = section.prepared;
    if (
      section.stack?.verdict === "unknown" ||
      findings.some(
        (f) => f.kind !== "coverage" && f.item.verdict === "unknown",
      )
    )
      report.contextHint = section.stack
        ? "If you know who controls the input, add that detail to the matching entry in --sources and rerun cs exploitability check."
        : "To clarify who controls the input, describe the callers in exploitability.scope.instructions and rerun with --config project.yaml. These instructions replace the default caller scope.";
    const claims = new Map(section.check?.claims?.map((c) => [claimKey(c), c]));
    for (const finding of [...findings, ...dismissed])
      loadExcerpts(section, finding, claims);
  }
  return report;
}

// A legacy sink may omit the revision. Bind only if the cited revision is
// unique. An explicit trace also needs a deciding reference for each step.
export function matchTraceFrame(
  finding: Finding,
  kind: StepKind,
  site: Site,
): { index: number; cite: Citation } | { gap: string } {
  const { item } = finding;
  const matches = item.evidence.filter(
    (c) =>
      c.path === site.path &&
      c.startLine <= site.line &&
      site.line <= c.endLine &&
      (c.commit === site.commit ||
        (kind === "sink" && site.commit === undefined)),
  );
  if (matches.some((c) => c.commit !== matches[0]?.commit))
    return { gap: "Sink revision is ambiguous across the cited copies." };
  const cite =
    matches.find((c) => finding.excerpts[citationKey(c)] !== undefined) ??
    matches[0];
  if (cite) {
    const ref = {
      kind: "source" as const,
      path: site.path,
      startLine: site.line,
      endLine: site.line,
      commit: cite.commit,
    };
    if ((kind === "sink" && !item.trace?.length) || reviewedRefs(item, [ref]))
      return { index: item.evidence.indexOf(cite), cite };
  }
  return { gap: "No matching reviewed citation for this step." };
}

export function sectionAdvisories({ check, stack }: Section) {
  // Use the same display projection (including the first body paragraph) without
  // altering the frozen advisory records used in the input and review digests.
  const details =
    check?.advisoryDetails ??
    (stack?.advisoryDetails &&
      reviewedDependencyCheckSchema.shape.advisoryDetails.parse(
        stack.advisoryDetails,
      )) ??
    [];
  return { details, urls: check?.advisories ?? details.map((a) => a.url) };
}

export function advisoryFunctions(details: Advisory[]) {
  return [
    ...new Set(
      details.flatMap((advisory) => [
        ...(advisory.vulnerableFunctions ?? []),
        ...(advisory.vulnerabilities ?? []).flatMap(
          (v) => v.vulnerable_functions ?? [],
        ),
        ...advisory.affected.flatMap((entry) => {
          const m = entry.ecosystem_specific;
          return !m
            ? []
            : "imports" in m
              ? m.imports.flatMap((i) => i.symbols ?? [])
              : (m.affects.functions ?? []);
        }),
      ]),
    ),
  ];
}
