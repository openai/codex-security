import {
  readStackReport,
  type StackReport,
  type StackAssessment,
} from "./dependency-report-stacks.js";
export type { StackReport, StackAssessment };

import { z } from "zod";
import type { dependencyAdvisoryDetailsSchema } from "./dependency-advisory.js";
import { dependencyInvestigationBlockedSchema } from "./dependency-report-reader.js";
import {
  claimKey,
  savedSnippets,
  citationKey,
} from "./dependency-report-proof.js";
export { citationKey };
type DependencyReportProof = NonNullable<ReviewedDependencyUse["proof"]>;
import {
  readDependencyCheckOutput,
  reviewedDependencyCheckSchema,
  type DependencyCoverageDisposition,
  type DependencyFindingDetails,
  type DependencyReviewReference,
  type DependencyUse,
  type DependencyVerdict,
  type ReviewedDependencyUse,
} from "./dependency-report-reader.js";
import { isRecord } from "./record.js";
import type { DependencyTarget } from "./dependency-source-identity.js";

export type {
  DependencyCoverageDisposition,
  DependencyFindingDetails,
  DependencyReviewReference,
  DependencyUse,
  DependencyVerdict,
  ReviewedDependencyUse,
};
export type Check = z.infer<typeof reviewedDependencyCheckSchema>;
export type Advisory = z.infer<typeof dependencyAdvisoryDetailsSchema>;
export type Blocked = z.infer<typeof dependencyInvestigationBlockedSchema>;
export type Citation = DependencyUse["evidence"][number];
export type Service = NonNullable<DependencyFindingDetails["services"]>[number];
export type InputSource = NonNullable<DependencyFindingDetails["inputSource"]>;
export type RuntimeContext = NonNullable<
  DependencyFindingDetails["runtimeContext"]
>;
type Anchor = {
  path: string;
  line: number;
  endLine?: number;
  commit?: string;
  kind: "call" | "reference" | "last_verified";
};
type Entry = {
  id: string;
  original: number;
  anchor?: Anchor;
  label: string;
  excerpts: Record<string, { text: string }>;
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
        proof?: DependencyReportProof;
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
        proof?: DependencyReportProof;
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
  reviewNote?: string;
  title: string;
  context: string;
  description?: string;
  sections: Section[];
};
export function useCountLabel(section: Section, count: number | "No"): string {
  const state =
    section.check?.reviewer === "disabled" ? "reported" : "reviewed";
  return `${count} ${state} ${count === 1 ? "use" : "uses"}`;
}
export const verdictOrder: DependencyVerdict[] = [
  "exploitable",
  "potentially_exploitable",
  "unknown",
  "ruled_out",
];
const verdictRank = (verdict: DependencyVerdict) =>
  verdictOrder.indexOf(verdict);
const useId = (check: number, index: number) => `use-${check}-${index}`;

function unwrap(value: unknown) {
  return isRecord(value) &&
    (value["answer"] !== undefined || value["data"] !== undefined)
    ? (value["answer"] ?? value["data"])
    : value;
}
function readReport(raw: unknown): Report {
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
export function reviewedRefs(
  item: Finding["item"],
  refs: DependencyReviewReference[],
) {
  return (
    refs.length > 0 &&
    refs.every((ref) =>
      (item.decidingEvidence ?? []).some((original) =>
        refMatches(ref, original),
      ),
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
    ...(p
      ? [
          p.environment && `env:${p.environment}`,
          p.variant && `variant:${p.variant}`,
          p.role && `role:${p.role}`,
          p.platform && `platform:${p.platform}`,
          p.kind !== "unknown" && `kind:${p.kind}`,
        ]
      : []),
  ].filter((name): name is string => !!name);
  return [...new Set(names)].map((name) => ({ name }));
}
function prepareCheck(check: Check, index: number) {
  const findings: Finding[] = [
    ...check.uses.map((item, i): Finding => ({
      ...identity(item, item.proof),
      id: useId(index, i + 1),
      original: i,
      kind: "use",
      item,
      proof: item.proof,
    })),
    ...(check.coverage ?? []).flatMap((item, i): Finding[] =>
      item.kind === "unresolved"
        ? [
            {
              ...identity(item),
              id: `coverage-${index}-${i + 1}`,
              original: i,
              kind: "coverage",
              item,
            },
          ]
        : [],
    ),
  ];
  return prepareFindings(findings);
}
function prepareFindings(findings: Finding[]): PreparedCheck {
  const order = (finding: Finding) =>
    finding.kind !== "coverage" ? verdictRank(finding.item.verdict) : 2.5;
  findings.sort(
    (a, b) =>
      order(a) - order(b) ||
      a.original - b.original ||
      a.id.localeCompare(b.id),
  );
  return { findings, dismissed: [] };
}
export function counts(findings: readonly Finding[]) {
  const breakdown = Object.fromEntries(
    verdictOrder.map((v) => [v, 0]),
  ) as Record<DependencyVerdict, number>;
  let assessed = 0;
  let reviewed = 0,
    unresolved = 0;
  for (const item of findings)
    if (item.kind === "use") {
      reviewed++;
      breakdown[item.item.verdict]++;
    } else if (item.kind === "stack") {
      assessed++;
      breakdown[item.item.verdict]++;
    } else unresolved++;
  return { reviewed, assessed, unresolved, breakdown };
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
  if (site) {
    const revisions = new Set(
      item.evidence
        .filter(
          (c) =>
            c.path === site.path &&
            c.startLine <= site.line &&
            c.endLine >= site.line,
        )
        .map((c) => c.commit),
    );
    const commit =
      site.commit ?? (revisions.size === 1 ? [...revisions][0] : undefined);
    anchor = { ...site, commit, kind: "call" };
  } else if (candidate?.line)
    anchor = { kind: "reference", path: candidate.path, line: candidate.line };
  else if (cite)
    anchor = {
      kind: "reference",
      path: cite.path,
      commit: cite.commit,
      line: cite.startLine,
      endLine: cite.endLine,
    };
  const label =
    item.location ?? proof?.sink?.function ?? anchor?.path ?? item.reason;
  return { anchor, label, excerpts: {} };
}
function stackFinding(
  assessment: StackAssessment,
  section: number,
  original: number,
): Finding {
  const id = "stack-" + section + "-" + (original + 1);
  const { use, observation } = assessment;
  const source = observation?.frames.find(
    (f) => f.rawIndex === observation.sourceIndex,
  )?.frame.name;
  const sink = observation?.frames.find(
    (f) => f.rawIndex === observation.sinkIndex,
  )?.frame.name;
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
    id,
    original,
    kind: "stack",
    assessment,
    item,
    proof,
    label,
  };
}
function loadExcerpts(
  section: Section,
  finding: Finding,
  claims: Map<string, Claims[number]>,
) {
  const saved = savedSnippets(section, finding, claims);
  for (const cite of finding.item.evidence) {
    const key = citationKey(cite);
    const text = saved.get(key);
    if (text !== undefined) finding.excerpts[key] = { text };
  }
}

export function prepareDependencyReport(value: unknown): Report {
  const raw = unwrap(value);
  const report = readReport(raw);
  if (isRecord(raw) && raw["reviewer"] === "disabled")
    report.reviewNote = "Independent review disabled";
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
      section.prepared.dismissed = (check.coverage ?? []).flatMap(
        (item, j): Finding[] =>
          item.kind === "dismissed"
            ? [
                {
                  kind: "coverage",
                  id: "coverage-" + (i + 1) + "-" + (j + 1),
                  original: j,
                  item,
                  ...identity(item),
                },
              ]
            : [],
      );
    }
    if (
      section.check?.uses.some((use) => use.verdict === "unknown") ||
      section.stack?.verdict === "unknown" ||
      section.stack?.assessments.some((a) => a.verdict === "unknown")
    )
      report.contextHint = section.stack
        ? "Have more context? Describe who controls the input in the relevant entry in your --sources JSON, then rerun cs exploitability check with the updated inputs."
        : "Have more context? Set exploitability.scope.instructions in project.yaml to describe the callers and what they control, then rerun with --config project.yaml. This replaces the default caller scope.";
    const claims = new Map(section.check?.claims?.map((c) => [claimKey(c), c]));
    if (section.prepared)
      for (const finding of [
        ...section.prepared.findings,
        ...section.prepared.dismissed,
      ])
        loadExcerpts(section, finding, claims);
  }
  return report;
}

// A legacy sink may omit the revision. Bind only if the cited revision is
// unique. An explicit trace also needs a deciding reference for each step.
export function matchTraceFrame(
  finding: Finding,
  kind: "source" | "handoff" | "sink",
  site: { path: string; line: number; commit?: string },
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
  if (new Set(matches.map((c) => c.commit)).size > 1)
    return { gap: "Sink revision is ambiguous across the cited copies." };
  const cite =
    matches.find((c) => finding.excerpts[citationKey(c)]) ?? matches[0];
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
