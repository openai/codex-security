import { createHash } from "node:crypto";
import { realpath } from "node:fs/promises";
import { z } from "zod";
import type { dependencyAdvisoryDetailsSchema } from "./dependency-advisory.js";
import { dependencyInvestigationBlockedSchema } from "./dependency-report-submission.js";
import { renderDependencyCode } from "./dependency-report-code.js";
import {
  parseDependencyReportProof,
  type DependencyReportProof,
} from "./dependency-report-proof.js";
import { reportInteractions, reportStyles } from "./dependency-report-ui.js";
import { dependencyVerdictLabels } from "./dependency-verdict-labels.js";
import {
  readDependencyCheckOutput,
  readDependencyEvidence,
  type reviewedDependencyCheckSchema,
  type DependencyCoverageDisposition,
  type DependencyFindingDetails,
  type DependencyReviewReference,
  type DependencyUse,
  type DependencyVerdict,
  type ReviewedDependencyUse,
} from "./dependency-reachability.js";
import { isRecord } from "./record.js";

type Check = z.infer<typeof reviewedDependencyCheckSchema>;
type Advisory = z.infer<typeof dependencyAdvisoryDetailsSchema>;
type Blocked = z.infer<typeof dependencyInvestigationBlockedSchema>;
type Citation = DependencyUse["evidence"][number];
type Place = ReviewedDependencyUse["place"];
type Service = NonNullable<DependencyFindingDetails["services"]>[number];
type InputSource = NonNullable<DependencyFindingDetails["inputSource"]>;
type RuntimeContext = NonNullable<DependencyFindingDetails["runtimeContext"]>;
type Finding = { id: string; groups: string[]; original: number } & (
  | {
      kind: "use";
      item: ReviewedDependencyUse;
      proof?: DependencyReportProof;
      calls: ProductionCall[];
    }
  | { kind: "coverage"; item: DependencyCoverageDisposition }
);
type Group = {
  id: string;
  name: string;
  stableId?: string;
  findings: Finding[];
  fallback?: boolean;
};
type Section = { title: string; check?: Check; blocked?: Blocked };
type Report = {
  title: string;
  context: string;
  description?: string;
  sections: Section[];
};
interface ReportRenderOptions {
  code?: ReadonlyMap<string, string>;
  productionCalls?: unknown;
  advisoryDetails?: readonly Advisory[];
  useEvidence?: unknown;
}

const productionCallSchema = z
  .strictObject({
    useId: z.string().min(1),
    location: z.string().min(1),
    step: z.enum(["source", "path", "sink"]),
    environment: z.literal("prod"),
    count: z.number().int().nonnegative(),
    from: z.iso.datetime({ offset: true }),
    until: z.iso.datetime({ offset: true }),
    target: z.string().trim().min(1),
    record: z.string().trim().min(1),
  })
  .refine(({ from, until }) => Date.parse(from) < Date.parse(until), {
    path: ["until"],
    message: "The production measurement must end after it starts.",
  });
type ProductionCall = z.infer<typeof productionCallSchema>;

const verdictOrder: DependencyVerdict[] = [
  "exploitable",
  "potentially_exploitable",
  "unknown",
  "ruled_out",
];
const verdictRank = (verdict: DependencyVerdict) =>
  verdictOrder.indexOf(verdict);
const esc = (value: string) =>
  value.replace(
    /[&<>"'\r]/gu,
    (ch) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
        "\r": "&#13;",
      })[ch]!,
  );
const code = (value: string) => `<code>${esc(value)}</code>`;
const n = (count: number, noun: string) =>
  `${count.toLocaleString("en-US")} ${noun}${count === 1 ? "" : "s"}`;
const useId = (check: number, index: number) => `use-${check}-${index}`;
const citationKey = ({
  path,
  commit,
  startLine,
  endLine,
}: Pick<Citation, "path" | "commit" | "startLine" | "endLine">) =>
  JSON.stringify(
    commit ? [path, commit, startLine, endLine] : [path, startLine, endLine],
  );
const rangeLabel = ({
  path,
  startLine,
  endLine,
}: Pick<Citation, "path" | "startLine" | "endLine">) =>
  `${path}:${startLine}${endLine === startLine ? "" : `–${endLine}`}`;
const status = (verdict: DependencyVerdict) =>
  `<span class="status" data-verdict="${verdict}"><span class="dot" aria-hidden="true"></span>${dependencyVerdictLabels[verdict]}</span>`;
const coverageStatus =
  '<span class="status coverage-status"><span class="dot" aria-hidden="true"></span>Unresolved coverage</span>';
const normalize = (value: string) =>
  value.trim().replace(/\s+/gu, " ").toLocaleLowerCase();
const digest = (value: string) =>
  createHash("sha256").update(value).digest("hex").slice(0, 16);

function link(value: string, label = value) {
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
function prose(text: string) {
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
function unwrap(value: unknown) {
  return isRecord(value) &&
    (value["answer"] !== undefined || value["data"] !== undefined)
    ? (value["answer"] ?? value["data"])
    : value;
}
function readReport(value: unknown): Report {
  const raw = unwrap(value);
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
      return { title: pkg.name, context: `${pkg.ecosystem} package`, sections };
    }
    const outcome = dependencyInvestigationBlockedSchema.parse(raw);
    return {
      title: "Investigation blocked",
      context: "Run status",
      sections: [{ title: "Investigation", blocked: outcome }],
    };
  }
  const parsed = readDependencyCheckOutput(raw);
  if ("cve" in parsed)
    return {
      title: parsed.cve,
      context: "Dependency advisory",
      sections: [{ title: parsed.cve, check: parsed }],
    };
  return {
    title: parsed.package.name,
    context: `${parsed.package.ecosystem} package`,
    description: parsed.vulnDescription,
    sections: parsed.checks.map((check) => ({
      title: check.advisoryId ?? "Supplied advisory",
      check,
    })),
  };
}

/** Read exactly the individually cited ranges from the explicitly supplied checkout. */
export async function readDependencyReportCode(
  value: unknown,
  checkout: string,
) {
  const citations = new Map(
    readReport(value).sections.flatMap(({ check }) =>
      check
        ? [...check.uses, ...(check.coverage ?? [])].flatMap(({ evidence }) =>
            evidence.map((cite) => [citationKey(cite), cite] as const),
          )
        : [],
    ),
  );
  const snippets = new Map<string, string>();
  if (citations.size)
    await readDependencyEvidence(
      [...citations.values()],
      await realpath(checkout),
      undefined,
      (excerpt) => snippets.set(citationKey(excerpt), excerpt.text),
    );
  return snippets;
}

function refMatches(
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
function servicesFor(
  item: ReviewedDependencyUse | DependencyCoverageDisposition,
): Service[] {
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
      (item.decidingEvidence ?? []).some((original) =>
        refMatches(ref, original),
      ),
    )
  );
}
function inputFor(item: Finding["item"]): InputSource | undefined {
  return item.inputSource && reviewedRefs(item, item.inputSource.evidence)
    ? item.inputSource
    : undefined;
}
function runtimeFor(item: Finding["item"]): RuntimeContext | undefined {
  return item.runtimeContext && reviewedRefs(item, item.runtimeContext.evidence)
    ? item.runtimeContext
    : undefined;
}
const exposureLabels = {
  internet: "Internet exposed",
  not_internet: "Not internet exposed",
  unknown: "Exposure unverified",
} as const;
function exposure(finding: Finding): InputSource["exposure"] {
  return inputFor(finding.item)?.exposure ?? "unknown";
}
function tagsFor(finding: Finding) {
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
  return [...new Set(names)].map((name) => ({
    id: `tag-${digest(name)}`,
    name,
  }));
}
function fallback(place?: Place): { key: string; name: string } {
  const sourceOnly =
    place?.kind === "library_caller" &&
    place.deploymentBasis === "unknown" &&
    !place.environment &&
    !place.artifact;
  return sourceOnly
    ? { key: "source", name: "Source-only findings" }
    : { key: "unmapped", name: "Service not established" };
}
function buildGroups(
  check: Check,
  index: number,
  proofs: ReadonlyMap<string, DependencyReportProof>,
  calls: ReadonlyMap<string, ProductionCall[]>,
) {
  const findings: Finding[] = [
    ...check.uses.map((item, i): Finding => ({
      id: useId(index, i + 1),
      original: i,
      groups: [],
      kind: "use",
      item,
      proof: proofs.get(useId(index, i + 1)),
      calls: calls.get(useId(index, i + 1)) ?? [],
    })),
    ...(check.coverage ?? []).flatMap((item, i): Finding[] =>
      item.kind === "unresolved"
        ? [
            {
              id: `coverage-${index}-${i + 1}`,
              original: i,
              groups: [],
              kind: "coverage",
              item,
            },
          ]
        : [],
    ),
  ];
  const groups = new Map<string, Group>();
  for (const finding of findings) {
    const services = servicesFor(finding.item);
    const selected: {
      key: string;
      name: string;
      stableId?: string;
      fallback?: boolean;
    }[] = services.length
      ? services.map((service) => ({
          key: `catalog:${service.id}`,
          name: service.name,
          stableId: service.id,
        }))
      : [{ ...fallback(finding.item.place), fallback: true }];
    for (const selection of selected) {
      const id = `service-${index}-${digest(selection.key)}`;
      let group = groups.get(id);
      if (!group) {
        group = {
          id,
          name: selection.name,
          ...(selection.stableId && { stableId: selection.stableId }),
          ...(selection.fallback && { fallback: true }),
          findings: [],
        };
        groups.set(id, group);
      }
      if (!finding.groups.includes(id)) {
        finding.groups.push(id);
        group.findings.push(finding);
      }
    }
  }
  const order = (finding: Finding) =>
    finding.kind === "use" ? verdictRank(finding.item.verdict) : 2.5;
  findings.sort(
    (a, b) =>
      order(a) - order(b) ||
      a.original - b.original ||
      a.id.localeCompare(b.id),
  );
  for (const group of groups.values())
    group.findings.sort(
      (a, b) => order(a) - order(b) || a.original - b.original,
    );
  return {
    findings,
    groups: [...groups.values()].sort(
      (a, b) =>
        Number(!!a.fallback) - Number(!!b.fallback) ||
        a.name.localeCompare(b.name) ||
        a.id.localeCompare(b.id),
    ),
  };
}
function counts(findings: readonly Finding[]) {
  const breakdown = Object.fromEntries(
    verdictOrder.map((v) => [v, 0]),
  ) as Record<DependencyVerdict, number>;
  let reviewed = 0,
    unresolved = 0;
  for (const item of findings)
    if (item.kind === "use") {
      reviewed++;
      breakdown[item.item.verdict]++;
    } else unresolved++;
  return { reviewed, unresolved, breakdown };
}
function shortBreakdown(data: ReturnType<typeof counts>) {
  return verdictOrder
    .filter((v) => data.breakdown[v])
    .map(
      (v) =>
        `<span class="status" data-verdict="${v}">${data.breakdown[v]} ${dependencyVerdictLabels[v]}</span>`,
    )
    .join("");
}
function serviceIndex(groups: Group[], findings: Finding[], index: number) {
  const first = findings[0]?.id ?? `check-${index}`;
  const entry = (
    id: string,
    name: string,
    list: Finding[],
    stable?: string,
  ) => {
    const c = counts(list),
      href = list[0]?.id ?? first;
    const exposed = list.filter((f) => exposure(f) === "internet").length;
    const unverified = list.filter((f) => exposure(f) === "unknown").length;
    return `<li><a class="service-link" href="#${href}" data-service-link data-service="${id}" data-name="${esc(name)}"${stable ? ` title="${esc(stable)}"` : ""}><span class="service-name">${esc(name)}</span><span class="service-counts">${n(c.reviewed, "reviewed use")}${c.unresolved ? ` · ${n(c.unresolved, "unresolved item")}` : ""}</span>${shortBreakdown(c) ? `<span class="service-breakdown">${shortBreakdown(c)}</span>` : ""}${exposed || unverified ? `<span class="service-exposure">${exposed ? `${exposed} internet exposed` : ""}${exposed && unverified ? " · " : ""}${unverified ? `${unverified} exposure unverified` : ""}</span>` : ""}</a></li>`;
  };
  const tags = [
    ...new Map(findings.flatMap(tagsFor).map((tag) => [tag.id, tag])).values(),
  ].sort((a, b) => a.name.localeCompare(b.name));
  return `<aside class="sidebar"><details class="service-navigation" data-service-navigation open><summary>Services and source scope</summary><nav aria-label="Services in advisory ${index}"><div class="filters" data-filters hidden><label>Find a service, instance or finding<input type="search" data-search autocomplete="off"></label><label>Input source exposure<select data-exposure-filter><option value="">All exposure states</option>${Object.entries(
    exposureLabels,
  )
    .map(([value, label]) => `<option value="${value}">${label}</option>`)
    .join(
      "",
    )}</select></label><label>Outcome<select data-verdict-filter><option value="">All outcomes</option>${verdictOrder.map((v) => `<option value="${v}">${dependencyVerdictLabels[v]}</option>`).join("")}<option value="unresolved">Unresolved coverage</option></select></label><label>Deployment<select data-deployment-filter><option value="">All deployment states</option><option value="confirmed">Observed running</option><option value="configured">Configured</option><option value="unknown">Deployment unverified</option></select></label>${tags.length ? `<label>Tag<select data-tag-filter><option value="">All tags</option>${tags.map((tag) => `<option value="${tag.id}">${esc(tag.name)}</option>`).join("")}</select></label>` : ""}</div><ul class="service-list">${entry("all", "All services and source scope", findings)}${groups.map((g) => entry(g.id, g.name, g.findings, g.stableId)).join("")}</ul></nav></details></aside>`;
}
function advisoryFunctions(details: Advisory[]) {
  return [
    ...new Set(
      details.flatMap((advisory) => [
        ...(advisory.vulnerableFunctions ?? []),
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
function advisoryBrief(check: Check, extra: Map<string, Advisory>) {
  const details = check.advisories
    .map(
      (url) =>
        check.advisoryDetails?.find((a) => a.url === url) ?? extra.get(url),
    )
    .filter((x): x is Advisory => !!x);
  const primary =
    details.find((d) => d.overview) ??
    details.find((d) => d.summary) ??
    details[0];
  const functions = advisoryFunctions(details);
  const packages = [
    ...new Map(
      details.flatMap((d) =>
        d.affected.flatMap((a) =>
          a.package
            ? [
                [
                  `${a.package.ecosystem}:${a.package.name}`,
                  a.ranges?.flatMap((r) =>
                    r.type === "GIT"
                      ? []
                      : r.events.flatMap((e) =>
                          "fixed" in e ? [e.fixed] : [],
                        ),
                  ) ?? [],
                ] as const,
              ]
            : [],
        ),
      ),
    ).entries(),
  ];
  if (!primary && !check.advisories.length) return "";
  return `<section class="brief" aria-label="Advisory context"><div class="brief-title"><h3>${primary?.summary ? prose(primary.summary) : "Advisory"}</h3>${primary ? link(primary.url, primary.id ?? "Advisory source") : ""}</div>${primary?.overview ? `<p>${prose(primary.overview)}</p>` : ""}${functions.length ? `<div class="symbols"><span class="muted">Vulnerable functions</span>${functions.map(code).join("")}</div>` : ""}${packages.length ? `<p class="muted">Affected ${packages.map(([name, fixes]) => `${code(name)}${fixes.length ? ` (fixed in ${fixes.map(esc).join(", ")})` : ""}`).join(" · ")}</p>` : ""}${
    details.some((d) => d.applicability)
      ? `<details><summary>Advisory conditions</summary>${details
          .filter((d) => d.applicability)
          .map((d) => `<p>${prose(d.applicability!)}</p>`)
          .join("")}</details>`
      : ""
  }${check.advisories.length > 1 || !primary ? `<p class="muted">References: ${check.advisories.map((url) => link(url)).join(" · ")}</p>` : ""}</section>`;
}

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
function deployment(finding: Finding) {
  return finding.item.place?.deploymentBasis === "observed"
    ? "confirmed"
    : finding.item.place?.deploymentBasis === "configured"
      ? "configured"
      : finding.kind === "use"
        ? finding.item.deployment
        : "unknown";
}
function scopeLine(finding: Finding) {
  const p = finding.item.place;
  const recordedDeployment = p
    ? deploymentLabels[p.deploymentBasis]
    : finding.kind === "use"
      ? {
          confirmed: "Observed running",
          configured: "Configured",
          unknown: "Deployment unverified",
        }[finding.item.deployment]
      : undefined;
  const values = [
    p && placeLabels[p.kind],
    recordedDeployment,
    p?.environment,
    p?.variant,
    p?.role,
    p?.platform,
    p?.observationWindow,
  ].filter((x): x is string => !!x);
  return values.length
    ? `<div class="scope-line">${values.map((v) => `<span>${esc(v)}</span>`).join("")}</div>`
    : "";
}
function sourceIndex(
  item: Finding["item"],
  ref: Extract<DependencyReviewReference, { kind: "source" }>,
) {
  return item.evidence.findIndex(
    (c) =>
      c.path === ref.path &&
      c.commit === ref.commit &&
      c.startLine <= ref.startLine &&
      c.endLine >= ref.endLine,
  );
}
function receiptRefs(item: Finding["item"]) {
  return [
    ...new Map(
      (item.decidingEvidence ?? [])
        .filter(
          (r): r is Extract<DependencyReviewReference, { kind: "receipt" }> =>
            r.kind === "receipt",
        )
        .map((r) => [JSON.stringify(r), r]),
    ).values(),
  ];
}
function refLink(finding: Finding, ref: DependencyReviewReference) {
  const at =
    ref.kind === "source"
      ? sourceIndex(finding.item, ref)
      : receiptRefs(finding.item).findIndex((r) => refMatches(ref, r));
  const label = ref.kind === "source" ? rangeLabel(ref) : ref.receiptId;
  return at < 0
    ? code(label)
    : `<a href="#${finding.id}-${ref.kind === "source" ? "source" : "receipt"}-${at + 1}">${code(label)}</a>`;
}
function referenceList(finding: Finding, refs: DependencyReviewReference[]) {
  return refs.map((ref) => refLink(finding, ref)).join(" · ");
}
function findSavedSnippet(
  check: Check,
  finding: Finding,
  cite: Citation,
): string | undefined {
  const refs = [
    finding.item.conclusionClaim,
    ...(finding.item.supportingClaims ?? []),
  ].filter(Boolean);
  const sourceIds = new Set(
    refs.flatMap(
      (ref) =>
        check.claims?.find(
          (claim) =>
            claim.id === ref!.id &&
            claim.revision === ref!.revision &&
            claim.hash === ref!.hash,
        )?.evidence.sourceIds ?? [],
    ),
  );
  for (const id of sourceIds) {
    const source = check.claimEvidence?.sources[id];
    if (
      isRecord(source) &&
      source["path"] === cite.path &&
      source["commit"] === cite.commit &&
      source["startLine"] === cite.startLine &&
      source["endLine"] === cite.endLine &&
      typeof source["text"] === "string"
    )
      return source["text"];
  }
}
function snippet(
  check: Check,
  finding: Finding,
  cite: Citation,
  options: ReportRenderOptions,
) {
  return (
    options.code?.get(citationKey(cite)) ??
    findSavedSnippet(check, finding, cite)
  );
}
function renderSource(
  check: Check,
  finding: Finding,
  cite: Citation,
  i: number,
  options: ReportRenderOptions,
) {
  const text = snippet(check, finding, cite, options);
  const sink =
    finding.kind === "use" ? finding.proof?.sink?.callSite : undefined;
  const highlight =
    sink &&
    sink.path === cite.path &&
    sink.line >= cite.startLine &&
    sink.line <= cite.endLine
      ? new Set([sink.line])
      : undefined;
  const deciding = (finding.item.decidingEvidence ?? []).some(
    (r) =>
      r.kind === "source" &&
      r.path === cite.path &&
      r.commit === cite.commit &&
      r.startLine <= cite.endLine &&
      r.endLine >= cite.startLine,
  );
  const firstSinkRange =
    sink &&
    finding.item.evidence.findIndex(
      (range) =>
        range.path === sink.path &&
        range.startLine <= sink.line &&
        range.endLine >= sink.line,
    );
  const primary = !!highlight && text !== undefined && firstSinkRange === i;
  const label = primary
    ? `<a href="#${finding.id}-source-${i + 1}">${code(rangeLabel(cite))}</a>`
    : code(rangeLabel(cite));
  return `<li${primary ? "" : ` id="${finding.id}-source-${i + 1}"`}><div>${label}${cite.commit ? ` <span class="muted">revision ${code(cite.commit)}</span>` : ""}${deciding ? ' <span class="evidence-ref">· Reviewer cited</span>' : ""}</div>${cite.supports.length ? `<div class="evidence-ref">${cite.supports.map((f) => factLabels[f] ?? esc(f)).join(" · ")}</div>` : ""}${text !== undefined && !primary ? `<details class="source-snippet"><summary>Source excerpt</summary>${renderDependencyCode(text, cite.path, cite.startLine, highlight)}</details>` : ""}</li>`;
}
function receiptMetadata(
  check: Check,
  ref: Extract<DependencyReviewReference, { kind: "receipt" }>,
) {
  return Object.values(check.claimEvidence?.receipts ?? {}).find(
    (v) =>
      isRecord(v) &&
      v["receiptId"] === ref.receiptId &&
      v["originalPayloadSha256"] === ref.originalPayloadSha256 &&
      JSON.stringify(v["selection"] ?? null) ===
        JSON.stringify(ref.selection ?? null),
  );
}
function renderReceipt(
  check: Check,
  finding: Finding,
  ref: Extract<DependencyReviewReference, { kind: "receipt" }>,
  i: number,
) {
  const saved = receiptMetadata(check, ref);
  const origin =
    isRecord(saved) && isRecord(saved["origin"]) ? saved["origin"] : undefined;
  const tool = origin && isRecord(origin["tool"]) ? origin["tool"] : undefined;
  const server =
    isRecord(saved) && typeof saved["server"] === "string"
      ? saved["server"]
      : undefined;
  const name =
    tool && typeof tool["name"] === "string"
      ? tool["name"]
      : typeof origin?.["tool"] === "string"
        ? origin["tool"]
        : undefined;
  const outcome =
    isRecord(saved) && typeof saved["outcome"] === "string"
      ? saved["outcome"]
      : undefined;
  return `<li id="${finding.id}-receipt-${i + 1}"><strong>${code(ref.receiptId)}</strong><div class="receipt-meta">${server ? `<span>${esc(server)}${name ? ` / ${esc(name)}` : ""}</span>` : ""}${outcome ? `<span>Recorded outcome: ${esc(outcome)}</span>` : ""}<span>SHA-256 ${code(ref.originalPayloadSha256)}</span>${ref.selection ? `<span>Selected record ${code(JSON.stringify(ref.selection))}</span>` : ""}</div></li>`;
}
function evidence(
  check: Check,
  finding: Finding,
  options: ReportRenderOptions,
) {
  const refs = receiptRefs(finding.item),
    obs = finding.item.observations;
  return `<details class="disclosure"><summary>Evidence and review references</summary>${finding.item.evidence.length ? `<h4 class="section-title">Source ranges</h4><ul class="evidence-list">${finding.item.evidence.map((c, i) => renderSource(check, finding, c, i, options)).join("")}</ul>` : ""}${refs.length ? `<h4 class="section-title" style="margin-top:1rem">Original receipts</h4><ul class="evidence-list">${refs.map((r, i) => renderReceipt(check, finding, r, i)).join("")}</ul>` : ""}${obs.length ? `<h4 class="section-title" style="margin-top:1rem">Recorded observations</h4><ul class="evidence-list">${obs.map((o) => `<li><strong>${esc(o.server)}</strong><p>${esc(o.record)}</p>${o.supports.length ? `<p class="evidence-ref">${o.supports.map((f) => factLabels[f]).join(" · ")}</p>` : ""}</li>`).join("")}</ul>` : ""}${finding.item.supportingClaims?.length ? `<p class="evidence-ref" style="margin-top:.8rem">Approved shared premises: ${finding.item.supportingClaims.map((p) => code(`${p.id}${":r"}${p.revision}`)).join(" · ")}</p>` : ""}${!finding.item.evidence.length && !refs.length && !obs.length ? '<p class="muted">No original references were saved.</p>' : ""}</details>`;
}
function serviceMappings(finding: Finding) {
  const verified = servicesFor(finding.item);
  if (!verified.length)
    return finding.item.services?.length
      ? '<p class="muted">The proposed service mapping was not confirmed by this item’s deciding evidence.</p>'
      : "";
  return `<details class="disclosure"><summary>Verified service association${verified.length === 1 ? "" : "s"}</summary><ul class="evidence-list">${verified.map((s) => `<li><strong>${esc(s.name)}</strong> <span class="muted">${code(s.id)}</span><p class="evidence-ref">Mapping source: ${esc(s.source)} · ${referenceList(finding, s.evidence)}</p></li>`).join("")}</ul></details>`;
}
function targetDetails(finding: Finding) {
  const p = finding.item.place;
  if (!p) return "";
  const pairs: [string, string | null | undefined][] = [
    ["Workload", p.workload],
    ["Environment", p.environment],
    ["Variant", p.variant],
    ["Role", p.role],
    ["Revision", p.revision],
    ["Artifact", p.artifact],
    ["Image index", p.imageIndex],
    ["Platform manifest", p.platformManifest],
    ["Platform", p.platform],
    ["Observation window", p.observationWindow],
    ["Deployment basis", p.deploymentDetail],
    ["Selected dependency", p.dependencySelection],
    ["Patch or backport", p.patch],
  ];
  const present = pairs.filter(
    (x): x is [string, string] => typeof x[1] === "string" && !!x[1],
  );
  return present.length
    ? `<details class="disclosure"><summary>Target, shipped artifact and dependency selection</summary><dl class="metadata">${present.map(([label, value]) => `<dt>${label}</dt><dd>${esc(value)}</dd>`).join("")}</dl></details>`
    : "";
}
function sourceContext(finding: Finding) {
  const source = inputFor(finding.item);
  if (!source) return "";
  return `<section class="source-context"><h4 class="section-title">Input source</h4><p><strong>${exposureLabels[source.exposure]}</strong>${source.endpoint ? ` · ${link(source.endpoint)}` : ""}</p><p class="evidence-ref">${referenceList(finding, source.evidence)}</p><p class="evidence-ref">Internet exposure describes the input boundary. It does not by itself establish control of the bytes or a path to the vulnerable operation.</p></section>`;
}
function runtimeContext(finding: Finding) {
  const runtime = runtimeFor(finding.item);
  if (!runtime) return "";
  const mitigation = runtime.mitigation;
  return `<section class="runtime-context"><h4 class="section-title">Instance and launch</h4>${runtime.launch ? `<p><b>Launch command (${runtime.launch.basis}):</b> ${code(runtime.launch.command)}</p>` : ""}${mitigation ? `<p><b>Mitigation ${mitigation.state === "unknown" ? "unverified" : mitigation.state} (${mitigation.basis}):</b> ${esc(mitigation.detail)}</p>` : ""}${runtime.containerUrl ? `<p><b>Container:</b> ${link(runtime.containerUrl)}</p>` : ""}${runtime.traceUrl ? `<p><b>Reachability trace:</b> ${link(runtime.traceUrl)}</p>` : ""}<p class="evidence-ref">Instance evidence: ${referenceList(finding, runtime.evidence)}</p></section>`;
}
function openQuestions(finding: Finding) {
  const item = finding.item;
  const structured = item.openConditions ?? [];
  const alreadyInSummary = (question: string) =>
    normalize(item.reason).includes(normalize(question)) ||
    normalize(structured[0]?.question ?? "") === normalize(question);
  const old = (item.place?.unresolvedQuestions ?? []).filter(
    (q) =>
      !alreadyInSummary(q) &&
      !structured.some((s) => normalize(s.question) === normalize(q)),
  );
  if (!structured.length && !old.length)
    return (finding.kind === "use" && finding.item.verdict === "unknown") ||
      finding.kind === "coverage"
      ? '<p class="muted">No separate deciding check was recorded.</p>'
      : "";
  return `<section class="need"><h4>What would decide this</h4><ul class="questions">${structured.map((q) => `<li>${alreadyInSummary(q.question) ? "" : `<p class="question">${esc(q.question)}</p>`}<p class="question-detail"><b>Target:</b> ${esc(q.target)}</p>${q.decidingCheck ? `<p class="question-detail"><b>Deciding check:</b> ${esc(q.decidingCheck)}</p>` : '<p class="question-detail">No deciding check recorded.</p>'}${q.ruledOutIf ? `<p class="question-detail"><b>Rules out this path if:</b> ${esc(q.ruledOutIf)}</p>` : ""}${q.assignee ? `<p class="question-detail"><b>Assignee:</b> ${esc(q.assignee.name)} · ${referenceList(finding, q.assignee.evidence)}</p>` : ""}</li>`).join("")}${old.map((q) => `<li><p class="question">${esc(q)}</p><p class="question-detail">No deciding check recorded.</p></li>`).join("")}</ul></section>`;
}
function conditions(finding: Finding) {
  if (finding.kind !== "use" || !finding.proof?.conditions.length) return "";
  return `<section><h4 class="section-title">Advisory conditions for this use</h4><ul class="fact-list">${finding.proof.conditions
    .map(
      (c) =>
        `<li data-condition-status="${c.status}"><span class="fact-kind ${c.status}">${{ met: "Established", unknown: "Open", ruled_out: "Excluded" }[c.status]}</span><strong>${esc(c.label)}</strong><p class="fact-explanation">${esc(c.explanation)}${
          c.citations.length
            ? ` · ${c.citations
                .map((site) => {
                  const i = finding.item.evidence.findIndex(
                    (r) =>
                      r.path === site.path &&
                      r.startLine <= site.line &&
                      r.endLine >= site.line,
                  );
                  return i < 0
                    ? code(`${site.path}:${site.line}`)
                    : `<a href="#${finding.id}-source-${i + 1}">${code(`${site.path}:${site.line}`)}</a>`;
                })
                .join(" · ")}`
            : ""
        }</p></li>`,
    )
    .join("")}</ul></section>`;
}
const outcomes: Record<
  NonNullable<DependencyFindingDetails["inspections"]>[number]["outcome"],
  string
> = {
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
function inspections(finding: Finding) {
  const list = finding.item.inspections ?? [];
  if (!list.length)
    return finding.kind === "coverage" ||
      (finding.kind === "use" && finding.item.verdict === "unknown")
      ? '<p class="muted">No inspection attempt was recorded.</p>'
      : "";
  return `<section><h4 class="section-title">Inspections and results</h4><ol class="inspection-list">${list
    .map((i) => {
      const t = i.target;
      const rel = {
        target: "Exact target",
        shared_artifact: "Shared immutable artifact",
        comparison: "Comparison workload",
      }[t.relationship];
      const facts = [
        t.environment,
        t.workload,
        t.variant,
        t.role,
        t.revision,
        t.platform,
        t.observationWindow,
      ].filter(Boolean);
      return `<li class="inspection"><div class="inspection-head"><strong>${esc(i.question)}</strong><span class="outcome">${outcomes[i.outcome]}</span></div><p class="inspection-target">${rel}: ${esc(t.label)}${facts.length ? ` · ${facts.map((v) => esc(v!)).join(" · ")}` : ""}</p>${t.imageIndex ? `<p class="inspection-meta">Image index ${code(t.imageIndex)}</p>` : ""}${t.platformManifest ? `<p class="inspection-meta">Platform manifest ${code(t.platformManifest)}</p>` : ""}${t.artifact ? `<p class="inspection-meta">Artifact ${code(t.artifact)}</p>` : ""}${i.source ? `<p class="inspection-meta">Attempted via ${esc(i.source)}</p>` : ""}${i.result ? `<p>${esc(i.result)}</p>` : ""}${i.measurement ? `<p>${n(i.measurement.count, i.measurement.unit === "cpu_samples" ? "CPU sample" : "call")}${i.measurement.frameTypes?.length ? ` · frames: ${i.measurement.frameTypes.map(esc).join(", ")}` : ""}</p>` : ""}${i.completeness ? `<p class="inspection-meta">Completeness: ${{ complete: "reported complete", partial: "backend reported partial", not_reported: "not reported by backend" }[i.completeness]}</p>` : i.measurement ? '<p class="inspection-meta">Completeness not recorded.</p>' : ""}${i.transferBasis ? `<p class="inspection-meta">Transfer basis: ${esc(i.transferBasis)}</p>` : ""}${i.evidence.length ? `<p class="inspection-meta">Evidence: ${referenceList(finding, i.evidence)}</p>` : ""}</li>`;
    })
    .join("")}</ol></section>`;
}
function path(check: Check, finding: Finding, options: ReportRenderOptions) {
  if (finding.kind === "coverage")
    return finding.item.handoff
      ? `<section id="${finding.id}-trace" class="handoff"><h4 class="section-title">Where the path is open</h4><p><b>Verified handoff:</b> ${esc(finding.item.handoff.verified)}</p><p><b>Missing link:</b> ${esc(finding.item.handoff.missing)}</p></section>`
      : "";
  const chain = finding.item.location.split(/\s*(?:→|->)\s*/u).filter(Boolean);
  const sink = finding.proof?.sink;
  const exclusion = finding.proof?.conditions.find(
    (condition) => condition.status === "ruled_out",
  )?.label;
  const why = exclusion ?? finding.item.reason;
  if (!sink && chain.length < 2) {
    if (finding.item.verdict !== "ruled_out") return "";
    return `<section id="${finding.id}-trace"><h4 class="section-title">Why this target is ruled out</h4><ol class="path"><li><small>Target</small><strong>${esc(finding.item.place?.workload ?? finding.item.place?.artifact ?? finding.item.location)}</strong></li><li><small>Exclusion</small><strong>${esc(why)}</strong></li><li><small>Assessment</small><strong>Ruled out</strong></li></ol></section>`;
  }
  const steps: [string, string][] = [];
  const sourceEndpoint = inputFor(finding.item)?.endpoint;
  if (sourceEndpoint || chain.length > 1)
    steps.push(["Input / entrypoint", sourceEndpoint ?? chain[0]!]);
  if (chain.length > 2) steps.push(["Path", chain.slice(1, -1).join(" → ")]);
  if (sink) steps.push(["Operation", sink.function]);
  else if (chain.length > 1) steps.push(["Reported handoff", chain.at(-1)!]);
  steps.push(
    finding.item.verdict === "ruled_out"
      ? ["Exclusion", why]
      : ["Assessment", dependencyVerdictLabels[finding.item.verdict]],
  );
  const at = sink
    ? finding.item.evidence.findIndex(
        (c) =>
          c.path === sink.callSite.path &&
          c.startLine <= sink.callSite.line &&
          c.endLine >= sink.callSite.line,
      )
    : -1;
  const cite = at >= 0 ? finding.item.evidence[at] : undefined;
  const source = cite ? snippet(check, finding, cite, options) : undefined;
  const call =
    sink && cite
      ? source !== undefined
        ? `<div id="${finding.id}-source-${at + 1}" class="source-snippet"><p class="evidence-ref">Call site ${code(`${sink.callSite.path}:${sink.callSite.line}`)}</p>${renderDependencyCode(source, cite.path, cite.startLine, new Set([sink.callSite.line]))}</div>`
        : `<p class="evidence-ref">Call site <a href="#${finding.id}-source-${at + 1}">${code(`${sink.callSite.path}:${sink.callSite.line}`)}</a></p>`
      : "";
  return `<section id="${finding.id}-trace"><h4 class="section-title">Source to operation</h4><ol class="path">${steps.map(([label, value]) => `<li><small>${label}</small><strong>${esc(value)}</strong></li>`).join("")}</ol>${call}</section>`;
}
function productionCalls(finding: Finding) {
  if (finding.kind !== "use" || !finding.calls.length) return "";
  return `<section><h4 class="section-title">Production call measurements</h4><ul class="fact-list">${finding.calls.map((m) => `<li><strong>${n(m.count, "production call")} recorded at ${esc(m.step)}</strong><p class="fact-explanation">${esc(m.target)} · prod · ${esc(m.from)} to ${esc(m.until)} · ${link(m.record)}</p></li>`).join("")}</ul><p class="evidence-ref">Each count applies to its recorded step, target and window; it does not measure the entire path.</p></section>`;
}
function findingTitle(finding: Finding) {
  if (finding.kind === "use") return finding.item.location;
  return (
    finding.item.location ??
    (finding.item.locations?.length
      ? finding.item.locations
          .map((c) => `${c.path}${c.line ? `:${c.line}` : ""}`)
          .join(", ")
      : finding.item.evidence[0]
        ? rangeLabel(finding.item.evidence[0])
        : "Unresolved implementation handoff")
  );
}
function renderFinding(
  check: Check,
  finding: Finding,
  options: ReportRenderOptions,
  initiallyOpen = false,
) {
  const item = finding.item;
  const title = findingTitle(finding);
  const use = finding.kind === "use" ? finding.item : undefined;
  const source = inputFor(item),
    runtime = runtimeFor(item),
    place = item.place;
  const question =
    item.openConditions?.[0]?.question ??
    place?.unresolvedQuestions[0] ??
    (finding.kind === "coverage" ? finding.item.handoff?.missing : undefined);
  const next =
    use?.verdict !== "ruled_out" &&
    question &&
    !normalize(item.reason).includes(normalize(question))
      ? question
      : item.reason;
  const instance = place?.workload ?? title;
  const sink = finding.kind === "use" ? finding.proof?.sink : undefined;
  const launch = runtime?.mitigation
    ? `Mitigation ${runtime.mitigation.state === "unknown" ? "unverified" : runtime.mitigation.state} (${runtime.mitigation.basis})`
    : runtime?.launch
      ? `Launch ${runtime.launch.basis}`
      : "Launch mitigation unverified";
  const tags = tagsFor(finding);
  return `<article class="finding" id="${finding.id}" data-finding data-kind="${finding.kind}" data-services="${finding.groups.join(" ")}" data-verdict="${use?.verdict ?? ""}" data-deployment="${deployment(finding)}" data-exposure="${exposure(finding)}" data-tags="${tags.map((tag) => tag.id).join(" ")}"><details${initiallyOpen ? " open" : ""}><summary class="triage-row"><span class="triage-target"><span class="instance-mode"><span class="finding-title">${esc(instance)}</span>${instance !== title ? `<span class="triage-secondary">${esc(title)}</span>` : ""}</span><span class="code-mode"><span class="finding-title">${sink ? code(sink.function) : esc(title)}</span>${sink ? `<span class="triage-secondary">${code(`${sink.callSite.path}:${sink.callSite.line}`)}</span>` : ""}</span><span class="finding-sub">${[
    ...servicesFor(item).map((service) => service.name),
    place?.environment,
    place?.variant,
    place?.role,
    place?.platform,
    place ? deploymentLabels[place.deploymentBasis] : undefined,
  ]
    .filter(Boolean)
    .map((x) => `<span>${esc(x!)}</span>`)
    .join(
      "",
    )}${use ? `<span>${esc(use.component)} · ${use.version ? code(use.version) : "Version unverified"}</span>` : ""}</span></span><span class="triage-source"><span class="triage-label">Input source</span><strong class="exposure" data-source-exposure="${exposure(finding)}">${exposureLabels[exposure(finding)]}</strong>${source?.endpoint ? `<span class="triage-secondary">${code(source.endpoint)}</span>` : ""}</span><span class="triage-runtime instance-mode"><span class="triage-label">Launch / mitigation</span><strong>${esc(launch)}</strong>${runtime?.launch ? `<span class="triage-secondary">${code(runtime.launch.command)}</span>` : ""}</span><span class="triage-runtime code-mode"><span class="triage-label">Call path</span><strong>${sink ? "Vulnerable operation bound" : finding.kind === "coverage" ? "Implementation handoff open" : "Operation unbound"}</strong></span><span class="triage-decision">${use ? status(use.verdict) : coverageStatus}<span class="triage-secondary">${esc(next)}</span></span></summary><div class="body">${scopeLine(finding)}${next === item.reason ? "" : `<p class="lead">${esc(item.reason)}</p>`}${sourceContext(finding)}${runtimeContext(finding)}${openQuestions(finding)}${path(check, finding, options)}${conditions(finding)}${inspections(finding)}${productionCalls(finding)}${targetDetails(finding)}${serviceMappings(finding)}${evidence(check, finding, options)}</div></details></article>`;
}

function totals(findings: Finding[]) {
  const c = counts(findings);
  const internet = findings.filter((f) => exposure(f) === "internet").length;
  const privateInputs = findings.filter(
    (f) => exposure(f) === "not_internet",
  ).length;
  const unknown = findings.length - internet - privateInputs;
  return `<div class="totals" aria-label="Unique report counts"><span class="metric"><strong>${c.reviewed}</strong> reviewed use${c.reviewed === 1 ? "" : "s"}</span>${verdictOrder
    .filter((v) => c.breakdown[v])
    .map(
      (v) =>
        `<span class="metric status" data-verdict="${v}"><span class="dot" aria-hidden="true"></span><strong>${c.breakdown[v]}</strong> ${dependencyVerdictLabels[v]}</span>`,
    )
    .join(
      "",
    )}<span class="metric"><strong>${c.unresolved}</strong> unresolved coverage item${c.unresolved === 1 ? "" : "s"}</span>${findings.length ? `<span class="metric exposure-metric">Input exposure by item: <strong>${internet}</strong> internet · <strong>${privateInputs}</strong> not internet · <strong>${unknown}</strong> unverified</span>` : ""}</div>`;
}
function reportLimitations(check: Check, findings: Finding[], index: number) {
  const grouped = new Map<
    string,
    { text: string; items: Finding[]; scopes: Set<string> }
  >();
  for (const original of check.limitations) {
    const marker = /\s+Unresolved source locations:\s*/u.exec(original);
    const text = (marker ? original.slice(0, marker.index) : original).trim();
    const scope = marker
      ? original.slice(marker.index + marker[0].length).trim()
      : "";
    const matching = findings.filter(
      (f) => normalize(f.item.reason) === normalize(text),
    );
    if (matching.length === 1 && !scope) continue;
    const key = normalize(text);
    const current = grouped.get(key) ?? {
      text,
      items: [],
      scopes: new Set<string>(),
    };
    for (const f of matching)
      if (!current.items.includes(f)) current.items.push(f);
    if (scope) current.scopes.add(scope);
    grouped.set(key, current);
  }
  const entries = [...grouped.values()].map(({ text, items, scopes }) => {
    const links = items
      .map((f) => `<a href="#${f.id}">${esc(findingTitle(f))}</a>`)
      .join(", ");
    const reason = items.length === 1 ? "" : esc(text);
    const affected = links
      ? `${reason ? " " : ""}<span class="muted">Affected: ${links}</span>`
      : "";
    const locations = scopes.size
      ? `<div class="muted">Unresolved source locations: ${[...scopes].map(esc).join(" ")}</div>`
      : "";
    return `<li>${reason}${affected}${locations}</li>`;
  });
  return `<section class="report-end" aria-labelledby="limits-${index}"><h3 id="limits-${index}">Report limitations</h3>${entries.length ? `<ul>${entries.join("")}</ul>` : '<p class="end-caption">Item-specific gaps are listed with the affected findings. No additional shared limitation was recorded.</p>'}</section>`;
}
function investigationScope(
  check: Check,
  index: number,
  options: ReportRenderOptions,
) {
  const dismissed = (check.coverage ?? []).flatMap((c, i) =>
    c.kind === "dismissed" ? [{ item: c, position: i }] : [],
  );
  return `<section class="report-end"><h3>Investigation scope and search coverage</h3>${check.assumptions.length ? `<p class="end-caption">Scope or assumptions: ${check.assumptions.map(esc).join(" · ")}</p>` : ""}<details class="disclosure"><summary>Search records (${check.searches.length})</summary>${check.searches.length ? `<ul class="evidence-list">${check.searches.map((s) => `<li><strong>${esc(s.source)} / ${code(s.tool)}</strong><p>${s.scope.map(esc).join(", ") || "Scope unrecorded"} · ${esc(s.finishedAt)}</p><p class="evidence-ref">Result: ${esc(s.result.replaceAll("_", " "))} · Completeness: ${s.completeness === "unknown" ? "not established" : esc(s.completeness)}${s.details.length ? ` · ${s.details.map(esc).join("; ")}` : ""}</p>${s.evidenceReferences.length ? `<p class="evidence-ref">${s.evidenceReferences.map(code).join(" · ")}</p>` : ""}</li>`).join("")}</ul>` : '<p class="muted">No captured search records.</p>'}</details>${
    dismissed.length
      ? `<details class="disclosure"><summary>Dismissed coverage (${dismissed.length})</summary><ul class="evidence-list">${dismissed
          .map(({ item: c, position }) => {
            const f: Finding = {
              id: `coverage-${index}-${position + 1}`,
              kind: "coverage",
              item: c,
              groups: [],
              original: position,
            };
            return `<li id="${f.id}"><p>${esc(c.reason)}</p>${c.classification ? `<p class="evidence-ref">${esc(c.classification.replaceAll("_", " "))}</p>` : ""}${evidence(check, f, options)}</li>`;
          })
          .join("")}</ul></details>`
      : ""
  }<p class="end-caption" style="margin-top:.75rem">Counts are distinct reviewed uses in this advisory. A shared use may appear under more than one verified service; unresolved coverage is counted separately.</p></section>`;
}
function blockedCheck(outcome: Blocked, index: number, title: string) {
  return `<section id="check-${index}" class="check" data-check><div class="check-heading"><h2>${esc(title)}</h2></div><section class="brief"><p class="eyebrow">Run status</p><h3>Investigation blocked before final review</h3><p>${esc(outcome.reason)}</p><p><b>Affected scope:</b> ${esc(outcome.affectedScope)}</p><p><b>Impact:</b> ${esc(outcome.scopeImpact)}</p><p><b>Unblock condition:</b> ${esc(outcome.unblockCondition)}</p><p class="muted">This is an operational outcome, not an exploitability verdict. No completed report was submitted for this check.</p></section></section>`;
}
type PreparedCheck = ReturnType<typeof buildGroups>;
function defaultView(findings: Finding[]) {
  return findings.some((finding) => {
    const place = finding.item.place;
    const runtime = runtimeFor(finding.item);
    return !!(
      place?.workload ||
      place?.artifact ||
      place?.platformManifest ||
      runtime?.launch ||
      runtime?.mitigation ||
      runtime?.containerUrl
    );
  })
    ? "instances"
    : "code";
}
function renderCheck(
  check: Check,
  title: string,
  index: number,
  options: ReportRenderOptions,
  extras: Map<string, Advisory>,
  prepared: PreparedCheck,
) {
  const { findings, groups } = prepared;
  const c = counts(findings);
  const view = defaultView(findings);
  return `<section id="check-${index}" class="check" data-check data-mode="${view}" aria-labelledby="check-${index}-title">
    <div class="check-heading"><h2 id="check-${index}-title">${esc(title)}</h2></div>
    ${totals(findings)}${advisoryBrief(check, extras)}
    ${
      findings.length
        ? `<div class="workspace">${serviceIndex(groups, findings, index)}<div class="reading" id="reading-${index}">
      <div class="reading-head"><div><h3 data-reading-title>All services and source scope</h3><p data-visible-count>${n(c.reviewed, "reviewed use")}${c.unresolved ? ` · ${n(c.unresolved, "unresolved coverage item")}` : ""}</p></div>
        <div class="mode-switch" aria-label="Finding view" data-mode-controls hidden><button type="button" data-mode-button="instances" aria-pressed="${view === "instances"}">Instances</button><button type="button" data-mode-button="code" aria-pressed="${view === "code"}">Code paths</button></div>
      </div>
      ${c.reviewed === 0 && c.unresolved ? `<p class="counting">No reviewed use was established. The evidence below records ${n(c.unresolved, "material unresolved handoff")}.</p>` : ""}
      <div class="triage-heading" aria-hidden="true"><span data-target-heading>${view === "code" ? "Operation / call site" : "Instance / target"}</span><span>Input source / endpoint</span><span data-runtime-heading>${view === "code" ? "Call path" : "Launch / mitigation"}</span><span>Outcome / deciding fact</span></div>
      <div class="empty" data-no-results hidden>No findings match this filter.<br><button class="reset" type="button" data-reset>Clear filters</button></div>
      ${findings.map((f, i) => renderFinding(check, f, options, c.reviewed === 0 && i === 0)).join("")}
    </div></div>`
        : '<p class="empty">No reviewed uses or unresolved coverage items were recorded for this advisory. Check the investigation scope and limitations before drawing a conclusion.</p>'
    }
    ${reportLimitations(check, findings, index)}${investigationScope(check, index, options)}</section>`;
}
function renderServiceView(
  report: Report,
  prepared: (PreparedCheck | undefined)[],
) {
  const all = new Map<
    string,
    {
      name: string;
      stableId?: string;
      checks: { title: string; checkId: string; group: Group }[];
    }
  >();
  for (const [i, section] of report.sections.entries()) {
    for (const group of prepared[i]?.groups ?? []) {
      const key = group.stableId
        ? `service:${group.stableId}`
        : `fallback:${group.name}`;
      const item = all.get(key) ?? {
        name: group.name,
        stableId: group.stableId,
        checks: [],
      };
      item.checks.push({
        title: section.title,
        checkId: `check-${i + 1}`,
        group,
      });
      all.set(key, item);
    }
  }
  const sorted = [...all.values()].sort(
    (a, b) =>
      Number(!a.stableId) - Number(!b.stableId) || a.name.localeCompare(b.name),
  );
  return `<section class="service-overview" id="services-view" data-service-view aria-labelledby="services-view-title"><div class="overview-head"><div><h2 id="services-view-title">Services → advisories</h2><p>Only services established by item-specific reviewed evidence are named. Source-only and unmapped findings stay visible.</p></div><label data-global-service-controls hidden>Find a service<input type="search" data-global-service-search autocomplete="off"></label></div>${
    sorted.length
      ? `<ul class="overview-list">${sorted
          .map(
            (service) =>
              `<li class="overview-service" data-overview-service data-search-name="${esc(service.name.toLocaleLowerCase())}"><div><h3>${esc(service.name)}</h3>${service.stableId ? `<p class="muted">${code(service.stableId)}</p>` : ""}</div><ul>${service.checks
                .map(({ title, checkId, group }) => {
                  const c = counts(group.findings),
                    e = group.findings.filter(
                      (f) => exposure(f) === "internet",
                    ).length,
                    u = group.findings.filter(
                      (f) => exposure(f) === "unknown",
                    ).length;
                  return `<li><a href="#${group.findings[0]?.id ?? checkId}" data-overview-link data-check-selection="${checkId}" data-service-selection="${group.id}">${esc(title)}</a><span>${n(c.reviewed, "reviewed use")}${c.unresolved ? ` · ${n(c.unresolved, "unresolved item")}` : ""}${e ? ` · ${e} internet exposed` : ""}${u ? ` · ${u} exposure unverified` : ""}</span></li>`;
                })
                .join("")}</ul></li>`,
          )
          .join(
            "",
          )}</ul><p class="empty" data-overview-empty hidden>No services match this search.</p>`
      : '<p class="empty">No service or source findings were recorded.</p>'
  }</section>`;
}

/** Render reviewed JSON and optional, identity-bound sidecars as a standalone offline report. */
export function renderDependencyReport(
  value: unknown,
  options: ReportRenderOptions = {},
): string {
  const report = readReport(value);
  const referenced = new Set(
    report.sections.flatMap((s) => s.check?.advisories ?? []),
  );
  const extras = new Map(
    (options.advisoryDetails ?? []).map((a) => {
      if (!referenced.has(a.url))
        throw new Error(
          `Saved advisory ${a.url} is not referenced by this report.`,
        );
      return [a.url, a] as const;
    }),
  );
  const uses = new Map(
    report.sections.flatMap(
      (s, i) =>
        s.check?.uses.map((use, j) => [useId(i + 1, j + 1), use] as const) ??
        [],
    ),
  );
  const proofs = new Map(
    parseDependencyReportProof(options.useEvidence ?? [], uses),
  );
  for (const [id, proof] of parseDependencyReportProof(
    [...uses].flatMap(([id, use]) =>
      use.proof ? [{ ...use.proof, useId: id, location: use.location }] : [],
    ),
    uses,
  ))
    proofs.set(id, proof);
  const calls = Map.groupBy(
    z.array(productionCallSchema).parse(options.productionCalls ?? []),
    (m) => {
      if (uses.get(m.useId)?.location !== m.location)
        throw new Error(
          `Production measurement does not match report use ${m.useId}.`,
        );
      return m.useId;
    },
  );
  const prepared = report.sections.map((s, i) =>
    s.check ? buildGroups(s.check, i + 1, proofs, calls) : undefined,
  );
  const html = report.sections
    .map((s, i) =>
      s.blocked
        ? blockedCheck(s.blocked, i + 1, s.title)
        : renderCheck(
            s.check!,
            report.sections.length === 1 &&
              normalize(s.title) === normalize(report.title)
              ? "Reviewed places"
              : s.title,
            i + 1,
            options,
            extras,
            prepared[i]!,
          ),
    )
    .join("");
  const hash = createHash("sha256").update(reportInteractions).digest("base64");
  const hasFindings = prepared.some((p) => p && p.findings.length);
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-${hash}'; base-uri 'none'; form-action 'none'"><title>${esc(report.title)} | Exploitability report</title><style>${reportStyles}</style></head><body><a class="skip" href="#report">Skip to report</a><main class="shell" id="report"><header class="masthead"><div class="brand">Codex Security</div><div class="report-label">Exploitability report</div></header><div class="intro"><div class="eyebrow">${esc(report.context)}</div><h1>${esc(report.title)}</h1><p>${report.sections.length && report.sections.every((s) => s.blocked) ? "The investigation did not produce a reviewed report. See the run status and unblock condition." : "Find affected inputs, their deployed instances and the evidence needed to decide each path."}</p>${report.description ? `<p>${esc(report.description)}</p>` : ""}</div>${hasFindings ? `<nav class="view-switch" aria-label="Browse report" data-view-controls hidden><button type="button" data-view-button="cve" aria-pressed="true">By CVE</button><button type="button" data-view-button="service" aria-pressed="false">By service</button></nav>` : ""}<div data-advisory-view>${report.sections.length > 1 ? `<nav class="advisory-tabs" aria-label="Advisory checks"><label data-advisory-controls hidden>Find a CVE or advisory<input type="search" data-advisory-search autocomplete="off"></label><div class="advisory-links">${report.sections.map((s, i) => `<a href="#check-${i + 1}" data-check-link="check-${i + 1}">${esc(s.title)}</a>`).join("")}</div><p data-advisory-empty hidden>No advisory in this report matches.</p></nav>` : ""}${html || '<p class="empty">No advisory checks were recorded for this package.</p>'}</div>${hasFindings ? renderServiceView(report, prepared) : ""}<footer class="footer">Codex Security · Evidence is scoped to the cited caller, artifact, workload and observation window.</footer></main><script>${reportInteractions}</script></body></html>\n`;
}
