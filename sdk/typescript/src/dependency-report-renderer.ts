import { createHash } from "node:crypto";
import { realpath } from "node:fs/promises";
import { z } from "zod";
import type { dependencyAdvisoryDetailsSchema } from "./dependency-advisory.js";
import { renderDependencyCode } from "./dependency-report-code.js";
import { dependencyReportSteps } from "./dependency-report-flow.js";
import {
  parseDependencyReportProof,
  type DependencyReportProof,
} from "./dependency-report-proof.js";
import {
  readDependencyCheckOutput,
  readDependencyEvidence,
  type reviewedDependencyCheckSchema,
  type DependencyUse,
  type DependencyVerdict,
  type ReviewedDependencyUse,
} from "./dependency-reachability.js";
import { isRecord } from "./record.js";

type Check = z.infer<typeof reviewedDependencyCheckSchema>;
type AdvisoryDetails = z.infer<typeof dependencyAdvisoryDetailsSchema>;
type EvidenceFact = DependencyUse["evidence"][number]["supports"][number];
type Citation = DependencyUse["evidence"][number];

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
interface ReportRenderOptions {
  code?: ReadonlyMap<string, string>;
  productionCalls?: unknown;
  advisoryDetails?: readonly AdvisoryDetails[];
  useEvidence?: unknown;
}

const verdicts = {
  exploitable: "Exploitable",
  potentially_exploitable: "Potentially exploitable",
  unknown: "Unknown",
  ruled_out: "Ruled out",
} satisfies Record<DependencyVerdict, string>;

const verdictOrder = Object.keys(verdicts) as DependencyVerdict[];
const verdictMeaning = {
  exploitable:
    "The report has evidence for an affected use, a running deployment, and relevant caller access.",
  potentially_exploitable:
    "The report identified an affected use. Proof of the running copy or caller access is still incomplete.",
  unknown:
    "The evidence leaves a deciding fact or part of the assessed scope unresolved.",
  ruled_out: "The evidence rules out the advisory for the assessed scope.",
} satisfies Record<DependencyVerdict, string>;

const deployments = {
  confirmed: "Confirmed running",
  configured: "Configured",
  unknown: "Unknown",
} satisfies Record<DependencyUse["deployment"], string>;

const deploymentOrder = ["confirmed", "configured", "unknown"] as const;
const facts = {
  affected_copy: "Dependency copy",
  affected_use: "Applicable use",
  running: "Running revision",
  access: "Caller access",
} satisfies Record<EvidenceFact, string>;

const escapeHtml = (text: string) =>
  text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");

const quantity = (count: number, singular: string) =>
  `${count.toLocaleString("en-US")} ${singular}${count === 1 ? "" : "s"}`;

function readReport(value: unknown) {
  return readDependencyCheckOutput(
    isRecord(value) &&
      (value["answer"] !== undefined || value["data"] !== undefined)
      ? (value["answer"] ?? value["data"])
      : value,
  );
}

const citationKey = ({
  path,
  commit,
  startLine,
  endLine,
}: Pick<Citation, "path" | "commit" | "startLine" | "endLine">) =>
  JSON.stringify(
    commit ? [path, commit, startLine, endLine] : [path, startLine, endLine],
  );

const sourceRevision = (commit?: string) =>
  commit ? " · Git <code>" + escapeHtml(commit) + "</code>" : "";

const useId = (check: number, use: number) => `use-${check}-${use}`;

/** Read only the cited ranges from the explicitly supplied checkout. */
export async function readDependencyReportCode(
  value: unknown,
  checkout: string,
) {
  const report = readReport(value);
  const checks = "cve" in report ? [report] : report.checks;
  const citations = new Map(
    checks.flatMap(({ uses, coverage }) =>
      [...uses, ...(coverage ?? [])].flatMap(({ evidence }) =>
        evidence.map((cite) => [citationKey(cite), cite] as const),
      ),
    ),
  );
  const snippets = new Map<string, string>();
  await readDependencyEvidence(
    [...citations.values()],
    await realpath(checkout),
    undefined,
    (excerpt) => {
      snippets.set(citationKey(excerpt), excerpt.text);
    },
  );
  return snippets;
}

function badge(verdict: DependencyVerdict) {
  return `<span class="badge tone" data-verdict="${verdict}">${verdicts[verdict]}</span>`;
}

function supportLabels(supports: readonly EvidenceFact[]) {
  return supports
    .map((fact) => `<span class="tag">${facts[fact]}</span>`)
    .join("");
}

function advisoryLink(value: string, display = value) {
  const label = escapeHtml(display);
  const url = URL.parse(value);
  return url?.protocol === "https:" || url?.protocol === "http:"
    ? `<a href="${escapeHtml(url.href)}" rel="noreferrer">${label}</a>`
    : `<code>${label}</code>`;
}

function advisoryName(url: string) {
  return URL.parse(url)?.pathname.split("/").filter(Boolean).at(-1) ?? url;
}

function advisoryProse(value: string) {
  return value
    .split(/(`[^`\n]+`|\*\*[^*\n]+\*\*)/u)
    .map((part) => {
      if (part.startsWith("`") && part.endsWith("`") && part.length > 2)
        return `<code>${escapeHtml(part.slice(1, -1))}</code>`;
      if (part.startsWith("**") && part.endsWith("**") && part.length > 4)
        return `<strong>${escapeHtml(part.slice(2, -2))}</strong>`;
      return escapeHtml(part);
    })
    .join("");
}

function advisoryFunctions(advisory: AdvisoryDetails) {
  return [
    ...(advisory.vulnerableFunctions ?? []).map((name) => ({
      name,
      scope: "",
      url: advisory.url,
    })),
    ...advisory.affected.flatMap((entry) => {
      const metadata = entry.ecosystem_specific;
      if (!metadata) return [];
      if ("imports" in metadata) {
        return metadata.imports.flatMap(({ path, symbols, goos, goarch }) => {
          const scope = [path, goos?.join(", "), goarch?.join(", ")]
            .filter(Boolean)
            .join(" · ");
          return (symbols ?? []).map((name) => ({
            name,
            scope,
            url: advisory.url,
          }));
        });
      }
      const { functions, os, arch } = metadata.affects;
      const scope = [entry.package?.name, os?.join(", "), arch?.join(", ")]
        .filter(Boolean)
        .join(" · ");
      return (functions ?? []).map((name) => ({
        name,
        scope,
        url: advisory.url,
      }));
    }),
  ];
}

function renderAdvisory(details: readonly AdvisoryDetails[]) {
  if (!details.length) return "";
  const primary =
    details.find(({ overview }) => overview) ??
    details.find(({ summary }) => summary) ??
    details[0]!;
  const symbols = new Map(
    details
      .flatMap(advisoryFunctions)
      .map((entry) => [JSON.stringify([entry.name, entry.scope]), entry]),
  );
  const packages = new Map<string, Set<string>>();
  for (const { affected } of details) {
    for (const entry of affected) {
      if (!entry.package) continue;
      const label = `${entry.package.ecosystem}:${entry.package.name}`;
      const fixes = packages.get(label) ?? new Set<string>();
      for (const range of entry.ranges ?? []) {
        if (range.type === "GIT") continue;
        for (const event of range.events)
          if ("fixed" in event) fixes.add(event.fixed);
      }
      packages.set(label, fixes);
    }
  }
  const functions = [...symbols.values()]
    .map(
      ({ name, scope, url }) =>
        `<li><code>${escapeHtml(name)}</code>${scope ? `<span>${escapeHtml(scope)}</span>` : ""}<span>${advisoryLink(url, advisoryName(url))}</span></li>`,
    )
    .join("");
  const packageList = [...packages]
    .map(
      ([label, fixes]) =>
        `<li><code>${escapeHtml(label)}</code>${fixes.size ? `<span>Fixed in ${[...fixes].map(escapeHtml).join(", ")}</span>` : ""}</li>`,
    )
    .join("");
  const applicability = details
    .filter(({ applicability }) => applicability)
    .map(
      ({ applicability, url }) =>
        `<section><p class="muted">${advisoryLink(url, advisoryName(url))}</p><p class="report-text">${advisoryProse(applicability!)}</p></section>`,
    )
    .join("");
  return `<details class="advisory-brief" open>
    <summary>Advisory</summary>
    <div class="advisory-body">
      <div class="advisory-heading">${primary.summary ? `<h3>${advisoryProse(primary.summary)}</h3>` : ""}<span>${advisoryLink(primary.url, advisoryName(primary.url))}</span></div>
      ${primary.overview ? `<p class="report-text advisory-description">${advisoryProse(primary.overview)}</p>` : ""}
      <div class="advisory-fields">
        ${functions ? `<section><h4>Vulnerable functions</h4><ul>${functions}</ul></section>` : ""}
        ${packageList ? `<section><h4>Affected packages</h4><ul>${packageList}</ul></section>` : ""}
      </div>
      ${applicability ? `<details class="advisory-applicability"><summary>Applicability conditions</summary>${applicability}</details>` : ""}
    </div>
  </details>`;
}

function renderProductionCalls(calls: readonly ProductionCall[]) {
  if (!calls.length) return "";
  return `<section class="production"><h4>Production calls</h4><ul>${calls
    .map(
      (measurement) => `<li>
    <strong>${quantity(measurement.count, "call")} observed</strong>
    <span>${escapeHtml(measurement.target)} · prod</span>
    <span class="muted"><time datetime="${escapeHtml(measurement.from)}">${escapeHtml(measurement.from)}</time> to <time datetime="${escapeHtml(measurement.until)}">${escapeHtml(measurement.until)}</time></span>
    <span class="muted">Evidence ${advisoryLink(measurement.record)}</span>
  </li>`,
    )
    .join("")}</ul></section>`;
}

const flowLabels = {
  source: "Source",
  path: "Path",
  sink: "Sink",
  result: "Outcome",
} as const;

type CallSite = NonNullable<DependencyReportProof["sink"]>["callSite"];

function containsLine(cite: Citation, location: CallSite) {
  return (
    cite.path === location.path &&
    cite.startLine <= location.line &&
    location.line <= cite.endLine
  );
}

function renderSnippet(
  cite: Citation,
  text: string,
  title: string,
  terms: readonly string[],
  callSite?: CallSite,
) {
  const highlightLine =
    callSite && containsLine(cite, callSite) ? callSite.line : undefined;
  const highlighted =
    highlightLine === undefined ? undefined : new Set([highlightLine]);
  const full = renderDependencyCode(
    text,
    cite.path,
    cite.startLine,
    highlighted,
  );
  const lines = text.split("\n");
  const previewLines = 8;
  if (lines.length <= previewLines) return full;

  const reference = title.indexOf(cite.path + ":");
  const lineNumber =
    highlightLine ??
    (reference < 0
      ? NaN
      : Number.parseInt(title.slice(reference + cite.path.length + 1), 10));
  let focus = 0;
  if (lineNumber >= cite.startLine && lineNumber <= cite.endLine) {
    focus = lineNumber - cite.startLine;
  } else {
    let best = 0;
    lines.forEach((line, index) => {
      const matches = terms.filter((term) => line.includes(term)).length;
      if (matches > best) {
        best = matches;
        focus = index;
      }
    });
  }
  const start = Math.min(
    Math.max(0, focus - (highlighted ? 4 : 2)),
    lines.length - previewLines,
  );
  const end = start + previewLines;
  return `<p class="muted">Lines ${cite.startLine + start}–${cite.startLine + end - 1}</p>
    ${renderDependencyCode(lines.slice(start, end).join("\n"), cite.path, cite.startLine + start, highlighted)}
    <details class="full-citation"><summary>Full cited range</summary>${full}</details>`;
}

function renderWalkthrough(
  use: DependencyUse,
  id: string,
  code: ReadonlyMap<string, string> | undefined,
  calls: readonly ProductionCall[],
  runtime: string,
  operation: string | undefined,
  proof: DependencyReportProof | undefined,
) {
  const steps = dependencyReportSteps(use);
  const excluded = use.verdict === "ruled_out";
  const sink = proof?.sink;
  const initial = excluded ? "result" : sink ? "sink" : steps[0]!.kind;
  const label = (kind: keyof typeof flowLabels) =>
    kind === "result" && excluded
      ? "Exclusion"
      : kind === "sink" && operation && !sink
        ? "Advisory function"
        : flowLabels[kind];
  const nodes = steps
    .map(({ kind, title }) => {
      const measurements = calls.filter(({ step }) => step === kind);
      return `<li><button type="button" class="flow-node" data-flow-step="${kind}" aria-controls="${id}-flow-${kind}" aria-pressed="${kind === initial}">
      <span class="flow-label">${label(kind)}</span><strong>${escapeHtml(kind === "sink" ? (sink?.function ?? operation ?? title) : title)}</strong>
      ${measurements.length === 1 ? `<span class="flow-count">${quantity(measurements[0]!.count, "prod call")}</span>` : ""}
    </button></li>`;
    })
    .join("");
  const detail = steps
    .map(({ kind, title, excerpt, evidence, observations }) => {
      // For display order only, prioritize identifiers in the deciding clause.
      const control =
        excluded && kind === "result"
          ? excerpt.search(
              /\b(?:skips?|skipped|prevents?|returns? before|fixed|fixes|patched)\b/iu,
            )
          : -1;
      const focus = control >= 0 ? excerpt.slice(control) : excerpt;
      const terms =
        focus.match(
          /\b(?:[a-z][a-z0-9]*[A-Z][A-Za-z0-9]*|[A-Z][A-Z0-9_]+|[\w$]+\.[\w$]+)\b/g,
        ) ?? [];
      const callSite =
        kind === "sink" || kind === "result" ? sink?.callSite : undefined;
      const callCitation =
        callSite && use.evidence.find((cite) => containsLine(cite, callSite));
      const cited = [
        ...new Set([
          ...(callCitation ? [callCitation] : []),
          ...evidence.map((index) => use.evidence[index]!),
        ]),
      ]
        .map((cite) => {
          const snippet = code?.get(citationKey(cite));
          const matches = terms.filter((term) =>
            snippet?.includes(term),
          ).length;
          return { cite, snippet, matches, exact: cite === callCitation };
        })
        .sort(
          (a, b) => Number(b.exact) - Number(a.exact) || b.matches - a.matches,
        );
      const snippets = cited
        .map(({ cite, snippet }, position) => {
          const lines =
            cite.startLine === cite.endLine
              ? cite.startLine
              : `${cite.startLine}–${cite.endLine}`;
          const reference = `<code>${escapeHtml(cite.path)}:${lines}</code>${sourceRevision(cite.commit)}`;
          return snippet === undefined
            ? `<li>${reference}</li>`
            : `<li><details class="snippet"${position === 0 ? " open" : ""}><summary>${reference}</summary>${renderSnippet(cite, snippet, title, terms, callSite)}</details></li>`;
        })
        .join("");
      const records = observations
        .map((index) => {
          const { server, record } = use.observations[index]!;
          return `<li><strong>${escapeHtml(server)}</strong><p class="report-text">${escapeHtml(record)}</p></li>`;
        })
        .join("");
      return `<section class="flow-detail" data-flow-detail="${kind}" id="${id}-flow-${kind}">
      <h4>${label(kind)}</h4>
      ${kind === "sink" && (sink || operation) ? `<p class="sink-reference"><code>${escapeHtml(sink?.function ?? operation!)}</code>${sink ? `<span class="muted">Call site <code>${escapeHtml(sink.callSite.path)}:${sink.callSite.line}</code></span>` : ""}</p>` : ""}
      ${excerpt ? `<p class="report-text">${escapeHtml(excerpt)}</p>` : ""}
      ${snippets ? `<ul class="step-citations">${snippets}</ul>` : ""}
      ${kind === "result" ? runtime : ""}
      ${records ? `<ul class="evidence-list">${records}</ul>` : ""}
      ${renderProductionCalls(calls.filter(({ step }) => kind === "result" || step === kind))}
    </section>`;
    })
    .join("");
  return `<section class="walkthrough tone" data-verdict="${use.verdict}" data-walkthrough>
    <div class="flow-heading"><h4>${steps[0]?.kind === "source" ? "Source to sink" : "Evidence walkthrough"}</h4><span class="muted">${code ? "Code from supplied checkout" : "Saved source references"}</span></div>
    <ol class="flow-nodes" data-steps="${steps.length}">${nodes}</ol>
    <p class="muted flow-caption">${calls.length ? "Production measurements are scoped to individual steps and time windows." : "No production call count recorded."}</p>
    ${detail}
    <div class="flow-actions" data-flow-actions hidden>
      <button type="button" data-flow-back>Back</button><span data-flow-progress aria-live="polite"></span><button type="button" data-flow-next>Next step</button>
    </div>
  </section>`;
}

function renderConditions(
  use: DependencyUse,
  proof: DependencyReportProof | undefined,
) {
  const supports = new Set(
    [...use.evidence, ...use.observations].flatMap(({ supports }) => supports),
  );
  const defaults = (
    [
      ["Affected dependency copy", "affected_copy"],
      ["Advisory prerequisites in code", "affected_use"],
    ] as const
  ).map(([label, fact]) => {
    const met = supports.has(fact);
    return {
      label,
      status: met ? ("met" as const) : ("unknown" as const),
      explanation: met
        ? "Supported by the citations for this use."
        : "No separate condition result was recorded.",
      citations: [],
    };
  });
  const conditions = proof?.conditions ?? defaults;
  const labels = {
    met: "Met",
    unknown: "Unknown",
    ruled_out: "Rules it out",
  } as const;
  const rows = conditions
    .map(
      ({ label, status, explanation, citations }) =>
        `<div class="condition" data-condition="${status}"><dt>${escapeHtml(label)}</dt><dd>
      <span class="condition-status">${labels[status]}</span>
      <div><p>${escapeHtml(explanation)}</p>${citations.length ? `<div class="condition-cites">${citations.map(({ path, line }) => `<code>${escapeHtml(path)}:${line}</code>`).join("")}</div>` : ""}</div>
    </dd></div>`,
    )
    .join("");
  const exclusion =
    use.verdict === "ruled_out" &&
    !conditions.some(({ status }) => status === "ruled_out")
      ? dependencyReportSteps(use).find(({ kind }) => kind === "result")
          ?.excerpt
      : undefined;
  return `<section class="conditions" aria-label="CVE conditions"><h4>CVE conditions</h4><dl>${rows}</dl>${exclusion ? `<p class="recorded-exclusion"><strong>Recorded exclusion</strong> ${escapeHtml(exclusion)}</p>` : ""}</section>`;
}

function renderUse(
  use: ReviewedDependencyUse,
  id: string,
  indexId: string,
  code: ReadonlyMap<string, string> | undefined,
  calls: readonly ProductionCall[],
  operation: string | undefined,
  useProof: DependencyReportProof | undefined,
) {
  const citations = use.evidence
    .map((cite) => {
      const { path, startLine, endLine, supports } = cite;
      const lines =
        startLine === endLine ? startLine : `${startLine}–${endLine}`;
      const reference = `<code>${escapeHtml(path)}:${lines}</code>`;
      const snippet = code?.get(citationKey(cite));
      return `<li>${snippet === undefined ? reference : `<details class="snippet" open><summary>${reference}</summary>${renderSnippet(cite, snippet, use.location, [], useProof?.sink?.callSite)}</details>`}<div class="tags">${supportLabels(supports)}</div></li>`;
    })
    .join("");
  const observations = use.observations
    .map(
      ({ server, record, supports }) =>
        `<li><strong>${escapeHtml(server)}</strong><p class="report-text">${escapeHtml(record)}</p><div class="tags">${supportLabels(supports) || '<span class="muted">No deciding fact recorded</span>'}</div></li>`,
    )
    .join("");
  const proof = new Set(
    [...use.evidence, ...use.observations].flatMap(({ supports }) => supports),
  );
  const runtime =
    use.verdict === "ruled_out"
      ? ""
      : `<dl class="runtime-proof">
    <div><dt>Running revision</dt><dd>${proof.has("running") ? "Evidence cited" : "No evidence cited"}</dd></div>
    <div><dt>Caller access</dt><dd>${proof.has("access") ? "Evidence cited" : "No evidence cited"}</dd></div>
  </dl>`;
  const { place } = use;
  const scopedDeployment = {
    observed: "Observed running within the cited scope",
    configured: "Configured",
    unknown: "Unknown",
    assumed_not_deployed: "Assumed not deployed within the supplied scope",
  }[place.deploymentBasis];
  const scope = [
    [
      "Place type",
      {
        service: "Service",
        job: "Job",
        configured_build: "Configured build",
        artifact: "Artifact",
        library_caller: "Library caller",
        unknown: "Unknown",
      }[place.kind],
    ],
    ["Deployment scope", scopedDeployment],
    ["Environment", place.environment],
    ["Revision", place.revision],
    ["Artifact", place.artifact],
    ["Observation window", place.observationWindow],
    ["Dependency selection", place.dependencySelection],
    ["Patch", place.patch],
  ]
    .map(
      ([label, value]) =>
        `<div><dt>${escapeHtml(label!)}</dt><dd>${escapeHtml(value ?? "Unverified")}</dd></div>`,
    )
    .join("");
  const decidingEvidence = use.decidingEvidence
    .map((ref) =>
      ref.kind === "source"
        ? `<li><code>${escapeHtml(ref.path)}:${ref.startLine}${ref.endLine === ref.startLine ? "" : `–${ref.endLine}`}</code>${sourceRevision(ref.commit)}</li>`
        : `<li><code>${escapeHtml(ref.receiptId)}</code><p class="report-text">SHA-256 ${escapeHtml(ref.originalPayloadSha256)}${ref.selection ? ` · ${escapeHtml(JSON.stringify(ref.selection))}` : ""}</p></li>`,
    )
    .join("");
  return `<article class="use-panel" id="${id}" data-use-panel aria-labelledby="${id}-title">
    <a class="back-link" href="#${indexId}">Back to places</a>
    <div class="panel-heading"><p class="eyebrow">Selected place</p>${badge(use.verdict)}</div>
    <h3 id="${id}-title" tabindex="-1">${escapeHtml(use.location)}</h3>
    <dl class="metadata">
      <div><dt>Dependency</dt><dd>${escapeHtml(use.component)}</dd></div>
      <div><dt>Version</dt><dd>${use.version === null ? "Unknown" : `<code>${escapeHtml(use.version)}</code>`}</dd></div>
      <div><dt>Deployment</dt><dd>${deployments[use.deployment]}</dd></div>
    </dl>
    ${renderConditions(use, useProof)}
    ${renderWalkthrough(use, id, code, calls, runtime, operation, useProof)}
    <section class="reason"><h4>Why this verdict</h4><p class="muted">${verdictMeaning[use.verdict]}</p><p class="report-text">${escapeHtml(use.reason)}</p></section>
    ${place.unresolvedQuestions.length ? `<section class="reason"><h4>Unresolved questions</h4><ul>${place.unresolvedQuestions.map((question) => `<li class="report-text">${escapeHtml(question)}</li>`).join("")}</ul></section>` : ""}
    <details class="context"><summary>Place and dependency scope</summary><dl class="metadata">${scope}</dl>${place.deploymentDetail ? `<p class="report-text">${escapeHtml(place.deploymentDetail)}</p>` : ""}</details>
    ${decidingEvidence ? `<details class="evidence" open><summary>Deciding evidence</summary><ul class="evidence-list">${decidingEvidence}</ul></details>` : ""}
    <details class="evidence" open><summary>Source citations <span>${use.evidence.length}</span></summary><ul class="evidence-list">${citations}</ul></details>
    ${
      observations
        ? `<details class="evidence"><summary>Inventory observations <span>${use.observations.length}</span></summary><ul class="evidence-list">${observations}</ul></details>`
        : '<p class="no-inventory">No inventory observations recorded for this use.</p>'
    }
  </article>`;
}

function renderPlaceSummary(
  check: Check,
  title: string,
  unresolvedCount: number,
) {
  const counts = verdictOrder.map((verdict) => ({
    verdict,
    count: check.uses.filter((use) => use.verdict === verdict).length,
  }));
  const breakdown = counts
    .filter(({ count }) => count > 0)
    .map(
      ({ verdict, count }) =>
        `<span class="decision-count tone" data-verdict="${verdict}"><strong>${count}</strong> ${verdicts[verdict].toLowerCase()}</span>`,
    )
    .join("");
  const unresolved = unresolvedCount
    ? ` · ${quantity(unresolvedCount, "unresolved item")}`
    : "";
  return `<section class="decision">
    <div><h2>${escapeHtml(title)}</h2><p>${quantity(check.uses.length, "reviewed place")}${unresolved}</p></div>
    <div class="scope">${breakdown ? `<p class="breakdown">${breakdown}</p>` : ""}</div>
  </section>`;
}

function renderSearchAudit(check: Check): string {
  const labels = {
    matches: "Matches returned",
    no_match: "No match observed",
    returned: "Response returned",
    unknown: "Result unknown",
    not_run: "Did not run",
    complete: "Complete for this search",
    partial: "Partial",
    error: "Error",
    unavailable: "Unavailable",
    skipped: "Skipped",
  };
  const rows = check.searches
    .map(
      ({
        source,
        tool,
        scope,
        startedAt,
        finishedAt,
        result,
        completeness,
        details,
        evidenceReferences,
      }) => {
        return `<tr><td><strong>${escapeHtml(source)}</strong><br><code>${escapeHtml(tool)}</code></td><td>${scope.length ? `<ul>${scope.map((entry) => `<li>${escapeHtml(entry)}</li>`).join("")}</ul>` : "Scope unavailable"}</td><td>${startedAt ? `${escapeHtml(startedAt)}<br>` : ""}${escapeHtml(finishedAt)}</td><td>${labels[result]}<br>${completeness === "unknown" ? "Completeness unknown" : labels[completeness]}${details.length ? `<ul>${details.map((detail) => `<li>${escapeHtml(detail)}</li>`).join("")}</ul>` : ""}</td><td>${evidenceReferences.map((ref) => `<code>${escapeHtml(ref)}</code>`).join("<br>") || "—"}</td></tr>`;
      },
    )
    .join("");
  return `<details class="context"><summary>Search coverage <span>${check.searches.length}</span></summary>${rows ? `<div class="audit-scroll"><table class="audit"><thead><tr><th>Source and tool</th><th>Search scope</th><th>Recorded UTC</th><th>Result and completeness</th><th>Evidence references</th></tr></thead><tbody>${rows}</tbody></table></div>` : '<p class="report-text">This report contains no captured search records.</p>'}</details>`;
}

function renderCoverage(
  coverage: Check["coverage"],
  code: ReadonlyMap<string, string> | undefined,
  open: boolean,
): string {
  if (!coverage?.length) return "";
  const decisions = coverage
    .map((item) => {
      const evidence = item.evidence
        .map((cite) => {
          const lines =
            cite.startLine === cite.endLine
              ? cite.startLine
              : `${cite.startLine}–${cite.endLine}`;
          const snippet = code?.get(citationKey(cite));
          return `<li><code>${escapeHtml(cite.path)}:${lines}</code>${sourceRevision(cite.commit)}${snippet === undefined ? "" : renderDependencyCode(snippet, cite.path, cite.startLine)}</li>`;
        })
        .join("");
      const observations = item.observations
        .map(
          ({ server, record }) =>
            `<li><strong>${escapeHtml(server)}</strong><p class="report-text">${escapeHtml(record)}</p></li>`,
        )
        .join("");
      return `<section class="reason">
      <h4>${item.kind === "dismissed" ? "Excluded" : "Unresolved"}</h4>
      <p class="report-text">${escapeHtml(item.reason)}</p>
      <ul class="evidence-list">${evidence}</ul>
      ${observations ? `<ul>${observations}</ul>` : ""}
    </section>`;
    })
    .join("");
  return `<details class="coverage"${open ? " open" : ""}><summary>Other checked code <span>${coverage.length}</span></summary>${decisions}</details>`;
}

function renderCheck(
  check: Check,
  title: string,
  number: number,
  code: ReadonlyMap<string, string> | undefined,
  productionCalls: ReadonlyMap<string, readonly ProductionCall[]>,
  supplementalAdvisories: ReadonlyMap<string, AdvisoryDetails>,
  useProof: ReadonlyMap<string, DependencyReportProof>,
) {
  const indexId = `index-${number}`;
  const unresolvedCount =
    check.coverage?.filter((item) => item.kind === "unresolved").length ?? 0;
  const advisoryDetails = new Map(
    (check.advisoryDetails ?? []).map((entry) => [entry.url, entry]),
  );
  for (const url of check.advisories) {
    const supplement = supplementalAdvisories.get(url);
    if (supplement && !advisoryDetails.has(url))
      advisoryDetails.set(url, supplement);
  }
  const details = [...advisoryDetails.values()];
  const entries = check.uses
    .map((use, index) => ({ use, id: useId(number, index + 1) }))
    .sort(
      (a, b) =>
        verdictOrder.indexOf(a.use.verdict) -
          verdictOrder.indexOf(b.use.verdict) ||
        deploymentOrder.indexOf(a.use.deployment) -
          deploymentOrder.indexOf(b.use.deployment),
    );
  const rows = entries
    .map(
      ({
        use,
        id,
      }) => `<li data-use-row data-verdict="${use.verdict}" data-deployment="${use.deployment}">
    <a href="#${id}" aria-controls="${id}">
      <span class="row-location">${escapeHtml(use.location)}</span>
      <span class="row-meta">${badge(use.verdict)}<span>${use.version === null ? "Version unknown" : `<code>${escapeHtml(use.version)}</code>`}</span><span>${deployments[use.deployment]}</span></span>
    </a>
  </li>`,
    )
    .join("");
  const panels = entries
    .map(({ use, id }) => {
      const names = new Set(
        details
          .filter(
            (detail) =>
              detail.affected.some(
                (entry) => entry.package?.name === use.component,
              ) &&
              detail.affected.every(
                (entry) =>
                  !entry.package || entry.package.name === use.component,
              ),
          )
          .flatMap(advisoryFunctions)
          .map(({ name }) => name),
      );
      const operation = names.size === 1 ? [...names][0] : undefined;
      return renderUse(
        use,
        id,
        indexId,
        code,
        productionCalls.get(id) ?? [],
        operation,
        useProof.get(id),
      );
    })
    .join("");
  const limitations = check.limitations.length
    ? `<details class="limits"><summary>Report limitations <span>${check.limitations.length}</span></summary><ul>${check.limitations.map((note) => `<li class="report-text">${escapeHtml(note)}</li>`).join("")}</ul></details>`
    : "";
  const assumptions = check.assumptions.length
    ? `<details class="context" open><summary>Supplied assumptions</summary><ul>${check.assumptions.map((note) => `<li class="report-text">${escapeHtml(note)}</li>`).join("")}</ul></details>`
    : "";
  const references = check.advisories.length
    ? `<details class="context"><summary>Advisory references <span>${check.advisories.length}</span></summary><ul>${check.advisories.map((url) => `<li>${advisoryLink(url)}</li>`).join("")}</ul></details>`
    : "";
  const usage = check.usage
    ? `<details class="context"><summary>Token usage</summary><dl class="metadata usage">
      <div><dt>Input</dt><dd>${check.usage.input_tokens.toLocaleString("en-US")}</dd></div>
      <div><dt>Cached input</dt><dd>${check.usage.cached_input_tokens.toLocaleString("en-US")}</dd></div>
      <div><dt>Cache write</dt><dd>${check.usage.cache_write_input_tokens.toLocaleString("en-US")}</dd></div>
      <div><dt>Output</dt><dd>${check.usage.output_tokens.toLocaleString("en-US")}</dd></div>
      <div><dt>Reasoning output</dt><dd>${check.usage.reasoning_output_tokens.toLocaleString("en-US")}</dd></div>
    </dl></details>`
    : "";
  return `<section class="check" id="check-${number}">
    ${renderPlaceSummary(check, title, unresolvedCount)}
    ${renderAdvisory(details)}
    ${
      rows
        ? `<section class="workspace" data-workbench aria-label="Assessed uses for ${escapeHtml(title)}">
      <div class="use-index" id="${indexId}">
        <header class="index-head"><h3>Reviewed places</h3><p data-count class="muted" aria-live="polite">${quantity(entries.length, "place")}</p></header>
        <div class="filters" data-filters hidden>
          <label>Find a place <input type="search" data-search placeholder="Location, dependency, or citation"></label>
          <label>Verdict <select data-verdict-filter><option value="">All verdicts</option>${verdictOrder.map((value) => `<option value="${value}">${verdicts[value]}</option>`).join("")}</select></label>
          <label>Deployment <select data-deployment-filter><option value="">All deployments</option>${deploymentOrder.map((value) => `<option value="${value}">${deployments[value]}</option>`).join("")}</select></label>
        </div>
        <p class="empty" data-no-results hidden>No places match these filters.</p>
        <ul class="use-list">${rows}</ul>
      </div>
      <div class="inspection">${panels}</div>
    </section>`
        : '<p class="empty">No reviewed places were recorded for this check.</p>'
    }
    ${renderCoverage(check.coverage, code, check.uses.length === 0 && unresolvedCount > 0)}
    ${renderSearchAudit(check)}
    ${assumptions}
    ${limitations}
    <footer class="report-details" aria-label="Report details">${references}${usage}</footer>
  </section>`;
}

/** Render saved exploitability output without reading its cited files. */
export function renderDependencyReport(
  value: unknown,
  options: ReportRenderOptions = {},
): string {
  const report = readReport(value);
  const single = "cve" in report;
  const title = single ? report.cve : report.package.name;
  const context = single
    ? "Dependency advisory"
    : `${report.package.ecosystem} package`;
  const checks = single ? [report] : report.checks;
  const referencedAdvisories = new Set(
    checks.flatMap((check) => check.advisories),
  );
  const supplementalAdvisories = new Map(
    (options.advisoryDetails ?? []).map((entry) => {
      if (!referencedAdvisories.has(entry.url))
        throw new Error(
          `Saved advisory ${entry.url} is not referenced by this report.`,
        );
      return [entry.url, entry] as const;
    }),
  );
  const uses = new Map(
    checks.flatMap((check, index) =>
      check.uses.map(
        (use, position) => [useId(index + 1, position + 1), use] as const,
      ),
    ),
  );
  const useProof = new Map(
    parseDependencyReportProof(
      options.useEvidence === undefined ? [] : options.useEvidence,
      uses,
    ),
  );
  const savedProof = parseDependencyReportProof(
    [...uses].flatMap(([id, use]) =>
      use.proof ? [{ ...use.proof, useId: id, location: use.location }] : [],
    ),
    uses,
  );
  for (const [id, proof] of savedProof) useProof.set(id, proof);
  const measurements = Map.groupBy(
    z
      .array(productionCallSchema)
      .parse(
        options.productionCalls === undefined ? [] : options.productionCalls,
      ),
    (measurement) => {
      if (uses.get(measurement.useId)?.location !== measurement.location)
        throw new Error(
          `Production measurement does not match report use ${measurement.useId}.`,
        );
      return measurement.useId;
    },
  );
  const headings = checks.map((check) =>
    "advisoryId" in check ? (check.advisoryId ?? "Supplied advisory") : title,
  );
  const sections = checks
    .map((check, index) =>
      renderCheck(
        check,
        headings[index]!,
        index + 1,
        options.code,
        measurements,
        supplementalAdvisories,
        useProof,
      ),
    )
    .join("");
  const digest = createHash("sha256").update(interactions).digest("base64");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-${digest}'; base-uri 'none'; form-action 'none'">
  <title>${escapeHtml(title)} | Exploitability report</title>
  <style>${styles}</style>
</head>
<body>
  <main class="layout">
    <header class="masthead">
      <div><p class="eyebrow">${escapeHtml(context)}</p><h1>${escapeHtml(title)}</h1></div>
      <span class="brand">Exploitability report <span aria-hidden="true">/</span> Codex Security</span>
    </header>
    ${
      !single && report.vulnDescription
        ? `<details class="context"><summary>Supplied vulnerability description</summary><p class="report-text">${escapeHtml(report.vulnDescription)}</p></details>`
        : ""
    }
    ${
      checks.length > 1
        ? `<nav class="advisory-index" aria-label="Advisory checks">${headings.map((heading, index) => `<a href="#check-${index + 1}">${escapeHtml(heading)}</a>`).join("")}</nav>`
        : ""
    }
    ${sections || '<p class="empty">No advisory checks were recorded for this package.</p>'}
  </main>
  <script>${interactions}</script>
</body>
</html>
`;
}

const interactions = `
  for (const walkthrough of document.querySelectorAll("[data-walkthrough]")) {
    const steps = [...walkthrough.querySelectorAll("[data-flow-step]")];
    const panels = [...walkthrough.querySelectorAll("[data-flow-detail]")];
    const actions = walkthrough.querySelector("[data-flow-actions]");
    const back = actions.querySelector("[data-flow-back]");
    const next = actions.querySelector("[data-flow-next]");
    const progress = actions.querySelector("[data-flow-progress]");
    let active;
    function show(index) {
      active = index;
      steps.forEach((step, position) => {
        step.setAttribute("aria-pressed", String(position === index));
        panels[position].hidden = position !== index;
      });
      back.disabled = index === 0;
      next.disabled = index === steps.length - 1;
      progress.textContent = "Step " + (index + 1) + " of " + steps.length;
    }
    steps.forEach((step, position) => step.addEventListener("click", () => show(position)));
    back.addEventListener("click", () => show(active - 1));
    next.addEventListener("click", () => show(active + 1));
    show(steps.findIndex(step => step.getAttribute("aria-pressed") === "true"));
    actions.hidden = false;
  }
  for (const bench of document.querySelectorAll("[data-workbench]")) {
    const filters = bench.querySelector("[data-filters]");
    const search = bench.querySelector("[data-search]");
    const verdict = bench.querySelector("[data-verdict-filter]");
    const deployment = bench.querySelector("[data-deployment-filter]");
    const count = bench.querySelector("[data-count]");
    const empty = bench.querySelector("[data-no-results]");
    const entries = [...bench.querySelectorAll("[data-use-row]")].map(row => {
      const link = row.querySelector("a");
      const panel = document.getElementById(link.getAttribute("aria-controls"));
      return { row, link, panel, text: panel.textContent.toLowerCase() };
    });
    let active;
    function select(entry) {
      active = entry;
      for (const { link, panel } of entries) {
        panel.hidden = panel !== active?.panel;
        if (panel === active?.panel) link.setAttribute("aria-current", "true");
        else link.removeAttribute("aria-current");
      }
    }
    function update() {
      const query = search.value.trim().toLowerCase();
      const matches = entries.filter(({ row, text }) => {
        const match = text.includes(query) &&
          (!verdict.value || verdict.value === row.dataset.verdict) &&
          (!deployment.value || deployment.value === row.dataset.deployment);
        row.hidden = !match;
        return match;
      });
      count.textContent = matches.length + " of " + entries.length + " shown";
      empty.hidden = matches.length !== 0;
      select(matches.includes(active) ? active : matches[0]);
    }
    for (const entry of entries) {
      entry.link.addEventListener("click", event => {
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
        event.preventDefault();
        select(entry);
        history.replaceState(null, "", entry.link.getAttribute("href"));
        if (matchMedia("(max-width: 760px)").matches) {
          entry.panel.querySelector("h3").focus({ preventScroll: true });
          entry.panel.scrollIntoView({ block: "start" });
        }
      });
    }
    addEventListener("hashchange", () => {
      const entry = entries.find(item => "#" + item.panel.id === location.hash);
      if (!entry) return;
      if (entry.row.hidden) {
        search.value = "";
        verdict.value = "";
        deployment.value = "";
        update();
      }
      select(entry);
    });
    search.addEventListener("input", update);
    verdict.addEventListener("change", update);
    deployment.addEventListener("change", update);
    active = entries.find(({ panel }) => "#" + panel.id === location.hash);
    filters.hidden = false;
    update();
    if (active && "#" + active.panel.id === location.hash) active.panel.scrollIntoView({ block: "start" });
  }
  let closedForPrint = [];
  addEventListener("beforeprint", () => {
    closedForPrint = [...document.querySelectorAll("details:not([open])")];
    closedForPrint.forEach(detail => { detail.open = true; });
  });
  addEventListener("afterprint", () => {
    closedForPrint.forEach(detail => { detail.open = false; });
    closedForPrint = [];
  });
`;

const styles = `
  :root {
    color-scheme: light dark;
    --page: #fbfaf8;
    --surface: #fff;
    --text: #242422;
    --muted: #625f58;
    --border: #dedbd3;
    --wash: #f3f1ec;
    --selected: #eeece5;
    --accent: #3d5038;
    --met: #245641; --unknown: #785326; --exclusion: #914137;
    --code-keyword: #853b92; --code-string: #276542; --code-number: #8b5018;
    --code-property: #235d8a; --code-focus: #f6eac5; --code-marker: #a17623;
    font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
    background: var(--page);
    color: var(--text);
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --page: #191917; --surface: #20201d; --text: #eeece5; --muted: #b5b1a7;
      --border: #393834; --wash: #242421; --selected: #30312b; --accent: #c6d9ba;
      --met: #9bd7b3; --unknown: #e1c183; --exclusion: #efa99e;
      --code-keyword: #dba7e7; --code-string: #abd6ab; --code-number: #e9ba86;
      --code-property: #9fcbe9; --code-focus: #443a25; --code-marker: #d6aa58;
    }
  }
  * { box-sizing: border-box; }
  body, h1, h2, h3, h4, p, dl, dd { margin: 0; }
  [hidden] { display: none !important; }
  a { color: var(--accent); text-underline-offset: .16em; }
  code { font: .92em/1.5 ui-monospace, "SFMono-Regular", Consolas, monospace; }
  .layout { width: min(1200px, calc(100% - 64px)); margin-inline: auto; padding-bottom: 48px; }
  .masthead { display: flex; justify-content: space-between; align-items: end; flex-wrap: wrap; gap: 6px 16px; padding: 26px 0 20px; border-bottom: 1px solid var(--border); }
  .eyebrow { color: var(--muted); font-size: .71rem; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
  h1 { font-size: clamp(1.38rem, 3vw, 2rem); line-height: 1.14; letter-spacing: -.035em; overflow-wrap: anywhere; }
  h2 { font-size: clamp(1.35rem, 2.6vw, 1.9rem); line-height: 1.22; letter-spacing: -.03em; }
  h3 { font-size: 1.06rem; line-height: 1.35; }
  h4 { font-size: .89rem; margin-bottom: 4px; }
  .brand, .muted { color: var(--muted); font-size: .82rem; }
  .brand span { margin-inline: 4px; }
  .tone[data-verdict="exploitable"] { --tone: #9f2d45; --tint: #fbe6eb; }
  .tone[data-verdict="potentially_exploitable"] { --tone: #794a0c; --tint: #fceccd; }
  .tone[data-verdict="ruled_out"] { --tone: #156248; --tint: #e0f2e9; }
  .tone[data-verdict="unknown"] { --tone: #494f81; --tint: #eaedfa; }
  .badge, .decision-count { display: inline-block; width: fit-content; padding: 2px 7px; border-radius: 3px; background: var(--tint); color: var(--tone); font-size: .74rem; font-weight: 650; }
  .check { margin-block: 20px 32px; }
  .decision { display: grid; grid-template-columns: minmax(0, 1.6fr) minmax(0, 1fr); align-items: center; gap: 16px 32px; padding-block: 2px; overflow-wrap: anywhere; }
  .audit-scroll { overflow-x: auto; }
  .audit { border-collapse: collapse; width: 100%; overflow-wrap: anywhere; }
  .audit th, .audit td { padding: 8px; text-align: start; vertical-align: top; border-bottom: 1px solid var(--border); }
  .audit ul { margin: 0; padding-inline-start: 1.2em; }
  .decision h2 { margin-top: 2px; }
  .meaning { color: var(--muted); margin-top: 4px; font-size: .92rem; }
  .scope { border-inline-start: 1px solid var(--border); padding-inline-start: 18px; font-size: .85rem; }
  .scope > p { color: var(--muted); margin-top: 3px; }
  .breakdown { display: flex; flex-wrap: wrap; gap: 5px; }
  summary { cursor: pointer; font-weight: 665; }
  summary span { margin-inline-start: 7px; font-size: .79rem; color: var(--muted); }
  .limits, .context, .empty { padding-block: 10px; overflow-wrap: anywhere; }
  .limits { margin-top: 16px; border-top: 1px solid var(--border); }
  .report-details { border-top: 1px solid var(--border); }
  .advisory-brief { margin: 16px 0; padding-block: 10px; border-top: 1px solid var(--border); overflow-wrap: anywhere; }
  .advisory-body { margin-top: 6px; }
  .advisory-heading { display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; gap: 4px 14px; }
  .advisory-heading > span { color: var(--muted); font-size: .8rem; }
  .advisory-description { margin-top: 5px; font-size: .9rem; }
  .advisory-fields { display: flex; flex-wrap: wrap; gap: 7px 28px; margin-top: 8px; }
  .advisory-fields ul { list-style: none; margin: 0; padding: 0; }
  .advisory-fields li { display: flex; flex-wrap: wrap; gap: 3px 8px; align-items: baseline; font-size: .84rem; }
  .advisory-fields li > span { color: var(--muted); font-size: .79rem; }
  .advisory-fields li + li { margin-top: 3px; }
  .advisory-applicability { margin-top: 8px; font-size: .84rem; }
  .advisory-applicability section { margin-top: 5px; }
  .limits ul, .context ul { margin: 7px 0 0; padding-inline-start: 19px; }
  .limits li + li, .context li + li { margin-top: 5px; }
  .context { margin-top: 7px; font-size: .87rem; }
  .context p, .usage { margin-top: 7px; }
  .advisory-index { display: flex; flex-wrap: wrap; gap: 8px 14px; margin-block: 8px 12px; }
  .workspace { display: grid; grid-template-columns: minmax(260px, .95fr) minmax(0, 2.3fr); align-items: start; margin-block: 14px; border-top: 1px solid var(--border); }
  .use-index, .use-panel { min-width: 0; }
  .index-head { display: flex; justify-content: space-between; align-items: baseline; gap: 6px 12px; padding: 16px 12px 8px 0; }
  .filters { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 7px; padding: 0 12px 13px 0; }
  .filters label { display: grid; gap: 3px; color: var(--muted); font-size: .75rem; font-weight: 650; }
  .filters label:first-child { grid-column: 1 / -1; }
  .filters input, .filters select { min-width: 0; width: 100%; min-height: 34px; padding: 5px 7px; font: inherit; font-size: .85rem; color: var(--text); background: var(--wash); border: 1px solid var(--border); border-radius: 5px; }
  .use-list { list-style: none; margin: 0; padding: 0; max-height: min(58vh, 530px); overflow: auto; }
  .use-list li { border-top: 1px solid var(--border); }
  .use-list a { display: block; padding: 8px 11px; border-inline-start: 3px solid transparent; color: var(--text); text-decoration: none; }
  .use-list a:hover { background: var(--wash); }
  .use-list a[aria-current="true"] { border-inline-start-color: var(--accent); background: var(--selected); }
  .row-location { display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; overflow-wrap: anywhere; font-size: .86rem; font-weight: 670; line-height: 1.3; }
  .row-meta { display: flex; align-items: center; flex-wrap: wrap; gap: 4px 7px; color: var(--muted); font-size: .73rem; margin-top: 4px; }
  .row-meta .badge { padding: 2px 6px; font-size: .69rem; }
  .empty { color: var(--muted); }
  .use-index .empty { margin: 3px 10px 10px; }
  .use-panel { padding: 16px 0 10px 24px; border-inline-start: 1px solid var(--border); overflow-wrap: anywhere; scroll-margin-top: 12px; }
  .use-panel + .use-panel { margin-top: 9px; }
  .use-panel[hidden] + .use-panel { margin-top: 0; }
  .panel-heading { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 4px 10px; margin-bottom: 5px; }
  .use-panel h3 { font-size: 1.22rem; letter-spacing: -.02em; }
  .back-link { display: none; font-size: .85rem; margin-bottom: 8px; }
  .metadata, .runtime-proof { display: flex; flex-wrap: wrap; gap: 7px 22px; margin-top: 10px; }
  .metadata dt, .runtime-proof dt { color: var(--muted); font-size: .73rem; }
  .metadata dd, .runtime-proof dd { font-size: .88rem; font-weight: 660; }
  .reason { margin-block: 12px; font-size: .92rem; }
  .report-text { white-space: pre-wrap; overflow-wrap: anywhere; }
  .runtime-proof { padding-block: 7px; margin-bottom: 10px; border-block: 1px solid var(--border); }
  .conditions { margin-block: 18px 20px; }
  .conditions h4 { margin-bottom: 7px; }
  .condition { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 2.2fr); gap: 8px; padding: 7px 0; border-top: 1px solid var(--border); font-size: .84rem; }
  .condition dt { font-weight: 635; }
  .condition dd { display: grid; grid-template-columns: 84px minmax(0, 1fr); gap: 7px; }
  .condition-status { color: var(--unknown); font-weight: 660; }
  .condition[data-condition="met"] .condition-status { color: var(--met); }
  .condition[data-condition="ruled_out"] .condition-status { color: var(--exclusion); }
  .condition-cites { display: flex; flex-wrap: wrap; gap: 2px 9px; margin-top: 2px; color: var(--muted); }
  .recorded-exclusion { border-top: 1px solid var(--border); padding-top: 7px; font-size: .85rem; }
  .walkthrough { margin-block: 13px 16px; padding-top: 11px; border-top: 1px solid var(--border); }
  .flow-heading, .flow-actions { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 5px 9px; }
  .flow-heading h4 { margin: 0; }
  .flow-nodes { list-style: none; display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 15px; margin: 8px 0 5px; padding: 0; }
  .flow-nodes[data-steps="3"] { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .flow-nodes li { position: relative; min-width: 0; }
  .flow-nodes li + li::before { position: absolute; left: -13px; top: 24px; content: "→"; color: var(--muted); }
  .flow-node { display: flex; flex-direction: column; text-align: start; gap: 3px; width: 100%; height: 100%; min-height: 60px; padding: 7px; font: inherit; font-size: .78rem; color: var(--text); border: 0; border-bottom: 2px solid var(--border); background: var(--wash); cursor: pointer; overflow-wrap: anywhere; }
  .flow-node[aria-pressed="true"] { border-bottom-color: var(--accent); background: var(--selected); }
  .flow-label, .flow-count { font-size: .69rem; color: var(--muted); }
  .flow-node[data-flow-step="result"] .flow-label { font-weight: 700; }
  .walkthrough[data-verdict="ruled_out"] .flow-node[data-flow-step="result"] { border-color: var(--tone); }
  .flow-caption { margin-block: 5px 7px; }
  .flow-detail { padding-block: 8px; font-size: .87rem; }
  .sink-reference { display: flex; flex-wrap: wrap; gap: 3px 14px; align-items: baseline; margin-bottom: 6px; }
  .sink-reference > code { font-weight: 650; }
  .flow-actions { margin-top: 7px; font-size: .78rem; color: var(--muted); }
  .flow-actions button { border: 1px solid var(--border); padding: 4px 9px; border-radius: 4px; background: var(--surface); color: var(--text); font: inherit; cursor: pointer; }
  .flow-actions button:disabled { opacity: .45; cursor: default; }
  .step-citations, .production ul { list-style: none; padding: 0; margin: 6px 0 0; }
  .step-citations li + li, .production li + li { margin-top: 5px; }
  .snippet { border-top: 1px solid var(--border); padding-block: 6px; }
  .snippet pre { margin: 5px 0 0; padding-block: 7px; max-height: 280px; overflow: auto; background: var(--wash); border: 1px solid var(--border); border-radius: 3px; font-size: .88rem; }
  .code-listing > code { display: block; min-width: max-content; }
  .code-row { display: flex; min-height: 1.5em; border-inline-start: 3px solid transparent; padding-inline-end: 12px; }
  .code-row[data-highlighted] { background: var(--code-focus); border-inline-start-color: var(--code-marker); }
  .code-number { flex: 0 0 auto; min-width: 5ch; text-align: end; margin-inline-end: 2ch; color: var(--muted); user-select: none; }
  .code-text { white-space: pre; tab-size: 4; }
  .tok-keyword { color: var(--code-keyword); }
  .tok-string { color: var(--code-string); }
  .tok-number, .tok-literal { color: var(--code-number); }
  .tok-property { color: var(--code-property); }
  .tok-comment { color: var(--muted); }
  .snippet > p, .full-citation { margin-top: 4px; }
  .full-citation summary { color: var(--muted); font-size: .77rem; }
  .production { margin-top: 7px; }
  .production li { display: grid; gap: 2px; background: var(--wash); padding: 5px 7px; border-radius: 4px; }
  .evidence { border-top: 1px solid var(--border); padding-block: 8px; }
  .evidence-list { list-style: none; padding: 0; margin: 5px 0 0; }
  .evidence-list li { border-bottom: 1px solid var(--border); padding: 6px 0; }
  .evidence-list li:last-child { border-bottom: 0; }
  .evidence-list li p { margin-top: 3px; }
  .tags { display: flex; flex-wrap: wrap; gap: 4px; }
  .tags:not(:empty) { margin-top: 3px; }
  .tag { padding: 2px 6px; border-radius: 4px; background: var(--wash); color: var(--muted); font-size: .73rem; }
  .no-inventory { border-top: 1px solid var(--border); padding-top: 7px; color: var(--muted); font-size: .81rem; }
  :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  .use-list a:focus-visible { outline-offset: -3px; }
  @media (max-width: 760px) {
    .layout { width: calc(100% - 24px); }
    .masthead { padding-block: 12px; }
    .decision, .workspace { grid-template-columns: minmax(0, 1fr); gap: 10px; }
    .scope { border-inline-start: 0; border-top: 1px solid var(--border); padding: 6px 0 0; }
    .use-list { max-height: min(44vh, 350px); }
    .use-panel { border-inline-start: 0; border-top: 1px solid var(--border); padding-inline: 0; }
    .condition { grid-template-columns: minmax(0, 1fr); gap: 2px; }
    .back-link { display: inline-block; }
    .flow-nodes, .flow-nodes[data-steps="3"] { grid-template-columns: 1fr; gap: 13px; }
    .flow-nodes li + li::before { left: 9px; top: -14px; content: "↓"; }
    .flow-node { min-height: 42px; }
  }
  @media print {
    :root { color-scheme: light; --page: #fff; --surface: #fff; --text: #242422; --muted: #625f58; --border: #dedbd3; --wash: #f3f1ec; --accent: #3d5038; }
    .layout { width: 100%; }
    .workspace { display: block; }
    .use-panel { border-inline-start: 0; padding-inline-start: 0; }
    .use-index, .back-link, .advisory-index { display: none !important; }
    .flow-actions { display: none !important; }
    .flow-detail[hidden] { display: block !important; }
    .use-panel[hidden] { display: block !important; }
    .use-panel + .use-panel { margin-top: 9px; }
    .decision, .badge { print-color-adjust: exact; }
    .panel-heading, h3, h4 { break-after: avoid; }
    .evidence-list li { break-inside: avoid; }
  }
`;
