import {
  advisoryFunctions,
  sectionAdvisories,
  servicesFor,
  useCountLabel,
  inputFor,
  verdictOrder,
  type Advisory,
  type DependencyVerdict,
  type Finding,
  type Report,
  type Section,
} from "./dependency-report-model.js";
import { inspectPath, type PathInspector } from "./dependency-report-path.js";
import {
  escapeHtml as esc,
  safeLink,
  prose,
} from "./dependency-report-audit.js";
import { dependencyVerdictLabels } from "./dependency-verdict-labels.js";

export type State =
  DependencyVerdict | "unresolved" | "blocked" | "empty" | "pending";
export type Entry = {
  id: string;
  state: State;
  file: string;
  name: string;
  scope: string;
  location?: string;
  finding?: Finding;
  path?: PathInspector;
};
export type Group = { section: Section; entries: Entry[] };

const labels: Record<State, string> = {
  ...dependencyVerdictLabels,
  unresolved: "Unresolved candidate",
  blocked: "Blocked",
  pending: "Not started",
  empty: "No findings",
};

export function status(state: State): string {
  return `<span class="status" data-verdict="${state}">${labels[state]}</span>`;
}
export function basename(path: string): string {
  return path.split(/[\\/]/u).at(-1) || path;
}
function context(values: (string | undefined | null)[]) {
  return [...new Set(values.filter(Boolean))].join(" · ");
}
function image(digest?: string | null) {
  if (!digest) return;
  const hex = /^sha256:([0-9a-f]{64})$/iu.exec(digest);
  return "Image " + (hex ? hex[1]!.slice(0, 12) : digest);
}
function scope(f: Finding, includeImage = true) {
  if (f.kind === "stack") {
    const s = f.assessment.scope;
    return context([
      s.service,
      s.environment,
      s.cluster,
      s.container,
      includeImage ? image(s.image_digest) : undefined,
    ]);
  }
  const place = f.item.place;
  return context([
    ...servicesFor(f.item).map((s) => s.name),
    place?.workload,
    place?.environment,
    place?.variant,
    place?.platform,
    includeImage ? image(place?.platformManifest) : undefined,
  ]);
}
function label(f: Finding, path: PathInspector): string {
  if (f.kind === "stack") {
    if (f.assessment.status === "no_match") return "No matching stack";
    if (f.assessment.status === "no_coverage") return "No sampling coverage";
    return (
      path.frames.find((frame) => frame.role === "call_site")?.label ??
      f.proof?.sink?.function ??
      path.frames.find((frame) => frame.role === "sink")?.label ??
      "Sampled call"
    );
  }
  if (f.kind === "coverage") return f.item.location ?? "Unresolved candidate";
  return f.item.location || f.proof?.sink?.function || f.item.component;
}

export function entries(section: Section, index: number): Entry[] {
  const findings = section.prepared?.findings;
  if (!findings?.length) {
    const state = section.pending
      ? "pending"
      : section.blocked
        ? "blocked"
        : "empty";
    const name = section.pending
      ? "Investigation not started"
      : section.blocked
        ? "Investigation blocked"
        : useCountLabel(section, "No");
    return [
      { id: "empty-" + index, state, name, file: section.title, scope: "" },
    ];
  }
  const items = findings.map((finding): Entry => {
    const { anchor } = finding;
    const path = inspectPath(finding, section.stack?.target);
    const location = anchor ? anchor.path + ":" + anchor.line : undefined;
    const name = label(finding, path);
    return {
      id: finding.id,
      state: finding.kind === "coverage" ? "unresolved" : finding.item.verdict,
      file: location ? basename(location) : name,
      name,
      scope: scope(finding),
      location,
      finding,
      path,
    };
  });
  const fileGroups = Map.groupBy(items, (item) => item.file);
  for (const group of fileGroups.values()) {
    if (new Set(group.map((item) => item.location)).size > 1) {
      for (const item of group) if (item.location) item.file = item.location;
    }
  }
  // Each variant keeps its own verdict and URL. Only exact source locations
  // share a heading. Group order follows the highest-priority use at each site.
  return [...siteGroups(items)].flat();
}
const siteGroups = (items: Entry[]) =>
  Map.groupBy(items, (entry) => entry.location ?? entry).values();

function searchTerms(entry: Entry, section: Section) {
  const f = entry.finding;
  return [
    section.title,
    entry.location,
    entry.scope,
    f?.item.location,
    ...(entry.path?.frames.map((frame) => frame.label) ?? []),
    f && inputFor(f.item)?.endpoint,
    f && f.kind !== "coverage" ? f.item.component : undefined,
  ]
    .filter(Boolean)
    .join(" ");
}
function queueGroup({ section, entries: items }: Group, multi: boolean) {
  const rows = [...siteGroups(items)]
    .map((variants) => {
      const nested = variants.length > 1;
      const key = (v: Entry) => JSON.stringify([v.name, v.scope, v.state]);
      const repeats = Map.groupBy(variants, key);
      const links = variants
        .map((entry, i) => {
          const name =
            entry.name === entry.file || !entry.finding ? "" : entry.name;
          const duplicate = repeats.get(key(entry))!.length > 1;
          const navScope = entry.finding
            ? scope(entry.finding, nested)
            : entry.scope;
          const detail = context([
            navScope,
            duplicate ? "Assessment " + (i + 1) : undefined,
          ]);
          return `<a class="queue-item" data-entry="${entry.id}" data-verdict="${entry.state}" data-search-text="${esc(searchTerms(entry, section))}" href="#${entry.id}">
        <span class="queue-file${nested ? " sr-only" : ""}">${esc(entry.file)}</span>
        ${name ? `<span class="queue-name">${esc(name)}</span>` : ""}
        ${detail ? `<span class="queue-context">${esc(detail)}</span>` : ""}
        ${status(entry.state)}
      </a>`;
        })
        .join("");
      if (!nested) return links;
      const first = variants[0]!;
      return `<div class="site-group"><div class="site-group-title queue-file">${esc(first.file)}</div>${links}</div>`;
    })
    .join("");
  return `<div class="queue-group">${multi ? `<h3 class="queue-title">${esc(section.title)}</h3>` : ""}${rows}</div>`;
}
export function rail(groups: Group[]): string {
  const items = groups.flatMap((group) => group.entries);
  const otherStates = (
    ["unresolved", "blocked", "pending", "empty"] as const
  ).filter((s) => items.some((e) => e.state === s));
  const buttons = [...verdictOrder, ...otherStates]
    .map((s) => `<option value="${s}">${labels[s]}</option>`)
    .join("");
  const heading =
    items.length && items.every((e) => !e.finding)
      ? "Assessments"
      : "Call sites";
  const nav = groups
    .map((group) => queueGroup(group, groups.length > 1))
    .join("");
  const tools =
    items.length > 1
      ? `<div class="rail-tools" data-js hidden>
      <input aria-label="Search report" type="search" data-search placeholder="Search files or functions" autocomplete="off">
      <select aria-label="Filter by verdict" data-verdict-filter><option value="">All verdicts</option>${buttons}</select>
    </div>`
      : "";
  return `<aside class="rail">
    <details class="rail-disclosure" open>
      <summary class="rail-toggle">${heading}</summary>
      <div class="rail-body">
        <div class="rail-heading"><h2>${heading}</h2><span class="count" data-count aria-label="Visible assessments" aria-live="polite">${items.length}</span></div>
        ${tools}
        <nav aria-label="${heading}">${nav}</nav>
        <p data-empty hidden>No matching assessments.</p>
      </div>
    </details>
  </aside>`;
}

function packages(details: Advisory[]) {
  const result = new Set<string>();
  for (const advisory of details) {
    for (const affected of advisory.affected) {
      if (!affected.package) continue;
      const fixes = new Set<string>();
      for (const range of affected.ranges ?? []) {
        if (range.type === "GIT") continue;
        for (const event of range.events)
          if ("fixed" in event) fixes.add(event.fixed);
      }
      const suffix = fixes.size
        ? " (fixed in " + [...fixes].map(esc).join(", ") + ")"
        : "";
      result.add(
        `<code>${esc(affected.package.ecosystem + ":" + affected.package.name)}</code>` +
          suffix,
      );
    }
    for (const v of advisory.vulnerabilities ?? []) {
      if (!v.package.name) continue;
      const affected = v.vulnerable_version_range
        ? " " + esc(v.vulnerable_version_range)
        : "";
      const fix = v.first_patched_version
        ? " (fixed in " + esc(v.first_patched_version) + ")"
        : "";
      result.add(
        `<code>${esc(v.package.ecosystem + ":" + v.package.name)}</code>` +
          affected +
          fix,
      );
    }
  }
  return [...result];
}

function advisoryDetails(
  section: Section,
  details: Advisory[],
  urls: string[],
) {
  const functions = advisoryFunctions(details).map(
    (name) => `<code>${esc(name)}</code>`,
  );
  const sources = [...new Set(urls)].map((url) => {
    const item = details.find((d) => d.url === url);
    return safeLink(url, item?.id || url);
  });
  const applicability = [
    ...new Set(
      details.flatMap((d) => (d.applicability ? [prose(d.applicability)] : [])),
    ),
  ];
  const field = (name: string, values: string[]) =>
    values.length ? `<dt>${name}</dt><dd>${values.join("<br>")}</dd>` : "";
  const rows =
    field("Affected packages", packages(details)) +
    field("Vulnerable functions", functions) +
    field("Applies when", applicability) +
    field("Advisory sources", sources);
  const body =
    section.stack && !details.length
      ? "<p>This capture omits the advisory description.</p>"
      : rows
        ? `<dl class="facts">${rows}</dl>`
        : "";
  return body
    ? `<details class="advisory-more"><summary>Advisory details</summary>${body}</details>`
    : "";
}

export function checkout(target: Report["target"]) {
  if (!target) return '<p class="checkout">Checkout not recorded</p>';
  const sha = esc(target.sha);
  return `<div class="checkout"><span class="checkout-repo">Repository <code>${esc(target.repository)}</code></span><details class="checkout-commit"><summary>Analyzed commit <code title="${sha}">${sha.slice(0, 12)}</code></summary><code>${sha}</code></details></div>`;
}

export function advisoryHeader(report: Report, section: Section): string {
  const { details, urls } = sectionAdvisories(section);
  const summary = details.find((d) => d.summary)?.summary;
  const overview =
    details.find((d) => d.overview)?.overview ?? report.description;
  const isPackage = report.context.endsWith(" package");
  const id = section.blocked?.cve ?? section.title;
  const title = summary || id;
  const eyebrow = context([
    isPackage ? report.title : undefined,
    title !== id ? id : undefined,
    report.reviewNote,
  ]);
  return `<header class="advisory-head">
   ${eyebrow ? `<p class="eyebrow">${esc(eyebrow)}</p>` : ""}
   <h1>${prose(title)}</h1>
   ${overview && overview !== title ? `<p class="overview">${prose(overview)}</p>` : ""}
   ${advisoryDetails(section, details, urls)}
 </header>`;
}
