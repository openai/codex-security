import { createHash } from "node:crypto";
import {
  advisoryFunctions,
  citationKey,
  findingLabels,
  findingState,
  matchTraceFrame,
  prepareDependencyReport,
  sectionAdvisories,
  verdictOrder,
  type Advisory,
  type Finding,
  type Report,
  type Section,
} from "./dependency-report-model.js";
import {
  inspectPath,
  type PathFrame,
  type PathInspector,
} from "./dependency-report-path.js";
import {
  code,
  findingAudit,
  para,
  prose,
  safeLink,
  sectionAudit,
} from "./dependency-report-audit.js";
import {
  escapeHtml as esc,
  renderDependencyCode,
} from "./dependency-report-code.js";
import { reportInteractions, reportStyles } from "./dependency-report-ui.js";

type State = keyof typeof labels;
type Entry = {
  id: string;
  state: State;
  file: string;
  name: string;
  scope: string;
  location?: string;
  finding?: Finding;
  path?: PathInspector;
};
type Group = { section: Section; sites: Entry[][] };

const labels = {
  ...findingLabels,
  blocked: "Blocked",
  pending: "Not started",
  empty: "No findings",
};

function status(state: State): string {
  return `<span class="status" data-verdict="${state}">${labels[state]}</span>`;
}
function basename(path: string): string {
  return path.split(/[\\/]/u).at(-1) || path;
}
function join(values: (string | undefined | null | false)[]) {
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
    return join([
      s.service,
      s.environment,
      s.cluster,
      s.container,
      includeImage ? image(s.image_digest) : undefined,
    ]);
  }
  const place = f.item.place;
  return join([
    ...(f.item.services ?? []).map((s) => s.name),
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
      f.item.proof?.sink?.function ??
      path.frames.find((frame) => frame.role === "sink")?.label ??
      "Sampled call"
    );
  }
  if (f.kind === "coverage") return f.item.location ?? labels.unresolved;
  return f.item.location || f.item.proof?.sink?.function || f.item.component;
}

function sites(section: Section, index: number): Entry[][] {
  const findings = section.prepared?.findings;
  if (!findings?.length) {
    const state = section.pending
      ? "pending"
      : section.blocked
        ? "blocked"
        : "empty";
    return [
      [
        {
          id: "empty-" + index,
          state,
          name: "",
          file: section.title,
          scope: "",
        },
      ],
    ];
  }
  const items = findings.map((finding): Entry => {
    const { anchor } = finding;
    const path = inspectPath(finding, section.stack?.target);
    const location = anchor ? anchor.path + ":" + anchor.line : undefined;
    const name = label(finding, path);
    return {
      id: finding.id,
      state: findingState(finding),
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
  return [...Map.groupBy(items, (entry) => entry.location ?? entry).values()];
}
function searchTerms(entry: Entry, section: Section) {
  const f = entry.finding;
  return [
    section.title,
    entry.location,
    entry.scope,
    f?.item.location,
    ...(entry.path?.frames.map((frame) => frame.label) ?? []),
    f?.item.inputSource?.endpoint,
    f && f.kind !== "coverage" ? f.item.component : undefined,
  ]
    .filter(Boolean)
    .join(" ");
}
function queueGroup({ section, sites }: Group, multi: boolean) {
  const rows = sites
    .map((variants) => {
      const nested = variants.length > 1;
      const key = (v: Entry) => JSON.stringify([v.name, v.scope, v.state]);
      const repeats = Map.groupBy(variants, key);
      const links = variants
        .map((entry, i) => {
          const name = entry.name === entry.file ? "" : entry.name;
          const duplicate = repeats.get(key(entry))!.length > 1;
          const navScope =
            entry.finding && !nested
              ? scope(entry.finding, false)
              : entry.scope;
          const detail = join([
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
function rail(groups: Group[]): string {
  const items = groups.flatMap((group) => group.sites.flat());
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
  const add = (name: string, fixes: string[], range?: string | null) => {
    const suffix = fixes.length
      ? " (fixed in " + fixes.map(esc).join(", ") + ")"
      : "";
    result.add(code(name) + (range ? " " + esc(range) : "") + suffix);
  };
  for (const advisory of details) {
    for (const affected of advisory.affected) {
      if (!affected.package) continue;
      const fixes = new Set<string>();
      for (const range of affected.ranges ?? []) {
        if (range.type === "GIT") continue;
        for (const event of range.events)
          if ("fixed" in event) fixes.add(event.fixed);
      }
      add(affected.package.ecosystem + ":" + affected.package.name, [...fixes]);
    }
    for (const v of advisory.vulnerabilities ?? []) {
      if (!v.package.name) continue;
      add(
        v.package.ecosystem + ":" + v.package.name,
        v.first_patched_version ? [v.first_patched_version] : [],
        v.vulnerable_version_range,
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
  const functions = advisoryFunctions(details).map(code);
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

function checkout(target: Report["target"]) {
  if (!target) return '<p class="checkout">Checkout not recorded</p>';
  const sha = esc(target.sha);
  return `<div class="checkout"><span class="checkout-repo">Repository <code>${esc(target.repository)}</code></span><details class="checkout-commit"><summary>Analyzed commit <code title="${sha}">${sha.slice(0, 12)}</code></summary><code>${sha}</code></details></div>`;
}

function advisoryHeader(report: Report, section: Section): string {
  const { details, urls } = sectionAdvisories(section);
  const summary = details.find((d) => d.summary)?.summary;
  const overview =
    details.find((d) => d.overview)?.overview ?? report.description;
  const isPackage = report.context.endsWith(" package");
  const id = section.blocked?.cve ?? section.title;
  const title = summary || id;
  const eyebrow = join([
    isPackage ? report.title : undefined,
    title !== id ? id : undefined,
  ]);
  return `<header class="advisory-head">
   ${eyebrow ? `<p class="eyebrow">${esc(eyebrow)}</p>` : ""}
   <h1>${prose(title)}</h1>
   ${overview && overview !== title ? `<p class="overview">${prose(overview)}</p>` : ""}
   ${advisoryDetails(section, details, urls)}
 </header>`;
}

const roles = {
  source: "Source",
  call: "Call",
  sink: "Sink",
  query_sink: "Query sink",
  call_site: "Call site",
  gap: "Gap",
};
const conditionStates = {
  met: "Met",
  unknown: "Unknown",
  ruled_out: "Ruled out",
};
const line = (path: string, n?: number) =>
  path + (n !== undefined ? ":" + n : "");
// A second frame may refer to a different line in the same excerpt. Stop
// at gaps or changes in scope; a shared filename is not a shared call path.
function relatedLines(frames: PathFrame[], index: number) {
  const active = frames[index]!;
  const code = active.code!;
  const lines = new Set<number>();
  for (const direction of [-1, 1]) {
    for (
      let i = index + direction;
      i >= 0 && i < frames.length;
      i += direction
    ) {
      const next = frames[i]!;
      const other = next.code;
      if (
        frames[direction > 0 ? i : i + 1]!.omittedBefore ||
        next.inRange !== active.inRange ||
        !other ||
        other.path !== code.path ||
        other.commit !== code.commit ||
        other.startLine !== code.startLine ||
        other.text !== code.text
      )
        break;
      if (next.line !== undefined) lines.add(next.line);
    }
  }
  return lines;
}
function frameContents(path: PathInspector, index: number, id: string) {
  const frame = path.frames[index]!;
  const { code, line: n, argument } = frame;
  const detail = frame.detail
    ? `<p class="frame-detail">${prose(frame.detail)}</p>`
    : "";
  if (!code)
    return `<p class="unavailable">${esc(frame.unavailable || "No matching source excerpt in this report.")}</p>${detail}`;
  const listing = renderDependencyCode(
    code.text,
    code.path,
    code.startLine,
    n ? new Set([n]) : undefined,
    n && argument ? { line: n, expression: argument } : undefined,
    true,
    relatedLines(path.frames, index),
  );
  const position = esc(line(code.path, n));
  const citation =
    code.citationIndex === undefined
      ? position
      : `<a href="#${id}-source-${code.citationIndex + 1}">${position}</a>`;
  return `<div class="code-meta">${citation}${code.commit ? `<span title="${esc(code.commit)}">${esc(code.commit.slice(0, 10))}</span>` : ""}</div>${listing}${detail}`;
}
function frameRow(path: PathInspector, index: number, id: string) {
  const frame = path.frames[index]!;
  const attrs = `data-in-range="${frame.inRange}"`;
  if (frame.role === "gap")
    return `<p class="gap" ${attrs}>${prose(frame.label)}</p>`;
  const pathName = frame.code?.path || frame.path;
  const location = pathName ? line(basename(pathName), frame.line) : "";
  const omitted = frame.omittedBefore;
  const before = omitted
    ? `<p class="gap" data-in-range="${frame.inRange && path.frames[index - 1]?.inRange === true}">${omitted} ${omitted === 1 ? "frame" : "frames"} omitted from this report</p>`
    : "";
  return `${before}<details class="frame" id="${id}-frame-${index}" data-frame="${index}" data-role="${frame.role}" ${attrs}${index === path.initialIndex ? " open" : ""}>
   <summary><span class="frame-role">${roles[frame.role]}</span><span class="frame-name">${esc(frame.label)}</span><span class="frame-location" title="${esc(pathName || "")}">${esc(join([location, frame.rawIndex !== undefined && "Frame " + frame.rawIndex]))}</span></summary>
   <div class="frame-body">${frameContents(path, index, id)}</div></details>`;
}
function inspector(path: PathInspector, id: string) {
  if (!path.frames.length) return "";
  const frames = path.frames.filter((f) => f.role !== "gap");
  const description =
    path.basis === "sampled" ? "Observed stack" : "Source review";
  const heading =
    frames.length === 1 && frames[0]?.role === "call_site"
      ? "Call site"
      : "Call path";
  const hasRange = frames.some((f) => !f.inRange);
  const destination =
    frames.find((f) => f.role === "sink") ||
    frames.find((f) => f.role === "query_sink") ||
    frames.find((f) => f.role === "call_site");
  const tools =
    frames.length > 1
      ? `<div class="inspector-tools" data-js hidden>
   ${hasRange ? '<button type="button" data-range aria-pressed="false">Show full stack</button>' : ""}
   ${destination ? '<button type="button" data-jump>Jump to ' + roles[destination.role].toLowerCase() + "</button>" : ""}
   <button type="button" data-prev aria-label="Previous frame" title="Previous frame">←</button>
   <span data-position aria-live="polite"></span>
   <button type="button" data-next aria-label="Next frame" title="Next frame">→</button>
   <button type="button" data-expand aria-pressed="false">Expand all</button>
   <button type="button" data-focus aria-pressed="false">Focus</button></div>`
      : "";
  return `<section class="inspector" data-inspector aria-label="${description}">
   <div class="inspector-head"><div><p class="eyebrow">${description}</p><h3>${heading}</h3></div>${tools}</div>
   <div class="path-list">${path.frames.map((_, i) => frameRow(path, i, id)).join("")}</div>
   ${path.notes.length ? `<p class="inspector-notes">${esc(path.notes.join(" "))}</p>` : ""}</section>`;
}
function conditions(f: Finding) {
  const conditions =
    f.kind === "coverage" ? [] : f.item.proof?.conditions || [];
  if (!conditions.length) return "";
  return `<section class="conditions"><h3>Advisory conditions</h3>
   <ul class="condition-list">${conditions
     .map((c) => {
       const refs = c.citations.map((ref) => {
         const indices = f.item.evidence.flatMap((cite, i) =>
           cite.path === ref.path &&
           cite.startLine <= ref.line &&
           ref.line <= cite.endLine
             ? [i]
             : [],
         );
         const label = esc(line(basename(ref.path), ref.line));
         if (
           !indices.length ||
           new Set(indices.map((i) => f.item.evidence[i]!.commit)).size !== 1
         )
           return label;
         return `<a href="#${f.id}-source-${indices[0]! + 1}" title="${esc(ref.path)}">${label}</a>`;
       });
       return `<li data-condition="${c.status}"><span class="condition-state">${conditionStates[c.status]}</span><div><strong>${prose(c.label)}</strong><p>${prose(c.explanation)}</p>${refs.length ? `<p class="condition-refs">${refs.join(" · ")}</p>` : ""}</div></li>`;
     })
     .join("")}</ul></section>`;
}
function decision(f: Finding) {
  // Prefer a recorded deciding question over the full stack narrative, which remains in the evidence.
  if (f.kind === "stack" && f.item.verdict === "unknown") {
    const q = f.assessment.remainingQuestions[0];
    if (q) return `<strong>Open question</strong> ${prose(q)}`;
  }
  return prose(f.item.reason);
}
// Repository evidence can identify the caller even when the profile has no
// build binding for that frame. Display it independently of the sampled path.
function citedCaller(f: Finding, path: PathInspector) {
  if (path.basis !== "sampled" || f.kind !== "stack") return "";
  const site = f.item.proof?.sink?.callSite;
  if (!site) return "";
  const match = matchTraceFrame(f, "sink", site);
  if ("gap" in match) return "";
  const { cite } = match;
  if (
    path.frames.some(
      (frame) =>
        frame.code?.path === site.path &&
        frame.code.commit === cite.commit &&
        frame.line === site.line,
    )
  )
    return "";
  const excerpt = f.excerpts[citationKey(cite)];
  if (excerpt === undefined) return "";
  return `<section class="inspector"><div class="inspector-head"><div><p class="eyebrow">Repository evidence</p><h3>Cited call site</h3></div></div>
  <div class="frame-body"><div class="code-meta">${esc(line(site.path, site.line))}</div>${renderDependencyCode(excerpt, site.path, cite.startLine, new Set([site.line]))}</div>
  <p class="inspector-notes">The capture does not link this source line to a specific frame.</p></section>`;
}
function evidencePreview(f: Finding) {
  for (const c of f.item.evidence) {
    const excerpt = f.excerpts[citationKey(c)];
    if (excerpt === undefined) continue;
    return `<section class="inspector"><div class="inspector-head"><h3>Cited evidence</h3></div>
     <div class="frame-body"><div class="code-meta">${esc(line(c.path, c.startLine))}</div>${renderDependencyCode(excerpt, c.path, c.startLine)}</div></section>`;
  }
  return "";
}
function content(section: Section, e: Entry) {
  const f = e.finding;
  if (!f) {
    if (section.pending)
      return "<h2>Investigation pending</h2><p>The package check stopped before it assessed this advisory.</p>";
    if (section.blocked) {
      const b = section.blocked;
      return `<h2>Investigation blocked</h2>${[b.reason, b.affectedScope, b.scopeImpact, b.unblockCondition].map(para).join("")}`;
    }
    return `<h2>No findings</h2><p>${section.stack ? "No stacks from this capture were assessed." : "No dependency use was reviewed."}</p>`;
  }
  const path = e.path!;
  const source = path.frames.find((fr) => fr.role === "source");
  const sink =
    path.frames.find((fr) => fr.role === "sink") ||
    path.frames.find((fr) => fr.role === "call_site");
  const title =
    source && sink ? source.label + " → " + sink.label : e.name || e.file;
  const component =
    f.kind !== "coverage" && f.item.component
      ? f.item.component + (f.item.version ? " " + f.item.version : "")
      : "";
  const context = join([component, e.scope]);
  const input = f.item.inputSource;
  const questions = f.item.openConditions;
  const deciding = questions?.[0]?.decidingCheck || questions?.[0]?.question;
  return `<header class="finding-head">
       <div class="finding-line"><h2>${esc(title)}</h2>${status(e.state)}</div>
       ${context ? `<p class="finding-scope">${esc(context)}</p>` : ""}
       <p class="decision">${decision(f)}</p>
       ${input?.endpoint ? `<p class="input-line"><strong>Input</strong> <code>${esc(input.endpoint)}</code></p>` : ""}
     </header>
     ${citedCaller(f, path)}
     ${inspector(path, e.id) || evidencePreview(f)}
     ${conditions(f)}
     ${deciding && deciding !== f.item.reason ? `<div class="deciding-check"><h3>What would decide this</h3><p>${prose(deciding)}</p></div>` : ""}
     ${findingAudit(section, f)}`;
}

export function renderPreparedDependencyReport(report: Report): string {
  const groups = report.sections.map((section, i) => ({
    section,
    sites: sites(section, i + 1),
  }));
  const pages = groups
    .map(({ section, sites }, i) => {
      const articles = sites
        .flat()
        .map(
          (e) =>
            `<article class="finding" data-finding id="${e.id}" data-verdict="${e.state}">${content(section, e)}</article>`,
        );
      return `<section class="advisory" data-section id="check-${i + 1}">
  ${advisoryHeader(report, section)}
  ${articles.join("")}
  ${sectionAudit(section)}</section>`;
    })
    .join("");
  const hash = createHash("sha256").update(reportInteractions).digest("base64");
  const policy = `default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-${hash}'; base-uri 'none'; form-action 'none'`;
  const empty = `${advisoryHeader(report, { title: report.title })}<p>No advisory checks were recorded for this package.</p>`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${policy}"><meta name="referrer" content="no-referrer">
<title>${esc(report.title)} · Exploitability report</title><style>${reportStyles}</style></head>
<body><header class="masthead"><span class="brand">Codex Security</span><span class="product">Exploitability report</span>${checkout(report.target)}</header>
<div class="workspace">${rail(groups)}
  <main class="reader"><p data-no-results hidden>No findings match these filters.</p>${pages || empty}${report.contextHint ? `<p>${esc(report.contextHint)}</p>` : ""}</main>
</div><script>${reportInteractions}</script></body></html>\n`;
}
export function renderDependencyReport(value: unknown) {
  return renderPreparedDependencyReport(prepareDependencyReport(value));
}
