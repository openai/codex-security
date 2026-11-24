import { createHash } from "node:crypto";
import {
  citationKey,
  matchTraceFrame,
  prepareDependencyReport,
  type Finding,
  type Report,
  type Section,
} from "./dependency-report-model.js";
import type { PathInspector, PathFrame } from "./dependency-report-path.js";
import {
  para,
  prose,
  findingAudit,
  sectionAudit,
} from "./dependency-report-audit.js";
import {
  advisoryHeader,
  basename,
  checkout,
  sites,
  context as join,
  rail,
  status,
  type Entry,
} from "./dependency-report-index.js";
import {
  escapeHtml as esc,
  renderDependencyCode,
} from "./dependency-report-code.js";
import { reportStyles } from "./dependency-report-ui.js";
import { reportInteractions } from "./dependency-report-interactions.js";

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
