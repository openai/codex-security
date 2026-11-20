import {
  citationKey,
  inputFor,
  matchTraceFrame,
  type Finding,
  type StackReport,
} from "./dependency-report-model.js";
import { stackFrames } from "./dependency-report-stacks.js";

type StackFinding = Extract<Finding, { kind: "stack" }>;
type Target = StackReport["target"];
type SavedSource =
  StackFinding["assessment"]["claims"][number]["sources"][number];
export type PathFrame = {
  role: "source" | "call" | "sink" | "query_sink" | "call_site" | "gap";
  label: string;
  rawIndex?: number;
  path?: string;
  line?: number;
  argument?: string;
  code?: {
    text: string;
    path: string;
    startLine: number;
    commit?: string;
    citationIndex?: number;
  };
  unavailable?: string;
  detail?: string;
  omittedBefore: number;
  inRange: boolean;
};
export type PathInspector = {
  basis: "sampled" | "source";
  frames: PathFrame[];
  notes: string[];
  initialIndex: number;
};

// Some producers embed the line in location instead of supplying frame.line.
function locationOf(location?: string, line?: number) {
  if (!location) return { line };
  const match = /^(.*):([1-9][0-9]*)$/u.exec(location);
  if (!match) return { path: location, line };
  const parsed = Number(match[2]);
  if (!Number.isSafeInteger(parsed) || (line !== undefined && line !== parsed))
    return { path: location };
  return { path: match[1], line: parsed };
}
function repoPath(path: string) {
  // Only map the main Bazel runfiles tree. A dependency or an unrelated checkout
  // can have the same file name, so never match arbitrary path suffixes.
  return path
    .replaceAll("\\", "/")
    .replace(/^(?:.*\/)?[^/]+\.runfiles\/_main\//u, "");
}

function sampledCode(
  finding: StackFinding,
  target: Target | undefined,
  byPath: Map<string, SavedSource[]>,
  rawIndex: number,
  path?: string,
  line?: number,
): Pick<PathFrame, "code" | "unavailable"> {
  if (!path || line === undefined)
    return { unavailable: "No source file and line recorded for this frame." };
  const { assessment } = finding;
  const sources = (byPath.get(repoPath(path)) ?? []).filter(
    (c) => c.startLine <= line && line <= c.endLine,
  );
  if (!sources.length)
    return { unavailable: "No saved source excerpt covers this frame." };
  if (assessment.scopeConflicts.length)
    return {
      unavailable: "Conflicting sampling scopes; source match unverified.",
    };
  const frameBindings = assessment.observation!.bindings.filter((b) =>
    b.frameIndices?.includes(rawIndex),
  );
  if (
    frameBindings.some(
      (b) => b.package !== target?.repository && b.sourceSha !== target?.sha,
    )
  )
    return {
      unavailable:
        "This frame belongs to a different package; no matching source revision recorded.",
    };
  const bindings = assessment.observation!.bindings.filter(
    (b) =>
      b.sourceSha &&
      (b.frameIndices?.length
        ? b.frameIndices.includes(rawIndex)
        : b.package === target?.repository),
  );
  if (!target || !bindings.length)
    return {
      unavailable: "No source revision bound to this frame or its build.",
    };
  const image = assessment.scope.image_digest;
  if (
    bindings.some(
      (b) => b.sourceSha !== target.sha || (image && image !== b.imageDigest),
    )
  )
    return {
      unavailable:
        "Build binding does not match the target revision or sampled image.",
    };
  const matches = sources.filter((c) => c.commit === target.sha);
  if (!matches.length)
    return { unavailable: "No saved source matches the sampled revision." };
  const lines = matches.map((c) => c.text.split("\n")[line - c.startLine]);
  if (lines.some((s) => s === undefined) || new Set(lines).size !== 1)
    return { unavailable: "Saved excerpts disagree or omit this line." };
  const cite = matches[0]!;
  const index = finding.item.evidence.findIndex(
    (e) => citationKey(e) === citationKey(cite),
  );
  return {
    code: {
      path: cite.path,
      text: cite.text,
      commit: cite.commit,
      startLine: cite.startLine,
      citationIndex: index === -1 ? undefined : index,
    },
  };
}
function sampledPath(
  finding: StackFinding,
  target: Target | undefined,
): PathInspector {
  const { assessment: a } = finding;
  const o = a.observation!;
  const source = o.sourceIndex;
  const matches = new Set(o.sinkMatches.map((m) => m.rawIndex));
  const sinks = o.sinkIndex === null ? [...matches] : [...matches, o.sinkIndex];
  const first = sinks.length ? Math.min(...sinks) : null;
  const inside = (i: number) =>
    source === null ||
    first === null ||
    source < first ||
    (i >= first && i <= source);
  const site = finding.proof?.sink?.callSite;
  const byPath = Map.groupBy(
    a.claims.flatMap((c) => c.sources),
    (c) => c.path,
  );
  const frames = stackFrames(o).map(
    ({ frame, rawIndex, omittedBefore }): PathFrame => {
      const { path, line } = locationOf(frame.location, frame.line);
      const mapped = sampledCode(finding, target, byPath, rawIndex, path, line);
      const callSite =
        site &&
        mapped.code &&
        site.path === mapped.code.path &&
        line === site.line;
      const role = matches.has(rawIndex)
        ? "sink"
        : rawIndex === o.sinkIndex
          ? "query_sink"
          : rawIndex === source
            ? "source"
            : callSite
              ? "call_site"
              : "call";
      const detail =
        rawIndex === source && role !== "source"
          ? "This is also the source frame."
          : undefined;
      return {
        role,
        rawIndex,
        label: frame.name || frame.binary || "Unnamed frame",
        path,
        line,
        detail,
        ...mapped,
        omittedBefore,
        inRange: inside(rawIndex),
      };
    },
  );
  const notes: string[] = [];
  if (source === null) notes.push("Source frame unassigned.");
  else if (!frames.some((f) => f.rawIndex === source))
    notes.push(`Source frame #${source} absent.`);
  if (o.sinkIndex === null) notes.push("Query sink frame unassigned.");
  else if (!frames.some((f) => f.rawIndex === o.sinkIndex))
    notes.push(`Query sink frame #${o.sinkIndex} absent.`);
  for (const { sinkId, rawIndex } of o.sinkMatches)
    if (!frames.some((f) => f.rawIndex === rawIndex))
      notes.push(`Matched sink ${sinkId} frame #${rawIndex} absent.`);
  if (o.framesTruncated === true) notes.push("Frames truncated.");
  if (o.framesTruncated === null) notes.push("Frame truncation unknown.");
  if (!frames.length) notes.push("No saved frames.");
  // Show the reviewed caller if possible; otherwise begin with the first retained
  // frame with code inside the path. Jump to source/sink using the original indices.
  const selected =
    frames.find((f) => f.inRange && f.role === "call_site") ??
    frames.find((f) => f.inRange && f.code) ??
    frames.find((f) => f.inRange) ??
    frames[0];
  return {
    basis: "sampled",
    frames,
    notes,
    initialIndex: selected ? frames.indexOf(selected) : -1,
  };
}
function sourcePath(finding: Finding): PathInspector {
  const { item } = finding;
  const frames: PathFrame[] = [];
  const notes: string[] = [];
  const trail = item.trace ?? [];
  const sink = finding.kind === "coverage" ? undefined : finding.proof?.sink;
  const endpoint = inputFor(item)?.endpoint;
  const base = { omittedBefore: 0, inRange: true };
  const gap = (label: string) => frames.push({ ...base, role: "gap", label });
  function add(
    kind: "source" | "handoff" | "sink",
    label: string,
    site: { path: string; line: number; commit?: string },
    argument?: string,
  ) {
    const match = matchTraceFrame(finding, kind, site);
    if ("gap" in match) {
      gap(match.gap);
      return;
    }
    const { cite, index } = match;
    const { path, line } = site;
    const text = finding.excerpts[citationKey(cite)]?.text;
    const code =
      text !== undefined &&
      text.split("\n")[line - cite.startLine] !== undefined
        ? {
            text,
            path,
            startLine: cite.startLine,
            commit: cite.commit,
            citationIndex: index,
          }
        : undefined;
    frames.push({
      ...base,
      role:
        kind === "sink" ? "call_site" : kind === "handoff" ? "call" : "source",
      label,
      path,
      line,
      argument,
      code,
      unavailable: code
        ? undefined
        : "The report cites this line but contains no matching excerpt.",
    });
  }
  for (const step of trail) {
    if (step.kind === "gap") gap(step.label);
    else add(step.kind, step.label, step.site, step.argument);
  }
  if (sink) {
    add("sink", sink.function, sink.callSite, sink.argument);
    if (!trail.length)
      notes.push(
        endpoint
          ? "No intermediate calls recorded between the endpoint and call site."
          : "Upstream callers not recorded.",
      );
    else if (trail[0]?.kind === "handoff" && !endpoint)
      notes.push("Input source unverified.");
  } else if (finding.kind === "coverage" && finding.item.handoff) {
    notes.push("Last verified: " + finding.item.handoff.verified);
    gap(finding.item.handoff.missing);
  } else if (trail.length) {
    notes.push("No cited sink recorded.");
  }
  const selected =
    frames.find((f) => f.role === "source" && f.code) ??
    frames.find((f) => f.role === "call_site" && f.code) ??
    frames.find((f) => f.code) ??
    frames.find((f) => f.role !== "gap");
  return {
    basis: "source",
    frames,
    notes,
    initialIndex: selected ? frames.indexOf(selected) : -1,
  };
}

// Project only steps cited for this finding. Service associations, endpoints,
// location labels and code quotations are not a captured call stack.
export function inspectPath(finding: Finding, target?: Target): PathInspector {
  return finding.kind === "stack" && finding.assessment.observation
    ? sampledPath(finding, target)
    : sourcePath(finding);
}
