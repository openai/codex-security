import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

// Related fixtures ask the same questions. Their checkouts determine the
// answers, including which branches actually matter to the supplied caller.
function targetsFor({ id, suite, component, callerScope }) {
  if (suite === "resolution")
    return [
      "Which launcher profile and module resolution anchor determine the parser that handles POST /addresses? If the selector is external, assess both possible copies.",
      "For each copy that the configuration can select, do its version and implementation permit the advisory condition on the submitted text? Distinguish the copies despite identical version labels.",
    ];
  if (suite === "application")
    return [
      "Which Compose service, application entry point and Starlette build handle this POST /clips request? Resolve the gate setting for that service, including possible values if externally supplied.",
      "For the relevant content types, does validation stop the request before parsing? Trace the gateway, form parser selection, parser limits and handler checks in order, up to the decisive step.",
    ];
  if (suite === "backstage")
    return [
      "Which backend, vm2 release, catalog template and skeleton are selected for this authenticated task? What can the requester change?",
      "Trace the name parameter through workflow step rendering and file rendering. At each relevant VM entry, distinguish control of values from control of executable JavaScript.",
    ];
  if (id.startsWith("thumbnail-"))
    return [
      "Which worker serves the configured route? Join the listener, process, mapped inode, package receipt and patch status. Identify gaps and distinguish the other worker and the currently installed file.",
      "Does the submitted image reach the affected native decode operation in that copy? Distinguish captured worker observations from the assumptions about the next request.",
    ];
  if (suite === "pillow")
    return [
      "Which wheel and native libwebp build does this deployment select? Connect the artifact identity and bundled version to the advisory.",
      "What image operations can the controlled bytes trigger? Distinguish decode from encode and account for the relevant plugin dispatch and native backend up to the point that decides applicability.",
    ];
  if (id.startsWith("zip-import-"))
    return [
      "Does validation check the same bytes for every archive member that the worker later reads, including duplicate filenames? Follow member selection, header validation and the queued bundle.",
      "Which installed address parser receives each imported message, and can the submitting caller influence a parsed address header?",
    ];
  if (id.startsWith("archive-worker-"))
    return [
      "Which queue, worker, installed parser and object generation does a POST /messages job select? Follow the original and rewritten bytes through storage and retrieval.",
      "Can the caller control any address header consumed by that parser, including MIME child headers if applicable? Consider the selected media policy and where it acts.",
    ];
  if (id.startsWith("archive-"))
    return [
      "Can any encoded upload produce a delimiter recognized by this MIME receiver? Compare the configured boundary with the emitted bytes, including wrapping.",
      "Which installed address parser handles the resulting message? Determine whether relevant headers are fixed by the service or can come from an additional MIME part.",
    ];
  if (component === "linkify-it")
    return [
      "Where does the configured POST /inbox route send the caller's bytes? Follow the relevant direct or queued handoff, including any route guard and the identity of the receiver.",
      "For a reachable receiver, can the submitted text get to the affected link matcher with the configured options? Bind the dependency version to that receiver, or explain the missing evidence.",
    ];
  if (component === "nodemailer")
    return [
      "For the configured inbox route, can submitted address headers survive preprocessing and reach the address parser?",
      "Which parser copy and version does the receiver select? Where relevant, check whether its recursion is bounded in the actual installed source.",
    ];
  if (component === "glibc")
    return [
      "Which charset data can the inbox caller control, and in which direction does the selected converter operate relative to the advisory?",
      "What does the checkout establish about the native backend and its version? Explain whether unresolved implementation details affect the scoped conclusion.",
    ];
  return [callerScope];
}

function additionalSources(scenario) {
  if (scenario.suite === "application")
    return [{ path: "starlette/formparsers.py" }];
  if (scenario.suite === "pillow" && scenario.id !== "affected-encode-only") {
    const webp = "src/PIL/WebPImagePlugin.py";
    const tiff = "src/PIL/TiffImagePlugin.py";
    // The /thumbnail handler accepts arbitrary image formats. The _webp
    // artifact record identifies one native backend; TIFF can use another.
    return [
      { path: webp, contains: "_webp.WebPDecode(" },
      { path: webp, contains: "_webp.WebPAnimDecoder(" },
      { path: webp, contains: "self._decoder.get_next()" },
      { path: "src/_webp.c", contains: "WebPAnimDecoderGetNext(" },
      { path: "src/_webp.c", contains: "WebPDecode(webp," },
      { path: tiff, contains: '50001: "webp"' },
      { path: tiff, contains: "self.use_load_libtiff =" },
      { path: tiff, contains: "return self._load_libtiff()" },
      { path: "src/PIL/MicImagePlugin.py", contains: "class MicImageFile" },
    ];
  }
  return [];
}

function selectedRanges(source, { path, contains, startLine, endLine }) {
  const lines = source.split("\n").length;
  if (!contains) {
    const start = startLine ?? 1;
    const end = endLine ?? lines;
    assert(
      Number.isSafeInteger(start) &&
        Number.isSafeInteger(end) &&
        start >= 1 &&
        start <= end &&
        end <= lines,
      `Invalid reference range ${path}:${start}–${end}`,
    );
    return [[start, end]];
  }
  // Include surrounding control flow, including alternative matches for
  // ambiguous snippets. The model sees source, without highlighted anchors.
  const ranges = [];
  for (
    let at = source.indexOf(contains);
    at >= 0;
    at = source.indexOf(contains, at + contains.length)
  ) {
    const first = source.slice(0, at).split("\n").length;
    const last = first + contains.split("\n").length - 1;
    ranges.push([Math.max(1, first - 6), Math.min(lines, last + 6)]);
  }
  return ranges;
}

// A selector identifies an entire file, an inclusive range, or context
// surrounding a literal. Read committed blobs even if a worktree changed.
export function sourceExcerpts(repo, sha, selectors) {
  const files = new Map();
  for (const selector of selectors) {
    const { path } = selector;
    if (!files.has(path)) {
      const source = execFileSync(
        "git",
        ["-C", repo, "show", `${sha}:${path}`],
        {
          encoding: "utf8",
          maxBuffer: Infinity,
        },
      )
        .replaceAll("\r\n", "\n")
        .replace(/\n$/u, "");
      files.set(path, { source, ranges: [] });
    }
    const file = files.get(path);
    file.ranges.push(...selectedRanges(file.source, selector));
  }
  const excerpts = [];
  for (const [path, { source, ranges }] of files) {
    const lines = source.split("\n");
    const merged = [];
    for (const [start, end] of ranges.sort((a, b) => a[0] - b[0])) {
      const prev = merged.at(-1);
      if (prev && start <= prev.endLine + 1)
        prev.endLine = Math.max(prev.endLine, end);
      else merged.push({ path, startLine: start, endLine: end });
    }
    for (const ref of merged)
      excerpts.push({
        ...ref,
        text: lines.slice(ref.startLine - 1, ref.endLine).join("\n"),
      });
  }
  return excerpts;
}

export function reportReference(scenario, repo, sha) {
  // Include the application's own entry points and configuration in full.
  // The older, finer-grained source map also locates intermediary library
  // code. These excerpts provide context for assessing equivalent proofs.
  const fixtures = scenario.stage
    .filter((file) => file.kind === "fixture" || file.kind === "json")
    .map((file) => ({ path: file.destination }));
  const groups = [
    ...scenario.identityEvidence,
    ...(scenario.skillEvidenceGroups ?? scenario.evidenceGroups),
  ];
  const selectors = groups
    .flat()
    .map(({ path, contains, completeFile }) =>
      completeFile ? { path } : { path, contains },
    );
  return {
    question: scenario.callerScope,
    cve: scenario.cve,
    component: scenario.component,
    targets: targetsFor(scenario),
    sources: sourceExcerpts(repo, sha, [
      ...fixtures,
      ...selectors,
      ...additionalSources(scenario),
    ]),
  };
}
