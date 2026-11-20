import { expect, test } from "bun:test";
import { renderDependencyReport } from "../src/dependency-report-renderer.js";
import { renderDependencyCode } from "../src/dependency-report-code.js";
import {
  report,
  reviewed,
  sourceRef,
  unresolved,
  withExcerpts,
} from "./support/dependency-report-fixtures.js";

function frames(html: string) {
  const result: string[] = [];
  new HTMLRewriter()
    .on("details.frame[data-role]", {
      element(node) {
        result.push(node.getAttribute("data-role")!);
      },
    })
    .transform(html);
  return result;
}

test("follows cited argument renames and retains an exact anchor for each frame", () => {
  const input = "read.ts";
  const output = "write.ts";
  const item = reviewed(1, {
    evidence: [
      { path: input, startLine: 1, endLine: 2, supports: [] },
      { path: output, startLine: 4, endLine: 4, supports: [] },
    ],
    decidingEvidence: [
      sourceRef(input, 1),
      sourceRef(input, 2),
      sourceRef(output, 4),
    ],
    trace: [
      {
        kind: "source",
        label: "Request bytes",
        site: { path: input, line: 1 },
        argument: "request.body",
      },
      {
        kind: "handoff",
        label: "Document handler",
        site: { path: input, line: 2 },
        argument: "doc",
      },
    ],
    proof: {
      sink: {
        function: "codec.read",
        callSite: { path: output, line: 4 },
        argument: "payload",
      },
      conditions: [],
    },
  });
  const html = renderDependencyReport(
    withExcerpts(report([item]), [
      "const doc = request.body;\nhandle(doc);",
      "codec.read(payload);",
    ]),
  );
  expect(frames(html)).toEqual(["source", "call", "call_site"]);
  const opened: string[] = [];
  new HTMLRewriter()
    .on("details.frame[open]", {
      element(node) {
        opened.push(node.getAttribute("data-role")!);
      },
    })
    .transform(html);
  expect(opened).toEqual(["source"]);
  const lines: string[] = [];
  new HTMLRewriter()
    .on("details.frame[open] .code-row", {
      element(node) {
        const state = node.hasAttribute("data-highlighted")
          ? "active"
          : node.hasAttribute("data-related")
            ? "related"
            : "other";
        lines.push(node.getAttribute("data-line") + ":" + state);
      },
    })
    .on("details.frame[open] [data-follow]", {
      element() {
        lines.push("follow");
      },
    })
    .transform(html);
  expect(lines).toEqual(["1:active", "follow", "2:related"]);
  const gapped = {
    ...item,
    trace: [
      item.trace![0]!,
      { kind: "gap" as const, label: "Missing caller" },
      item.trace![1]!,
    ],
  };
  const gappedHtml = renderDependencyReport(
    withExcerpts(report([gapped]), [
      "const doc = request.body;\nhandle(doc);",
      "codec.read(payload);",
    ]),
  );
  expect(gappedHtml).not.toContain('data-line="2" data-related');

  for (const value of ["request.body", "doc", "payload"])
    expect(html).toContain(`<mark class="trace-argument">${value}</mark>`);
  for (const ordinal of [1, 2]) {
    const id = `use-1-1-source-${ordinal}`;
    expect(html).toContain(`href="#${id}"`);
    expect(html.split(`id="${id}"`).length).toBe(2);
  }
});

test("never converts location labels into call frames or a coverage gap into a sink", () => {
  const item = reviewed(1, {
    location: "Upload → allegedWrapper() → allegedSink()",
  });
  expect(frames(renderDependencyReport(report([item])))).toEqual([]);
  const gap = unresolved(1, {
    trace: [
      {
        kind: "source",
        label: "Upload",
        site: { path: "src/parser-1.ts", line: 2 },
      },
    ],
    handoff: {
      verified: "Bytes reach the parser.",
      missing: "Which plugin handles the document?",
    },
  });
  const html = renderDependencyReport(report([], [gap]));
  expect(frames(html)).toEqual(["source"]);
  expect(html).toContain("Which plugin handles the document?");
  expect(html).toContain("Bytes reach the parser.");
});

test("withholds frame claims tied to a different revision or absent deciding citation", () => {
  const path = "src/handler-1.ts";
  const item = reviewed(1, {
    trace: [
      {
        kind: "source",
        label: "Unsupported frame",
        site: { path, line: 2, commit: "a".repeat(40) },
      },
    ],
  });
  expect(frames(renderDependencyReport(report([item])))).not.toContain(
    "source",
  );
  item.trace = [
    { kind: "source", label: "Unsupported frame", site: { path, line: 2 } },
  ];
  item.decidingEvidence = [];
  expect(frames(renderDependencyReport(report([item])))).not.toContain(
    "source",
  );
});

test("marks only unambiguous expressions on the cited line and escapes syntax inside the mark", () => {
  const listing = (line: string, argument: string) =>
    renderDependencyCode(line, "src.ts", 3, new Set([3]), {
      line: 3,
      expression: argument,
    });
  expect(listing("run(a, a)", "a")).not.toContain("<mark");
  expect(listing("run(payload)", "load")).not.toContain("<mark");
  const marked = listing('read(doc["<main>"])', 'doc["<main>"]');
  expect(marked).toContain(
    '<mark class="trace-argument">doc[<span class="tok-string">&quot;&lt;main&gt;&quot;</span>]</mark>',
  );
});
