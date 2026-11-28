import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { stackReport } from "./support/dependency-stack-report-fixture.js";
import { renderDependencyCode } from "../src/exploitability/report/audit.js";
import { renderDependencyReport } from "../src/exploitability/report/renderer.js";
import { prepareDependencyReport } from "../src/exploitability/report/model.js";
import {
  renderPreparedDependencyReportMarkdown,
  summarizeDependencyReport,
} from "../src/exploitability/report/text.js";
import {
  broadReport,
  place,
  receiptRef,
  report,
  reviewed,
  service,
  sourceRef,
  unresolved,
  variantReport,
  withExcerpts,
  zeroReport,
} from "./support/dependency-report-fixtures.js";

function text(html: string) {
  const content =
    elements(html, ".workspace")[0] ?? elements(html, "article")[0];
  if (!content) throw new Error("Missing report or finding");
  return content.text;
}
function elements(html: string, selector: string, attrs: string[] = []) {
  const result: { text: string; attrs: Record<string, string | null> }[] = [];
  new HTMLRewriter()
    .on(selector, {
      element(node) {
        result.push({
          text: "",
          attrs: Object.fromEntries(
            attrs.map((a) => [a, node.getAttribute(a)]),
          ),
        });
      },
      text(node) {
        result.at(-1)!.text += " " + node.text;
      },
    })
    .transform(html);
  return result.map((r) => ({
    ...r,
    text: r.text.replace(/\s+/gu, " ").trim(),
  }));
}
function attributes(html: string, selector: string, attr: string) {
  return elements(html, selector, [attr]).map((node) => node.attrs[attr]);
}

function panel(html: string, id: string) {
  const article = html.match(
    new RegExp('<article[^>]* id="' + id + '"[^>]*>[\\s\\S]*?</article>'),
  )?.[0];
  if (!article) throw new Error("Missing finding: " + id);
  return article;
}
test("renders untrusted source as escaped, numbered lines", () => {
  const source =
    'const item = "<img src=x onerror=alert(1)> & data";\r\n\nreturn item;\n';
  const html = renderDependencyCode(source, "worker.ts", 17, new Set([19]));
  expect(html).not.toContain("<img");
  expect(html).toContain("&lt;img src=x onerror=alert(1)&gt; &amp; data");
  expect(html).toContain("&#13;");
  expect(attributes(html, ".code-row", "data-line")).toEqual([
    "17",
    "18",
    "19",
    "20",
  ]);
  expect(attributes(html, "[data-highlighted]", "data-line")).toEqual(["19"]);
  expect(elements(html, ".tok-keyword").map((t) => t.text)).toEqual([
    "const",
    "return",
  ]);
  const plain = renderDependencyCode(source, "notes.txt", 17);
  expect(plain).not.toContain("<img");
  expect(plain).not.toContain("tok-");
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

describe("call site report", () => {
  test("combined results keep the caller and the sampled evidence in separate sections", () => {
    const stacks = stackReport();
    const repository = {
      ...report([reviewed(1, { verdict: "potentially_exploitable" })]),
      cve: stacks.cve,
      target: { repository: "code<svg>", sha: stacks.target.sha },
    };
    const raw = { subject: stacks.cve, analyzers: { repository, stacks } };
    expect(() =>
      prepareDependencyReport({ ...raw, analyzers: { repository: stacks } }),
    ).toThrow(/Unexpected report for repository/);
    const prepared = prepareDependencyReport(raw);
    for (const view of [
      summarizeDependencyReport(prepared),
      renderPreparedDependencyReportMarkdown(prepared),
    ]) {
      const [repo, sampled] = view.split("Stacks analyzer");
      expect(repo).toContain("Repository analyzer");
      expect(repo).toContain("Handler 1");
      expect(repo).not.toContain("scheduled-job");
      expect(sampled).toContain("scheduled-job");
      expect(sampled).not.toContain("Handler 1");
      expect(view).not.toContain("RAW_RECEIPT_CONTENT");
    }
    const html = renderDependencyReport(raw);
    expect(elements(html, ".queue-title").map((e) => e.text)).toEqual([
      "Repository analyzer",
      "Stacks analyzer",
    ]);
    expect(attributes(html, "a[data-entry]", "href")).toEqual([
      "#use-1-1",
      "#stack-2-1",
      "#stack-2-2",
    ]);
    expect(text(panel(html, "use-1-1"))).not.toContain("Sampled copy 1.0");
    expect(text(panel(html, "stack-2-1"))).toContain("Sampled copy 1.0");
    expect(html).not.toContain("code<svg>");
    expect(html).not.toContain("RAW_RECEIPT_CONTENT");
  });
  test("a blocked analyzer preserves pending and completed results", () => {
    const stacks = stackReport();
    const blocked = {
      status: "blocked",
      code: "INVESTIGATION_BLOCKED",
      reason: "Missing inventory.",
    };
    const raw = {
      ...blocked,
      subject: stacks.cve,
      analyzers: { repository: blocked },
      pendingAnalyzers: ["stacks"],
    };
    expect(
      attributes(renderDependencyReport(raw), "[data-entry]", "data-verdict"),
    ).toEqual(["blocked", "pending"]);
    const part = {
      ...raw,
      analyzers: { repository: blocked, stacks },
      pendingAnalyzers: [],
    };
    const summary = summarizeDependencyReport(prepareDependencyReport(part));
    expect(summary).toContain("Missing inventory.");
    expect(summary).toContain("scheduled-job");
    expect(summary).not.toContain("Not started");
  });
  test("walks retained frames, opens the exact caller line, and does not pass caller code off as dependency code", () => {
    const raw = stackReport(),
      [assessment, empty] = raw.assessments;
    const caller = {
      rawIndex: 2,
      frame: {
        name: "caller",
        sourceRevision: raw.target.sha,
        location: "/app.runfiles/_main/src/codec.ts:3",
      },
    };
    const stack = {
      ...assessment.stack,
      frames: [...assessment.stack.frames, caller],
    };
    const html = renderDependencyReport({
      ...raw,
      assessments: [{ ...assessment, stack }, empty],
    });
    const observed = panel(html, "stack-1-1");
    const frames = elements(observed, "details.frame", ["data-role"]);
    expect(frames.map((f) => f.attrs["data-role"])).toEqual([
      "call",
      "call_site",
      "sink",
    ]);
    expect(attributes(observed, "details.frame[open]", "id")).toEqual([
      "stack-1-1-frame-1",
    ]);
    expect(frames[1]!.text).toContain("caller");
    expect(
      elements(observed, "#stack-1-1-frame-1 [data-highlighted]"),
    ).toHaveLength(1);
    expect(elements(observed, "#stack-1-1-frame-2 pre")).toHaveLength(0);
    expect(
      elements(observed, "#stack-1-1-frame-2 .unavailable").length,
    ).toBeGreaterThan(0);
    for (const selector of ["[data-next]", "[data-prev]", ".gap"])
      expect(elements(observed, selector).length).toBeGreaterThan(0);
    expect(text(observed)).toContain("Sampled copy 1.0");
    expect(text(observed)).toContain("Which decoder mode ran?");
    expect(text(observed)).toContain("The guard is configurable.");
    expect(text(observed)).toContain("Search coverage partial");
    expect(text(html)).toContain("Finalized offline");
    expect(text(html)).toContain("omits the advisory description");
    expect(html).not.toContain("RAW_RECEIPT_CONTENT");
    const missing = panel(html, "stack-1-2");
    expect(elements(missing, "details.frame")).toHaveLength(0);
    expect(text(missing)).not.toContain("Sampled copy 1.0");
  });
  test("queue links name call sites, not stack hashes, and cover every item exactly once", () => {
    const stack = renderDependencyReport(stackReport());
    const [entry] = elements(stack, '[data-entry="stack-1-1"]');
    expect(entry!.text).toContain("codec.ts:3");
    expect(entry!.text).not.toContain("stack-a");
    const html = renderDependencyReport(broadReport());
    const articles = elements(html, "article[data-finding]", [
      "id",
      "data-verdict",
    ]);
    expect(attributes(html, "a[data-entry]", "href")).toEqual(
      articles.map((a) => "#" + a.attrs["id"]),
    );
    expect(new Set(articles.map((a) => a.attrs["id"])).size).toBe(88);
    expect(
      articles.filter((a) => a.attrs["data-verdict"] === "unknown"),
    ).toHaveLength(48);
    expect(
      articles.filter((a) => a.attrs["data-verdict"] === "ruled_out"),
    ).toHaveLength(16);
    expect(
      articles.filter((a) => a.attrs["data-verdict"] === "unresolved"),
    ).toHaveLength(24);
  });
  test("source-only code starts at the reviewed call, with conditions and the deciding check", () => {
    const raw = variantReport();
    const html = renderDependencyReport(
      withExcerpts(raw, ["return decodeFrame(document);"]),
    );
    const source = panel(html, "use-1-1");
    expect(text(source)).toContain("Source review");
    expect(text(source)).toContain("Upstream callers not recorded");
    expect(attributes(source, "details.frame", "data-role")).toEqual([
      "call_site",
    ]);
    const active = elements(source, "details.frame[open] [data-highlighted]", [
      "data-line",
    ]);
    expect(active.map((row) => row.attrs["data-line"])).toEqual(["2"]);
    expect(active[0]!.text).toContain("decodeFrame");
    expect(attributes(source, "[data-condition]", "data-condition")).toEqual([
      "met",
      "unknown",
    ]);
    for (const fact of [
      "Request reaches decoder before authentication",
      "Read the admitted worker setting",
      "Cedar prod stable linux/amd64",
      "The guard rejects",
    ])
      expect(text(source)).toContain(fact);
    const shared = panel(html, "use-1-3");
    expect(text(shared)).toContain("Cedar");
    expect(text(shared)).toContain("Spruce");
    expect(elements(html, '[data-entry="use-1-3"]')).toHaveLength(1);
    const canary = panel(html, "use-1-2");
    expect(text(canary)).toContain("linux/arm64");
    expect(canary).not.toContain("2".repeat(64));
    expect(source).not.toContain("3".repeat(64));
  });
  test("an artifact exclusion does not fabricate a sampled path", () => {
    const use = reviewed(1, {
      verdict: "ruled_out",
      reason: "This copy contains the fix.",
      place: place({
        kind: "artifact",
        patch: "Verified image-specific backport",
      }),
    });
    const article = panel(renderDependencyReport(report([use])), "use-1-1");
    expect(text(article)).toContain("Verified image-specific backport");
    expect(text(article)).toContain("This copy contains the fix.");
    expect(elements(article, "details.frame[data-role=sink]")).toHaveLength(0);
  });
  test("unresolved handoffs retain worker-specific launch and mitigation facts", () => {
    const html = renderDependencyReport(zeroReport());
    const stable = text(panel(html, "coverage-1-1")),
      canary = text(panel(html, "coverage-1-2"));
    expect(stable).toContain("Submitted bytes reach the parser entrypoint");
    expect(stable).toContain("Which registered provider handles this field?");
    expect(stable).toContain("parser-worker --variant=stable");
    expect(stable).toContain("Mitigation enabled (configured)");
    expect(canary).toContain("Mitigation disabled (configured)");
    expect(canary).not.toContain("parser-worker --variant=stable");
    expect(elements(html, "details.frame[data-role=sink]")).toHaveLength(0);
  });
  test("does not promote uncited associations into service or input facts", () => {
    const u = reviewed(1, {
      services: [service("wrong", "Wrong service", sourceRef("other.ts", 9))],
      inputSource: {
        exposure: "internet",
        endpoint: "POST /unverified",
        evidence: [receiptRef("not-cited")],
      },
    });
    const html = renderDependencyReport(report([u]));
    expect(html).not.toContain("POST /unverified");
    expect(html).not.toContain("Wrong service");
  });
  test("preserves measurements, target, time window, missing data and comparison scope without relabeling samples as calls", () => {
    const u = reviewed(1);
    const ref = receiptRef("sampled");
    u.decidingEvidence.push(ref);
    const target = {
      label: "Live worker",
      relationship: "target" as const,
      observationWindow: "00:00–01:00",
    };
    u.inspections = [
      {
        question: "Target samples",
        target,
        source: "profiler",
        outcome: "zero_results",
        evidence: [ref],
        measurement: { unit: "cpu_samples", count: 0 },
      },
      {
        question: "Other window",
        target,
        source: "profiler",
        outcome: "no_data",
        evidence: [ref],
      },
      {
        question: "Peer",
        target: { ...target, label: "Neighbor", relationship: "comparison" },
        source: "profiler",
        outcome: "partial",
        evidence: [ref],
        measurement: { unit: "cpu_samples", count: 321 },
        completeness: "partial",
      },
      {
        question: "Image",
        target,
        source: "registry",
        outcome: "denied",
        evidence: [ref],
        result: "Registry denied the request.",
      },
    ];
    const h = text(panel(renderDependencyReport(report([u])), "use-1-1"));
    for (const fact of [
      "0 CPU samples",
      "00:00–01:00",
      "No measurement or data",
      "Comparison workload Neighbor",
      "321 CPU samples",
      "Backend reported partial",
      "Registry denied the request.",
    ])
      expect(h).toContain(fact);
    expect(h).not.toContain("321 calls");
  });
  test("legacy uses retain their verdict without an invented matched sink", () => {
    const { place: _place, decidingEvidence: _ref, ...u } = reviewed(1);
    const html = renderDependencyReport({
      cve: "CVE-2099-44001",
      advisories: [],
      usage: null,
      status: "unknown",
      uses: [u],
      limitations: [],
    });
    const item = panel(html, "use-1-1");
    expect(text(item)).toContain("Requires more information");
    expect(elements(item, "[data-role=sink]")).toHaveLength(0);
    expect(text(item)).toContain("Deployment unverified");
  });
  test("distinguishes an empty check from blocked and pending advisories", () => {
    const blocked = {
      status: "blocked",
      code: "INVESTIGATION_BLOCKED",
      reason: "The service did not respond.",
      unblockCondition: "Restore inventory.",
    };
    const { cve: _cve, ...check } = report([reviewed(1)]);
    const html = renderDependencyReport({
      ...blocked,
      package: { ecosystem: "npm", name: "sample-codec" },
      checks: [
        { ...check, advisoryId: "CVE-2099-44001" },
        { ...check, uses: [], advisoryId: "CVE-2099-44002" },
        { ...blocked, advisoryId: "CVE-2099-44003" },
      ],
      pendingAdvisories: ["CVE-2099-44004"],
    });
    expect(attributes(html, "[data-entry]", "data-verdict")).toEqual([
      "unknown",
      "empty",
      "blocked",
      "pending",
    ]);
    expect(text(panel(html, "empty-3"))).toContain(blocked.unblockCondition);
  });
  test("keeps receipt metadata but never embeds raw inventory payloads in HTML", () => {
    const u = reviewed(1);
    const ref = receiptRef("fixture-receipt");
    u.decidingEvidence.push(ref);
    const r = {
      ...report([u]),
      claimEvidence: {
        sources: {},
        receipts: {
          r1: {
            receiptId: "fixture-receipt",
            originalPayloadSha256: "a".repeat(64),
            server: "artifacts",
            origin: { tool: "inspect", arguments: { secret: "DO_NOT_EMBED" } },
            result: { token: "DO_NOT_EMBED", massiveStack: "DO_NOT_EMBED" },
          },
        },
      },
    };
    const html = renderDependencyReport(r);
    expect(html).toContain("fixture-receipt");
    expect(html).toContain("SHA-256");
    expect(html).not.toContain("DO_NOT_EMBED");
  });
  test("preserves links, dismissed coverage and source bindings after priority sorting", () => {
    const a = reviewed(1, {
        verdict: "ruled_out",
        reason: "Excluded by a source guard.",
      }),
      b = reviewed(2, { verdict: "potentially_exploitable", version: "1.0" });
    a.services = [service("svc:a", "Alpha", a.decidingEvidence[0]!)];
    // Both use the same range; only the first use has an approved source claim.
    b.evidence = a.evidence;
    b.decidingEvidence = a.decidingEvidence;
    b.services = [service("svc:b", "Beta", b.decidingEvidence[0]!)];
    const dismissed = unresolved(2, {
      kind: "dismissed",
      evidence: [
        { path: "src/handler-1.ts", startLine: 1, endLine: 1, supports: [] },
      ],
      decidingEvidence: [sourceRef("src/handler-1.ts", 1)],
    });
    const input = withExcerpts(
      report([a], [dismissed]),
      ["safeMode();"],
      ["dismissedMode();"],
    );
    input.uses.push(b);
    input.coverage.unshift(unresolved(1));
    input.coverage.push(unresolved(3));
    input.claimEvidence.sources["uncited"] = {
      path: "src/handler-1.ts",
      startLine: 3,
      endLine: 3,
      excerpt: "uncitedMode();",
    };
    const html = renderDependencyReport(input);
    expect(attributes(html, "a[data-entry]", "href")).toEqual([
      "#use-1-2",
      "#use-1-1",
      "#coverage-1-1",
      "#coverage-1-3",
    ]);
    const dismissedItems = elements(html, "details#coverage-1-2");
    expect(dismissedItems).toHaveLength(1);
    expect(dismissedItems[0]!.text).toContain("dismissedMode");
    expect(html).not.toContain("uncitedMode");
    expect(panel(html, "use-1-1")).toContain("safeMode");
    expect(panel(html, "use-1-2")).not.toContain("safeMode");
  });
  test("shows a premise excerpt only for the cited claim revision and source commit", () => {
    const use = reviewed(1);
    use.evidence[0]!.commit = "a".repeat(40);
    const input = withExcerpts(report([use]), ["hiddenExcerpt()"]);
    const premise = input.uses[0]!.supportingClaims![0]!;
    const ref = { ...premise, id: "conclusion" };
    const conclusion = {
      ...input.claims[0]!,
      ...ref,
      dependencies: [premise],
      evidence: { sourceIds: [], receiptIds: [] },
    };
    const render = () =>
      renderDependencyReport({
        ...input,
        uses: [{ ...use, conclusionClaim: ref }],
        claims: [conclusion, ...input.claims],
      });
    expect(render()).toContain("hiddenExcerpt");
    conclusion.revision++;
    expect(render()).not.toContain("hiddenExcerpt");
    conclusion.revision--;
    input.claimEvidence.sources["cite-0-0"]!.commit = "f".repeat(40);
    expect(render()).not.toContain("hiddenExcerpt");
  });
  test("renders advisory description, affected package versions and vulnerable functions with safe links", () => {
    const u = reviewed(1),
      url = "https://example.invalid/advisories/CVE-2099-44001",
      raw = "<img src=x onerror=alert(1)>";
    const r = {
      ...report([u]),
      advisoryDetails: [
        {
          url,
          summary: `Decoder issue ${raw}`,
          overview: "A malformed frame crosses a bound.",
          applicability: "Only frame mode is affected.",
          vulnerableFunctions: [`Decoder.decode ${raw}`],
          affected: [
            {
              package: { ecosystem: "npm", name: "sample-codec" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "1.2.4" }],
                },
              ],
            },
          ],
        },
      ],
      advisories: [url, "javascript:alert(1)"],
    };
    const html = renderDependencyReport(r);
    for (const v of [
      "A malformed frame",
      "Decoder.decode",
      "sample-codec",
      "fixed in 1.2.4",
      "Only frame mode",
    ])
      expect(text(html)).toContain(v);
    expect(html).not.toContain(raw);
    expect(html).not.toContain('href="javascript:');
    expect(html).toContain("&lt;img");
    const unrelated = renderDependencyReport({
      ...report([u]),
      advisoryDetails: [
        {
          url: "https://unrelated.invalid",
          summary: "Unreferenced advisory",
          affected: [],
        },
      ],
    });
    expect(unrelated).not.toContain("Unreferenced advisory");
  });
  test.each([
    [
      "Go",
      {
        imports: [
          { path: "example.invalid/codec", symbols: ["Decoder.Decode"] },
        ],
      },
      "Decoder.Decode",
    ],
    ["Rust", { affects: { functions: ["decode::run"] } }, "decode::run"],
  ] as const)(
    "extracts %s vulnerable functions from ecosystem metadata",
    (_, metadata, symbol) => {
      const r = report([reviewed(1)]);
      const html = renderDependencyReport({
        ...r,
        advisoryDetails: [
          {
            url: r.advisories[0],
            affected: [{ ecosystem_specific: metadata }],
          },
        ],
      });
      expect(text(html)).toContain(symbol);
    },
  );
  test("deduplicates unresolved limitations without removing source records or merging leads", () => {
    const a = unresolved(1, { reason: "The selected build is missing." }),
      b = unresolved(2, { reason: "The selected build is missing." });
    const r = {
      ...report([], [a, b]),
      limitations: [
        "The selected build is missing. Unresolved source locations: src/parser-1.ts:2.",
        "The selected build is missing. Unresolved source locations: src/parser-2.ts:3.",
        "Independent shared limitation.",
      ],
    };
    const html = renderDependencyReport(r);
    expect(elements(html, "article[data-verdict=unresolved]")).toHaveLength(2);
    expect(text(html)).toMatch(/Affected: Parser 1\s*,\s*Parser 2/u);
    expect(text(html)).toContain("Independent shared limitation");
    expect(text(html)).toContain("src/parser-1.ts:2.");
    expect(text(html)).toContain("src/parser-2.ts:3.");
  });
  test("escapes untrusted metadata and snippets, has a valid script hash, offline styles, keyboard and print fallbacks", () => {
    const raw = '<svg onload="alert(1)">',
      u = reviewed(1, {
        location: raw,
        reason: raw,
        component: raw,
        services: [service("svc:x", raw, sourceRef("src/handler-1.ts", 2))],
      });
    const r = { ...withExcerpts(report([u]), [raw]), limitations: [raw] };
    const html = renderDependencyReport(r);
    expect(html).not.toContain(raw);
    expect(html).toContain("&lt;svg");
    const scripts: string[] = [];
    new HTMLRewriter()
      .on("script", {
        element() {
          scripts.push("");
        },
        text(node) {
          scripts[scripts.length - 1] += node.text;
        },
      })
      .transform(html);
    expect(scripts).toHaveLength(1);
    const script = scripts[0]!;
    const policy = elements(
      html,
      'meta[http-equiv="Content-Security-Policy"]',
      ["content"],
    )[0]?.attrs["content"];
    expect(policy).toContain(
      `script-src 'sha256-${createHash("sha256").update(script).digest("base64")}'`,
    );
    expect(policy).toContain("default-src 'none'");
    expect(html).toContain("@media print");
    expect(html).toContain(":focus-visible");
    expect(elements(html, "script[src]")).toHaveLength(0);
    expect(elements(html, "link[rel]")).toHaveLength(0);
  });
  test("does not activate or display credential-bearing URLs", () => {
    const suspicious =
      "https://fixture:synthetic-password@example.invalid/advisory?token=synthetic-token";
    const html = renderDependencyReport({
      ...report([reviewed(1)]),
      advisories: [suspicious],
    });
    expect(html).toContain("Link omitted (credentials in URL)");
    expect(html).not.toContain("synthetic-password");
    expect(html).not.toContain("synthetic-token");
  });
  test("rejects workload samples presented as transferable immutable artifact evidence", () => {
    const u = reviewed(1);
    u.inspections = [
      {
        question: "Sample a worker",
        target: { label: "shared bytes", relationship: "shared_artifact" },
        source: "profiler",
        outcome: "succeeded",
        evidence: [u.decidingEvidence[0]!],
        measurement: { unit: "cpu_samples", count: 1 },
        transferBasis: "The files match.",
      },
    ];
    expect(() => renderDependencyReport(report([u]))).toThrow();
  });
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
    const excerpts = [
      "const doc = request.body;\nhandle(doc);",
      "codec.read(payload);",
    ];
    const html = renderDependencyReport(withExcerpts(report([item]), excerpts));
    expect(attributes(html, "details.frame", "data-role")).toEqual([
      "source",
      "call",
      "call_site",
    ]);
    expect(attributes(html, "details.frame[open]", "data-role")).toEqual([
      "source",
    ]);
    expect(
      attributes(html, "details.frame[open] [data-highlighted]", "data-line"),
    ).toEqual(["1"]);
    expect(
      elements(html, "details.frame[open] [data-highlighted] [data-follow]"),
    ).toHaveLength(1);
    expect(
      attributes(html, "details.frame[open] [data-related]", "data-line"),
    ).toEqual(["2"]);
    const gapped = {
      ...item,
      trace: [
        item.trace![0]!,
        { kind: "gap" as const, label: "Missing caller" },
        item.trace![1]!,
      ],
    };
    const gappedHtml = renderDependencyReport(
      withExcerpts(report([gapped]), excerpts),
    );
    expect(
      elements(gappedHtml, "details.frame[open] [data-related]"),
    ).toHaveLength(0);

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
    expect(
      elements(renderDependencyReport(report([item])), "details.frame"),
    ).toHaveLength(0);
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
    expect(attributes(html, "details.frame", "data-role")).toEqual(["source"]);
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
    const sourceFrames = () =>
      elements(
        renderDependencyReport(report([item])),
        "details.frame[data-role=source]",
      );
    expect(sourceFrames()).toHaveLength(0);
    item.trace = [
      { kind: "source", label: "Unsupported frame", site: { path, line: 2 } },
    ];
    item.decidingEvidence = [];
    expect(sourceFrames()).toHaveLength(0);
  });
});
