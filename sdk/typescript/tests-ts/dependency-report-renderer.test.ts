import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { stackReport } from "./support/dependency-stack-report-fixture.js";
import { renderDependencyReport } from "../src/dependency-report-renderer.js";
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
function panel(html: string, id: string) {
  const article = html.match(
    new RegExp('<article[^>]* id="' + id + '"[^>]*>[\\s\\S]*?</article>'),
  )?.[0];
  if (!article) throw new Error("Missing finding: " + id);
  return article;
}
describe("call site report", () => {
  test("walks retained frames, opens the exact caller line, and does not pass caller code off as dependency code", () => {
    const raw = stackReport(),
      [assessment, empty] = raw.assessments;
    const o = assessment.observation;
    const html = renderDependencyReport({
      ...raw,
      assessments: [
        {
          ...assessment,
          observation: {
            ...o,
            frames: [
              ...o.frames,
              { rawIndex: 7, frame: { name: "outer", type: "function" } },
              {
                rawIndex: 2,
                frame: {
                  name: "caller",
                  location: "/app.runfiles/_main/src/codec.ts:3",
                  type: "function",
                },
              },
            ],
            bindings: [
              ...o.bindings,
              {
                package: "example",
                sourceSha: raw.target.sha,
                version: raw.target.sha,
                provenance: "sampled build",
              },
            ],
          },
        },
        empty,
      ],
    });
    const observed = panel(html, "stack-1-1");
    const frames = elements(observed, "details.frame", [
      "id",
      "data-role",
      "data-in-range",
      "open",
    ]);
    expect(frames.map((f) => f.attrs["data-role"])).toEqual([
      "call",
      "source",
      "call_site",
      "sink",
    ]);
    expect(frames[0]!.attrs["data-in-range"]).toBe("false");
    expect(
      elements(observed, "details.frame[open]", ["id"]).map(
        (f) => f.attrs["id"],
      ),
    ).toEqual(["stack-1-1-frame-2"]);
    expect(frames[2]!.text).toContain("caller");
    expect(
      elements(observed, "#stack-1-1-frame-2 [data-highlighted]"),
    ).toHaveLength(1);
    expect(elements(observed, "#stack-1-1-frame-3 pre")).toHaveLength(0);
    expect(
      elements(observed, "#stack-1-1-frame-3 .unavailable").length,
    ).toBeGreaterThan(0);
    for (const selector of [
      "[data-range]",
      "[data-next]",
      "[data-prev]",
      ".gap",
    ])
      expect(elements(observed, selector).length).toBeGreaterThan(0);
    expect(text(observed)).toContain("Sampled copy 1.0");
    expect(text(observed)).toContain("Which decoder mode ran?");
    expect(text(observed)).toContain("The guard is configurable.");
    expect(text(observed)).toContain("Query truncated Yes");
    expect(text(html)).toContain("No independent review");
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
    const links = elements(html, "a[data-entry]", ["href"]);
    const articles = elements(html, "article[data-finding]", [
      "id",
      "data-verdict",
    ]);
    expect(links.map((l) => l.attrs["href"])).toEqual(
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
    const frames = elements(source, "details.frame", ["data-role", "open"]);
    expect(frames.map((f) => f.attrs["data-role"])).toEqual(["call_site"]);
    expect(elements(source, "details.frame[open]")).toHaveLength(1);
    expect(elements(source, ".frame [data-highlighted]")).toHaveLength(1);
    expect(
      elements(source, "[data-condition]", ["data-condition"]).map(
        (c) => c.attrs["data-condition"],
      ),
    ).toEqual(["met", "unknown"]);
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
  test("shows blocked and pending advisories as states, not as use verdicts", () => {
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
        { ...blocked, advisoryId: "CVE-2099-44002" },
      ],
      pendingAdvisories: ["CVE-2099-44003"],
    });
    const entries = elements(html, "[data-entry]", ["data-verdict"]);
    expect(entries).toHaveLength(3);
    expect(
      entries.filter((a) => a.attrs["data-verdict"] === "unknown"),
    ).toHaveLength(1);
    expect(text(html)).toContain("Restore inventory.");
    expect(text(html)).toMatch(/not (started|investigated)/i);
    expect(text(html)).not.toContain("undefined");
  });
  test("empty report has no vulnerable or cleared findings", () => {
    const html = renderDependencyReport(report([]));
    expect(elements(html, "[data-entry][data-verdict=ruled_out]")).toHaveLength(
      0,
    );
    expect(text(html)).toMatch(
      /no (reviewed|assessed|findings|uses|call sites)/i,
    );
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
  test("preserves original use IDs and source bindings after priority sorting", () => {
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
    const html = renderDependencyReport(
      withExcerpts(report([a, b]), ["const mode = 'safe';"]),
    );
    expect(html.indexOf('id="use-1-2"')).toBeLessThan(
      html.indexOf('id="use-1-1"'),
    );
    expect(panel(html, "use-1-1")).toContain("tok-keyword");
    expect(panel(html, "use-1-2")).not.toContain("tok-keyword");
    expect(html).toContain('value="unknown"');
    expect(html).toContain('href="#use-1-1"');
  });
  test("does not display excerpts from the wrong claim revision or source revision", () => {
    const input = withExcerpts(report([reviewed(1)]), ["hiddenExcerpt()"]);
    expect(renderDependencyReport(input)).toContain("hiddenExcerpt");
    input.claims[0]!.revision = 2;
    expect(renderDependencyReport(input)).not.toContain("hiddenExcerpt");
    input.claims[0]!.revision = 1;
    input.claimEvidence.sources["cite-0-0"]!.commit = "f".repeat(40);
    expect(renderDependencyReport(input)).not.toContain("hiddenExcerpt");
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
  test("shows only cited excerpts including dismissed coverage, and highlights the exact call site", () => {
    const u = reviewed(1, {
      location: "POST /upload → decodeFrame",
      evidence: [{ path: "entry.ts", startLine: 2, endLine: 2, supports: [] }],
      decidingEvidence: [sourceRef("entry.ts", 2)],
      proof: {
        sink: {
          function: "decodeFrame",
          callSite: { path: "entry.ts", line: 2 },
        },
        conditions: [],
      },
    });
    const dismissed = unresolved(2, {
      kind: "dismissed",
      reason: "Excluded from the requested scope.",
      evidence: [{ path: "entry.ts", startLine: 1, endLine: 1, supports: [] }],
      decidingEvidence: [sourceRef("entry.ts", 1)],
    });
    const r = withExcerpts(
      report([u], [dismissed]),
      ["const value = decodeFrame(input);"],
      ["const input = 1;"],
    );
    r.claimEvidence.sources["uncited"] = {
      path: "entry.ts",
      startLine: 3,
      endLine: 3,
      excerpt: "const unused = 3;",
    };
    const html = renderDependencyReport(r);
    expect(html).toContain("data-highlighted");
    expect(html).toContain("tok-keyword");
    expect(html).toContain("decodeFrame(input)");
    expect(text(html)).toContain("const input");
    expect(html).not.toContain("const unused");
  });
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
    expect(html.indexOf("Report limitations")).toBeLessThan(
      html.indexOf("Investigation scope and search coverage"),
    );
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
});
