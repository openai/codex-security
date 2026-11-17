import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { readDependencyCheckOutput } from "../src/dependency-reachability.js";
import {
  readDependencyReportCode,
  renderDependencyReport,
} from "../src/dependency-report-renderer.js";
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
  zeroReport,
} from "./support/dependency-report-fixtures.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

function text(html: string) {
  return html
    .replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1>/giu, "")
    .replace(/<[^>]*>/gu, " ")
    .replace(/\s+/gu, " ")
    .trim();
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
  return (
    html
      .split(`<article class="finding" id="${id}"`)[1]
      ?.split("</article>")[0] ?? ""
  );
}
const call = (useId: string, location: string, count = 0) => ({
  useId,
  location,
  step: "sink" as const,
  environment: "prod" as const,
  count,
  from: "2026-01-01T00:00:00Z",
  until: "2026-01-01T01:00:00Z",
  target: "Synthetic prod worker",
  record: "sample-measurement-1",
});

describe("service-oriented exploitability report", () => {
  test("reconciles unique uses, information gaps, exclusions and separate coverage leads", () => {
    const html = renderDependencyReport(broadReport());
    expect(elements(html, ".check-heading h2")[0]!.text).toBe(
      "Reviewed places",
    );
    const metrics = text(elements(html, ".totals")[0]!.text);
    expect(metrics).toContain("64 reviewed uses");
    expect(metrics).toContain("48 Requires more information");
    expect(metrics).toContain("16 Ruled out");
    expect(metrics).toContain("24 unresolved coverage items");
    const items = elements(html, "article[data-finding]", [
      "id",
      "data-kind",
      "data-services",
    ]);
    expect(items.filter((i) => i.attrs["data-kind"] === "use")).toHaveLength(
      64,
    );
    expect(
      items.filter((i) => i.attrs["data-kind"] === "coverage"),
    ).toHaveLength(24);
    expect(new Set(items.map((i) => i.attrs["id"])).size).toBe(88);
    expect(items.every((i) => !!i.attrs["data-services"])).toBe(true);
    expect(text(html)).toContain("Service not established");
    expect(text(html)).toContain("Source-only findings");
    expect(html).toContain(
      '<option value="unknown">Requires more information</option>',
    );
    expect(metrics).toContain("8 internet");
    expect(metrics).toContain("8 not internet");
    expect(metrics).toContain("72 unverified");
  });
  test("triages the evidenced input boundary and exact instance rather than inferring exposure from a service or code path", () => {
    const item = reviewed(1, {
      place: place({
        kind: "service",
        workload: "cedar-web-stable",
        environment: "prod",
        variant: "stable",
        deploymentBasis: "observed",
      }),
    });
    const r = receiptRef("input-and-runtime");
    item.decidingEvidence.push(r);
    item.services = [service("svc:cedar", "Cedar", item.decidingEvidence[0]!)];
    item.inputSource = {
      exposure: "internet",
      endpoint: "POST /upload",
      evidence: [r],
    };
    item.runtimeContext = {
      launch: { command: "worker --guard=on", basis: "configured" },
      mitigation: {
        state: "enabled",
        basis: "configured",
        detail: "The process setting has not been observed.",
      },
      containerUrl: "https://registry.example.invalid/image/cedar",
      evidence: [r],
    };
    item.tags = [{ name: "documents", evidence: [r] }];
    const unmapped = reviewed(2, { location: "Public-looking code path" });
    unmapped.services = [
      service("svc:public", "Public service", unmapped.decidingEvidence[0]!),
    ];
    unmapped.inputSource = {
      exposure: "internet",
      endpoint: "POST /unverified",
      evidence: [receiptRef("not-cited")],
    };
    const html = renderDependencyReport(report([item, unmapped]));
    const rows = elements(html, "article[data-finding]", [
      "id",
      "data-exposure",
      "data-tags",
    ]);
    expect(rows[0]!.attrs["data-exposure"]).toBe("internet");
    expect(rows[1]!.attrs["data-exposure"]).toBe("unknown");
    expect(text(panel(html, "use-1-1"))).toContain("cedar-web-stable");
    expect(text(panel(html, "use-1-1"))).toContain("POST /upload");
    expect(text(panel(html, "use-1-1"))).toContain("worker --guard=on");
    expect(text(panel(html, "use-1-1"))).toContain(
      "Mitigation enabled (configured)",
    );
    expect(panel(html, "use-1-2")).not.toContain("POST /unverified");
    expect(html).toContain("data-exposure-filter");
    expect(html).toContain("data-tag-filter");
    expect(html).toContain('data-mode="instances"');
    expect(html).toContain('data-mode-button="code"');
    expect(html).toContain(
      'href="https://registry.example.invalid/image/cedar"',
    );
  });
  test("starts on actual call sites when the report has no instance context", () => {
    const html = renderDependencyReport(report([reviewed(1)]));
    expect(html).toContain('data-mode="code"');
    expect(html).toContain('data-mode-button="code" aria-pressed="true"');
    expect(html).toContain("Operation / call site");
  });
  test("diagrams an artifact exclusion without fabricating a reachable operation", () => {
    const use = reviewed(1, {
      verdict: "ruled_out",
      reason: "The selected artifact contains the verified fix.",
      place: place({ kind: "artifact", artifact: "sha256:" + "3".repeat(64) }),
    });
    const html = panel(renderDependencyReport(report([use])), "use-1-1");
    expect(html).toContain("Why this target is ruled out");
    expect(html).toContain("The selected artifact contains the verified fix.");
    expect(html).not.toContain("Source to operation");
    expect(html).not.toContain("Vulnerable operation bound");
  });
  test("opens material unresolved leads when there are no reviewed uses", () => {
    const html = renderDependencyReport(zeroReport());
    expect(text(html)).toContain("0 reviewed uses");
    expect(text(html)).toContain("5 unresolved coverage items");
    expect(text(html)).toContain("No reviewed use was established");
    expect(elements(html, "article[data-kind=coverage]")).toHaveLength(5);
    expect(html).toContain('id="coverage-1-1"');
    expect(panel(html, "coverage-1-1")).toContain("<details open>");
    expect(text(panel(html, "coverage-1-1"))).toContain(
      "Submitted bytes reach the parser entrypoint",
    );
    expect(text(panel(html, "coverage-1-1"))).toContain(
      "Which registered provider handles this field?",
    );
    const stable = text(panel(html, "coverage-1-1"));
    const canary = text(panel(html, "coverage-1-2"));
    expect(stable).toContain("Observed running");
    expect(stable).toContain("linux/amd64");
    expect(stable).toContain("enables the document renderer");
    expect(canary).toContain("linux/arm64");
    expect(canary).toContain("disables the document renderer");
    expect(stable).not.toContain("linux/arm64");
    expect(text(html).toLowerCase()).not.toContain("all clear");
  });
  test("groups library callers and jobs by reviewed associations and counts a shared finding once", () => {
    const html = renderDependencyReport(variantReport());
    const nav = elements(html, "a[data-service-link]", [
      "data-name",
      "href",
      "data-service",
    ]);
    expect(nav.find((a) => a.attrs["data-name"] === "Cedar")?.text).toMatch(
      /3 reviewed uses/,
    );
    expect(nav.find((a) => a.attrs["data-name"] === "Spruce")?.text).toMatch(
      /1 reviewed use.*1 unresolved item/,
    );
    expect(elements(html, ".totals")[0]!.text).toContain("3 reviewed uses");
    expect(elements(html, "article#use-1-3")).toHaveLength(1);
    expect(
      (
        elements(html, "article#use-1-3", ["data-services"])[0]!.attrs[
          "data-services"
        ] ?? ""
      ).split(" "),
    ).toHaveLength(2);
    expect(text(panel(html, "use-1-1"))).toContain("stable");
    expect(text(panel(html, "use-1-2"))).toContain("canary");
    expect(text(panel(html, "use-1-1"))).toContain("linux/amd64");
    expect(text(panel(html, "use-1-2"))).toContain("linux/arm64");
    expect(text(panel(html, "use-1-1"))).toContain("Image index");
    expect(text(panel(html, "use-1-1"))).toContain("Platform manifest");
    expect(panel(html, "use-1-1")).not.toContain("3".repeat(64));
    expect(panel(html, "use-1-2")).not.toContain("2".repeat(64));
  });
  test("does not trust a service kind, free-text name, or an unreviewed association", () => {
    const u = reviewed(1, {
      location: "misleading-service",
      place: place({ kind: "service" }),
      services: [
        service("svc:spoof", "Wrong service", sourceRef("different.ts", 2)),
      ],
    });
    const html = renderDependencyReport(report([u]));
    expect(text(html)).toContain("Service not established");
    expect(
      elements(html, "a[data-service-link]", ["data-name"]).some(
        (a) => a.attrs["data-name"] === "Wrong service",
      ),
    ).toBe(false);
    expect(text(panel(html, "use-1-1"))).toContain("not confirmed");
  });
  test("renders exact questions, target, exclusion and next check without inventing them from historical prose", () => {
    const html = renderDependencyReport(variantReport());
    const p = text(panel(html, "use-1-1"));
    expect(p).toContain("Is the affected mode enabled for the stable worker?");
    expect(p).toContain("Cedar prod stable linux/amd64");
    expect(p).toContain("Read the admitted worker setting");
    expect(p).toContain("The guard rejects");
    expect(p).toContain("Request reaches decoder before authentication");
    const legacy = reviewed(9, {
      reason: "The source was checked. The runtime flag is unknown.",
      place: place({ unresolvedQuestions: ["The runtime flag is unknown."] }),
    });
    const h = panel(renderDependencyReport(report([legacy])), "use-1-1");
    expect(text(h).split("The runtime flag is unknown.")).toHaveLength(2);
    expect(text(h)).toContain("No separate deciding check was recorded");
    expect(text(h)).toContain("No inspection attempt was recorded");
  });
  test("distinguishes open reviewed use from an unbound implementation handoff", () => {
    const html = renderDependencyReport(variantReport());
    expect(text(panel(html, "use-1-1"))).toContain("Requires more information");
    const c = text(panel(html, "coverage-1-1"));
    expect(c).toContain("Unresolved coverage");
    expect(c).toContain("Document bytes reach the parser entrypoint");
    expect(c).toContain("has not been linked to decodeFrame");
    expect(c).not.toContain("Requires more information");
  });
  test("keeps denied, unsupported, timed out, not attempted and successful fallback inspections separate", () => {
    const u = reviewed(1);
    const refs = ["denied", "unsupported", "timeout", "fallback"].map((id, i) =>
      receiptRef(id, String(i + 1)),
    );
    u.decidingEvidence.push(...refs);
    const target = {
      label: "Cedar stable platform image",
      relationship: "target" as const,
      platform: "linux/amd64",
      imageIndex: "sha256:index",
      platformManifest: "sha256:amd64",
    };
    u.inspections = [
      ...(["denied", "unsupported", "timeout"] as const).map((outcome, i) => ({
        question: `Inspect selected JAR via ${outcome}`,
        target,
        source: "artifact inventory",
        outcome,
        result:
          outcome === "denied"
            ? "Registry returned 403."
            : "Inspection did not complete.",
        evidence: [refs[i]!],
      })),
      {
        question: "Inspect registered plugin",
        target,
        outcome: "not_attempted",
        evidence: [],
      },
      {
        question: "Inspect publisher copy",
        target: { ...target, relationship: "shared_artifact" },
        source: "publisher artifact",
        outcome: "succeeded",
        result: "Digest-matched publisher copy contains the backport.",
        evidence: [refs[3]!],
        transferBasis:
          "The publisher file has the identical selected platform-manifest digest.",
      },
    ];
    const h = panel(renderDependencyReport(report([u])), "use-1-1");
    for (const v of [
      "Access denied",
      "Unsupported source",
      "Timed out",
      "Not attempted",
      "Completed",
      "Registry returned 403",
      "Digest-matched publisher copy",
      "Transfer basis",
      "Platform manifest",
    ])
      expect(text(h)).toContain(v);
    expect(text(h)).not.toContain("retried");
  });
  test("attributes CPU samples to exact or comparison workloads and distinguishes zero, missing, partial and absent symbols", () => {
    const u = reviewed(1);
    const refs = ["zero", "missing", "partial", "peer", "confirmed"].map(
      (id, i) => receiptRef(id, String(i + 1)),
    );
    u.decidingEvidence.push(...refs);
    const t = {
      label: "Cedar target JVM",
      relationship: "target" as const,
      workload: "cedar-stable",
      observationWindow: "00:00–01:00",
    };
    const p = {
      label: "Cedar peer",
      relationship: "comparison" as const,
      workload: "cedar-peer",
      observationWindow: "00:00–01:00",
    };
    u.inspections = [
      {
        question: "Target samples",
        target: t,
        source: "CPU profiler",
        outcome: "zero_results",
        evidence: [refs[0]!],
        measurement: { unit: "cpu_samples", count: 0 },
        completeness: "not_reported",
      },
      {
        question: "Target measurement",
        target: t,
        source: "CPU profiler",
        outcome: "no_data",
        evidence: [refs[1]!],
      },
      {
        question: "Partial window",
        target: t,
        source: "CPU profiler",
        outcome: "partial",
        evidence: [refs[2]!],
        completeness: "partial",
      },
      {
        question: "Peer frame coverage",
        target: p,
        source: "CPU profiler",
        outcome: "insufficient_symbols",
        result:
          "Peer rows do not establish Java-function execution on the target.",
        evidence: [refs[3]!],
        measurement: {
          unit: "cpu_samples",
          count: 321,
          frameTypes: ["native", "kernel", "other"],
        },
        completeness: "not_reported",
      },
      {
        question: "Target function execution",
        target: t,
        source: "CPU profiler",
        outcome: "succeeded",
        evidence: [refs[4]!],
        measurement: { unit: "cpu_samples", count: 3, frameTypes: ["java"] },
        result: "The exact target sample contains Decoder.decodeFrame.",
      },
    ];
    const h = text(panel(renderDependencyReport(report([u])), "use-1-1"));
    for (const v of [
      "Returned zero",
      "0 CPU samples",
      "No measurement or data",
      "backend reported partial",
      "Comparison workload: Cedar peer",
      "321 CPU samples",
      "Required symbols absent",
      "not reported by backend",
      "Decoder.decodeFrame",
    ])
      expect(h).toContain(v);
    expect(h).not.toContain("321 calls");
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
  test("preserves original use IDs and sidecar bindings after priority sorting and service filtering", () => {
    const a = reviewed(1, {
        verdict: "ruled_out",
        reason: "Excluded by a source guard.",
      }),
      b = reviewed(2, { verdict: "potentially_exploitable", version: "1.0" });
    a.services = [service("svc:a", "Alpha", a.decidingEvidence[0]!)];
    b.services = [service("svc:b", "Beta", b.decidingEvidence[0]!)];
    const input = report([a, b]);
    const html = renderDependencyReport(input, {
      productionCalls: [call("use-1-1", a.location, 0)],
      code: new Map([
        [JSON.stringify([a.evidence[0]!.path, 2, 2]), "const mode = 'safe';"],
      ]),
    });
    expect(html.indexOf('id="use-1-2"')).toBeLessThan(
      html.indexOf('id="use-1-1"'),
    );
    expect(text(panel(html, "use-1-1"))).toContain("0 production calls");
    expect(panel(html, "use-1-2")).not.toContain("production calls");
    expect(panel(html, "use-1-1")).toContain("const");
    expect(html).toContain("history.pushState");
    expect(html).toContain("popstate");
    expect(html).toContain('value="unknown"');
    expect(html).toContain('href="#use-1-1"');
  });
  test("rejects an incorrect measurement identity, invalid interval and proof outside a bound source range", () => {
    const u = reviewed(1);
    expect(() =>
      renderDependencyReport(report([u]), {
        productionCalls: [call("use-1-1", "Wrong")],
      }),
    ).toThrow("does not match");
    expect(() =>
      renderDependencyReport(report([u]), {
        productionCalls: [
          { ...call("use-1-1", u.location), until: "2025-12-01T00:00:00Z" },
        ],
      }),
    ).toThrow();
    expect(() =>
      renderDependencyReport(report([u]), {
        useEvidence: [
          {
            useId: "use-1-1",
            location: u.location,
            sink: { function: "f", callSite: { path: "outside.ts", line: 1 } },
            conditions: [],
          },
        ],
      }),
    ).toThrow("outside");
  });
  test("loads v1 JSON, retains the enum, and displays honest fallbacks", () => {
    const u = reviewed(1);
    const { decidingEvidence: _refs, place: _p, ...old } = u;
    const legacy = {
      cve: "CVE-2099-44001",
      advisories: [],
      usage: null,
      status: "unknown",
      uses: [old],
      limitations: [],
    };
    const parsed = readDependencyCheckOutput(legacy);
    expect("cve" in parsed && parsed.uses[0]!.verdict).toBe("unknown");
    const html = renderDependencyReport(legacy);
    const h = text(html);
    expect(h).toContain("Requires more information");
    expect(h).toContain("Service not established");
    expect(text(panel(html, "use-1-1"))).toContain("Deployment unverified");
    expect(h).toContain("Version unverified");
    const observed = renderDependencyReport({
      ...legacy,
      uses: [{ ...old, deployment: "confirmed" }],
    });
    expect(text(panel(observed, "use-1-1"))).toContain("Observed running");
  });
  test("keeps independent advisory checks, anchors, custom descriptions, and status filters", () => {
    const first = reviewed(1),
      second = unresolved(1);
    first.services = [
      service("svc:cedar", "Cedar", first.decidingEvidence[0]!),
    ];
    second.services = [
      service("svc:cedar", "Cedar", second.decidingEvidence![0]!),
    ];
    const { cve: _cve, ...one } = report([first]);
    const { cve: _cve2, ...two } = report([], [second]);
    const html = renderDependencyReport({
      package: { ecosystem: "npm", name: "sample-codec" },
      vulnDescription: "A supplied advisory description.",
      checks: [
        { ...one, advisoryId: "CVE-2099-44001" },
        { ...two, advisoryId: "CVE-2099-44002" },
      ],
    });
    expect(text(html)).toContain("A supplied advisory description.");
    expect(html).toContain('id="check-1"');
    expect(html).toContain('id="check-2"');
    expect(html).toContain('id="coverage-2-1"');
    expect(html).toContain('data-check-link="check-2"');
    expect(html).toContain("data-search");
    expect(html).toContain("data-deployment-filter");
    expect(html).toContain("data-advisory-search");
    const overview = elements(html, "[data-overview-service]");
    expect(overview).toHaveLength(1);
    expect(overview[0]!.text).toContain("CVE-2099-44001");
    expect(overview[0]!.text).toContain("CVE-2099-44002");
    expect(html).toContain('data-check-selection="check-2"');
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
      "Vulnerable functions",
      "Decoder.decode",
      "sample-codec",
      "fixed in 1.2.4",
      "Only frame mode",
    ])
      expect(text(html)).toContain(v);
    expect(html).not.toContain(raw);
    expect(html).not.toContain('href="javascript:');
    expect(html).toContain("&lt;img");
    expect(() =>
      renderDependencyReport(report([u]), {
        advisoryDetails: [{ url: "https://unrelated.invalid", affected: [] }],
      }),
    ).toThrow("not referenced");
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
  test("loads only cited source ranges including dismissed coverage, and highlights the exact call site", async () => {
    await using repo = await scopedTemporaryDirectory("report-code-");
    await writeFile(
      join(repo.path, "entry.ts"),
      "const input = 1;\nconst value = decodeFrame(input);\nconst unused = 3;\n",
    );
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
    const r = report([u], [dismissed]);
    const codeMap = await readDependencyReportCode(r, repo.path);
    expect(codeMap.size).toBe(2);
    const html = renderDependencyReport(r, { code: codeMap });
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
    expect(elements(html, "article[data-kind=coverage]")).toHaveLength(2);
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
    const r = { ...report([u]), limitations: [raw] };
    const html = renderDependencyReport(r, {
      code: new Map([[JSON.stringify(["src/handler-1.ts", 2, 2]), raw]]),
    });
    expect(html).not.toContain(raw);
    expect(html).toContain("&lt;svg");
    const script = html.match(/<script>([\s\S]*?)<\/script>/u)![1]!;
    expect(html).toContain(
      `script-src 'sha256-${createHash("sha256").update(script).digest("base64")}'`,
    );
    expect(html).toContain("default-src 'none'");
    expect(html).toContain("@media print");
    expect(html).toContain(":focus-visible");
    expect(html).toMatch(/@media\s*\(max-width:\s*650px\)/u);
    expect(html).toContain("Skip to report");
    expect(html).not.toContain("<script src=");
    expect(html).not.toContain("<link rel=");
  });
  test("rejects an invalid report envelope and reports empty checks without an all-clear", () => {
    expect(() =>
      renderDependencyReport({
        answer: {
          ...report([reviewed(1)]),
          uses: [{ ...reviewed(1), version: 2 }],
        },
      }),
    ).toThrow();
    expect(
      text(
        renderDependencyReport({
          package: { ecosystem: "npm", name: "codec" },
          checks: [],
        }),
      ),
    ).toContain("No advisory checks");
    expect(text(renderDependencyReport(report([])))).toContain(
      "No reviewed uses or unresolved coverage items were recorded",
    );
  });
  test("renders a blocked run as an operational status, never as a use verdict", () => {
    const blocked = {
      status: "blocked",
      code: "INVESTIGATION_BLOCKED",
      reason: "The required inventory server did not start.",
      category: "widespread_required_data_unavailable",
      affectedScope: "Synthetic production workers",
      coverage: {
        basis: "server_startup",
        server: "inventory",
        receiptId: "inventory-1",
        requiredCheck: "Resolve selected artifacts",
      },
      scopeImpact: "Required artifact evidence is unavailable.",
      unblockCondition: "Restore the inventory service and start a new check.",
      evidenceReferences: [],
      retainedEvidence: {
        assessmentRevisions: [],
        inventoryReceiptIds: ["inventory-1"],
      },
    };
    const html = renderDependencyReport(blocked);
    expect(text(html)).toContain("Investigation blocked before final review");
    expect(text(html)).toContain(
      "operational outcome, not an exploitability verdict",
    );
    expect(elements(html, "article[data-finding]")).toHaveLength(0);
    const { cve: _cve, ...complete } = report([reviewed(1)]);
    const mixed = renderDependencyReport({
      status: "blocked",
      code: "INVESTIGATION_BLOCKED",
      package: { ecosystem: "npm", name: "sample-codec" },
      checks: [
        { ...complete, advisoryId: "CVE-2099-44001" },
        { ...blocked, advisoryId: "CVE-2099-44002" },
      ],
    });
    expect(mixed).toContain('id="use-1-1"');
    expect(mixed).toContain('id="check-2"');
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
