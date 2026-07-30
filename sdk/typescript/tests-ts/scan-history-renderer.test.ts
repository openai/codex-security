import { stripVTControlCharacters } from "node:util";
import { describe, expect, test } from "bun:test";
import { renderScanHistory } from "../src/scan-history-renderer.js";

describe("scan history renderer", () => {
  test("leads comparisons with the outcome and groups root causes", () => {
    const text = stripVTControlCharacters(
      renderScanHistory(
        {
          repository: "/demo/juice-shop",
          beforeScanId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
          afterScanId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
          comparable: true,
          coverage: { afterCompleteness: "complete" },
          summary: {
            new: 1,
            persisting: 2,
            resolved: 2,
            reopened: 0,
            unknown: 2,
          },
          findings: [
            {
              findingId: "internal-persisting-id",
              status: "persisting",
              severity: "high",
              title: "Basket ownership check is missing",
              path: "routes/basket.ts",
              beforeOccurrenceIds: ["before-one", "before-two"],
              afterOccurrenceIds: ["after-one"],
              matchReason:
                "Both routes share the same unchecked basket lookup.",
            },
            {
              status: "persisting",
              severity: "high",
              title: "Basket modification omits the ownership check",
              path: "routes/basket.ts",
            },
            {
              status: "new",
              severity: "medium",
              title: "Order input is evaluated",
              path: "routes/b2bOrder.ts",
            },
            {
              status: "resolved",
              severity: "informational",
              title: "Informational cookie observation",
              path: "routes/session.ts",
            },
            {
              status: "resolved",
              severity: "critical",
              title: "Login SQL injection bypasses authentication",
              path: "routes/login.ts",
              beforeOccurrenceId: "before-resolved",
            },
            {
              status: "unknown",
              severity: "high",
              title: "Complaint upload can overwrite trusted files",
              path: "routes/fileUpload.ts",
              reason:
                "The affected path was excluded or outside the later scope.",
            },
            {
              status: "unknown",
              severity: "medium",
              title: "Session handling might match an earlier finding",
              path: "routes/session.ts",
              reason: "The two findings describe different session flows.",
            },
          ],
        },
        "compare",
      ),
    );

    expect(text).toContain("CODEX SECURITY");
    expect(text).toMatch(
      /SCAN COMPARISON[\s\S]*━━ ✓ Resolved \(2 findings\) ━+[\s\S]*━━ \+ New \(1 finding\) ━+[\s\S]*━━ ● Persisting \(2 findings\) ━+[\s\S]*━━ ○ Not rescanned \(1 finding\) ━+[\s\S]*━━ \? Unknown \(1 finding\) ━+/,
    );
    expect(
      text.indexOf("Login SQL injection bypasses authentication"),
    ).toBeLessThan(text.indexOf("Informational cookie observation"));
    for (const expected of [
      "Complaint upload can overwrite trusted files",
      "Outside follow-up scan coverage",
      "Session handling might match an earlier finding",
      "The two findings describe different session flows.",
      "juice-shop",
      "aaaaaaaa → bbbbbbbb",
      "CRITICAL",
      "2 → 1",
      "Both routes share the same unchecked basket lookup.",
    ]) {
      expect(text).toContain(expected);
    }
    for (const hidden of [
      "follow-up scope",
      "internal-persisting-id",
      "before-resolved",
      "NOT_RESCANNED",
      "REOPENED",
    ]) {
      expect(text).not.toContain(hidden);
    }
  });

  test("reserves dim styling for finding and knowledge-base paths", () => {
    const output = renderScanHistory(
      {
        targetPath: "/demo/juice-shop",
        scanId: "scan-1",
        progress: { status: "complete" },
        mode: "standard",
        recipe: { knowledgeBasePaths: ["/demo/threat-model.md"] },
        findings: [
          {
            severity: "HIGH",
            title: "Missing auth",
            path: "routes/login.ts",
          },
        ],
      },
      "show",
    );
    expect(output).toContain("\u001B[1mKNOWLEDGE BASE\u001B[0m");
    expect(
      [...output.matchAll(/\u001B\[90m([^\u001B]*)\u001B\[0m/g)].map(
        ([, value]) => value,
      ),
    ).toEqual(["/demo/threat-model.md", "routes/login.ts"]);
    for (const coverage of ["partial", "unknown", "complete"]) {
      const comparison = renderScanHistory(
        {
          beforeScanId: "before-scan",
          afterScanId: "after-scan",
          coverage: { afterCompleteness: coverage },
          summary: {},
          findings: [],
        },
        "compare",
        { color: false },
      );
      if (coverage === "complete") {
        expect(comparison).not.toContain("Follow-up coverage");
      } else {
        expect(comparison).toContain(
          `⚠ Follow-up coverage is ${coverage}; resolved findings cannot be confirmed.`,
        );
      }
    }
  });

  test("keeps repositories visible at narrow and wide terminal widths", () => {
    const scans = [
      {
        scanId: "11111111-1111-4111-8111-111111111111",
        targetPath: "/demo/juice-shop",
        mode: "standard",
        progress: { status: "complete" },
        findingCount: 8,
        startedAt: "2026-07-24T12:00:00Z",
      },
      {
        scanId: "22222222-2222-4222-8222-222222222222",
        targetPath: "/demo/payment-service",
        mode: "deep",
        progress: { status: "complete" },
        findingCount: 2,
        startedAt: "2026-07-23T12:00:00Z",
      },
    ];

    for (const columns of [72, 100]) {
      const output = stripVTControlCharacters(
        renderScanHistory({ scans }, "list", {
          columns,
          scanRoot: "/demo/results",
        }),
      );
      expect(output).toContain("results");
      expect(output).toContain("juice-shop");
      expect(output).toContain("payment-service");
      expect(output).toContain(scans[0]!.scanId);
      expect(output).toContain(scans[1]!.scanId);
      if (columns >= 96) expect(output).toContain("REPOSITORY");
    }
  });

  test("shows bounded findings, saved configuration, and failure reasons", () => {
    const scan = {
      scanId: "12345678-abcd-4567-abcd-1234567890ab",
      parentScanId: "87654321-abcd-4567-abcd-1234567890ab",
      targetPath: "/demo/juice-shop",
      mode: "standard",
      progress: {
        status: "complete",
        coverage: { closedRows: 12, worklistRows: 15, filesTotal: 9 },
      },
      findingCount: 75,
      findingsTruncated: true,
      artifacts: { markdownReport: "/demo/results/report.md" },
      recipe: {
        config: { model: "gpt-5.6-sol", model_reasoning_effort: "high" },
      },
      findings: Array.from({ length: 20 }, (_, index) => ({
        severity: { level: "high" },
        title: `Finding ${index + 1}`,
        locations: [{ path: "routes/login.ts", startLine: index + 1 }],
      })),
    };
    const output = stripVTControlCharacters(renderScanHistory(scan, "show"));
    for (const expected of [
      "FINDINGS  20 of 75",
      "PARENT SCAN  87654321",
      "CONFIGURATION",
      "model=gpt-5.6-sol",
      "COVERAGE",
      "12 of 15 reviewed",
      "9 files",
      "ARTIFACTS",
      "/demo/results/report.md",
    ]) {
      expect(output).toContain(expected);
    }

    const failed = stripVTControlCharacters(
      renderScanHistory(
        {
          ...scan,
          progress: { status: "failed" },
          failureMessage: "Repository checkout became unavailable.",
          findings: [],
        },
        "show",
      ),
    );
    expect(failed).toContain("ERROR  Repository checkout became unavailable.");
  });

  test("shows saved completion warnings without marking a scan failed", () => {
    const output = stripVTControlCharacters(
      renderScanHistory(
        {
          scanId: "12345678-abcd-4567-abcd-1234567890ab",
          targetPath: "/demo/juice-shop",
          mode: "standard",
          progress: { status: "complete" },
          findings: [],
          warnings: [
            "Repository HEAD changed while the scan was running; results were saved for the original revision.",
          ],
        },
        "show",
      ),
    );

    expect(output).toContain("COMPLETE");
    expect(output).toContain("WARNING");
    expect(output).toContain(
      "Repository HEAD changed while the scan was running",
    );
    expect(output).not.toContain("ERROR");
  });

  test("renders match-all results from the original workbench data", () => {
    const output = stripVTControlCharacters(
      renderScanHistory(
        {
          repository: "/demo/juice-shop",
          scanCount: 5,
          unavailableScans: 2,
          matchedPairs: 0,
          findingMatches: 0,
        },
        "match-all",
      ),
    );
    for (const expected of [
      "MATCH RESULTS",
      "juice-shop",
      "5 scans",
      "0 comparisons",
      "0 root-cause matches",
      "2 scans unavailable",
    ]) {
      expect(output).toContain(expected);
    }
  });
});

describe("scan history renderer resilience", () => {
  // The workbench response is only checked for being a JSON object
  // (src/runtime.ts runWorkbench), so a plugin or database that drifts from the
  // shape this renderer expects must degrade instead of crashing the command.
  const plain = (
    result: Parameters<typeof renderScanHistory>[0],
    command: Parameters<typeof renderScanHistory>[1],
    options = {},
  ) =>
    stripVTControlCharacters(
      renderScanHistory(result, command, { color: false, ...options }),
    );

  test("renders comparison findings with a missing or null severity", () => {
    for (const severity of [undefined, null]) {
      const text = plain(
        {
          beforeScanId: "before-scan",
          afterScanId: "after-scan",
          coverage: { afterCompleteness: "complete" },
          summary: { resolved: 1 },
          findings: [
            {
              ...(severity === undefined ? {} : { severity }),
              status: "resolved",
              title: "Reflected XSS in the search handler",
              locations: [{ path: "src/search.ts", startLine: 10 }],
            },
          ],
        },
        "compare",
      );
      expect(text).toContain("Reflected XSS in the search handler");
      expect(text).toContain("src/search.ts:10");
    }
  });

  test("sorts an unrecognized severity below every known severity", () => {
    const text = plain(
      {
        beforeScanId: "before-scan",
        afterScanId: "after-scan",
        coverage: { afterCompleteness: "complete" },
        summary: { new: 2 },
        findings: [
          {
            status: "new",
            severity: "not-a-severity",
            title: "Unknown severity finding",
            path: "a.ts",
          },
          {
            status: "new",
            severity: "critical",
            title: "Critical severity finding",
            path: "b.ts",
          },
        ],
      },
      "compare",
    );
    expect(text.indexOf("Critical severity finding")).toBeLessThan(
      text.indexOf("Unknown severity finding"),
    );
  });

  test("lists scans that carry no progress record", () => {
    const text = plain(
      {
        scans: [
          {
            scanId: "11111111-1111-4111-8111-111111111111",
            targetPath: "/repo",
            mode: "standard",
            startedAt: "2026-07-01T00:00:00Z",
            findingCount: 3,
          },
        ],
      },
      "list",
    );
    expect(text).toContain("11111111-1111-4111-8111-111111111111");
    expect(text).toContain("UNKNOWN");
  });

  test("falls back to the raw value for an unparsable knownSince", () => {
    const text = plain(
      {
        scanId: "scan-1",
        targetPath: "/repo",
        mode: "standard",
        progress: { status: "complete" },
        findings: [
          {
            severity: { level: "high" },
            title: "Path traversal",
            knownSince: "not-a-timestamp",
            matches: [
              {
                scanId: "older-scan",
                title: "Path traversal",
                reason: "same sink",
              },
            ],
            locations: [{ path: "src/fs.ts", startLine: 22 }],
          },
        ],
      },
      "show",
      { showLinkedFindings: true },
    );
    expect(text).toContain("Known since not-a-timestamp");
    expect(text).toContain("Path traversal");
  });

  test("renders every command from an empty payload", () => {
    for (const command of ["list", "show", "compare", "match-all"] as const) {
      expect(() => plain({}, command)).not.toThrow();
    }
  });
});
