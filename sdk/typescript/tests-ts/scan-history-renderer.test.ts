import { stripVTControlCharacters } from "node:util";
import { describe, expect, test } from "bun:test";
import { renderScanHistory } from "../src/scan-history-renderer.js";

describe("scan history renderer", () => {
  test("separates current repository findings from earlier observations", () => {
    const text = renderScanHistory(
      {
        repository: "/repo",
        findings: [true, false].map((confirmed) => ({
          title: confirmed ? "Current finding" : "Earlier finding",
          severity: { level: "high" },
          locationPath: "source.ts",
          confirmedInLatestScan: confirmed,
        })),
      },
      "findings",
      { color: false },
    );
    expect(text).toMatch(
      /Seen this scan[\s\S]*Current finding[\s\S]*Not confirmed in latest scan[\s\S]*Earlier finding/,
    );
  });

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
        startedAt: "2026-07-23T12:00:00Z",
      },
      {
        scanId: "22222222-2222-4222-8222-222222222222",
        targetPath: "/demo/payment-service",
        mode: "deep",
        progress: { status: "complete" },
        findingCount: 2,
        startedAt: "2026-07-24T12:00:00Z",
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
      expect(output).toContain("latest: 8 findings");
      expect(output).toContain("scans show 11111111");
      if (columns >= 96) expect(output).toContain("REPOSITORY");
    }
  });

  test("keeps finding links repository-scoped from checkout subdirectories", () => {
    const scan = {
      scanId: "11111111-1111-4111-8111-111111111111",
      targetPath: "/demo/repository",
      mode: "standard",
      progress: { status: "complete" },
      findingCount: 2,
      startedAt: "2026-07-23T12:00:00Z",
    };

    const current = stripVTControlCharacters(
      renderScanHistory({ scans: [scan] }, "list", {
        currentDirectory: "/demo/repository/src",
        repository: "/demo/repository/src",
      }),
    );
    expect(current).toContain("codex-security findings list");
    expect(current).not.toContain("codex-security findings list --scan");

    const other = stripVTControlCharacters(
      renderScanHistory({ scans: [scan] }, "list", {
        currentDirectory: "/demo/another-repository",
        repository: "/demo/repository",
      }),
    );
    expect(other).toContain("codex-security findings list --scan 11111111");
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
        config: {
          model: "gpt-5.6-sol",
          model_reasoning_effort: "high",
          features: { goals: true, multi_agent_v2: { enabled: true } },
          trusted_paths: ["src", "packages/core"],
        },
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
      'features={"goals":true,"multi_agent_v2":{"enabled":true}}',
      'trusted_paths=["src","packages/core"]',
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

  test("renders saved findings with identifiers and pagination", () => {
    const output = stripVTControlCharacters(
      renderScanHistory(
        {
          scanId: "31107fbe-abcd-4567-abcd-1234567890ab",
          findings: [
            {
              occurrenceId: "saved-occurrence",
              severity: { level: "high" },
              title: "Missing authorization",
              locations: [{ path: "routes/login.ts", startLine: 34 }],
              triage: { status: "open" },
            },
          ],
          offset: 20,
          nextOffset: 21,
          total: 25,
        },
        "findings",
      ),
    );

    for (const expected of [
      "SAVED FINDINGS",
      "21-21 of 25",
      "routes/login.ts:34",
      "ID saved-occurrence",
      "--offset 21",
      "findings show OCCURRENCE_ID",
    ]) {
      expect(output).toContain(expected);
    }
  });

  test("renders stored finding details and authoritative triage", () => {
    const output = stripVTControlCharacters(
      renderScanHistory(
        {
          occurrenceId: "saved-occurrence",
          scanId: "31107fbe-abcd-4567-abcd-1234567890ab",
          targetPath: "/demo/juice-shop",
          severity: { level: "high" },
          title: "Missing authorization",
          summary: "Customer records are accessible without a session.",
          locations: [{ path: "routes/login.ts", startLine: 34 }],
          remediation: "Require an authenticated session.",
          status: "closed",
          triage: { status: "open" },
        },
        "finding",
      ),
    );

    for (const expected of [
      "FINDING DETAILS",
      "juice-shop",
      "OPEN",
      "Customer records are accessible without a session.",
      "Require an authenticated session.",
      "findings false-positive saved-occurrence",
    ]) {
      expect(output).toContain(expected);
    }
    expect(output).not.toContain("CLOSED");
  });

  test("renders repeated finding history without a semantic match", () => {
    const output = stripVTControlCharacters(
      renderScanHistory(
        {
          occurrenceId: "saved-occurrence",
          scanId: "latest-scan",
          targetPath: "/demo/repository",
          severity: { level: "high" },
          title: "Missing authorization",
          locations: [{ path: "routes/login.ts", startLine: 34 }],
          knownSince: "2026-01-01T00:00:00Z",
          knownScanIds: ["earlier-scan", "latest-scan"],
          occurrenceCount: 2,
          triage: { status: "open" },
        },
        "finding",
      ),
    );

    expect(output).toContain("Known since");
    expect(output).toContain("2 scans");
    expect(output).not.toContain("LINKED FINDINGS");
  });

  test.each([
    [["latest-scan"], "1 scan"],
    [undefined, "2 occurrences"],
  ] as const)(
    "reports the distinct scan count for repeated finding occurrences",
    (knownScanIds, expected) => {
      const output = stripVTControlCharacters(
        renderScanHistory(
          {
            occurrenceId: "saved-occurrence",
            scanId: "latest-scan",
            targetPath: "/demo/repository",
            severity: { level: "high" },
            title: "Missing authorization",
            locations: [{ path: "routes/login.ts", startLine: 34 }],
            ...(knownScanIds ? { knownScanIds: [...knownScanIds] } : {}),
            occurrenceCount: 2,
            triage: { status: "open" },
          },
          "finding",
        ),
      );

      expect(output).toContain(expected);
      expect(output).not.toContain("2 scans");
    },
  );

  test.each([
    ["already_fixed", "FIXED", "Fixed"],
    ["false_positive", "FALSE POSITIVE", "False Positive"],
    ["wont_fix", "IGNORED", "Ignored"],
  ])("uses clear finding-status labels for %s", (reason, status, label) => {
    const output = stripVTControlCharacters(
      renderScanHistory(
        {
          occurrenceId: "saved-occurrence",
          scanId: "saved-scan",
          targetPath: "/demo/repository",
          severity: { level: "high" },
          title: "Missing authorization",
          locations: [{ path: "routes/login.ts", startLine: 34 }],
          triage: { closeReason: reason, status: "closed" },
        },
        "finding",
      ),
    );

    expect(output).toContain(status);
    expect(output).toContain(`Reason: ${label}`);
    expect(output).not.toContain(reason);
    expect(output).not.toContain("CLOSED");
  });
});
