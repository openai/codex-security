import { stripVTControlCharacters } from "node:util";
import { describe, expect, test } from "bun:test";
import type { JsonObject } from "../src/config.js";
import { renderScanHistory } from "../src/scan-history-renderer.js";

describe("scan history renderer", () => {
  test.each(["dataflow", "dataFlow", "data_flow"])(
    "renders transformation-only attack paths in %s",
    (key) => {
      const output = renderScanHistory(
        {
          title: "Synthetic saved finding",
          severity: { level: "high" },
          attackPath: {
            [key]: { transformations: ["Decode payload", "Load sink"] },
          },
        },
        "finding",
        { color: false },
      );
      expect(output).toContain("ATTACK PATH");
      expect(output).toContain("Decode payload");
      expect(output).toContain("Load sink");
    },
  );

  test.each([
    "validation",
    "attackPath",
    "dataflow",
    "dataFlow",
    "data_flow",
    "reachability",
  ])("renders supported embedded code-evidence catalogs in %s", (key) => {
    const evidence = {
      codeEvidence: [{ code: "synthetic_section_source();" }],
      code_evidence: [{ code: "synthetic_section_legacy();" }],
    };
    const section: JsonObject =
      key === "validation" || key === "attackPath"
        ? { [key]: evidence }
        : { attackPath: { [key]: evidence } };
    const output = renderScanHistory(
      {
        title: "Synthetic saved finding",
        severity: { level: "high" },
        ...section,
      },
      "finding",
      { color: false },
    );
    expect(output).toContain("synthetic_section_source();");
    expect(output).toContain("synthetic_section_legacy();");
  });

  test.each(["rootCause", "root_cause"])(
    "renders embedded section evidence in %s alongside its summary",
    (key) => {
      const output = renderScanHistory(
        {
          title: "Synthetic saved finding",
          severity: { level: "high" },
          [key]: {
            summary: "Synthetic embedded root cause",
            codeEvidence: [
              { id: "root", code: "synthetic_embedded_source();" },
            ],
            code_evidence: [
              { id: "legacy", code: "synthetic_embedded_legacy();" },
            ],
          },
        },
        "finding",
        { color: false },
      );
      expect(output).toContain("Synthetic embedded root cause");
      expect(output).toContain("synthetic_embedded_source();");
      expect(output).toContain("synthetic_embedded_legacy();");
    },
  );
  test.each([false, true])(
    "keeps native reachability and complementary root evidence with catalogs %s",
    (catalog) => {
      const output = renderScanHistory(
        {
          title: "Synthetic saved finding",
          severity: { level: "high" },
          rootCause: {
            summary: "Synthetic modern root summary",
            code: "synthetic_modern_control();",
          },
          root_cause: { code: "synthetic_legacy_control();" },
          codeEvidence: catalog
            ? [
                {
                  label: "Existing catalog",
                  code: "synthetic_modern_control();",
                },
              ]
            : [],
          attackPath: {
            reachability: {
              summary: "Supported reachability",
              source: "Synthetic reachability input",
              sink: "Synthetic authorized filesystem sink",
            },
          },
        },
        "finding",
        { color: false },
      );
      for (const detail of [
        "Synthetic modern root summary",
        "synthetic_modern_control();",
        "synthetic_legacy_control();",
        "Synthetic reachability input",
        "Synthetic authorized filesystem sink",
      ]) {
        expect(output).toContain(detail);
      }
      expect(output.split("synthetic_modern_control();")).toHaveLength(2);
    },
  );

  test("keeps supported attack-path caveats", () => {
    const output = renderScanHistory(
      {
        title: "Synthetic saved finding",
        severity: { level: "high" },
        attackPath: {
          assumptions: ["Synthetic attacker can submit archives"],
          controls: ["Existing path authorization check"],
          blindspots: ["Unreviewed synthetic deployment setting"],
        },
      },
      "finding",
      { color: false },
    );
    for (const detail of [
      "Synthetic attacker can submit archives",
      "Existing path authorization check",
      "Unreviewed synthetic deployment setting",
    ]) {
      expect(output).toContain(detail);
    }
  });

  test("keeps supported validation outcomes and legacy dataflow details", () => {
    const output = renderScanHistory(
      {
        title: "Synthetic saved finding",
        severity: { level: "high" },
        validation: {
          status: "verified",
          disposition: "confirmed",
          result: "reachable",
        },
        attackPath: {
          data_flow: {
            source: "Synthetic upload handler",
            sink: "Synthetic filesystem write",
            outcome: "Writes outside the output path",
          },
        },
      },
      "finding",
      { color: false },
    );
    for (const detail of [
      "verified",
      "confirmed",
      "reachable",
      "Synthetic upload handler",
      "Synthetic filesystem write",
      "Writes outside the output path",
    ]) {
      expect(output).toContain(detail);
    }
  });

  test.each([false, true])(
    "keeps both evidence catalogs when modern evidence is %s",
    (modern) => {
      const output = renderScanHistory(
        {
          title: "Synthetic saved finding",
          severity: { level: "high" },
          codeEvidence: modern
            ? [
                {
                  id: "modern",
                  label: "Modern source",
                  code: "modern_source();",
                },
              ]
            : [],
          code_evidence: [
            { id: "legacy", label: "Legacy source", code: "legacy_source();" },
          ],
        },
        "finding",
        { color: false },
      );
      expect(output).toContain("Legacy source");
      expect(output).toContain("legacy_source();");
      if (modern) {
        expect(output).toContain("Modern source");
        expect(output).toContain("modern_source();");
      }
    },
  );

  test.each([
    [
      "spaced Chinese",
      "权限校验失败 导致任意用户读取其他用户的私人扫描结果",
      ["权限校验失败", "导致任意用户读取其他用户的私人扫", "描结果"],
    ],
    [
      "unspaced Chinese",
      "中文".repeat(20),
      ["中文".repeat(8), "中文".repeat(8), "中文".repeat(4)],
    ],
    ["mixed text", "a".repeat(31) + "中文", ["a".repeat(31), "中文"]],
    [
      "combining marks",
      "e\u0301".repeat(33),
      ["e\u0301".repeat(32), "e\u0301"],
    ],
    ["joined emoji", "👩‍💻".repeat(17), ["👩‍💻".repeat(16), "👩‍💻"]],
    ["long ASCII word", "a".repeat(65), ["a".repeat(32), "a".repeat(32), "a"]],
    [
      "English words",
      "A finding title with several words that should wrap",
      ["A finding title with several", "words that should wrap"],
    ],
  ] as const)(
    "wraps %s titles at terminal columns",
    (_name, title, expected) => {
      for (const color of [false, true]) {
        const output = renderScanHistory(
          {
            repository: "/repo",
            findings: [{ title, severity: "high", path: "source.ts" }],
          },
          "findings",
          { columns: 48, color },
        );
        const lines = stripVTControlCharacters(output).split("\n");
        const start = lines.findIndex((line) => line.startsWith("    HIGH"));
        const end = lines.indexOf("              source.ts");
        expect(lines.slice(start, end)).toEqual(
          expected.map(
            (line, index) =>
              `${index === 0 ? "    HIGH      " : "              "}${line}`,
          ),
        );
        if (color) expect(output).toContain("\u001B[31mHIGH    \u001B[0m");
      }
    },
  );

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
      /Seen in latest scan[\s\S]*Current finding[\s\S]*Not confirmed in latest scan[\s\S]*Earlier finding/,
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
      updatedAt: "2026-01-01T12:00:00Z",
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
      `UPDATED  ${scan.updatedAt}`,
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
          relatedPairs: 2,
          uncertainPairs: 1,
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
      "2 related pairs recorded",
      "1 uncertain pair",
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

  test.each([undefined, 25])(
    "offers recovery from an empty findings page with total %s",
    (total) => {
      const output = renderScanHistory(
        {
          findings: [],
          offset: 200,
          ...(total === undefined ? {} : { scanId: "saved-scan", total }),
        },
        "findings",
        { color: false, status: "closed" },
      );

      expect(output).toContain("offset 200");
      expect(output).toContain("--offset 0");
      expect(output).toContain("Status: closed");
      expect(output).not.toContain("No saved findings");
    },
  );

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

  test("keeps linked occurrence identifiers available for inspection", () => {
    const output = renderScanHistory(
      {
        occurrenceId: "current-occurrence",
        scanId: "current-scan",
        severity: { level: "high" },
        title: "Missing authorization",
        matches: [
          {
            occurrenceId: "earlier-occurrence",
            scanId: "earlier-scan",
            title: "Earlier authorization finding",
            reason: "Same root cause.",
          },
        ],
      },
      "finding",
      { color: false },
    );
    expect(output).toContain("ID current-occurrence");
    expect(output).toContain("ID earlier-occurrence");
    expect(output).toContain("Earlier authorization finding");
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
    const finding = {
      occurrenceId: "saved-occurrence",
      scanId: "saved-scan",
      targetPath: "/demo/repository",
      severity: { level: "high" },
      title: "Missing authorization",
      locations: [{ path: "routes/login.ts", startLine: 34 }],
      triage: { closeReason: reason, status: "closed" },
    };
    for (const command of ["finding", "show"] as const) {
      const output = renderScanHistory(
        command === "finding"
          ? finding
          : {
              scanId: finding.scanId,
              targetPath: finding.targetPath,
              mode: "standard",
              progress: { status: "complete" },
              findings: [finding],
            },
        command,
        { color: false },
      );

      expect(output).toContain(status);
      expect(output).toContain("ID saved-occurrence");
      expect(output).toContain(
        command === "finding"
          ? `Reason: ${label}`
          : "findings show OCCURRENCE_ID",
      );
      expect(output).not.toContain(reason);
      expect(output).not.toContain("CLOSED");
    }
  });

  test("renders related findings separately in scan details and comparisons", () => {
    const relation = {
      beforeTitle: "Archive writer boundary",
      afterTitle: "Archive reader boundary",
      title: "Archive reader boundary",
      scanId: "12345678-abcd-4567-abcd-1234567890ab",
      reason: "The two controls require independent corrections.",
    };
    const comparison = renderScanHistory(
      {
        beforeScanId: "before",
        afterScanId: "after",
        coverage: { afterCompleteness: "complete" },
        summary: {},
        findings: [],
        related: [relation],
      },
      "compare",
      { color: false },
    );
    for (const value of [
      "Related findings, kept separate",
      relation.beforeTitle,
      relation.afterTitle,
      relation.reason,
    ]) {
      expect(comparison).toContain(value);
    }

    const scan = {
      scanId: "current-scan",
      targetPath: "/synthetic/repository",
      progress: { status: "complete" },
      findings: [
        { title: relation.beforeTitle, severity: "high", related: [relation] },
      ],
    };
    const compact = renderScanHistory(scan, "show", { color: false });
    expect(compact).toContain("1 related finding, kept separate");
    expect(compact).not.toContain(relation.reason);
    const expanded = renderScanHistory(scan, "show", {
      color: false,
      showLinkedFindings: true,
    });
    for (const value of [
      relation.afterTitle,
      relation.scanId.slice(0, 8),
      relation.reason,
    ]) {
      expect(expanded).toContain(value);
    }
  });
});

const validationEvidenceCases: JsonObject[] = [
  { evidence: "Synthetic validation proof" },
  { evidence: ["Synthetic validation proof"] },
];
test.each(validationEvidenceCases)(
  "renders accepted scalar and array validation evidence: %j",
  (validation) => {
    const text = renderScanHistory(
      {
        title: "Synthetic saved finding",
        severity: { level: "high" },
        validation,
      },
      "finding",
      { color: false },
    );
    expect(text).toContain("Synthetic validation proof");
    expect(text).toContain("VALIDATION");
  },
);

test("renders accepted attack-path steps without a summary", () => {
  const text = renderScanHistory(
    {
      title: "Synthetic saved finding",
      severity: { level: "high" },
      attackPath: {
        steps: ["Upload a synthetic archive.", "Trigger extraction."],
      },
    },
    "finding",
    { color: false },
  );
  expect(text).toContain("Upload a synthetic archive.");
  expect(text).toContain("Trigger extraction.");
  expect(text).toContain("ATTACK PATH");
});
