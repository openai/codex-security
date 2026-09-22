import { describe, expect, test } from "bun:test";
import type { JsonObject } from "../src/config.js";
import type {
  DependencyFindingAssessment,
  DependencyReport,
  ImportedDependencyFinding,
} from "../src/dependency-findings.js";
import { renderDependencyFindings } from "../src/dependency-findings-renderer.js";

const report: DependencyReport = {
  id: "report-example-1",
  targetPath: "/example/application",
  targetRevision: "abcdef1234567890",
  reportName: "findings.csv",
  vendor: "endor",
  createdAt: "2026-09-01T12:00:00Z",
  findingCount: 2437,
  warnings: ["The report does not record the repository revision."],
  reportDigest: "report-digest",
};

const assessment: DependencyFindingAssessment = {
  findingId: "finding-example-1",
  assessmentId: "assessment-example-1",
  verdict: "inconclusive",
  summary:
    "The declared package is affected; its application use remains unclear.",
  applicability: "The deployed entry point was unavailable for inspection.",
  versionBasis: "declared",
  packageVersion: "2.0.0",
  targetRevision: report.targetRevision,
  createdAt: "2026-09-01T13:00:00Z",
  unknowns: ["Whether user input reaches the parser."],
  limitations: ["No deployed artifact was available."],
  resolution: null,
  codeEvidence: [],
};

const finding: ImportedDependencyFinding = {
  id: "finding-example-1",
  reportId: report.id,
  title: "Untrusted parser input can exhaust memory",
  sourceId: "vendor-finding-1",
  originalSeverity: "FINDING_LEVEL_CRITICAL",
  kind: "vulnerability",
  package: { name: "example-parser", version: "1.0.0", ecosystem: "npm" },
  advisoryIds: ["EXAMPLE-1"],
  dependencyPaths: [],
  locations: [],
  fix: null,
  evidence: "RAW_VENDOR_PAYLOAD",
  inputWarnings: [],
  assessment: null,
};

const json = (value: unknown): JsonObject => value as JsonObject;

describe("dependency findings renderer", () => {
  test("import displays repository context, warnings, count, and the next command", () => {
    const output = renderDependencyFindings(json({ report }), "import", {
      color: false,
    });
    for (const value of [
      report.targetPath,
      report.targetRevision,
      report.reportName,
      report.warnings[0]!,
      "2,437",
      `codex-security dependency-findings show ${report.id}`,
    ])
      expect(output).toContain(value);
    expect(output).not.toContain(report.reportDigest);
    expect(output).not.toContain("\u001B[");
  });

  test("show separates scanner severity from assessment and preserves pagination filters", () => {
    for (const columns of [48, 96]) {
      for (const originalSeverity of ["critical", "FINDING_LEVEL_CRITICAL"]) {
        const entry: ImportedDependencyFinding = {
          ...finding,
          originalSeverity,
          assessment: { ...assessment, verdict: "not_applicable" },
        };
        const output = renderDependencyFindings(
          json({ report, findings: [entry], total: 30, nextOffset: 11 }),
          "show",
          {
            color: false,
            columns,
            offset: 10,
            limit: 1,
            verdict: "not_applicable",
          },
        );
        expect(output).toContain("11–11 of 30");
        expect(output).toMatch(/SCANNER SEVERITY|Scanner severity/);
        expect(output).toMatch(/APPLICATION IMPACT|Application impact/);
        expect(output).not.toContain("Not assessed");
        for (const value of [
          "Critical",
          "Not applicable",
          "example-parser@1.0.0",
          finding.id,
        ]) {
          expect(output).toContain(value);
        }
        expect(output).not.toContain("FINDING_LEVEL_CRITICAL");
        expect(entry.originalSeverity).toBe(originalSeverity);
        expect(output).toContain(
          `show ${report.id} --offset 11 --limit 1 --verdict not_applicable`,
        );
        expect(output.replace(/\s+/g, " ")).toContain(assessment.summary);
        expect(output).not.toContain("RAW_VENDOR_PAYLOAD");
        expect(output).not.toContain(assessment.applicability);
      }
    }
  });

  test("assess shows current results, unresolved gaps, and the version actually assessed", () => {
    const output = renderDependencyFindings(
      json({
        report,
        findings: [
          {
            ...finding,
            assessment: { ...assessment, verdict: "affects_application" },
          },
        ],
        assessment: { id: assessment.assessmentId, state: "complete" },
        results: [assessment],
      }),
      "assess",
      { color: false },
    );
    for (const value of [
      assessment.summary,
      assessment.applicability,
      ...assessment.unknowns,
      ...assessment.limitations!,
    ]) {
      expect(output).toContain(value);
    }
    expect(output).toContain("1 inconclusive");
    expect(output).toContain("0 affects application");
    expect(output).toContain("Inconclusive");
    expect(output).toContain("example-parser@1.0.0");
    expect(output).toContain("Assessed version: 2.0.0 (declared)");
    expect(output).toContain(assessment.targetRevision);
    expect(output).toContain(finding.id);
    expect(output).not.toContain("RAW_VENDOR_PAYLOAD");
  });

  test("list keeps reports and repositories identifiable and handles an empty page", () => {
    const otherReport = {
      ...report,
      id: "report-example-2",
      targetPath: "/example/another-application",
    };
    const output = renderDependencyFindings(
      json({ reports: [report, otherReport], nextOffset: 2 }),
      "list",
      { color: false },
    );
    for (const entry of [report, otherReport]) {
      expect(output).toContain(entry.id);
      expect(output).toContain(entry.targetPath);
    }
    expect(output).toContain("--offset 2");
    expect(output).toContain(
      "codex-security dependency-findings show REPORT_ID",
    );
    const empty = renderDependencyFindings(
      json({ reports: [], nextOffset: null }),
      "list",
      { color: false },
    );
    expect(empty).toContain("import REPORT_FILE --vendor VENDOR");
    const pastEnd = renderDependencyFindings(
      json({ reports: [], nextOffset: null }),
      "list",
      { color: false, offset: 2 },
    );
    expect(pastEnd).not.toContain("import REPORT_FILE");
  });
});
