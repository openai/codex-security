import { describe, expect, test } from "bun:test";
import { normalizeArmorCodeFindings } from "../src/armorcode-findings.js";

describe("ArmorCode finding imports", () => {
  test("normalizes findings and retains the source records", () => {
    const result = normalizeArmorCodeFindings({
      findings: [
        {
          findingId: "AC-42",
          name: "Unsafe query construction",
          severity: "HIGH",
          description: "Untrusted input reaches a query.",
          location: { filePath: "src/query.ts", startLine: 18 },
          status: "open",
        },
      ],
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      source_finding_id: "AC-42",
      evidence: {
        title: "Unsafe query construction",
        severity: "high",
        locations: [{ path: "src/query.ts", line: 18 }],
        source_data: { status: "open" },
      },
    });
  });

  test("excludes colliding source IDs instead of selecting one", () => {
    const result = normalizeArmorCodeFindings(
      [
        { id: "same", title: "First" },
        { id: "same", title: "Second" },
      ],
      "local",
    );

    expect(result.findings).toHaveLength(0);
    expect(result.excluded).toHaveLength(2);
  });

  test("normalizes the ArmorCode findings API response envelope", () => {
    const result = normalizeArmorCodeFindings({
      data: {
        findings: [
          {
            id: 1097722461,
            title: "Container(s) run as root",
            severity: "CRITICAL",
            description: "Container is configured to run as root.",
            mitigation: "Set runAsUser to a non-zero ID.",
            findingUrl: "https://armorcode.example/findings/1097722461",
            filePath: "deploy/workload.yaml",
            lineNumber: 12,
            cve: [],
            status: "OPEN",
            lastUpdated: 1792740664000,
          },
        ],
      },
      success: true,
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      source_finding_id: "1097722461",
      evidence: {
        title: "Container(s) run as root",
        severity: "critical",
        description:
          "Container is configured to run as root.\n\nMitigation: Set runAsUser to a non-zero ID.",
        url: "https://armorcode.example/findings/1097722461",
        locations: [{ path: "deploy/workload.yaml", line: 12 }],
        source_updated_at: 1792740664,
        source_data: { status: "OPEN" },
      },
    });
  });

  test("projects typed SAST metadata and keeps both scanner links", () => {
    const result = normalizeArmorCodeFindings({
      data: {
        findings: [
          {
            id: 42,
            title: "Buffer index access",
            repositoryUrl: "https://github.com/example/repository",
            severity: "HIGH",
            description: "Query: Buffer index access",
            mitigation: "Validate the buffer index.",
            source: "Checkmarx",
            status: "OPEN",
            toolStatusOriginal: "TO VERIFY",
            scanType: ["SAST"],
            ruleId: ["CX-101"],
            cwe: "CWE-129",
            url: "https://scanner.example/findings/42",
            findingUrl: "https://armorcode.example/findings/42",
          },
        ],
      },
    });

    expect(result.findings[0]).toMatchObject({
      source_finding_id: "42",
      evidence: {
        url: "https://scanner.example/findings/42",
        description: "Query: Buffer index access",
        details: {
          kind: "sast",
          repository: { url: "https://github.com/example/repository" },
          source_status: "OPEN",
          scanner_origin: "Checkmarx",
          scanner_verdict: "TO VERIFY",
          rule: { id: "CX-101" },
          weakness_ids: ["CWE-129"],
          remediation_instructions: "Validate the buffer index.",
        },
        source_data: { findingUrl: "https://armorcode.example/findings/42" },
      },
    });
  });
});
