import { describe, expect, test } from "bun:test";
import { normalizeArmorCodeFindings } from "../src/armorcode-findings.js";
import { localReportFixture } from "./external-findings-local-helpers.js";

describe("ArmorCode finding imports", () => {
  const repositoryUrl = "https://github.com/example/project";
  const source = { provider: "armorcode", sourceKey: "org/app" } as const;

  test("uses a declared source for SAST rows without changing the stored source record", async () => {
    await using fixture = await localReportFixture("armorcode.json", source, {
      remote: repositoryUrl,
    });
    const row = { id: 1, title: "Unchecked index", scanType: ["SAST"] };
    await fixture.writeJson({ data: { findings: [row] } });
    const { preview } = await fixture.prepare({
      sourceRepositoryUrl: repositoryUrl,
    });
    expect(preview.excluded).toEqual([]);
    expect(preview.findings[0]?.evidence.details).toMatchObject({
      kind: "sast",
      repository: { url: repositoryUrl },
    });
    expect(preview.findings[0]?.evidence.source_data).toEqual(row);
    await expect(
      fixture.prepare({
        sourceRepositoryUrl: "https://github.com/example/other",
      }),
    ).rejects.toThrow(/does not match/iu);
  });

  test("rejects a mixed report when a generic row belongs to another checkout", async () => {
    await using fixture = await localReportFixture("armorcode.json", source, {
      remote: repositoryUrl,
    });
    const report = {
      data: {
        findings: [
          {
            id: 1,
            title: "Unchecked index",
            scanType: ["SAST"],
            repositoryUrl,
          },
          {
            id: 2,
            title: "Vulnerable package",
            scanType: ["SCA"],
            repository: { url: "https://github.com/example/other" },
          },
        ],
      },
    };
    await fixture.writeJson(report);
    await expect(fixture.prepare()).rejects.toThrow(
      /single source repository/iu,
    );
    await expect(
      fixture.prepareNormalized(normalizeArmorCodeFindings(report, "local")),
    ).rejects.toThrow(/single source repository/iu);
  });

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

  test("normalizes repository file paths, empty location arrays, and CVE values without excluding valid rows", () => {
    const result = normalizeArmorCodeFindings({
      data: {
        findings: [
          {
            id: 101,
            title: "Windows SAST path and empty locations envelope",
            severity: "MEDIUM",
            locations: [],
            filePath: "src\\auth\\query.ts",
            lineNumber: 27,
            cve: "CVE-2026-0101",
          },
          {
            id: 102,
            title: "Container runtime configuration",
            severity: "HIGH",
            locations: [
              { path: "/etc/nginx/nginx.conf", line: 14 },
              { path: "C:\\app\\web.config", line: 9 },
              { path: "https://app.example/login", line: 1 },
              { path: "../shared/base.yaml", line: 3 },
              { path: "deploy/", line: 1 },
              { path: "./deploy/nginx.yaml", line: 8 },
            ],
          },
          {
            id: 103,
            title: "Blank and duplicate advisory entries",
            severity: "LOW",
            location: { file: "package.json", line: 4 },
            cve: ["", "   ", "CVE-2026-0102", "CVE-2026-0102"],
          },
        ],
      },
    });

    expect(result.excluded).toEqual([]);
    expect(result.findings).toHaveLength(3);
    expect(result.findings[0]).toMatchObject({
      source_finding_id: "101",
      evidence: {
        advisory_ids: ["CVE-2026-0101"],
        locations: [{ path: "src/auth/query.ts", line: 27 }],
        source_data: {
          locations: [],
          filePath: "src\\auth\\query.ts",
        },
      },
    });
    expect(result.findings[1]).toMatchObject({
      source_finding_id: "102",
      evidence: {
        locations: [{ path: "deploy/nginx.yaml", line: 8 }],
      },
    });
    expect(result.findings[2]).toMatchObject({
      source_finding_id: "103",
      evidence: {
        advisory_ids: ["CVE-2026-0102"],
        locations: [{ path: "package.json", line: 4 }],
      },
    });
  });

  test("falls back to location or filePath when locations contain only non-repository paths", () => {
    const result = normalizeArmorCodeFindings({
      data: {
        findings: [
          {
            id: 201,
            title: "Service configuration exposure",
            severity: "MEDIUM",
            locations: [{ path: "/etc/service.conf" }],
            filePath: "src/service.ts",
            lineNumber: 11,
          },
          {
            id: 202,
            title: "Fallback through non-repository location object",
            severity: "LOW",
            locations: [{ path: "/var/log/app.log" }],
            location: { path: "https://app.example/status" },
            filePath: "src/status.ts",
            lineNumber: 5,
          },
          {
            id: 203,
            title:
              "Fallback to location object when locations are non-repository",
            severity: "HIGH",
            locations: [{ path: "/etc/service.conf" }],
            location: { filePath: "src/handler.ts", startLine: 19 },
          },
        ],
      },
    });

    expect(result.excluded).toEqual([]);
    expect(result.findings).toHaveLength(3);
    expect(result.findings[0]).toMatchObject({
      source_finding_id: "201",
      evidence: {
        locations: [{ path: "src/service.ts", line: 11 }],
        source_data: {
          locations: [{ path: "/etc/service.conf" }],
          filePath: "src/service.ts",
          lineNumber: 11,
        },
      },
    });
    expect(result.findings[1]).toMatchObject({
      source_finding_id: "202",
      evidence: {
        locations: [{ path: "src/status.ts", line: 5 }],
      },
    });
    expect(result.findings[2]).toMatchObject({
      source_finding_id: "203",
      evidence: {
        locations: [{ path: "src/handler.ts", line: 19 }],
      },
    });
  });
});
