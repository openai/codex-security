import { expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import { normalizeContinuumFindings } from "../src/continuum-findings.js";
import {
  createAndReplayFinding,
  localReportFixture,
  updateStoredFinding,
} from "./external-findings-local-helpers.js";
import {
  continuumDetail,
  continuumRepository,
  continuumSummary,
} from "./support/continuum-import-fixtures.js";

const normalize = (input: unknown) =>
  normalizeContinuumFindings(input, continuumRepository);

test("a Continuum list and a detailed finding share the AWS occurrence ARN", () => {
  const first = continuumSummary();
  const second = continuumSummary("two");
  const list = normalize({ items: [first, second] });
  expect(list.excluded).toEqual([]);
  expect(
    list.findings.map(({ source_finding_id }) => source_finding_id),
  ).toEqual([first.findingArn, second.findingArn]);
  expect(list.findings[0]!.evidence).toMatchObject({
    title: first.title,
    severity: "critical",
    locations: [{ path: first.filePath, line: null }],
    source_data: { sourceRepositoryUrl: continuumRepository, finding: first },
  });

  expect(list.findings[0]!.evidence.details).toBeUndefined();

  const detail = continuumDetail();
  expect(normalize(detail)).toMatchObject({
    read: 1,
    excluded: [],
    findings: [
      {
        source_finding_id: first.findingArn,
        evidence: {
          severity: "critical",
          description: detail.detailedDescription,
          locations: [
            { path: first.filePath, line: 3 },
            { path: "src/other.ts", line: 12 },
          ],
          details: {
            repository: { url: continuumRepository },
            source_status: "CONFIRMED",
            scanner_verdict: "TRUE_POSITIVE",
            weakness_ids: ["CWE-20"],
            remediation_instructions: detail.mitigation,
            code: { end_line: 5, snippet: detail.vulnerableCode },
          },
          source_data: { finding: detail },
        },
      },
    ],
  });
});

test("preserves dependency and posture evidence without classifying it as a code flaw", () => {
  const summary = continuumSummary();
  const dependency = {
    ...summary,
    ocsfClass: "VULNERABILITY_FINDING",
    cveId: "CVE-2099-0001",
    affectedPackages: [
      { name: "example", version: "1.0.0", fixedInVersion: "1.0.1" },
    ],
  };
  const posture = {
    ...summary,
    ocsfClass: "APPLICATION_SECURITY_POSTURE_FINDING",
    posture: { status: "Failed", control: "Example control" },
  };
  for (const finding of [dependency, posture]) {
    const result = normalize(finding);
    expect(result.excluded).toEqual([]);
    const evidence = result.findings[0]!.evidence;
    expect(evidence.details).toBeUndefined();
    expect(evidence.source_data?.["finding"]).toEqual(finding);
  }
  expect(normalize(dependency).findings[0]!.evidence.advisory_ids).toEqual([
    dependency.cveId,
  ]);
});

test("unsafe paths stay in native evidence without becoming checkout locations", () => {
  const detail = {
    ...continuumDetail(),
    filePath: "../other/src/example.ts",
    vulnerabilities: [
      { locations: [{ filePath: "C:\\other\\example.ts", startLine: 2 }] },
    ],
  };
  expect(normalize(detail)).toMatchObject({
    excluded: [],
    findings: [
      { evidence: { locations: [], source_data: { finding: detail } } },
    ],
  });
});

test("distinguishes an empty export from incomplete, mixed-environment and malformed reports", () => {
  expect(normalize({ items: [] })).toMatchObject({
    read: 0,
    findings: [],
    excluded: [],
  });
  for (const report of [
    { items: [continuumSummary()], nextToken: "page2" },
    { items: [continuumSummary()], NextToken: "page2" },
    { items: [continuumSummary(), continuumSummary("two", "other")] },
    { findings: [] },
  ])
    expect(() => normalize(report)).toThrow();

  const malformed = { ...continuumSummary("two"), environmentId: "wrong" };
  const result = normalize({ items: [continuumSummary(), malformed] });
  expect(result.findings).toHaveLength(1);
  expect(result.excluded).toMatchObject([{ position: 2 }]);
});

test("local replay enriches one unassessed occurrence when the detailed record arrives", async () => {
  const options = {
    provider: "continuum" as const,
    sourceKey: "continuum/example/project",
    sourceRepositoryUrl: continuumRepository,
  };
  const fixture = await localReportFixture("findings.json", options, {
    remote: continuumRepository,
  });
  try {
    await fixture.writeJson({ items: [continuumSummary()] });
    const previous = await createAndReplayFinding(fixture);
    await writeFile(fixture.file, gzipSync(JSON.stringify(continuumDetail())));
    const updated = await updateStoredFinding(fixture, previous);
    const normalized = normalize(continuumDetail());
    normalized.findings[0]!.evidence.details!.repository!.url =
      "https://github.com/example/other";
    await expect(
      prepareNormalizedLocalImport(
        normalized,
        { ...options, repository: fixture.repository },
        { environment: fixture.environment },
      ),
    ).rejects.toThrow(/repository|remote/i);
    expect(updated.provider).toBe("continuum");
    expect(updated.evidence.details?.scanner_verdict).toBe("TRUE_POSITIVE");
    await expect(
      fixture.prepare({
        sourceRepositoryUrl: "https://github.com/example/other",
      }),
    ).rejects.toThrow(/repository|remote/i);
  } finally {
    await fixture.dispose();
  }
});
