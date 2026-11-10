import { expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import {
  normalizeContinuumFindings,
  normalizePreviousContinuumFindings,
} from "../src/continuum-findings.js";
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
    source_updated_at: Date.parse(first.statusUpdatedAt) / 1000,
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
          source_updated_at: Date.parse(detail.statusUpdatedAt) / 1000,
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

test("a selected array retains the same evidence as separate GetCodeFinding responses", () => {
  const first = continuumDetail();
  const second = {
    ...first,
    ...continuumSummary("two"),
    statusUpdatedAt: 1_767_312_123.5,
  };
  const selected = normalize([first, second]);
  expect(selected.excluded).toEqual([]);
  expect(selected.findings).toEqual([
    ...normalize(first).findings,
    ...normalize(second).findings,
  ]);
  expect(selected.findings[1]!.evidence.source_updated_at).toBe(1_767_312_123);
  expect(() => normalize([first, continuumSummary("two", "other")])).toThrow(
    /same environment/,
  );
  expect(normalize([first, first]).excluded).toHaveLength(2);
});

test("preserves dependency and posture evidence without classifying it as a code flaw", () => {
  const summary = continuumSummary();
  const pkg = {
    name: "example",
    version: "1.0.0",
    packageManager: "npm",
    fixedInVersion: "1.0.1",
  };
  const dependency = {
    ...summary,
    ocsfClass: "VULNERABILITY_FINDING",
    cveId: "CVE-2099-0001",
    affectedPackages: [pkg],
    vulnerabilities: [
      {
        affectedPackages: [
          pkg,
          { name: "other", packageManager: "npm", version: "^2.0.0" },
        ],
      },
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
  expect(normalize(dependency).findings[0]!.evidence).toMatchObject({
    advisory_ids: [dependency.cveId],
    packages: [
      {
        name: "example",
        ecosystem: "npm",
        installed_version: "1.0.0",
        fixed_versions: ["1.0.1"],
      },
      {
        name: "other",
        ecosystem: "npm",
        installed_version: null,
        fixed_versions: [],
      },
    ],
  });
});

test("reads the weakness Continuum names in subCategory for its own findings", () => {
  const { cweIds: _, vulnerabilities: __, ...detail } = continuumDetail();
  const native = {
    ...detail,
    type: "CONTINUUM_CODE_VULN",
    category: "CWE-137: Data Neutralization Issues",
    subCategory: "CWE-89: Improper Neutralization of Special Elements",
    vulnerabilities: [],
  };
  const weaknesses = (finding: unknown) =>
    normalize(finding).findings[0]!.evidence.details?.weakness_ids;

  expect(weaknesses(native)).toEqual(["CWE-89"]);
  // Explicit IDs win, and other category text is not a weakness.
  expect(weaknesses({ ...native, cweIds: ["CWE-20"] })).toEqual(["CWE-20"]);
  expect(weaknesses({ ...native, subCategory: "Injection" })).toEqual([]);
  expect(
    normalizePreviousContinuumFindings(native, continuumRepository).findings[0]!
      .evidence.details?.weakness_ids,
  ).toEqual([]);
});

test("an inferred weakness cannot exclude a Cloud finding at its evidence limit", () => {
  const { cweIds: _, ...detail } = continuumDetail();
  const finding = {
    ...detail,
    type: "CONTINUUM_CODE_VULN",
    subCategory: "CWE-89: SQL Injection",
    vulnerabilities: [],
    stepsToReproduce: Array<string>(31).fill("x".repeat(8192)).concat(""),
  };
  const original = normalizePreviousContinuumFindings(
    finding,
    continuumRepository,
  ).findings[0]!.evidence;
  const bytes = Buffer.byteLength(JSON.stringify(original));
  finding.stepsToReproduce[31] = "x".repeat(256 * 1024 - bytes);
  const result = normalize(finding);
  expect(result.excluded).toEqual([]);
  expect(result.findings[0]!.evidence).toMatchObject({
    details: { weakness_ids: [] },
    source_data: { finding },
  });
  // Leave room for the status timestamp, but not both it and the inferred CWE.
  finding.stepsToReproduce[31] = finding.stepsToReproduce[31]!.slice(10);
  expect(normalize(finding).findings[0]!.evidence).toMatchObject({
    source_updated_at: Date.parse(finding.statusUpdatedAt) / 1000,
    details: { weakness_ids: [] },
  });
});

test("keeps package-manager selectors in the native finding", () => {
  const finding = {
    ...continuumSummary(),
    affectedPackages: [
      { name: "example-java", packageManager: "Gradle", version: "1.+" },
      { name: "example-js", packageManager: "pnpm", version: "1" },
    ],
  };
  const [row] = normalize(finding).findings;
  expect(row!.evidence.packages?.map((p) => p.installed_version)).toEqual([
    null,
    null,
  ]);
  expect(row!.evidence.source_data?.["finding"]).toEqual(finding);
});

test("retains status timestamps without inventing an update time from other AWS fields", () => {
  const summary = continuumSummary();
  for (const statusUpdatedAt of [undefined, "unknown", "2026-01-02T00:01:00"]) {
    const { findings, excluded } = normalize({ ...summary, statusUpdatedAt });
    expect(excluded).toEqual([]);
    expect(findings[0]!.evidence.source_updated_at).toBeNull();
  }
  const offset = normalize({
    ...summary,
    statusUpdatedAt: "2026-01-02T01:01:00.999+01:00",
  });
  expect(offset.findings[0]!.evidence.source_updated_at).toBe(
    Date.parse(summary.statusUpdatedAt) / 1000,
  );
});

test("Cloud projects packages within its limits and retains all AWS package evidence", () => {
  const valid = Array.from({ length: 101 }, (_, i) => ({
    name: `package-${i}`,
  }));
  const finding = {
    ...continuumSummary(),
    affectedPackages: [{ name: "界".repeat(200) }, ...valid],
  };
  const cloud = normalize(finding);
  expect(cloud.excluded).toEqual([]);
  expect(cloud.findings[0]!.evidence.packages?.map((pkg) => pkg.name)).toEqual(
    valid.slice(0, 100).map((pkg) => pkg.name),
  );
  expect(cloud.findings[0]!.evidence.source_data?.["finding"]).toEqual(finding);
  const local = normalizeContinuumFindings(
    finding,
    continuumRepository,
    "local",
  );
  expect(local.findings[0]!.evidence.packages).toHaveLength(102);
});

test("a Cloud finding that fits with native packages alone still imports", () => {
  const finding = {
    ...continuumSummary(),
    affectedPackages: [
      { name: "example", version: "1.0.0", packageManager: "npm" },
    ],
    padding: "",
  };
  const previous = normalizePreviousContinuumFindings(
    finding,
    continuumRepository,
  );
  const bytes = Buffer.byteLength(
    JSON.stringify(previous.findings[0]!.evidence),
  );
  finding.padding = "x".repeat(256 * 1024 - bytes);
  const result = normalize(finding);
  expect(result.excluded).toEqual([]);
  expect(result.findings[0]!.evidence.packages).toEqual([]);
  expect(result.findings[0]!.evidence.source_data?.["finding"]).toEqual(
    finding,
  );
  finding.padding = finding.padding.slice(10);
  const withTimestamp = normalize(finding);
  expect(withTimestamp.findings[0]!.evidence).toMatchObject({
    packages: [],
    source_updated_at: Date.parse(finding.statusUpdatedAt) / 1000,
    source_data: { finding },
  });
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
