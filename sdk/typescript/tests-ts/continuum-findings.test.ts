import { expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import { normalizeContinuumFindings } from "../src/continuum-findings.js";
import { projectStoredFinding } from "../src/stored-finding-projection.js";
import {
  createAndReplayFinding,
  localReportFixture,
  updateStoredFinding,
} from "./external-findings-local-helpers.js";
import {
  continuumDetail,
  continuumEvidenceArtifact,
  continuumIssueExport,
  continuumRepository,
  continuumSummary,
  continuumValidationArtifact,
  patchArtifact,
} from "./support/continuum-import-fixtures.js";

const normalize = (input: unknown) =>
  normalizeContinuumFindings(input, continuumRepository);

test("imports a Continuum issue by ARN with locations from every linked finding", () => {
  const report = continuumIssueExport();
  const { issue } = report.issues[0]!;
  expect(normalize(report)).toMatchObject({
    read: 1,
    excluded: [],
    findings: [
      {
        source_finding_id: issue.issueArn,
        evidence: {
          title: issue.name,
          severity: "high",
          description: "Example synopsis\n\nExample severity reasoning",
          locations: [
            { path: "src/example.ts", line: 3 },
            { path: "src/other.ts", line: 12 },
            { path: "src/second.ts", line: 20 },
          ],
          source_updated_at: Date.parse(issue.updatedAt) / 1000,
          details: {
            source_status: "COMPLETED",
            remediation_instructions: issue.summary,
            code: { end_line: 5, snippet: "readExample(input)" },
          },
          source_data: {
            issue,
            findings: [
              { findingId: "one" },
              {
                findingId: "two",
                filePath: "src/second.ts",
                lineNumber: 20,
                endLine: 24,
              },
            ],
          },
        },
      },
    ],
  });
});

test("a Continuum issue uses linked mitigation and code from its primary location and retains separate validation", () => {
  const report = continuumIssueExport();
  const row = report.issues[0]!;
  const first = continuumDetail();
  const second = {
    ...row.findings[0]!,
    vulnerableCode: "readOtherExample(input)",
    mitigation: "Check the other example.",
    validation: {
      verdict: "FALSE_POSITIVE",
      rationale: "Other example evidence.",
    },
  };
  const issue = { ...row.issue, summary: undefined };
  const linked = {
    ...first,
    lineNumber: undefined,
    vulnerabilities: [
      {
        code: "readNestedExample(input)",
        locations: [{ filePath: "src/nested.ts", startLine: 7, endLine: 9 }],
      },
    ],
  };
  const input = { ...report, issues: [{ issue, findings: [second, linked] }] };
  const result = normalize(input);
  expect(result.excluded).toEqual([]);
  expect(result.findings).toHaveLength(1);
  const finding = result.findings[0]!;
  expect(finding.source_finding_id).toBe(issue.issueArn);
  expect(finding.evidence.locations?.[0]).toEqual({
    path: "src/nested.ts",
    line: 7,
  });
  expect(finding.evidence).toMatchObject({
    details: {
      remediation_instructions: first.mitigation,
      code: { end_line: 9, snippet: "readNestedExample(input)" },
    },
    source_data: {
      findings: [
        { findingId: first.findingId, validation: first.validation },
        { findingId: second.findingId, validation: second.validation },
      ],
    },
  });
  expect(finding.evidence.details?.scanner_verdict ?? null).toBeNull();
});

test("oversized Continuum validation preserves the Cloud issue and its structured code evidence", () => {
  const report = continuumIssueExport();
  const row = report.issues[0]!;
  const first = continuumDetail();
  const large = {
    ...first,
    validation: {
      verdict: first.validation.verdict,
      evidence: Array.from({ length: 40 }, () => ({
        file: first.filePath,
        line: first.lineNumber,
        snippet: "x".repeat(8192),
      })),
    },
  };
  const issue = { ...row.issue, summary: undefined };
  const artifact = continuumEvidenceArtifact(issue.issueArn);
  const input = {
    ...report,
    issues: [
      {
        issue,
        findings: [row.findings[0], large],
        evidenceArtifacts: [artifact],
      },
    ],
  };
  const cloud = normalize(input);
  expect(cloud.excluded).toEqual([]);
  expect(cloud.findings).toMatchObject([
    {
      source_finding_id: issue.issueArn,
      evidence: {
        details: {
          remediation_instructions: first.mitigation,
          scanner_verdict: "EXPLOITABLE",
          code: { snippet: first.vulnerableCode },
        },
        source_data: {
          evidence_artifacts: [artifact],
          findings: [
            {
              findingId: first.findingId,
              validation: { verdict: first.validation.verdict },
            },
            { findingId: "two" },
          ],
        },
      },
    },
  ]);
  const local = normalizeContinuumFindings(input, continuumRepository, "local");
  expect(local.findings[0]?.evidence.source_data).toMatchObject({
    findings: [{ validation: large.validation }, { findingId: "two" }],
  });
});

test("Continuum evidence retains finding-scoped signals separately from the issue verdict", () => {
  const report = continuumIssueExport();
  const row = report.issues[0]!;
  const findingEvidence = continuumEvidenceArtifact(
    "one",
    "NOT_EXPLOITABLE",
    "evidence2",
  );
  const issueEvidence = continuumEvidenceArtifact(row.issue.issueId);
  const result = normalize({
    ...report,
    issues: [{ ...row, evidenceArtifacts: [issueEvidence, findingEvidence] }],
  });
  expect(result.excluded).toEqual([]);
  expect(result.findings).toHaveLength(1);
  expect(result.findings[0]?.evidence.details?.scanner_verdict).toBe(
    "EXPLOITABLE",
  );
  expect(
    result.findings[0]?.evidence.source_data?.["evidence_artifacts"],
  ).toEqual([issueEvidence, findingEvidence]);
});

test("Continuum evidence that exceeds the Cloud limit is excluded without dropping signals", () => {
  const report = continuumIssueExport();
  const row = report.issues[0]!;
  const artifact = continuumEvidenceArtifact(row.issue.issueId);
  artifact.body.prevalidationSignals.signals = Array.from(
    { length: 40 },
    () => ({
      subjectRef: row.issue.issueId,
      dimension: "IMPACT_ASSESSMENT",
      conclusion: "x".repeat(8192),
      computed: { impactBand: "LOW" },
    }),
  );
  const input = {
    ...report,
    issues: [{ ...row, evidenceArtifacts: [artifact] }],
  };
  expect(normalize(input)).toMatchObject({
    findings: [],
    excluded: [
      {
        source_finding_id: row.issue.issueArn,
        reason: "Evidence exceeds the Cloud limit of 256 KiB.",
      },
    ],
  });
  const local = normalizeContinuumFindings(input, continuumRepository, "local");
  expect(
    local.findings[0]?.evidence.source_data?.["evidence_artifacts"],
  ).toEqual([artifact]);
});

test("excludes a Continuum issue with missing, duplicate, or foreign linked findings", () => {
  const report = continuumIssueExport();
  const row = report.issues[0]!;
  const [second, first] = row.findings;
  for (const findings of [
    [first],
    [first, first],
    [first, continuumSummary("two", "foreign")],
    [first, second, continuumSummary("three")],
  ]) {
    expect(
      normalize({ ...report, issues: [{ ...row, findings }] }),
    ).toMatchObject({
      findings: [],
      excluded: [{ source_finding_id: row.issue.issueArn }],
    });
  }
});

test("an issue with linked dependency evidence retains its package and line range", () => {
  const report = continuumIssueExport();
  const row = report.issues[0]!;
  const dependency = {
    ...row.findings[0]!,
    cveId: "CVE-2099-0001",
    affectedPackages: [
      { name: "example", packageManager: "npm", version: "1.0.0" },
    ],
  };
  row.issue.findingIds = [dependency.findingId];
  row.findings = [dependency];
  expect(normalize(report)).toMatchObject({
    excluded: [],
    findings: [
      {
        evidence: {
          advisory_ids: ["CVE-2099-0001"],
          packages: [{ name: "example", installed_version: "1.0.0" }],
          locations: [{ path: "src/second.ts", line: 20 }],
          details: { kind: "advisory", code: { end_line: 24 } },
        },
      },
    ],
  });
});

test("local Continuum issue import keeps evidence and reprojects ranges for Cloud publication", async () => {
  const input = continuumIssueExport();
  const small = patchArtifact("smallpatch", "+// café\n");
  const big = patchArtifact("bigpatch", "x".repeat(270_000));
  const report = {
    ...input,
    issues: input.issues.map((row) => ({
      ...row,
      issue: {
        ...row.issue,
        artifacts: [
          continuumEvidenceArtifact(row.issue.issueId),
          continuumValidationArtifact(),
          ...[big, small].map((patch) => ({
            artifactId: patch.artifactId,
            artifactType: "PATCH",
            body: { patch },
          })),
        ],
      },
    })),
  };
  const row = report.issues[0]!;
  const detailed = {
    ...continuumDetail(),
    vulnerabilities: [
      {
        locations: Array.from({ length: 102 }, (_, index) => ({
          filePath: `src/example${index}.ts`,
          startLine: index + 10,
          endLine: index + 11,
        })),
      },
    ],
  };
  row.findings = [row.findings[0]!, detailed];
  await using fixture = await localReportFixture(
    "issues.json",
    {
      provider: "continuum",
      sourceKey: "continuum/example/project",
    },
    { remote: continuumRepository },
  );
  await fixture.writeJson({
    ...report,
    sourceRepositoryUrl: continuumRepository,
  });
  await expect(
    fixture.prepare({
      sourceRepositoryUrl: "https://github.com/example/other",
    }),
  ).rejects.toThrow("Continuum export repository does not match");
  const stored = await createAndReplayFinding(fixture);
  expect(stored.evidence.source_data?.["sourceRepositoryUrl"]).toBe(
    continuumRepository,
  );
  expect(stored.evidence.locations).toHaveLength(104);
  const cloud = projectStoredFinding(stored, []);
  expect(cloud).toEqual(normalize(report));
  expect(cloud.findings[0]?.evidence.locations).toHaveLength(100);
  expect(stored.evidence.source_data?.["patches"]).toEqual([big, small]);
  const { patch: _, ...descriptor } = big;
  expect(cloud.findings[0]?.evidence).toMatchObject({
    details: {
      scanner_verdict: "EXPLOITABLE",
      code: { snippet: detailed.vulnerableCode },
    },
    source_data: {
      evidence_artifacts: [
        continuumEvidenceArtifact(row.issue.issueId),
        continuumValidationArtifact(),
      ],
      patches: [
        { ...descriptor, contentOmitted: "cloud_evidence_limit" },
        small,
      ],
    },
  });

  const normalized = normalize(report);
  normalized.findings[0]!.evidence.details!.repository!.url =
    "https://github.com/example/other";
  await expect(fixture.prepareNormalized(normalized)).rejects.toThrow(
    /repository/i,
  );

  const legacy = continuumDetail();
  await fixture.writeJson(legacy);
  const legacyImport = await fixture.prepare({
    sourceRepositoryUrl: continuumRepository,
  });
  expect((await legacyImport.import()).counts.created).toBe(1);
  expect(
    new Set((await fixture.read()).map((finding) => finding.sourceFindingId)),
  ).toEqual(new Set([stored.sourceFindingId, legacy.findingArn]));
});

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

test("patch captures retain the native finding, exact patch bytes and AWS descriptors", () => {
  const finding = { ...continuumDetail(), createdIssueId: "oneissue" };
  const patch = patchArtifact(
    "firstpatch",
    "--- a/src/example.ts\n+++ b/src/example.ts\n@@ -1 +1 @@\n-// example\n+// café\n",
  );
  const plain = continuumSummary("two");
  const prior = normalize(finding).findings[0]!;
  const captured = normalize([{ finding, patches: [patch] }, plain]);
  expect(captured.excluded).toEqual([]);
  expect(captured.findings).toEqual([
    {
      ...prior,
      evidence: {
        ...prior.evidence,
        source_data: { ...prior.evidence.source_data, patches: [patch] },
      },
    },
    ...normalize(plain).findings,
  ]);
  expect(normalize({ finding, patches: [] })).toEqual(normalize(finding));
});

test("a broken patch capture excludes only its own finding", () => {
  const detail = continuumDetail();
  const linked = { ...detail, duplicateOfIssueId: "otherissue" };
  const patch = patchArtifact("firstpatch", "+ok\n");
  const plain = continuumSummary("two");
  for (const broken of [
    { finding: detail, patches: [patch] },
    {
      finding: linked,
      patches: [{ ...patch, sizeBytes: patch.sizeBytes + 1 }],
    },
    { finding: linked, patches: [{ ...patch, patch: "+no\n" }] },
  ]) {
    const result = normalize([broken, plain]);
    expect(result.excluded).toMatchObject([{ position: 1 }]);
    expect(result.findings).toEqual(normalize(plain).findings);
  }
});

test("Cloud publication of a stored capture keeps fitting patches and identifies oversized patch bodies", () => {
  const finding = { ...continuumDetail(), duplicateOfIssueId: "otherissue" };
  const big = patchArtifact("bigpatch", "+example\n".repeat(32 * 1024));
  const small = patchArtifact("smallpatch", "+ok\n");
  const input = { finding, patches: [big, small] };
  const local = normalizeContinuumFindings(input, continuumRepository, "local");
  expect(local.excluded).toEqual([]);
  const stored = local.findings[0]!;
  expect(stored.evidence.source_data?.["patches"]).toEqual([big, small]);

  const cloud = normalize(input);
  expect(cloud.excluded).toEqual([]);
  const { patch: _, ...descriptor } = big;
  expect(cloud.findings[0]!.evidence.source_data?.["patches"]).toEqual([
    { ...descriptor, contentOmitted: "cloud_evidence_limit" },
    small,
  ]);
  expect(
    projectStoredFinding(
      {
        provider: "continuum",
        sourceFindingId: stored.source_finding_id,
        evidence: stored.evidence,
      },
      [],
    ).findings,
  ).toEqual(cloud.findings);
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
  const original = normalize(finding).findings[0]!.evidence;
  original.source_updated_at = null;
  original.details!.weakness_ids = [];
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

test("Cloud reprojects packages and retains selected finding validation without a patch", () => {
  const valid = Array.from({ length: 101 }, (_, i) => ({
    name: `package-${i}`,
  }));
  const finding = {
    ...continuumSummary(),
    createdIssueId: "issue1",
    affectedPackages: [{ name: "界".repeat(200) }, ...valid],
  };
  const artifact = {
    ...continuumValidationArtifact(),
    body: {
      validationEvidence: {
        exploitable: "EXPLOITABLE",
        sourceAnalysis: { summary: "Example proof" },
      },
    },
  };
  const { issueId, issueArn } = continuumIssueExport().issues[0]!.issue;
  const validationIssue = {
    issueId,
    issueArn,
    findingIds: [finding.findingId],
  };
  const evidenceArtifacts = [
    artifact,
    { ...artifact, artifactId: "validation2", body: { raw: "Example proof" } },
  ];
  const report = { finding, evidenceArtifacts, validationIssue };
  const cloud = normalize(report);
  expect(cloud.excluded).toEqual([]);
  expect(cloud.findings[0]!.evidence.packages?.map((pkg) => pkg.name)).toEqual(
    valid.slice(0, 100).map((pkg) => pkg.name),
  );
  expect(cloud.findings[0]!.evidence.source_data?.["finding"]).toEqual(finding);
  const local = normalizeContinuumFindings(
    report,
    continuumRepository,
    "local",
  );
  const stored = local.findings[0]!;
  expect(stored.evidence.packages).toHaveLength(102);
  for (const evidence of [stored.evidence, cloud.findings[0]!.evidence]) {
    expect(evidence.source_data?.["evidence_artifacts"]).toEqual(
      evidenceArtifacts,
    );
    expect(evidence.source_data?.["validation_issue"]).toEqual(validationIssue);
  }
  expect(
    projectStoredFinding(
      {
        provider: "continuum",
        sourceFindingId: stored.source_finding_id,
        evidence: stored.evidence,
      },
      [],
    ).findings,
  ).toEqual(cloud.findings);
});

test("a selected capture keeps its patches and omits issue-wide proof without a matching single-finding issue", () => {
  const { issueId, issueArn } = continuumIssueExport().issues[0]!.issue;
  const finding = { ...continuumDetail(), duplicateOfIssueId: issueId };
  const report = { finding, patches: [patchArtifact("firstpatch", "+ok\n")] };
  const expected = normalizeContinuumFindings(
    report,
    continuumRepository,
    "local",
  );
  expect(expected.excluded).toEqual([]);
  expect(expected.findings[0]!.evidence.source_data?.["patches"]).toEqual(
    report.patches,
  );
  const artifact = continuumValidationArtifact();
  const evidenceArtifacts = [
    { ...artifact, body: { validationEvidence: { exploitable: "UNCERTAIN" } } },
    { ...artifact, artifactId: "validation2", body: { raw: "Example proof" } },
  ];
  const single = { issueArn, issueId, findingIds: [finding.findingId] };
  for (const validationIssue of [
    undefined,
    {
      ...single,
      issueId: "other",
      issueArn: issueArn.replace(issueId, "other"),
    },
    { ...single, issueArn: issueArn.replace("us-east-1", "us-west-2") },
    { ...single, findingIds: ["two"] },
    { ...single, findingIds: [finding.findingId, "two"] },
  ]) {
    const capture = { ...report, evidenceArtifacts, validationIssue };
    expect(
      normalizeContinuumFindings(capture, continuumRepository, "local"),
    ).toEqual(expected);
  }
});

test.each(["plain finding", "patch capture"])(
  "Cloud imports a %s that fits only without the derived package list",
  (format) => {
    const finding = {
      ...continuumSummary(),
      createdIssueId: "oneissue",
      affectedPackages: [
        { name: "example", version: "1.0.0", packageManager: "npm" },
      ],
      padding: "",
    };
    const patches = [patchArtifact("firstpatch", "+checkedExample(input)\n")];
    const report = format === "patch capture" ? { finding, patches } : finding;
    const base = normalize(report).findings[0]!.evidence;
    base.packages = [];
    base.source_updated_at = null;
    const bytes = Buffer.byteLength(JSON.stringify(base));
    finding.padding = "x".repeat(256 * 1024 - bytes);
    const result = normalize(report);
    expect(result.excluded).toEqual([]);
    expect(result.findings[0]!.evidence.packages).toEqual([]);
    expect(result.findings[0]!.evidence.source_data?.["finding"]).toEqual(
      finding,
    );
    expect(result.findings[0]!.evidence.source_data?.["patches"]).toEqual(
      format === "patch capture" ? patches : undefined,
    );
    finding.padding = finding.padding.slice(10);
    const withTimestamp = normalize(report);
    expect(withTimestamp.findings[0]!.evidence).toMatchObject({
      packages: [],
      source_updated_at: Date.parse(finding.statusUpdatedAt) / 1000,
      source_data: { finding },
    });
  },
);

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
    const finding = { ...continuumDetail(), createdIssueId: "oneissue" };
    const patches = [patchArtifact("firstpatch", "+checkedExample(input)\n")];
    const artifact = continuumValidationArtifact();
    await writeFile(
      fixture.file,
      gzipSync(
        JSON.stringify({ finding, patches, evidenceArtifacts: [artifact] }),
      ),
    );
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
    expect(updated.evidence.source_data?.["patches"]).toEqual(patches);
    expect(updated.evidence.source_data?.["evidence_artifacts"]).toEqual([
      {
        ...artifact,
        body: {
          validationEvidence: {
            exploitable: "EXPLOITABLE",
            perFindingResults: [
              { findingId: finding.findingId, exploitable: "EXPLOITABLE" },
            ],
          },
        },
      },
    ]);
    await expect(
      fixture.prepare({
        sourceRepositoryUrl: "https://github.com/example/other",
      }),
    ).rejects.toThrow(/repository|remote/i);
  } finally {
    await fixture.dispose();
  }
});
