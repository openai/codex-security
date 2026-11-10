import { expect, mock, test } from "bun:test";
import { main } from "../src/cli.js";
import { readCrowdStrikeFindings } from "../src/crowdstrike-findings.js";
import {
  type NormalizedExternalPublicationOptions,
  prepareExternalPublication,
  prepareNormalizedExternalPublication,
} from "../src/external-findings-publish.js";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import { dependencies as cliDependencies } from "./cli-fixtures.js";
import {
  createAndReplayFinding,
  localReportFixture,
  updateStoredFinding,
} from "./external-findings-local-helpers.js";
import { createCliTest } from "./support/cli-run.js";

const repositoryUrl = "https://github.com/example/repo";
const detection = {
  file: "infra/net/main.tf",
  file_sha256: "0".repeat(64),
  line: 7,
  resource_type: "aws_security_group",
  resource_name: "example",
  issue_type: "IncorrectValue",
  reason: "aws_security_group[example] 'SSH' (Port:22) is public",
  recommendation:
    "aws_security_group[example] 'SSH' (Port:22) should not be public",
};
const misconfiguration = {
  rule_name: "Example Sensitive Port Is Exposed",
  rule_uuid: "10000000-0000-4000-8000-000000000001",
  rule_category: "Networking and Firewall",
  description: "Example rule description",
  severity: "High",
  platform: "Terraform",
  cloud_provider: "AWS",
  service: "EC2",
  rule_type: "Example",
  detections: [detection],
};
const secret = {
  rule_name: "Passwords And Secrets - Example Access Key",
  rule_uuid: "20000000-0000-4000-8000-000000000002",
  rule_category: "Secret Management",
  description: "Example secret description",
  severity: "Critical",
  platform: "Generic",
  cloud_provider: "common",
  service: "common",
  rule_type: "Example",
  detections: [
    {
      file: "infra/provider.tf",
      file_sha256: "1".repeat(64),
      line: 3,
      resource_type: null,
      resource_name: null,
      issue_type: "RedundantAttribute",
      reason: "Hardcoded secret key appears in source",
      recommendation: "Hardcoded secret key should not appear in source",
    },
  ],
};
const report = {
  fcs_version: "4.2.3",
  path: ".",
  project_name: "",
  scan_type: "Local",
  scan_uuid: "30000000-0000-4000-8000-000000000003",
  scan_performed_at: "2026-11-10T12:00:00Z",
  rule_detections: [misconfiguration, secret],
  detection_summary: {},
  stats: {},
};
const source = {
  provider: "crowdstrike",
  sourceKey: "example/crowdstrike/repo",
  sourceRepositoryUrl: repositoryUrl,
} as const;

function checkout() {
  return localReportFixture("fcs-iac.json", source, {
    remote: repositoryUrl + ".git",
  });
}

test("the reader maps misconfigurations and secrets to typed IaC evidence", async () => {
  await using fixture = await checkout();
  await fixture.writeJson(report);
  const { findings, excluded } = await readCrowdStrikeFindings(
    fixture.file,
    repositoryUrl,
  );
  expect(excluded).toEqual([]);
  expect(findings).toHaveLength(2);
  const { detections: _, ...rule } = misconfiguration;
  expect(findings[0]!.evidence).toMatchObject({
    title: misconfiguration.rule_name,
    severity: "high",
    description: `${misconfiguration.description}\n\n${detection.reason}`,
    locations: [{ path: "infra/net/main.tf", line: 7 }],
    source_scan_id: report.scan_uuid,
    details: {
      kind: "iac",
      repository: { url: repositoryUrl },
      rule: {
        id: misconfiguration.rule_uuid,
        name: misconfiguration.rule_name,
      },
      configuration: {
        platform: "Terraform",
        cloud_platform: "AWS",
        expected: detection.recommendation,
        actual: detection.reason,
      },
      remediation_instructions: detection.recommendation,
      scanner_origin: "CrowdStrike FCS CLI 4.2.3",
    },
    source_data: { repository_url: repositoryUrl, rule, detection },
  });
  expect(findings[1]!.evidence).toMatchObject({
    severity: "critical",
    locations: [{ path: "infra/provider.tf", line: 3 }],
    details: { kind: "secret", configuration: null },
  });
  expect(findings[0]!.source_finding_id).toMatch(/^crowdstrike:[a-f0-9]{64}$/u);
});

test("detections that differ only by line remain separate findings", async () => {
  await using fixture = await checkout();
  const [first] = secret.detections;
  await fixture.writeJson({
    ...report,
    rule_detections: [
      { ...secret, detections: [first, { ...first, line: 7 }] },
    ],
  });
  const { findings, excluded } = await readCrowdStrikeFindings(
    fixture.file,
    repositoryUrl,
  );
  expect(excluded).toEqual([]);
  expect(findings.map(({ evidence }) => evidence.locations)).toEqual([
    [{ path: "infra/provider.tf", line: 3 }],
    [{ path: "infra/provider.tf", line: 7 }],
  ]);
});

test("a remote git scan reports paths from the clone root", async () => {
  await using fixture = await checkout();
  await fixture.writeJson({
    ...report,
    path: "git::https://github.com/example/repo.git",
    rule_detections: [
      {
        ...misconfiguration,
        detections: [{ ...detection, file: "/infra/net/main.tf" }],
      },
    ],
  });
  const { findings } = await readCrowdStrikeFindings(
    fixture.file,
    repositoryUrl,
  );
  expect(findings[0]!.evidence.locations).toEqual([
    { path: "infra/net/main.tf", line: 7 },
  ]);
});

test("the reader rejects legacy reports and excludes paths outside the checkout", async () => {
  await using fixture = await checkout();
  await fixture.writeJson({ fcs_version: "1.0.0", violations: [] });
  await expect(
    readCrowdStrikeFindings(fixture.file, repositoryUrl),
  ).rejects.toThrow(/FCS CLI 4\.x IaC JSON report/u);
  await fixture.writeJson({
    ...report,
    rule_detections: [
      {
        ...misconfiguration,
        detections: [
          { ...detection, file: "/tmp/checkout/main.tf" },
          { ...detection, file: "../other/main.tf" },
          { ...detection, file: "C:\\checkout\\main.tf" },
        ],
      },
    ],
  });
  const { findings, excluded } = await readCrowdStrikeFindings(
    fixture.file,
    repositoryUrl,
  );
  expect(findings).toEqual([]);
  expect(excluded.map(({ reason }) => reason)).toEqual(
    Array(3).fill(expect.stringContaining("checkout root")),
  );
});

const single = { ...report, rule_detections: [misconfiguration] };

test("the CLI preview can be saved, replayed and updated with its original identity", async () => {
  await using fixture = await checkout();
  await fixture.writeJson(single);
  const cli = createCliTest(main);
  const code = await cli.runCli(
    [
      "publish",
      "findings",
      fixture.file,
      "--provider=crowdstrike",
      "--to=local",
      `--repository=${fixture.repository}`,
      `--source-repository-url=${repositoryUrl}`,
      `--source-key=${source.sourceKey}`,
      "--dry-run",
      "--format=json",
    ],
    cliDependencies({ environment: fixture.environment }),
  );
  expect(code, cli.stderr.text() || cli.stdout.text()).toBe(0);
  const preview = JSON.parse(cli.stdout.text());
  expect(preview.source).toEqual({
    provider: "crowdstrike",
    source_key: source.sourceKey,
  });
  const saved = await createAndReplayFinding(fixture, preview);
  expect(saved.provider).toBe("crowdstrike");
  expect(saved.evidence.locations).toEqual([
    { path: "infra/net/main.tf", line: 7 },
  ]);
  await fixture.writeJson({
    ...single,
    rule_detections: [{ ...misconfiguration, severity: "Medium" }],
  });
  expect((await updateStoredFinding(fixture, saved)).evidence.severity).toBe(
    "medium",
  );
});

test("file and normalized imports verify the repository, even for empty selections", async () => {
  await using fixture = await checkout();
  await fixture.writeJson(single);
  await expect(
    fixture.prepare({ sourceRepositoryUrl: undefined }),
  ).rejects.toThrow(/repository/i);
  const otherUrl = "https://github.com/example/other";
  const { preview } = await fixture.prepare();
  const wrongReport = structuredClone(preview);
  wrongReport.report!["repositoryUrl"] = otherUrl;
  await expect(fixture.prepareNormalized(wrongReport)).rejects.toThrow(
    /repository/i,
  );
  const wrongRow = structuredClone(preview);
  wrongRow.findings[0]!.evidence.source_data!["repository_url"] = otherUrl;
  await expect(fixture.prepareNormalized(wrongRow)).rejects.toThrow(
    /repository/i,
  );
  await expect(
    prepareNormalizedLocalImport(
      preview,
      {
        provider: "wiz",
        sourceKey: source.sourceKey,
        repository: fixture.repository,
      },
      { environment: fixture.environment },
    ),
  ).rejects.toThrow(/crowdstrike provider/i);
  fixture.git("remote", "set-url", "origin", otherUrl);
  for (const rule_detections of [[misconfiguration], []]) {
    await fixture.writeJson({ ...report, rule_detections });
    await expect(fixture.prepare()).rejects.toThrow(/remote|checkout/i);
  }
});

test("Cloud rejects local CrowdStrike findings before file access or credential lookup", async () => {
  await using fixture = await checkout();
  const options = { ...source, repository: fixture.repository };
  const unexpected = mock(async () => {
    throw new Error("Unexpected Cloud call");
  });
  const deps = {
    environment: fixture.environment,
    fetch: unexpected,
    credentials: unexpected,
  };
  // JavaScript callers may supply a local provider despite the SDK's Cloud types.
  const cloudOptions =
    options as unknown as NormalizedExternalPublicationOptions;
  const empty = { read: 0, findings: [], excluded: [] };
  await expect(
    prepareExternalPublication(fixture.file, cloudOptions, deps),
  ).rejects.toThrow(/local/i);
  await expect(
    prepareNormalizedExternalPublication(empty, cloudOptions, deps),
  ).rejects.toThrow(/local/i);
  await fixture.writeJson(single);
  const { preview } = await fixture.prepare();
  const relabeled = { ...options, provider: "wiz" as const };
  await expect(
    prepareNormalizedExternalPublication(preview, relabeled, deps),
  ).rejects.toThrow(/local/i);
  expect(unexpected).not.toHaveBeenCalled();
});
