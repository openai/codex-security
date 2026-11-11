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
import { createHash } from "node:crypto";
import { mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";

const repositoryUrl = "https://github.com/example/repo";
// The checkout fixture writes empty files, as FCS scanned them.
const emptyFile = createHash("sha256").update("").digest("hex");
const detection = {
  file: "infra/net/main.tf",
  file_sha256: emptyFile,
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
      file_sha256: emptyFile,
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

// The scanned files exist in the checkout, as they do after a scan from its root.
async function checkout() {
  const fixture = await localReportFixture("fcs-iac.json", source, {
    remote: repositoryUrl + ".git",
  });
  await mkdir(join(fixture.repository, "infra", "net"), { recursive: true });
  for (const file of ["infra/net/main.tf", "infra/provider.tf"])
    await writeFile(join(fixture.repository, ...file.split("/")), "");
  return fixture;
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

const revision = "0123456789abcdef0123456789abcdef01234567";
const scanned = "git::https://github.com/example/repo.git//infra";
// FCS writes git:: files, module sources and call sites from the scan root after
// a slash. For a URL with a user name, it writes them after the scanned path,
// and only `flags.path` keeps the user name and token.
test.each([
  ["a slash", `${scanned}?ref=${revision}`, ""],
  [
    "the scanned path",
    `git::https://example:synthetic-token@github.com/example/repo.git//infra?ref=${revision}`,
    scanned,
  ],
])(
  "git:: reports after %s keep module lines and record the scanned repository",
  async (_, given, root) => {
    await using fixture = await checkout();
    const call = `called by ${root}/main.tf at line 8.`;
    await fixture.writeJson({
      ...report,
      path: `${scanned}?ref=${revision}`,
      flags: { path: given },
      rule_detections: [
        {
          ...misconfiguration,
          detections: [
            {
              ...detection,
              file: `${root}/modules/example/main.tf`,
              line: 12,
              module_path: "example",
              module_source: `${root}/modules/example`,
              is_from_module: true,
              module_remediation: `This finding originates in module "${root}/modules/example", ${call}`,
            },
            {
              ...detection,
              file: `${root}/main.tf`,
              line: 1,
              module_path: "registry",
              module_source: "example/sg/aws",
              is_from_module: true,
              module_remediation: `This finding originates in module "example/sg/aws", ${call}`,
            },
          ],
        },
      ],
    });
    const result = await readCrowdStrikeFindings(fixture.file);
    expect(result.excluded).toEqual([]);
    expect(result.findings.map(({ evidence }) => evidence.locations)).toEqual([
      [{ path: "modules/example/main.tf", line: 12 }],
      [{ path: "main.tf", line: 8 }],
    ]);
    const repository = "https://github.com/example/repo.git";
    expect(result.report).toMatchObject({ git_scan: scanned });
    expect(result.report).not.toHaveProperty("repositoryUrl");
    expect(result.findings[0]!.evidence).toMatchObject({
      details: { kind: "iac", repository: { url: repository } },
      source_data: { repository_url: repository, git_scan: scanned },
    });
    expect(JSON.stringify(result)).not.toContain("synthetic-token");
  },
);

test.each([
  "git::ssh://git@github.com/example/repo.git",
  "git::http://github.com/example/repo.git",
])("a %s report imports without a scanned repository", async (path) => {
  await using fixture = await checkout();
  await fixture.writeJson({
    ...report,
    path,
    rule_detections: [
      {
        ...misconfiguration,
        detections: [{ ...detection, file: "/infra/net/main.tf" }],
      },
    ],
  });
  const { findings, report: read } = await readCrowdStrikeFindings(
    fixture.file,
  );
  expect(findings[0]!.evidence.locations).toEqual([
    { path: "infra/net/main.tf", line: 7 },
  ]);
  expect(findings[0]!.evidence.details).toBeUndefined();
  expect(read).not.toHaveProperty("repositoryUrl");
});

test("a git:: report's repository must agree with a declared URL", async () => {
  await using fixture = await checkout();
  const scan = (repository: string) =>
    fixture.writeJson({
      ...report,
      path: `git::https://github.com/example/${repository}.git`,
      rule_detections: [
        {
          ...misconfiguration,
          detections: [{ ...detection, file: "/infra/net/main.tf" }],
        },
      ],
    });
  await scan("repo");
  await fixture.prepare();
  await scan("upstream");
  await expect(fixture.prepare()).rejects.toThrow(/different repository/u);
  await fixture.writeJson({
    ...report,
    path: "git::https://github.com/example/upstream.git",
    rule_detections: [],
  });
  await expect(fixture.prepare()).rejects.toThrow(/different repository/u);
  await scan("upstream");
  // Without a declared URL, the scanned repository is recorded but does not bind the checkout.
  const { preview } = await fixture.prepare({ sourceRepositoryUrl: undefined });
  expect(preview.excluded).toEqual([]);
  expect(preview.findings[0]!.evidence.details?.repository?.url).toBe(
    "https://github.com/example/upstream.git",
  );
  await expect(fixture.prepareNormalized(preview)).rejects.toThrow(
    /different repository/u,
  );
  const replay = (input: typeof preview) =>
    prepareNormalizedLocalImport(
      input,
      {
        provider: "crowdstrike",
        sourceKey: source.sourceKey,
        repository: fixture.repository,
      },
      { environment: fixture.environment },
    );
  await replay(preview);
  const relabeled = structuredClone(preview);
  relabeled.findings[0]!.evidence.source_data!["git_scan"] =
    "git::https://github.com/example/repo.git";
  await expect(replay(relabeled)).rejects.toThrow(/different repository/u);
  await writeFile(join(fixture.repository, "infra", "net", "main.tf"), "\n");
  await expect(replay(preview)).rejects.toThrow(/changed after the FCS scan/u);
});

test("registry module detections use the call line that FCS reports for the module", async () => {
  await using fixture = await checkout();
  const call = (line: number) =>
    `This finding originates in module "example/sg/aws" (version 1.0.0), called by main.tf at line ${line}. To remediate, update the module.`;
  const registry = {
    ...detection,
    file: "main.tf",
    line: 1,
    module_path: "first_sg",
    module_source: "example/sg/aws",
    module_version: "1.0.0",
    is_from_module: true,
    module_remediation: call(5),
  };
  await fixture.writeJson({
    ...report,
    rule_detections: [
      {
        ...misconfiguration,
        detections: [
          registry,
          {
            ...registry,
            module_path: "second_sg",
            module_remediation: call(9),
          },
          {
            ...registry,
            module_path: "third_sg",
            module_remediation: "Update it.",
          },
          {
            ...detection,
            file: "modules/sg/main.tf",
            module_path: "local_sg",
            module_source: "modules/sg",
            is_from_module: true,
            module_remediation: call(1),
          },
        ],
      },
    ],
  });
  const { findings, excluded } = await readCrowdStrikeFindings(
    fixture.file,
    repositoryUrl,
  );
  expect(excluded).toEqual([]);
  expect(findings.map(({ evidence }) => evidence.locations)).toEqual([
    [{ path: "main.tf", line: 5 }],
    [{ path: "main.tf", line: 9 }],
    [{ path: "main.tf", line: null }],
    [{ path: "modules/sg/main.tf", line: 7 }],
  ]);
  expect(findings[0]!.evidence.details?.remediation_instructions).toBe(
    `${detection.recommendation}\n\n${call(5)}`,
  );
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

test("a plain directory imports without Git or a repository URL", async () => {
  await using fixture = await checkout();
  await fixture.writeJson(single);
  await rm(join(fixture.repository, ".git"), { recursive: true });
  const { preview } = await fixture.prepare({ sourceRepositoryUrl: undefined });
  expect(preview.excluded).toEqual([]);
  const { evidence } = preview.findings[0]!;
  expect(evidence.details).toBeUndefined();
  expect(evidence.locations).toEqual([{ path: "infra/net/main.tf", line: 7 }]);
  expect(evidence.source_data).toMatchObject({
    fcs_version: "4.2.3",
    detection,
  });
  expect(evidence.source_data).not.toHaveProperty("repository_url");
  // Without Git there are no remotes to compare, so the URL is retained as supplied.
  const bound = await fixture.prepare();
  expect(bound.preview.findings[0]!.evidence.details?.repository).toMatchObject(
    {
      url: repositoryUrl,
    },
  );
});

test("imports check the checkout files and repository claims, even for empty selections", async () => {
  await using fixture = await checkout();
  await fixture.writeJson(single);
  const { preview } = await fixture.prepare();
  await rm(join(fixture.repository, "infra", "net", "main.tf"));
  await expect(fixture.prepare()).rejects.toThrow(
    /"infra\/net\/main\.tf" is not in .*run the FCS CLI from its root/u,
  );
  await expect(fixture.prepareNormalized(preview)).rejects.toThrow(
    /is not in/u,
  );
  await writeFile(join(fixture.repository, "infra", "net", "main.tf"), "\n");
  await expect(fixture.prepare()).rejects.toThrow(
    /"infra\/net\/main\.tf" changed after the FCS scan/u,
  );
  await expect(fixture.prepareNormalized(preview)).rejects.toThrow(
    /changed after the FCS scan/u,
  );
  await writeFile(join(fixture.repository, "infra", "net", "main.tf"), "");
  // FCS follows a file symlink and records the hash of its target.
  const target = join(fixture.root, "shared.tf");
  await writeFile(target, "");
  await rm(join(fixture.repository, "infra", "net", "main.tf"));
  await symlink(target, join(fixture.repository, "infra", "net", "main.tf"));
  await fixture.prepare();
  const otherUrl = "https://github.com/example/other";
  const wrongReport = structuredClone(preview);
  wrongReport.report!["repositoryUrl"] = otherUrl;
  await expect(fixture.prepareNormalized(wrongReport)).rejects.toThrow(
    /different repository/u,
  );
  const wrongRow = structuredClone(preview);
  wrongRow.findings[0]!.evidence.source_data!["repository_url"] = otherUrl;
  await expect(fixture.prepareNormalized(wrongRow)).rejects.toThrow(
    /different repository/u,
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
    await expect(fixture.prepare()).rejects.toThrow(/fetch remote/u);
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
